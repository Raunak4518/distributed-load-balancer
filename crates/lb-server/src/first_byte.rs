//! Bounds the gap between a connection being ready and its first byte.
//!
//! HTTP/1.1 has `header_read_timeout` for this. HTTP/2 has nothing: hyper's
//! PING keep-alive is only armed once the client's preface and SETTINGS have
//! arrived (`hyper::proto::h2::server`, where `ping::channel` is built after
//! `State::Handshaking` resolves), so a client that negotiates `h2` over ALPN
//! and then goes silent is never timed out — it just holds its connection
//! permit and its per-IP slot forever. That is slowloris one layer up from
//! the one Phase 5 eliminated, and the layer above the TLS window Phase 6's
//! `handshake_timeout` closed.
//!
//! The deadline is armed at construction and disarmed by the first byte that
//! actually arrives. After that this is a transparent pass-through: an idle
//! *established* connection is normal, and policing that one is hyper's PING
//! settings, not ours.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct FirstByteDeadline<S> {
    inner: S,
    /// `None` once the first byte has arrived — the deadline is spent, and
    /// this is the flag as well as the timer.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FirstByteDeadline<S> {
    pub fn new(inner: S, within: Duration) -> Self {
        FirstByteDeadline {
            inner,
            timer: Some(Box::pin(tokio::time::sleep(within))),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstByteDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Polled before the inner read, so the timer's waker is registered
        // even when the inner stream parks. A stream that never becomes
        // readable is exactly the case this exists for, and it would never
        // wake us on its own.
        if let Some(timer) = me.timer.as_mut() {
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no data before the first-byte deadline",
                )));
            }
        }

        let before = buf.filled().len();
        let polled = Pin::new(&mut me.inner).poll_read(cx, buf);
        // Bytes, not readiness: a `Ready(Ok(()))` that filled nothing is EOF,
        // and a peer that connects and immediately half-closes has not
        // started sending anything. Dropping the timer also drops its
        // registration in the timer wheel.
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            me.timer = None;
        }
        polled
    }
}

/// Writes are none of this adapter's business, so every method delegates
/// unchanged. The deadline is about what the client sends, and the server
/// writes nothing before the client's preface anyway.
impl<S: AsyncWrite + Unpin> AsyncWrite for FirstByteDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    /// Must mirror the inner stream rather than return a constant: hyper
    /// picks between `poll_write` and `poll_write_vectored` on this answer,
    /// and getting it wrong costs a syscall per frame.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A peer that completed the handshake and then said nothing. It never
    /// registers a waker, so only the deadline can end the read.
    struct NeverReady;

    impl AsyncRead for NeverReady {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// A peer that starts sending and then stalls — an established
    /// connection going quiet, which is not this adapter's problem.
    struct OneByteThenStall {
        sent: bool,
    }

    impl AsyncRead for OneByteThenStall {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.sent {
                return Poll::Pending;
            }
            me.sent = true;
            buf.put_slice(b"P");
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_never_speaks_is_timed_out() {
        let mut stream = FirstByteDeadline::new(NeverReady, Duration::from_millis(300));
        let mut buf = [0u8; 8];

        let err = stream
            .read(&mut buf)
            .await
            .expect_err("a silent stream must not read successfully");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_byte_disarms_the_deadline() {
        let mut stream =
            FirstByteDeadline::new(OneByteThenStall { sent: false }, Duration::from_millis(300));
        let mut buf = [0u8; 8];

        assert_eq!(stream.read(&mut buf).await.unwrap(), 1);

        // Far past the deadline. If the timer were still armed this would
        // resolve to a `TimedOut` error rather than staying pending, and an
        // ordinary idle keep-alive connection would be killed mid-life.
        let stalled = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf)).await;
        assert!(
            stalled.is_err(),
            "the first byte should have disarmed the deadline, but the read resolved: {stalled:?}"
        );
    }

    /// EOF is `Ready(Ok(()))` with nothing filled. A peer that connects and
    /// immediately half-closes has not started sending, so readiness alone
    /// must not spend the deadline -- which is why the check above is on
    /// bytes filled, not on the `Poll` result.
    #[tokio::test(start_paused = true)]
    async fn end_of_stream_does_not_count_as_the_first_byte() {
        struct Eof;

        impl AsyncRead for Eof {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut stream = FirstByteDeadline::new(Eof, Duration::from_millis(300));
        let mut buf = [0u8; 8];

        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        assert!(
            stream.timer.is_some(),
            "a read that filled no bytes must leave the deadline armed"
        );
    }
}
