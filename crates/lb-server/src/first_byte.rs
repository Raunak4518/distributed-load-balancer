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
//! The deadline is armed at construction and disarmed only once the client's
//! 24-byte connection preface and its complete first frame (the SETTINGS frame
//! RFC 9113 requires next) have been read. Disarming on the first byte instead
//! would let a client send one byte and then hold the connection forever.
//! After that this is a transparent pass-through: an idle *established*
//! connection is normal, and policing that one is hyper's PING settings, not
//! ours.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct FirstByteDeadline<S> {
    inner: S,
    /// `None` once the preface and first frame have arrived — the deadline
    /// is spent, and this is the flag as well as the timer.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    fired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    head: Vec<u8>,
    read: usize,
    needed: Option<usize>,
}

const PREFACE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 9;
const HEAD_LEN: usize = PREFACE_LEN + FRAME_HEADER_LEN;

impl<S> FirstByteDeadline<S> {
    pub fn new(inner: S, within: Duration) -> Self {
        FirstByteDeadline {
            inner,
            timer: Some(Box::pin(tokio::time::sleep(within))),
            fired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            head: Vec::with_capacity(HEAD_LEN),
            read: 0,
            needed: None,
        }
    }

    fn observe(&mut self, new: &[u8]) {
        self.read += new.len();
        if self.head.len() < HEAD_LEN {
            let take = (HEAD_LEN - self.head.len()).min(new.len());
            self.head.extend_from_slice(&new[..take]);
        }
        if self.needed.is_none() && self.head.len() == HEAD_LEN {
            let length = (usize::from(self.head[PREFACE_LEN]) << 16)
                | (usize::from(self.head[PREFACE_LEN + 1]) << 8)
                | usize::from(self.head[PREFACE_LEN + 2]);
            self.needed = Some(HEAD_LEN + length);
        }
        if self.needed.is_some_and(|needed| self.read >= needed) {
            self.timer = None;
        }
    }

    pub fn fired_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.fired)
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
                me.fired.store(true, std::sync::atomic::Ordering::Relaxed);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP/2 preface and SETTINGS not received before the deadline",
                )));
            }
        }

        let before = buf.filled().len();
        let polled = Pin::new(&mut me.inner).poll_read(cx, buf);
        // Bytes, not readiness: a `Ready(Ok(()))` that filled nothing is EOF,
        // and a peer that connects and immediately half-closes has not
        // started sending anything. Dropping the timer also drops its
        // registration in the timer wheel.
        if matches!(polled, Poll::Ready(Ok(()))) && me.timer.is_some() {
            let filled = buf.filled()[before..].to_vec();
            me.observe(&filled);
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

    struct SendsThenStalls {
        data: Vec<u8>,
        sent: bool,
    }

    impl AsyncRead for SendsThenStalls {
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
            buf.put_slice(&me.data);
            Poll::Ready(Ok(()))
        }
    }

    fn preface_and_settings(settings_payload: usize) -> Vec<u8> {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        let len = settings_payload as u32;
        bytes.extend_from_slice(&[
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            0x4,
            0,
            0,
            0,
            0,
            0,
        ]);
        bytes.extend(std::iter::repeat_n(0u8, settings_payload));
        bytes
    }

    async fn stalls_past_the_deadline(data: Vec<u8>) -> bool {
        let mut stream = FirstByteDeadline::new(
            SendsThenStalls { data, sent: false },
            Duration::from_millis(300),
        );
        let mut buf = vec![0u8; 256];
        let _ = stream.read(&mut buf).await;
        let second = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf)).await;
        matches!(second, Ok(Err(ref err)) if err.kind() == io::ErrorKind::TimedOut)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_never_speaks_is_timed_out() {
        let mut stream = FirstByteDeadline::new(NeverReady, Duration::from_millis(300));
        let fired = stream.fired_flag();
        let mut buf = [0u8; 8];

        let err = stream
            .read(&mut buf)
            .await
            .expect_err("a silent stream must not read successfully");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(fired.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn one_byte_does_not_disarm_the_deadline() {
        assert!(stalls_past_the_deadline(b"P".to_vec()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_preface_without_its_settings_frame_does_not_disarm_the_deadline() {
        let mut partial = preface_and_settings(12);
        partial.truncate(PREFACE_LEN + FRAME_HEADER_LEN + 6);
        assert!(stalls_past_the_deadline(partial).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_complete_preface_and_settings_frame_disarms_the_deadline() {
        assert!(!stalls_past_the_deadline(preface_and_settings(12)).await);
        assert!(!stalls_past_the_deadline(preface_and_settings(0)).await);
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
