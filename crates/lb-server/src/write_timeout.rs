//! Bounds how long a write may take once the connection is established.
//!
//! Phase 5 closed every *read*-side slowloris gap: `header_read_timeout`
//! (HTTP/1.1 head), `body_read_timeout` (request body), and
//! `FirstByteDeadline` (HTTP/2's equivalent, see `first_byte.rs`). None of
//! them bound the opposite direction. A client that sends a perfectly normal
//! request and then reads the response one byte at a time -- or stops
//! reading altogether once its TCP receive window fills -- can hold this
//! connection's task, its connection-limit permit, and its per-IP slot open
//! indefinitely: hyper's server has no write timeout of its own, and nothing
//! else on this path watches the write side at all.
//!
//! Unlike `FirstByteDeadline`, which is a one-shot deadline armed at
//! construction and permanently disarmed by the first byte, this is a
//! continuous *idle* timeout in the same spirit as `lb_tcp::pump`'s read
//! timeout: the clock resets on every write that makes progress, so a
//! slow-but-steady client is never punished, only a genuinely stalled one.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct WriteIdleTimeout<S> {
    inner: S,
    timeout: Duration,
    timer: Pin<Box<tokio::time::Sleep>>,
}

impl<S> WriteIdleTimeout<S> {
    pub fn new(inner: S, timeout: Duration) -> Self {
        WriteIdleTimeout {
            inner,
            timeout,
            timer: Box::pin(tokio::time::sleep(timeout)),
        }
    }
}

/// Reads are none of this adapter's business -- the mirror image of
/// `FirstByteDeadline`, which polices reads and passes writes through
/// unchanged.
impl<S: AsyncRead + Unpin> AsyncRead for WriteIdleTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteIdleTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        // Polled before the inner write, so the timer's waker is registered
        // even when the inner stream parks -- a write that never becomes
        // possible is exactly the case this exists for, and it would never
        // wake us on its own (same reasoning as `FirstByteDeadline::poll_read`).
        if me.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "write idle timeout",
            )));
        }

        let polled = Pin::new(&mut me.inner).poll_write(cx, buf);
        if polled.is_ready() {
            // Progress, or a definitive error that will end the connection
            // regardless -- either way this write is no longer stuck, so
            // push the deadline back out. `reset` reuses the existing
            // timer-wheel registration rather than reallocating.
            me.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + me.timeout);
        }
        polled
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();

        if me.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "write idle timeout",
            )));
        }

        let polled = Pin::new(&mut me.inner).poll_write_vectored(cx, bufs);
        if polled.is_ready() {
            me.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + me.timeout);
        }
        polled
    }

    /// Must mirror the inner stream rather than return a constant, same
    /// reasoning as `FirstByteDeadline::is_write_vectored`: hyper picks
    /// between `poll_write` and `poll_write_vectored` on this answer.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// Flush and shutdown are not the stall this adapter exists for -- a
    /// stuck `poll_write` is the actual failure mode (an unread response
    /// body), so these pass through unchanged rather than doubling up on
    /// the timeout.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A peer whose socket never becomes writable -- a full TCP receive
    /// window from a client that has stopped reading. It never registers a
    /// waker, so only the deadline can end the write.
    struct NeverWritable;

    impl AsyncRead for NeverWritable {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for NeverWritable {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A peer that accepts one write and then stalls -- an established
    /// connection whose client has gone quiet mid-response, not mid-first-byte.
    struct OneWriteThenStall {
        accepted: bool,
    }

    impl AsyncRead for OneWriteThenStall {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for OneWriteThenStall {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            if me.accepted {
                return Poll::Pending;
            }
            me.accepted = true;
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_never_completes_is_timed_out() {
        let mut stream = WriteIdleTimeout::new(NeverWritable, Duration::from_millis(300));

        let err = stream
            .write_all(b"hello")
            .await
            .expect_err("a write to a socket that never drains must not succeed");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_that_stalls_after_the_first_one_is_timed_out() {
        let mut stream = WriteIdleTimeout::new(
            OneWriteThenStall { accepted: false },
            Duration::from_millis(300),
        );

        // The first write succeeds and resets the deadline...
        stream.write_all(b"first").await.unwrap();

        // ...but the second stalls, and only the (freshly reset) deadline
        // can end it.
        let err = stream
            .write_all(b"second")
            .await
            .expect_err("the second write must not succeed once the peer stalls");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// The whole point of an *idle* timeout rather than a flat deadline:
    /// total lifetime far exceeds the timeout, but no single gap between
    /// writes does, so this must succeed -- mirrors `pump.rs`'s
    /// `idle_timer_resets_on_activity` test on the read side.
    #[tokio::test(start_paused = true)]
    async fn a_steady_trickle_of_writes_never_times_out() {
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);
        let mut stream = WriteIdleTimeout::new(sink_tx, Duration::from_secs(5));

        let reader = tokio::spawn(async move {
            let mut received = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut sink_rx, &mut received)
                .await
                .unwrap();
            received
        });

        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            stream.write_all(b"tick").await.unwrap();
        }
        stream.shutdown().await.unwrap();
        drop(stream);

        assert_eq!(reader.await.unwrap(), b"tickticktick");
    }
}
