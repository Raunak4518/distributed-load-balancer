use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

const BUFFER_SIZE: usize = 8 * 1024;

pub struct IdleTracker {
    epoch: Instant,
    last_nanos: AtomicU64,
}

impl IdleTracker {
    pub fn new() -> Self {
        IdleTracker {
            epoch: Instant::now(),
            last_nanos: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let nanos = self.epoch.elapsed().as_nanos() as u64;
        self.last_nanos.store(nanos, Ordering::Relaxed);
    }

    fn last_activity(&self) -> Instant {
        self.epoch + Duration::from_nanos(self.last_nanos.load(Ordering::Relaxed))
    }
}

impl Default for IdleTracker {
    fn default() -> Self {
        Self::new()
    }
}

async fn with_idle_timeout<F, T>(
    fut: F,
    idle_timeout: Duration,
    activity: &IdleTracker,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::pin!(fut);
    loop {
        let deadline = activity.last_activity() + idle_timeout;
        tokio::select! {
            res = &mut fut => return res,
            _ = tokio::time::sleep_until(deadline) => {
                if Instant::now() >= activity.last_activity() + idle_timeout {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout"));
                }
            }
        }
    }
}

/// Copies bytes from `reader` to `writer` until EOF, enforcing an *idle*
/// timeout on both the read and the write: the clock restarts on every
/// successful transfer in either direction, so a long-lived but active
/// connection is never cut off — only one that stalls is. The write side
/// matters exactly as much as the read side: a peer that stops reading its
/// half (TCP receive window full, or simply gone quiet) would otherwise hold
/// this pump's `write_all` open forever, since only the far end's flow
/// control -- never a clock -- would ever unblock it.
///
/// On EOF the writer is explicitly shut down, which propagates the half-close
/// to the peer. That is what lets a caller run two pumps under `try_join!`
/// and still support protocols where one direction finishes early while the
/// other keeps streaming.
pub async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
    activity: &IdleTracker,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total: u64 = 0;

    loop {
        let read = with_idle_timeout(reader.read(&mut buf), idle_timeout, activity).await?;
        activity.touch();

        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        with_idle_timeout(writer.write_all(&buf[..read]), idle_timeout, activity).await?;
        activity.touch();
        total += read as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copies_bytes_until_eof() {
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);
        let activity = IdleTracker::new();

        let pumped = pump(source_rx, sink_tx, Duration::from_secs(5), &activity);
        let write = async {
            source_tx.write_all(b"hello world").await.unwrap();
            source_tx.shutdown().await.unwrap();
        };
        let read = async {
            let mut received = Vec::new();
            sink_rx.read_to_end(&mut received).await.unwrap();
            received
        };
        let (copied, _, received) = tokio::join!(pumped, write, read);

        assert_eq!(received, b"hello world");
        assert_eq!(copied.unwrap(), 11);
    }

    /// The write-side counterpart of the read timeout above: a peer that
    /// stops reading its half (here, `sink_rx` is simply never touched, so
    /// the duplex's bounded buffer fills and `write_all` blocks) must not be
    /// able to hold the pump open forever either.
    #[tokio::test(start_paused = true)]
    async fn times_out_when_the_writer_never_drains() {
        let (mut source_tx, source_rx) = tokio::io::duplex(16);
        let (sink_tx, _sink_rx) = tokio::io::duplex(16);
        let activity = IdleTracker::new();

        tokio::spawn(async move {
            let _ = source_tx.write_all(&[0u8; 256]).await;
        });

        let err = pump(source_rx, sink_tx, Duration::from_secs(5), &activity)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_when_no_data_ever_arrives() {
        // Keep the source alive but silent, so the read simply never resolves.
        let (_source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, _sink_rx) = tokio::io::duplex(1024);
        let activity = IdleTracker::new();

        let err = pump(source_rx, sink_tx, Duration::from_secs(5), &activity)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timer_resets_on_activity() {
        // Total lifetime (9s) far exceeds the 5s idle timeout, but no single
        // gap does — this must succeed, proving it is an idle timeout and not
        // a maximum-lifetime cap.
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);
        let activity = IdleTracker::new();

        let pumped = pump(source_rx, sink_tx, Duration::from_secs(5), &activity);
        let write = async {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                source_tx.write_all(b"tick").await.unwrap();
            }
            source_tx.shutdown().await.unwrap();
        };
        let read = async {
            let mut received = Vec::new();
            sink_rx.read_to_end(&mut received).await.unwrap();
            received
        };
        let (copied, _, received) = tokio::join!(pumped, write, read);

        assert_eq!(received, b"tickticktick");
        assert_eq!(copied.unwrap(), 12);
    }

    /// The other pump direction making progress must keep this one alive
    /// past its own idle timeout -- a server-push stream (backend talking,
    /// client silent) or a long-running query result (client silent while
    /// reading) must not be severed just because *this* direction has
    /// nothing to send.
    #[tokio::test(start_paused = true)]
    async fn activity_on_the_sibling_direction_keeps_this_one_alive() {
        let (mut silent_source_tx, silent_source_rx) = tokio::io::duplex(1024);
        let (silent_sink_tx, _silent_sink_rx) = tokio::io::duplex(1024);
        let (mut busy_source_tx, busy_source_rx) = tokio::io::duplex(1024);
        let (busy_sink_tx, mut busy_sink_rx) = tokio::io::duplex(1024);
        let activity = IdleTracker::new();

        let silent = pump(
            silent_source_rx,
            silent_sink_tx,
            Duration::from_secs(5),
            &activity,
        );
        let busy = pump(
            busy_source_rx,
            busy_sink_tx,
            Duration::from_secs(5),
            &activity,
        );
        let write = async {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                busy_source_tx.write_all(b"tick").await.unwrap();
            }
            busy_source_tx.shutdown().await.unwrap();
            silent_source_tx.shutdown().await.unwrap();
        };
        let read = async {
            let mut received = Vec::new();
            busy_sink_rx.read_to_end(&mut received).await.unwrap();
            received
        };

        let (silent_result, busy_result, _, received) = tokio::join!(silent, busy, write, read);

        assert_eq!(received, b"tickticktick");
        assert!(busy_result.is_ok());
        assert!(
            silent_result.is_ok(),
            "the silent direction must not time out while its sibling is active: {silent_result:?}"
        );
    }

    #[tokio::test]
    async fn shuts_down_writer_on_eof() {
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);
        let activity = IdleTracker::new();

        let pumped = pump(source_rx, sink_tx, Duration::from_secs(5), &activity);
        let write = async {
            source_tx.write_all(b"bye").await.unwrap();
            source_tx.shutdown().await.unwrap();
        };
        // read_to_end only returns once the writer half was shut down.
        let read = async {
            let mut received = Vec::new();
            sink_rx.read_to_end(&mut received).await.unwrap();
            received
        };
        let (copied, _, received) = tokio::join!(pumped, write, read);

        assert_eq!(received, b"bye");
        assert_eq!(copied.unwrap(), 3);
    }
}
