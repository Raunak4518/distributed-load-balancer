use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFFER_SIZE: usize = 8 * 1024;

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
pub async fn pump<R, W>(mut reader: R, mut writer: W, idle_timeout: Duration) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total: u64 = 0;

    loop {
        let read = tokio::time::timeout(idle_timeout, reader.read(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle timeout"))??;

        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        tokio::time::timeout(idle_timeout, writer.write_all(&buf[..read]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "idle timeout"))??;
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

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        source_tx.write_all(b"hello world").await.unwrap();
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();

        assert_eq!(received, b"hello world");
        assert_eq!(copied.await.unwrap().unwrap(), 11);
    }

    /// The write-side counterpart of the read timeout above: a peer that
    /// stops reading its half (here, `sink_rx` is simply never touched, so
    /// the duplex's bounded buffer fills and `write_all` blocks) must not be
    /// able to hold the pump open forever either.
    #[tokio::test(start_paused = true)]
    async fn times_out_when_the_writer_never_drains() {
        let (mut source_tx, source_rx) = tokio::io::duplex(16);
        let (sink_tx, _sink_rx) = tokio::io::duplex(16);

        let pumped = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));
        // Not awaited to completion here -- it stalls once `pump` stops
        // draining `source_rx`, which is fine: only `pumped`'s outcome
        // matters to this test.
        tokio::spawn(async move {
            let _ = source_tx.write_all(&[0u8; 256]).await;
        });

        let err = pumped.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_when_no_data_ever_arrives() {
        // Keep the source alive but silent, so the read simply never resolves.
        let (_source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, _sink_rx) = tokio::io::duplex(1024);

        let err = pump(source_rx, sink_tx, Duration::from_secs(5))
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

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            source_tx.write_all(b"tick").await.unwrap();
        }
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();

        assert_eq!(received, b"tickticktick");
        assert_eq!(copied.await.unwrap().unwrap(), 12);
    }

    #[tokio::test]
    async fn shuts_down_writer_on_eof() {
        let (mut source_tx, source_rx) = tokio::io::duplex(1024);
        let (sink_tx, mut sink_rx) = tokio::io::duplex(1024);

        let copied = tokio::spawn(pump(source_rx, sink_tx, Duration::from_secs(5)));

        source_tx.write_all(b"bye").await.unwrap();
        source_tx.shutdown().await.unwrap();
        drop(source_tx);

        // read_to_end only returns once the writer half was shut down.
        let mut received = Vec::new();
        sink_rx.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"bye");
        assert_eq!(copied.await.unwrap().unwrap(), 3);
    }
}
