use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Hard ceiling on one message. Checked *before* allocating: a length prefix
/// read from a socket is attacker-controlled, and trusting it is a textbook
/// memory-exhaustion bug.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMessage {
    pub node_id: String,
    pub entries: Vec<KeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub key: String,
    pub buckets: Vec<(u64, u64)>,
}

pub fn encode(msg: &SyncMessage) -> serde_json::Result<Vec<u8>> {
    let payload = serde_json::to_vec(msg)?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub async fn read_message<R>(reader: &mut R) -> io::Result<SyncMessage>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer announced {len} byte message, over the {MAX_MESSAGE_BYTES} limit"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed sync message: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SyncMessage {
        SyncMessage {
            node_id: "lb-1".into(),
            entries: vec![KeyEntry {
                key: "127.0.0.1".into(),
                buckets: vec![(1_700_000_000, 5), (1_700_000_001, 2)],
            }],
        }
    }

    #[tokio::test]
    async fn round_trips() {
        let encoded = encode(&sample()).unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert_eq!(decoded, sample());
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        // Claim 4 GiB, send nothing. Must fail on the length check rather
        // than trying to allocate the buffer.
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{err}").contains("over the"));
    }

    #[tokio::test]
    async fn rejects_truncated_payload() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&100u32.to_be_bytes());
        framed.extend_from_slice(b"only a few bytes");
        let mut cursor = std::io::Cursor::new(framed);

        assert!(read_message(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let payload = b"{not json";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_two_messages_from_one_stream() {
        // Framing must allow several messages back to back on one connection.
        let mut framed = encode(&sample()).unwrap();
        framed.extend_from_slice(&encode(&sample()).unwrap());
        let mut cursor = std::io::Cursor::new(framed);

        assert_eq!(read_message(&mut cursor).await.unwrap(), sample());
        assert_eq!(read_message(&mut cursor).await.unwrap(), sample());
    }
}
