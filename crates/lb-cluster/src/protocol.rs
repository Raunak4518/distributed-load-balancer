use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

type HmacSha256 = Hmac<Sha256>;

/// Length of the authentication tag prefixed to every payload.
pub const HMAC_TAG_LEN: usize = 32;

fn tag_for(secret: &[u8], payload: &[u8]) -> [u8; HMAC_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

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

/// Frames a message as `[4-byte length][32-byte tag][JSON payload]`, where
/// the length covers tag + payload.
pub fn encode(msg: &SyncMessage, secret: &[u8]) -> serde_json::Result<Vec<u8>> {
    let payload = serde_json::to_vec(msg)?;
    let tag = tag_for(secret, &payload);
    let len = (HMAC_TAG_LEN + payload.len()) as u32;

    let mut out = Vec::with_capacity(4 + HMAC_TAG_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub async fn read_message<R>(reader: &mut R, secret: &[u8]) -> io::Result<SyncMessage>
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
    if len < HMAC_TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too short to contain an authentication tag",
        ));
    }

    let mut framed = vec![0u8; len];
    reader.read_exact(&mut framed).await?;
    let (tag, payload) = framed.split_at(HMAC_TAG_LEN);

    // Verified BEFORE parsing: unauthenticated bytes must not reach the
    // deserialiser, let alone the counter store.
    //
    // `verify_slice` compares in constant time. A byte-wise `==` would leak
    // the expected tag one byte at a time through timing, which makes the
    // whole MAC pointless.
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.verify_slice(tag).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer message failed authentication",
        )
    })?;

    serde_json::from_slice(payload).map_err(|e| {
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

    const SECRET: &[u8] = b"shared-test-secret";

    #[tokio::test]
    async fn round_trips() {
        let encoded = encode(&sample(), SECRET).unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_message(&mut cursor, SECRET).await.unwrap();
        assert_eq!(decoded, sample());
    }

    #[tokio::test]
    async fn a_wrong_secret_is_rejected() {
        let encoded = encode(&sample(), b"right").unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        let err = read_message(&mut cursor, b"wrong").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn a_tampered_payload_is_rejected() {
        let mut encoded = encode(&sample(), SECRET).unwrap();
        // Flip a byte inside the JSON, leaving the tag untouched.
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        let mut cursor = std::io::Cursor::new(encoded);
        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn a_tampered_tag_is_rejected() {
        let mut encoded = encode(&sample(), SECRET).unwrap();
        encoded[4] ^= 0xFF; // first byte of the tag
        let mut cursor = std::io::Cursor::new(encoded);
        assert_eq!(
            read_message(&mut cursor, SECRET).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn a_frame_too_short_for_a_tag_is_rejected() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&4u32.to_be_bytes());
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        // Claim 4 GiB, send nothing. Must fail on the length check rather
        // than trying to allocate the buffer.
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{err}").contains("over the"));
    }

    #[tokio::test]
    async fn rejects_truncated_payload() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&100u32.to_be_bytes());
        framed.extend_from_slice(b"only a few bytes");
        let mut cursor = std::io::Cursor::new(framed);

        assert!(read_message(&mut cursor, SECRET).await.is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_json_that_is_correctly_signed() {
        // Signed with the right key, so it passes authentication and must
        // then fail at the parser — proving the two checks are distinct.
        let payload = b"{not json";
        let tag = tag_for(SECRET, payload);
        let mut framed = Vec::new();
        framed.extend_from_slice(&((HMAC_TAG_LEN + payload.len()) as u32).to_be_bytes());
        framed.extend_from_slice(&tag);
        framed.extend_from_slice(payload);
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_two_messages_from_one_stream() {
        // Framing must allow several messages back to back on one connection.
        let mut framed = encode(&sample(), SECRET).unwrap();
        framed.extend_from_slice(&encode(&sample(), SECRET).unwrap());
        let mut cursor = std::io::Cursor::new(framed);

        assert_eq!(read_message(&mut cursor, SECRET).await.unwrap(), sample());
        assert_eq!(read_message(&mut cursor, SECRET).await.unwrap(), sample());
    }

    #[tokio::test]
    async fn replayed_message_accepted_on_independent_readers() {
        let encoded = encode(&sample(), SECRET).unwrap();
        let mut cursor1 = std::io::Cursor::new(encoded.clone());
        let mut cursor2 = std::io::Cursor::new(encoded.clone());

        let first = read_message(&mut cursor1, SECRET).await.unwrap();
        let second = read_message(&mut cursor2, SECRET).await.unwrap();

        assert_eq!(first, sample());
        assert_eq!(second, sample());
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn valid_hmac_with_mismatched_payload_rejected() {
        let payload_a = b"{\"node_id\":\"a\",\"entries\":[]}";
        let payload_b = b"{\"node_id\":\"b\",\"entries\":[]}";
        let tag = tag_for(SECRET, payload_a);

        let mut framed = Vec::new();
        framed.extend_from_slice(&((HMAC_TAG_LEN + payload_b.len()) as u32).to_be_bytes());
        framed.extend_from_slice(&tag);
        framed.extend_from_slice(payload_b);
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn large_payload_under_limit_accepted() {
        let mut entries = Vec::new();
        for i in 0..1000 {
            entries.push(KeyEntry {
                key: format!("key-{}", i),
                buckets: vec![(1_700_000_000 + i as u64, 5)],
            });
        }
        let msg = SyncMessage {
            node_id: "lb-1".into(),
            entries,
        };

        let encoded = encode(&msg, SECRET).unwrap();
        assert!(encoded.len() < MAX_MESSAGE_BYTES);

        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_message(&mut cursor, SECRET).await.unwrap();
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn zero_length_frame_rejected() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&0u32.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn maximum_frame_size_accepted() {
        let payload_size = MAX_MESSAGE_BYTES - HMAC_TAG_LEN;
        let payload = vec![b'A'; payload_size];
        let tag = tag_for(SECRET, &payload);

        let mut framed = Vec::new();
        framed.extend_from_slice(&(MAX_MESSAGE_BYTES as u32).to_be_bytes());
        framed.extend_from_slice(&tag);
        framed.extend_from_slice(&payload);
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!format!("{err}").contains("over the"));
    }

    #[tokio::test]
    async fn one_byte_over_maximum_rejected() {
        let oversize_len = (MAX_MESSAGE_BYTES + 1) as u32;
        let mut framed = Vec::new();
        framed.extend_from_slice(&oversize_len.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{err}").contains("over the"));
    }

    #[tokio::test]
    async fn incomplete_frame_mid_payload_rejected() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&100u32.to_be_bytes());
        framed.extend_from_slice(b"incomplete");
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert!(
            err.kind() == io::ErrorKind::UnexpectedEof || err.kind() == io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn malicious_length_at_u32_max_rejected() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn corrupted_middle_frame_in_sequence_rejected() {
        let valid1 = encode(&sample(), SECRET).unwrap();
        let mut corrupted = Vec::new();
        corrupted.extend_from_slice(&50u32.to_be_bytes());
        corrupted.extend_from_slice(b"corrupt data");

        let mut sequence = valid1.clone();
        sequence.extend_from_slice(&corrupted);
        let mut cursor = std::io::Cursor::new(sequence);

        assert_eq!(read_message(&mut cursor, SECRET).await.unwrap(), sample());
        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert!(
            err.kind() == io::ErrorKind::InvalidData
                || err.kind() == io::ErrorKind::UnexpectedEof
                || err.kind() == io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn connection_close_at_frame_boundary_clean() {
        let encoded = encode(&sample(), SECRET).unwrap();
        let mut cursor = std::io::Cursor::new(encoded);

        assert_eq!(read_message(&mut cursor, SECRET).await.unwrap(), sample());
        let err = read_message(&mut cursor, SECRET).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
