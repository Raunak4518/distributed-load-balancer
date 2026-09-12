//! PROXY protocol v1 (text) and v2 (binary): lets a trusted front-end
//! proxy/ELB/CDN tell this listener the real client address, instead of
//! its own. Without this, every listener behind another proxy sees that
//! proxy's IP as the client -- breaking per-client rate limiting, access
//! logs, and tracing for any multi-tier deployment.
//!
//! Only meaningful as a hard trust boundary: a listener with
//! `proxy_protocol = true` is only ever meant to receive connections from
//! one specific, trusted front-end that always sends this header first. A
//! missing or malformed header is therefore treated as fatal (the
//! connection is dropped) rather than falling back to the raw TCP peer --
//! anything else would let an attacker who can reach the listener directly
//! (bypassing the trusted front-end) simply omit the header and inherit
//! whatever trust that implies, or worse, send a forged one to bypass
//! per-client rate limiting.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The exact 12-byte signature every v2 header starts with. Chosen by the
/// spec to be a byte sequence a v1 header (which always starts `"PROXY "`)
/// or ordinary protocol data could never produce by chance.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Spec's own hard ceiling on a v1 header's length, signature included.
const V1_MAX_LEN: usize = 107;

/// Sanity bound on v2's attacker-controlled `len` field -- generous for any
/// realistic TLV set (AWS NLB's included), but a length prefix from the
/// wire must never drive an unbounded read, same reasoning as
/// `lb_cluster::protocol::MAX_MESSAGE_BYTES`.
const V2_MAX_LEN: usize = 4096;

#[derive(Debug)]
pub enum ProxyProtocolError {
    Io(std::io::Error),
    Malformed(&'static str),
}

impl std::fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyProtocolError::Io(e) => write!(f, "{e}"),
            ProxyProtocolError::Malformed(reason) => write!(f, "malformed header: {reason}"),
        }
    }
}

impl From<std::io::Error> for ProxyProtocolError {
    fn from(err: std::io::Error) -> Self {
        ProxyProtocolError::Io(err)
    }
}

/// Reads and consumes a PROXY protocol header from the front of `stream`,
/// returning the real client address it announces. `Ok(None)` means the
/// header carries no client identity at all (v1 `UNKNOWN`, v2 `LOCAL` --
/// both mean "this connection did not originate from a real client," e.g.
/// the front proxy's own health check) -- the caller's existing raw peer
/// address is the right fallback for that case, not an error.
///
/// Consumes exactly the header's own bytes and nothing more: whatever the
/// real client sent next (a TLS ClientHello, a plaintext HTTP request) is
/// left untouched on the stream.
pub async fn read_header(stream: &mut TcpStream) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Err(ProxyProtocolError::Malformed(
            "connection closed before any header",
        ));
    }
    if first[0] == V2_SIGNATURE[0] {
        read_v2(stream).await
    } else {
        read_v1(stream).await
    }
}

async fn read_v2(stream: &mut TcpStream) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;
    if header[0..12] != V2_SIGNATURE {
        return Err(ProxyProtocolError::Malformed("bad v2 signature"));
    }

    let ver_cmd = header[12];
    let version = ver_cmd >> 4;
    let command = ver_cmd & 0x0F;
    if version != 2 {
        return Err(ProxyProtocolError::Malformed("unsupported v2 version"));
    }

    let family = header[13];
    let len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if len > V2_MAX_LEN {
        return Err(ProxyProtocolError::Malformed(
            "v2 length exceeds sanity bound",
        ));
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;

    // 0x0 = LOCAL: the proxy itself originated this connection (e.g. its
    // own health check), not a real client. The address block, if any, is
    // still consumed above -- it just isn't meaningful.
    if command == 0x0 {
        return Ok(None);
    }
    // 0x1 = PROXY: a real client is being relayed. Any other command value
    // is not defined by the spec.
    if command != 0x1 {
        return Err(ProxyProtocolError::Malformed("unsupported v2 command"));
    }

    match family {
        // AF_UNSPEC: PROXY command with no address -- treated the same as
        // LOCAL, per spec.
        0x00 => Ok(None),
        // TCP over IPv4: 4-byte src addr, 4-byte dst addr, 2-byte src port,
        // 2-byte dst port.
        0x11 => {
            if body.len() < 12 {
                return Err(ProxyProtocolError::Malformed(
                    "v2 TCPv4 address block too short",
                ));
            }
            let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        // TCP over IPv6: 16-byte src addr, 16-byte dst addr, 2-byte src
        // port, 2-byte dst port.
        0x21 => {
            if body.len() < 36 {
                return Err(ProxyProtocolError::Malformed(
                    "v2 TCPv6 address block too short",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[0..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(ip), port)))
        }
        _ => Err(ProxyProtocolError::Malformed(
            "unsupported v2 address family",
        )),
    }
}

async fn read_v1(stream: &mut TcpStream) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    // Read one byte at a time: the header's length isn't known in advance,
    // and there is no spare byte to safely over-read into -- whatever
    // follows (a TLS ClientHello, an HTTP request) is unframed and can't be
    // un-read without a buffering wrapper that would then need to flow
    // forward through the rest of the connection.
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            break;
        }
        if line.len() > V1_MAX_LEN {
            return Err(ProxyProtocolError::Malformed("v1 header exceeds 107 bytes"));
        }
    }

    let text = std::str::from_utf8(&line)
        .map_err(|_| ProxyProtocolError::Malformed("v1 header is not valid utf-8"))?;
    let text = text.trim_end_matches("\r\n");
    let mut parts = text.split(' ');

    if parts.next() != Some("PROXY") {
        return Err(ProxyProtocolError::Malformed(
            "v1 header missing PROXY keyword",
        ));
    }
    let protocol = parts.next().ok_or(ProxyProtocolError::Malformed(
        "v1 header missing protocol field",
    ))?;
    if protocol == "UNKNOWN" {
        return Ok(None);
    }
    if protocol != "TCP4" && protocol != "TCP6" {
        return Err(ProxyProtocolError::Malformed(
            "v1 header has an unsupported protocol",
        ));
    }

    let src_ip = parts.next().ok_or(ProxyProtocolError::Malformed(
        "v1 header missing source address",
    ))?;
    let _dst_ip = parts.next().ok_or(ProxyProtocolError::Malformed(
        "v1 header missing destination address",
    ))?;
    let src_port = parts.next().ok_or(ProxyProtocolError::Malformed(
        "v1 header missing source port",
    ))?;
    let _dst_port = parts.next().ok_or(ProxyProtocolError::Malformed(
        "v1 header missing destination port",
    ))?;

    let ip: IpAddr = src_ip.parse().map_err(|_| {
        ProxyProtocolError::Malformed("v1 header has an unparseable source address")
    })?;
    let port: u16 = src_port
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed("v1 header has an unparseable source port"))?;
    Ok(Some(SocketAddr::new(ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Connects a real loopback TCP pair, writes `sent` from the client
    /// side, and returns the server-side stream (so `read_header` can be
    /// exercised against a genuine `TcpStream`, not a test double) plus a
    /// join handle for the client task.
    async fn pair_with(sent: &'static [u8]) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(sent).await.unwrap();
            // Held open rather than shut down: shutting down would close
            // the write half before the server has necessarily finished
            // reading in the byte-at-a-time v1 path.
            std::future::pending::<()>().await;
        });
        let (server, _) = listener.accept().await.unwrap();
        server
    }

    #[tokio::test]
    async fn v1_tcp4_is_parsed() {
        let mut stream = pair_with(b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n").await;
        let addr = read_header(&mut stream).await.unwrap().unwrap();
        assert_eq!(addr, "192.168.0.1:56324".parse().unwrap());
    }

    #[tokio::test]
    async fn v1_tcp6_is_parsed() {
        let mut stream = pair_with(b"PROXY TCP6 ::1 ::1 56324 443\r\n").await;
        let addr = read_header(&mut stream).await.unwrap().unwrap();
        assert_eq!(addr, "[::1]:56324".parse().unwrap());
    }

    #[tokio::test]
    async fn v1_unknown_carries_no_client() {
        let mut stream = pair_with(b"PROXY UNKNOWN\r\n").await;
        assert_eq!(read_header(&mut stream).await.unwrap(), None);
    }

    #[tokio::test]
    async fn v1_missing_keyword_is_rejected() {
        let mut stream = pair_with(b"NOTPROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n").await;
        assert!(matches!(
            read_header(&mut stream).await,
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn v1_header_without_a_terminator_is_rejected() {
        // Never sends \r\n, and never sends more than the 107-byte cap --
        // proves the length guard fires rather than reading forever.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&[b'A'; 200]).await.unwrap();
            std::future::pending::<()>().await;
        });
        let (mut server, _) = listener.accept().await.unwrap();
        assert!(matches!(
            read_header(&mut server).await,
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn v1_unparseable_address_is_rejected() {
        let mut stream = pair_with(b"PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\n").await;
        assert!(matches!(
            read_header(&mut stream).await,
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    fn v2_header(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&V2_SIGNATURE);
        out.push(0x20 | command); // version 2, given command
        out.push(family);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn v2_tcpv4_is_parsed() {
        let mut body = Vec::new();
        body.extend_from_slice(&[192, 168, 0, 1]); // src
        body.extend_from_slice(&[192, 168, 0, 11]); // dst
        body.extend_from_slice(&56324u16.to_be_bytes()); // src port
        body.extend_from_slice(&443u16.to_be_bytes()); // dst port
        let sent = v2_header(0x1, 0x11, &body);
        let mut stream = pair_with_owned(sent).await;
        let addr = read_header(&mut stream).await.unwrap().unwrap();
        assert_eq!(addr, "192.168.0.1:56324".parse().unwrap());
    }

    #[tokio::test]
    async fn v2_tcpv6_is_parsed() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 15]);
        body.push(1); // src = ::1
        body.extend_from_slice(&[0u8; 15]);
        body.push(1); // dst = ::1
        body.extend_from_slice(&56324u16.to_be_bytes());
        body.extend_from_slice(&443u16.to_be_bytes());
        let sent = v2_header(0x1, 0x21, &body);
        let mut stream = pair_with_owned(sent).await;
        let addr = read_header(&mut stream).await.unwrap().unwrap();
        assert_eq!(addr, "[::1]:56324".parse().unwrap());
    }

    #[tokio::test]
    async fn v2_local_command_carries_no_client() {
        let sent = v2_header(0x0, 0x00, &[]);
        let mut stream = pair_with_owned(sent).await;
        assert_eq!(read_header(&mut stream).await.unwrap(), None);
    }

    #[tokio::test]
    async fn v2_bad_signature_is_rejected() {
        let mut sent = v2_header(0x1, 0x11, &[0u8; 12]);
        sent[0] = 0x0D; // keep first byte so v2 dispatch is chosen
        sent[1] = 0xFF; // corrupt the rest of the signature
        let mut stream = pair_with_owned(sent).await;
        assert!(matches!(
            read_header(&mut stream).await,
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn v2_oversized_length_is_rejected_without_allocating() {
        let mut header = Vec::new();
        header.extend_from_slice(&V2_SIGNATURE);
        header.push(0x21);
        header.push(0x11);
        header.extend_from_slice(&u16::MAX.to_be_bytes());
        let mut stream = pair_with_owned(header).await;
        assert!(matches!(
            read_header(&mut stream).await,
            Err(ProxyProtocolError::Malformed(_))
        ));
    }

    /// Same as `pair_with`, but for an owned buffer (the v2 tests build
    /// their header at runtime rather than using a `&'static` literal).
    async fn pair_with_owned(sent: Vec<u8>) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&sent).await.unwrap();
            std::future::pending::<()>().await;
        });
        let (server, _) = listener.accept().await.unwrap();
        server
    }
}
