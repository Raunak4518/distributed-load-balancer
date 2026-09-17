mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::Duration;
use support::spawn_counting_backend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// One HTTP listener with `proxy_protocol = true` and a tight per-source
/// budget (burst 1) -- tight enough that a second immediate request from
/// the *same* announced source is refused, which is exactly the signal
/// these tests read to prove which IP the limiter actually used.
fn proxy_protocol_config(listen: SocketAddr, backend: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
proxy_protocol = true

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 0.001
  burst = 1

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// Opens a fresh connection, sends a v1 PROXY header announcing
/// `announced_ip` as the source, then a bare HTTP GET, and returns the
/// response status line's code. A fresh connection each time because a
/// PROXY protocol header is only ever sent once, at the very start of a
/// connection -- exactly like a real front-end proxy would.
async fn get_via_proxy_protocol(listen: SocketAddr, announced_ip: &str) -> StatusCode {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(format!("PROXY TCP4 {announced_ip} 10.0.0.99 51234 443\r\n").as_bytes())
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    // "HTTP/1.1 200 OK" -> 200
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    StatusCode::from_u16(code).unwrap()
}

/// The direct proof: two connections claiming *different* source IPs, both
/// from this same test process's loopback address, get independent
/// rate-limit budgets. If the real client IP weren't being used, both would
/// share one budget (the test harness's own loopback address) and the
/// second would be refused exactly like the same-IP case below is.
#[tokio::test]
async fn different_announced_ips_get_independent_budgets() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    assert_eq!(
        get_via_proxy_protocol(listen, "10.0.0.1").await,
        StatusCode::OK
    );
    assert_eq!(
        get_via_proxy_protocol(listen, "10.0.0.2").await,
        StatusCode::OK
    );
}

/// The same announced IP, twice, in separate connections: the second must
/// be refused -- proving the budget is keyed on the *announced* address
/// (which persists across these two distinct TCP connections) rather than
/// on anything connection-specific.
#[tokio::test]
async fn the_same_announced_ip_shares_one_budget_across_connections() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    assert_eq!(
        get_via_proxy_protocol(listen, "10.0.0.5").await,
        StatusCode::OK
    );
    assert_eq!(
        get_via_proxy_protocol(listen, "10.0.0.5").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// A listener that requires PROXY protocol must not silently fall back to
/// the raw TCP peer when the header is missing -- that would let a client
/// bypass the trust boundary entirely by simply not sending one.
#[tokio::test]
async fn a_missing_header_drops_the_connection() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut stream = TcpStream::connect(listen).await.unwrap();
    // No PROXY header -- straight to a request, as an attacker bypassing
    // the trusted front-end (or a simple misconfiguration) would send.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap_or(());

    let mut response = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("connection was neither closed nor served within 3s");
    outcome.unwrap_or(0);

    assert!(
        response.is_empty(),
        "a connection with no PROXY header was served: {}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the backend must never see a request from a connection missing its required header"
    );
}

/// A malformed header (garbage instead of a real PROXY line) must be
/// rejected the same way a missing one is, not treated as ordinary request
/// bytes.
#[tokio::test]
async fn a_malformed_header_drops_the_connection() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(b"PROXY GARBAGE not a real header\r\n")
        .await
        .unwrap_or(());

    let mut response = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("connection was neither closed nor served within 3s");
    outcome.unwrap_or(0);

    assert!(response.is_empty(), "a malformed header was accepted");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

fn v2_header(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(0x20 | command);
    out.push(family);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn v2_fixed_header(ver_cmd: u8, family: u8, declared_len: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(ver_cmd);
    out.push(family);
    out.extend_from_slice(&declared_len.to_be_bytes());
    out
}

async fn send_then_close_and_read_response(listen: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(payload).await.unwrap_or(());
    stream.shutdown().await.unwrap_or(());
    let mut response = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("connection was neither closed nor served within 3s");
    outcome.unwrap_or(0);
    response
}

async fn assert_malformed_connection_rejected(payload: &[u8]) {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let response = send_then_close_and_read_response(listen, payload).await;
    assert!(
        response.is_empty(),
        "malformed payload was accepted: {}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn v1_truncated_mid_protocol_word_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY TC").await;
}

#[tokio::test]
async fn v1_truncated_mid_address_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY TCP4 192.168.0.1 192.16").await;
}

#[tokio::test]
async fn v1_missing_trailing_crlf_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2").await;
}

#[tokio::test]
async fn v1_oversized_header_without_terminator_is_rejected_without_hanging() {
    let payload = vec![b'A'; 200];
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v1_invalid_ipv4_address_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY TCP4 999.999.999.999 5.6.7.8 1 2\r\n").await;
}

#[tokio::test]
async fn v1_invalid_ipv6_address_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY TCP6 not-an-ipv6-address ::1 1 2\r\n").await;
}

#[tokio::test]
async fn v1_unsupported_protocol_keyword_is_rejected() {
    assert_malformed_connection_rejected(b"PROXY UDP6 1.2.3.4 5.6.7.8 1 2\r\n").await;
}

#[tokio::test]
async fn binary_garbage_with_no_crlf_is_rejected_without_hanging() {
    let payload = vec![0x41, 0x00, 0xff, 0xfe, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44];
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn binary_garbage_with_embedded_crlf_is_rejected() {
    let mut payload = vec![0xffu8, 0xfe, 0x00, 0x01, 0x02, 0x03];
    payload.extend_from_slice(b"\r\n");
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_truncated_signature_is_rejected() {
    assert_malformed_connection_rejected(&V2_SIGNATURE[..5]).await;
}

#[tokio::test]
async fn v2_truncated_fixed_header_is_rejected() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&V2_SIGNATURE);
    payload.push(0x21);
    payload.push(0x11);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_truncated_address_block_is_rejected() {
    let mut payload = v2_fixed_header(0x21, 0x11, 12);
    payload.extend_from_slice(&[9, 9]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_bad_signature_is_rejected() {
    let mut payload = V2_SIGNATURE.to_vec();
    payload[1] = 0xFF;
    payload.extend_from_slice(&[0x21, 0x11, 0x00, 0x00]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_body_shorter_than_declared_length_is_rejected() {
    let mut payload = v2_fixed_header(0x21, 0x11, 12);
    payload.extend_from_slice(&[1, 2, 3, 4]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_absurdly_large_length_is_rejected_without_hanging() {
    let payload = v2_fixed_header(0x21, 0x11, u16::MAX);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_length_too_short_for_declared_family_is_rejected() {
    let payload = v2_header(0x1, 0x11, &[1, 2, 3, 4]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_invalid_address_family_is_rejected() {
    let payload = v2_header(0x1, 0x99, &[]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_reserved_version_is_rejected() {
    let payload = v2_fixed_header(0x31, 0x11, 0);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn v2_reserved_command_is_rejected() {
    let payload = v2_header(0xF, 0x00, &[]);
    assert_malformed_connection_rejected(&payload).await;
}

#[tokio::test]
async fn valid_v1_header_and_full_request_in_one_write_is_served_correctly() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"PROXY TCP4 10.0.0.7 10.0.0.99 51234 443\r\n");
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(&payload).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    assert!(
        status_line.contains("200"),
        "expected 200 OK, got: {status_line}"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn valid_v2_header_and_full_request_in_one_write_is_served_correctly() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut body = Vec::new();
    body.extend_from_slice(&[10, 0, 0, 7]);
    body.extend_from_slice(&[10, 0, 0, 99]);
    body.extend_from_slice(&51234u16.to_be_bytes());
    body.extend_from_slice(&443u16.to_be_bytes());
    let mut payload = v2_header(0x1, 0x11, &body);
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(&payload).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    assert!(
        status_line.contains("200"),
        "expected 200 OK, got: {status_line}"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn valid_v1_header_followed_by_garbage_payload_does_not_hang() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"PROXY TCP4 10.0.0.7 10.0.0.99 51234 443\r\n");
    payload.extend_from_slice(&[0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
    payload.extend_from_slice(b"NOT AN HTTP REQUEST AT ALL");

    let _response = send_then_close_and_read_response(listen, &payload).await;
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn valid_v2_header_followed_by_garbage_payload_does_not_hang() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&proxy_protocol_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut body = Vec::new();
    body.extend_from_slice(&[10, 0, 0, 7]);
    body.extend_from_slice(&[10, 0, 0, 99]);
    body.extend_from_slice(&51234u16.to_be_bytes());
    body.extend_from_slice(&443u16.to_be_bytes());
    let mut payload = v2_header(0x1, 0x11, &body);
    payload.extend_from_slice(&[0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
    payload.extend_from_slice(b"NOT AN HTTP REQUEST AT ALL");

    let _response = send_then_close_and_read_response(listen, &payload).await;
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}
