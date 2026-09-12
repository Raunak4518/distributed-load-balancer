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
