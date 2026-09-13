mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use support::spawn_counting_backend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// `SO_KEEPALIVE`'s actual timing effect isn't observable within a test's
/// timescale -- this proves the golden path: a listener with both
/// `client_tcp_keepalive` and `backend_tcp_keepalive` configured still
/// accepts a connection and completes an ordinary request normally, meaning
/// the `apply_tcp_keepalive` calls (client-facing in `lb_server::lib`,
/// backend-facing via `HttpConnector`'s native setters) don't disrupt either
/// leg.
fn keepalive_config(listen: SocketAddr, backend: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [listeners.client_tcp_keepalive]
  time_secs = 30
  interval_secs = 5
  retries = 3

  [listeners.backend_tcp_keepalive]
  time_secs = 45
  interval_secs = 8
  retries = 4

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
  rate_per_sec = 100
  burst = 100

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

#[tokio::test]
async fn a_listener_with_tcp_keepalive_configured_serves_requests_normally() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&keepalive_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    assert!(
        status_line.contains("200"),
        "expected a 200 response, got: {status_line}"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}
