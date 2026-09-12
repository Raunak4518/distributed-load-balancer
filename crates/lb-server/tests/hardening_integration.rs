mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use support::spawn_counting_backend;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// An HTTP listener with tight, explicit hardening limits so the tests stay
/// fast. Timeouts are hundreds of milliseconds rather than seconds.
#[allow(clippy::too_many_arguments)]
fn hardened_config(
    listen: SocketAddr,
    backend: SocketAddr,
    max_connections: usize,
    max_per_ip: usize,
    header_timeout_ms: u64,
    body_timeout_ms: u64,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
max_connections = {max_connections}
max_connections_per_ip = {max_per_ip}
header_read_timeout_ms = {header_timeout_ms}
body_read_timeout_ms = {body_timeout_ms}

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
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// Slowloris: send a partial request head and never finish it. The server
/// must close the connection on its own rather than holding it forever.
#[tokio::test]
async fn a_connection_dribbling_headers_is_closed() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 300, 10_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut victim = TcpStream::connect(listen).await.unwrap();
    // A request head that is never terminated by the blank line.
    victim
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let started = Instant::now();
    let mut buf = [0u8; 64];
    // Returns 0 (EOF) or errors once the server gives up on us.
    let closed = tokio::time::timeout(Duration::from_secs(5), victim.read(&mut buf)).await;

    assert!(
        closed.is_ok(),
        "server never closed a slowloris connection within 5s"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "connection was held for {:?}, far longer than the 300ms header timeout",
        started.elapsed()
    );
}

/// Slow POST: announce a body and then dribble it. A size limit alone would
/// not catch this — the body is small, it is just arriving impossibly slowly.
#[tokio::test]
async fn a_connection_dribbling_a_body_is_timed_out() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 5_000, 300)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut victim = TcpStream::connect(listen).await.unwrap();
    // Complete head promising 1000 bytes, then send only one.
    victim
        .write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nA")
        .await
        .unwrap();

    let started = Instant::now();
    let mut response = Vec::new();
    let outcome =
        tokio::time::timeout(Duration::from_secs(5), victim.read_to_end(&mut response)).await;

    assert!(outcome.is_ok(), "server never gave up on a slow body");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "slow body held the connection for {:?}",
        started.elapsed()
    );
    // Either a 408 or a bare close is acceptable; what matters is that the
    // connection did not persist.
    let text = String::from_utf8_lossy(&response);
    if !text.is_empty() {
        assert!(
            text.contains("408"),
            "expected a 408 for a timed-out body, got: {text}"
        );
    }
}

/// The per-IP cap must refuse a single source beyond its budget while the
/// global cap still has plenty of room.
#[tokio::test]
async fn a_single_source_cannot_exceed_its_per_ip_budget() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    // Global 50, per-IP 3: the global cap is nowhere near binding.
    let config = Config::parse(&hardened_config(listen, backend, 50, 3, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    // Hold three idle connections open — all from 127.0.0.1.
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(TcpStream::connect(listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A fourth is accepted at the TCP level then immediately closed by the
    // per-IP cap, so a read returns EOF rather than a response.
    let mut extra = TcpStream::connect(listen).await.unwrap();
    extra
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap_or(());

    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "over-budget connection was neither served nor closed"
    );
    assert!(
        buf.is_empty(),
        "a connection over the per-IP cap was served: {}",
        String::from_utf8_lossy(&buf)
    );

    // Releasing one frees a slot for the same source.
    held.pop();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut allowed = TcpStream::connect(listen).await.unwrap();
    allowed
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(3), allowed.read(&mut buf))
        .await
        .expect("no response after a slot was freed")
        .expect("read failed");
    assert!(n > 0, "no bytes after freeing a per-IP slot");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("200"));
}

/// Ordinary traffic must be unaffected by the limits being present.
#[tokio::test]
async fn normal_requests_are_unaffected_by_the_limits() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&hardened_config(listen, backend, 100, 100, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    for _ in 0..5 {
        let status = reqwest::get(format!("http://{listen}/"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 5);
}
