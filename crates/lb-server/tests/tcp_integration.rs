mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use support::{spawn_echo_backend, tcp_config_toml, tcp_roundtrip};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn proxies_tcp_bytes_end_to_end() {
    let (backend_addr, _count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    let config = Config::parse(&tcp_config_toml(
        &listen.to_string(),
        &[("b1", backend_addr)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let echoed = tcp_roundtrip(listen, b"hello over tcp").await.unwrap();
    assert_eq!(echoed, b"hello over tcp");
}

#[tokio::test]
async fn rate_limited_tcp_connection_is_closed_with_no_data() {
    let (backend_addr, count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    // Burst of 3, not 2: `wait_until_listening` opens one real connection,
    // and a TCP listener rate-limits *connections*, so the readiness probe
    // itself consumes one unit of budget. It costs exactly one — a failed
    // connect is refused before the limiter sees it — so accounting for it
    // is deterministic. That leaves two for the assertions below.
    let config = Config::parse(&tcp_config_toml(
        &listen.to_string(),
        &[("b1", backend_addr)],
        2.0,
        3,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    assert_eq!(tcp_roundtrip(listen, b"one").await.unwrap(), b"one");
    assert_eq!(tcp_roundtrip(listen, b"two").await.unwrap(), b"two");

    // Third connection is accepted at the TCP level then immediately closed,
    // so the client sees an empty read rather than an error — that silence
    // *is* the L4 rejection.
    let third = tcp_roundtrip(listen, b"three").await.unwrap_or_default();
    assert!(
        third.is_empty(),
        "rate-limited connection should carry no data, got {third:?}"
    );

    // The backend only ever saw the two allowed connections.
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fails_over_to_a_healthy_tcp_backend() {
    // A port that nothing listens on, plus a real echo backend.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = closed.local_addr().unwrap();
    drop(closed);

    let (healthy_addr, count) = spawn_echo_backend().await;
    let listen = free_addr().await;

    let config = Config::parse(&tcp_config_toml(
        &listen.to_string(),
        &[("dead", dead_addr), ("alive", healthy_addr)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    for _ in 0..4 {
        let echoed = tcp_roundtrip(listen, b"ping").await.unwrap();
        assert_eq!(echoed, b"ping");
    }
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn serves_http_and_tcp_listeners_from_one_process() {
    // The headline Phase 2 capability: both protocols, one process.
    let (http_backend, _http_count) = support::spawn_counting_backend(hyper::StatusCode::OK).await;
    let (tcp_backend, _tcp_count) = spawn_echo_backend().await;
    let http_listen = free_addr().await;
    let tcp_listen = free_addr().await;

    let config_text = format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{http_listen}"

  [[listeners.backends]]
  id = "w1"
  address = "{http_backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"

[[listeners]]
name = "db"
protocol = "tcp"
listen = "{tcp_listen}"

  [[listeners.backends]]
  id = "t1"
  address = "{tcp_backend}"

  [listeners.health_check]
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    );

    let config = Config::parse(&config_text).unwrap();
    tokio::spawn(lb_server::run(config));
    // Both listeners must be up before either side is exercised.
    support::wait_until_listening(http_listen).await;
    support::wait_until_listening(tcp_listen).await;

    // HTTP side works...
    let resp = reqwest::Client::new()
        .get(format!("http://{http_listen}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // ...and the TCP side works, from the same process.
    let echoed = tcp_roundtrip(tcp_listen, b"both at once").await.unwrap();
    assert_eq!(echoed, b"both at once");
}
