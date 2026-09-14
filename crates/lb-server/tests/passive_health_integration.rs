mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn passive_latency_config_toml(listen: &str, fast: SocketAddr, slow: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "fast"
  address = "{fast}"

  [[listeners.backends]]
  id = "slow"
  address = "{slow}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 1
  cooldown_ms = 60000
  unhealthy_latency_ms = 50

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// A real running listener with `unhealthy_latency_ms` configured: a backend
/// answering slower than that threshold must be ejected via the ordinary
/// circuit breaker after the very first slow-but-otherwise-successful
/// response, exactly as a status-code/timeout failure would -- proving the
/// passive latency signal actually participates in backend selection end to
/// end, not just at the `CircuitBreaker` unit level.
#[tokio::test]
async fn a_backend_slower_than_the_latency_threshold_is_ejected() {
    let (fast_addr, fast_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (slow_addr, slow_count) =
        support::spawn_slow_counting_backend(StatusCode::OK, Duration::from_millis(150)).await;
    let listen = free_addr().await;

    let config = Config::parse(&passive_latency_config_toml(
        &listen.to_string(),
        fast_addr,
        slow_addr,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    for _ in 0..10 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let fast_total = fast_count.load(Ordering::SeqCst);
    let slow_total = slow_count.load(Ordering::SeqCst);
    assert_eq!(fast_total + slow_total, 10);
    assert_eq!(
        slow_total, 1,
        "the slow backend should be ejected after its first (too-slow) response: fast={fast_total} slow={slow_total}"
    );
}
