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

fn peak_ewma_config_toml(listen: &str, fast: SocketAddr, slow: SocketAddr) -> String {
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
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "peak_ewma_p2c"
"#
    )
}

/// A real running listener, `peak_ewma_p2c` strategy, one backend answering
/// in ~1ms and one answering in ~120ms: once enough requests have taught it
/// which is which, the fast backend must receive most of the traffic --
/// proving the strategy actually adapts to measured latency end to end, not
/// just at the unit level where the balancer is driven directly.
#[tokio::test]
async fn the_faster_backend_receives_most_of_the_traffic_once_latency_is_learned() {
    let (fast_addr, fast_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (slow_addr, slow_count) =
        support::spawn_slow_counting_backend(StatusCode::OK, Duration::from_millis(120)).await;
    let listen = free_addr().await;

    let config = Config::parse(&peak_ewma_config_toml(
        &listen.to_string(),
        fast_addr,
        slow_addr,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    for _ in 0..60 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let fast_total = fast_count.load(Ordering::SeqCst);
    let slow_total = slow_count.load(Ordering::SeqCst);
    assert_eq!(fast_total + slow_total, 60);
    assert!(
        fast_total > slow_total * 3,
        "expected the fast backend to dominate once latency was learned: fast={fast_total} slow={slow_total}"
    );
}
