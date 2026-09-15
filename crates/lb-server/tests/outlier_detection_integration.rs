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

fn outlier_config_toml(
    listen: &str,
    good_a: SocketAddr,
    good_b: SocketAddr,
    bad: SocketAddr,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "good-a"
  address = "{good_a}"

  [[listeners.backends]]
  id = "good-b"
  address = "{good_b}"

  [[listeners.backends]]
  id = "bad"
  address = "{bad}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 100
  timeout_ms = 200
  failure_threshold = 1000
  cooldown_ms = 60000

  [listeners.health_check.outlier_detection]
  min_volume = 5
  min_hosts = 2
  stddev_factor = 1.0

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

/// A real running listener with `outlier_detection` configured: a backend
/// whose `/health` probe passes (so the active checker alone would never
/// catch it) but whose real responses are mostly 500s must still be ejected
/// once its statistically-low success rate is detected -- proving the
/// signal actually participates in backend selection end to end, and
/// catches a failure mode (a backend that is "up" but wrong) the
/// status-code/timeout-only active probe and the absolute-threshold circuit
/// breaker (`failure_threshold = 1000` here, deliberately never tripped)
/// both miss.
#[tokio::test]
async fn a_statistically_low_success_rate_backend_is_ejected() {
    let (good_a_addr, good_a_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (good_b_addr, good_b_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (bad_addr, bad_count) =
        support::spawn_counting_backend(StatusCode::INTERNAL_SERVER_ERROR).await;
    let listen = free_addr().await;

    let config = Config::parse(&outlier_config_toml(
        &listen.to_string(),
        good_a_addr,
        good_b_addr,
        bad_addr,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();

    // Round-robin across 3 backends: enough requests that each backend
    // clears `min_volume = 5` well before the 100ms detection tick.
    for _ in 0..30 {
        let _ = client.get(format!("http://{listen}/")).send().await;
    }

    // Give the outlier detector at least one recompute tick to run and
    // propagate its verdict into the pool.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let before_bad = bad_count.load(Ordering::SeqCst);
    assert!(
        before_bad > 0,
        "the bad backend must have been tried at least once before ejection"
    );

    // Once ejected, no further requests should reach it, no matter how many
    // more are sent -- only the two healthy backends remain eligible.
    for _ in 0..20 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let after_bad = bad_count.load(Ordering::SeqCst);
    assert_eq!(
        after_bad, before_bad,
        "the outlier-ejected backend must receive no further traffic: good_a={} good_b={} bad_before={before_bad} bad_after={after_bad}",
        good_a_count.load(Ordering::SeqCst),
        good_b_count.load(Ordering::SeqCst),
    );
}
