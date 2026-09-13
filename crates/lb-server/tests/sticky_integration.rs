mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn sticky_config_toml(listen: &str, backend_a: SocketAddr, backend_b: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "a"
  address = "{backend_a}"

  [[listeners.backends]]
  id = "b"
  address = "{backend_b}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"

  [listeners.sticky]
  cookie_name = "lb_sticky"
"#
    )
}

/// A real running listener, round-robin across two backends, with
/// `[listeners.sticky]` enabled: the first request picks a backend and
/// gets a `Set-Cookie`, and every subsequent request carrying that cookie
/// keeps landing on the same backend -- even though round-robin alone would
/// alternate. Proves the pin overrides the algorithm end to end, not just
/// that `handle_inner`'s unit tests agree with the design.
#[tokio::test]
async fn a_sticky_cookie_keeps_a_client_on_the_same_backend_despite_round_robin() {
    let (addr_a, count_a) = support::spawn_counting_backend(StatusCode::OK).await;
    let (addr_b, count_b) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&sticky_config_toml(&listen.to_string(), addr_a, addr_b)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();

    let first = client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let set_cookie = first
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("first response must set the sticky cookie")
        .to_str()
        .unwrap()
        .to_string();
    // Only the name=value pair a client would actually echo back, not the
    // Set-Cookie attributes (Path/HttpOnly/SameSite/...).
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

    for _ in 0..5 {
        let resp = client
            .get(format!("http://{listen}/"))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let total_a = count_a.load(Ordering::SeqCst);
    let total_b = count_b.load(Ordering::SeqCst);
    assert_eq!(total_a + total_b, 6, "1 first request + 5 pinned requests");
    assert!(
        total_a == 0 || total_b == 0,
        "all 6 requests must land on the same backend once pinned: a={total_a} b={total_b}"
    );
}

/// Without a `Cookie` at all, round-robin behaves exactly as it always
/// did -- sticky being configured must not change behavior for a client
/// that never got pinned (e.g. a client whose first response was lost, or
/// one that doesn't retain cookies).
#[tokio::test]
async fn requests_with_no_cookie_still_distribute_round_robin() {
    let (addr_a, count_a) = support::spawn_counting_backend(StatusCode::OK).await;
    let (addr_b, count_b) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&sticky_config_toml(&listen.to_string(), addr_a, addr_b)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    for _ in 0..4 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    assert_eq!(count_a.load(Ordering::SeqCst), 2);
    assert_eq!(count_b.load(Ordering::SeqCst), 2);
}
