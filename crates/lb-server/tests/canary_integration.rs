mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn canary_config_toml(
    listen: &str,
    default_backend: SocketAddr,
    canary_backend: SocketAddr,
    percent: u8,
    sticky: bool,
) -> String {
    let sticky_section = if sticky {
        "\n  [listeners.sticky]\n  cookie_name = \"lb_sticky\"\n"
    } else {
        ""
    };
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "default-1"
  address = "{default_backend}"

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
{sticky_section}
  [[listeners.canary]]
  percent = {percent}

    [[listeners.canary.backends]]
    id = "canary-1"
    address = "{canary_backend}"

    [listeners.canary.health_check]
    path = "/health"
    interval_ms = 500
    timeout_ms = 200
    failure_threshold = 2
    cooldown_ms = 300

    [listeners.canary.load_balancing]
    strategy = "round_robin"
"#
    )
}

/// A real running listener with a default backend and one
/// `[[listeners.canary]]` pool at `percent = 25`: over exactly 100
/// sequential, un-cookied requests, the deterministic weighted-roll cursor
/// (see `lb_proxy::service::resolve_default_or_canary_pool`) must send
/// exactly 25 to the canary backend and 75 to the default one -- not just
/// "close to 25%", proving the split is exact, not probabilistic.
#[tokio::test]
async fn traffic_splits_across_default_and_canary_pools_by_exact_percentage() {
    let (default_addr, default_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (canary_addr, canary_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&canary_config_toml(
        &listen.to_string(),
        default_addr,
        canary_addr,
        25,
        false,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    for _ in 0..100 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    assert_eq!(canary_count.load(Ordering::SeqCst), 25);
    assert_eq!(default_count.load(Ordering::SeqCst), 75);
}

/// With both `[listeners.sticky]` and `[[listeners.canary]]` configured, a
/// client's first (un-cookied) request lands on whichever pool the roll
/// picks, and every subsequent request carrying that response's cookie
/// stays on that same pool -- proving `resolve_default_or_canary_pool`'s
/// pin-checking (backend id -> pool membership, checked before rolling)
/// composes correctly with sticky sessions, not just that each feature
/// works in isolation.
#[tokio::test]
async fn a_sticky_cookie_keeps_a_client_on_the_same_pool_it_first_landed_in() {
    let (default_addr, default_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (canary_addr, canary_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&canary_config_toml(
        &listen.to_string(),
        default_addr,
        canary_addr,
        50,
        true,
    ))
    .unwrap();
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
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

    for _ in 0..10 {
        let resp = client
            .get(format!("http://{listen}/"))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let total_default = default_count.load(Ordering::SeqCst);
    let total_canary = canary_count.load(Ordering::SeqCst);
    assert_eq!(
        total_default + total_canary,
        11,
        "1 first request + 10 pinned requests"
    );
    assert!(
        total_default == 0 || total_canary == 0,
        "all 11 requests must land on the same pool once pinned: default={total_default} canary={total_canary}"
    );
}
