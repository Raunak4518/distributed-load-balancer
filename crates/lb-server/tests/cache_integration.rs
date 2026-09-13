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

fn cache_config_toml(admin: SocketAddr, listen: &str, backend: SocketAddr) -> String {
    format!(
        r#"
[admin]
listen = "{admin}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

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
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"

  [listeners.cache]
"#
    )
}

async fn scrape(admin: SocketAddr) -> String {
    reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

/// A real running listener with `[listeners.cache]` enabled and a counting
/// backend -- two identical `GET /` requests must result in exactly one
/// backend hit, and the admin `/metrics` endpoint must show one cache `hit`
/// and one `miss`, proving the cache actually intercepts a repeat request
/// end to end, not just that `handle_inner`'s unit tests agree with the
/// design.
#[tokio::test]
async fn a_repeated_get_is_served_from_cache_without_a_second_backend_hit() {
    let (backend, count) = support::spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let listen = free_addr().await;

    let config = Config::parse(&cache_config_toml(admin, &listen.to_string(), backend)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    let first = client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the second request should be served from cache, not the backend"
    );

    let metrics = scrape(admin).await;
    assert!(
        metrics.contains(r#"lb_cache_result_total{listener="web",result="hit"} 1"#),
        "expected exactly one cache hit, got:\n{metrics}"
    );
    assert!(
        metrics.contains(r#"lb_cache_result_total{listener="web",result="miss"} 1"#),
        "expected exactly one cache miss, got:\n{metrics}"
    );
}

/// A listener with no `[listeners.cache]` section behaves exactly as every
/// other feature this session added when its own config section is absent:
/// every request reaches the backend, and the cache result counters (always
/// registered, same as every other per-listener metric) stay at zero rather
/// than ever recording a hit or a miss.
#[tokio::test]
async fn no_cache_section_means_every_request_reaches_the_backend() {
    let (backend, count) = support::spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let listen = free_addr().await;

    let config = Config::parse(&support::admin_config_toml(
        admin, listen, backend, 1000.0, 1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();
    client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(count.load(Ordering::SeqCst), 2);

    let metrics = scrape(admin).await;
    assert!(
        !metrics.contains(r#"lb_cache_result_total{listener="web",result="hit"} 1"#)
            && !metrics.contains(r#"lb_cache_result_total{listener="web",result="miss"} 1"#),
        "no cache hit or miss should be recorded for a listener with no [listeners.cache], got:\n{metrics}"
    );
}
