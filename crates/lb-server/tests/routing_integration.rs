mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn routing_config_toml(
    listen: &str,
    default_backend: SocketAddr,
    route_backend: SocketAddr,
) -> String {
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

  [[listeners.routes]]
  path_prefix = "/api"

    [[listeners.routes.backends]]
    id = "route-1"
    address = "{route_backend}"

    [listeners.routes.health_check]
    path = "/health"
    interval_ms = 500
    timeout_ms = 200
    failure_threshold = 2
    cooldown_ms = 300

    [listeners.routes.load_balancing]
    strategy = "round_robin"
"#
    )
}

/// A real running listener with a default backend and one
/// `[[listeners.routes]]` rule pointing at a different backend, proving end
/// to end that `/api/*` requests land on the route's backend and everything
/// else lands on the default -- not just that the config parses or that
/// `handle` picks the right pool in a unit test.
#[tokio::test]
async fn requests_under_the_path_prefix_are_routed_to_the_routes_backend() {
    let (default_addr, default_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let (route_addr, route_count) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&routing_config_toml(
        &listen.to_string(),
        default_addr,
        route_addr,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{listen}/api/orders"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = client
        .get(format!("http://{listen}/other"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // nginx's own `location /api` gotcha: `/apiary` shares the `/api`
    // prefix as a string but is not the same path segment.
    let resp = client
        .get(format!("http://{listen}/apiary"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    use std::sync::atomic::Ordering;
    assert_eq!(route_count.load(Ordering::SeqCst), 1, "only /api/orders");
    assert_eq!(
        default_count.load(Ordering::SeqCst),
        2,
        "/other and /apiary both fall through to the default"
    );
}
