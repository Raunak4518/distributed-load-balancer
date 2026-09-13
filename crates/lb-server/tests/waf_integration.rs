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

fn waf_config_toml(listen: &str, backend: SocketAddr, mode: &str) -> String {
    format!(
        r#"
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

  [listeners.waf]
  mode = "{mode}"
"#
    )
}

/// A real running listener with `[listeners.waf]` in its default `block`
/// mode and a counting backend -- a request whose query string carries an
/// SQL-injection token gets `403` and the backend is never hit, while a
/// benign request reaches the backend exactly as it always did.
#[tokio::test]
async fn a_malicious_looking_request_is_blocked_before_reaching_the_backend() {
    let (backend, count) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&waf_config_toml(&listen.to_string(), backend, "block")).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();

    let blocked = client
        .get(format!("http://{listen}/exec?cmd=xp_cmdshell"))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);

    let benign = client
        .get(format!("http://{listen}/orders?page=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(benign.status(), StatusCode::OK);

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "only the benign request should have reached the backend"
    );
}
