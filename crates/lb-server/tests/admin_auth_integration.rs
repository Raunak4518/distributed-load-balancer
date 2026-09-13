mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn admin_config_toml(admin_listen: SocketAddr, traffic_listen: SocketAddr, token: &str) -> String {
    format!(
        r#"
[admin]
listen = "{admin_listen}"
token = "{token}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "a"
  address = "127.0.0.1:1"

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
"#
    )
}

/// A real running server with `[admin] token` configured: the admin surface
/// -- `/metrics`, `/healthz`, `/ready`, and (via the extension) `/backends`
/// -- all reject a request with no `Authorization` header, and all accept
/// one with the correct `Bearer` token. Proves the auth check is wired
/// through the real `lb_server::run` startup path, not just exercised at
/// the `lb-metrics` unit level.
#[tokio::test]
async fn admin_endpoints_require_the_configured_bearer_token() {
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(&admin_config_toml(admin_listen, traffic_listen, "s3cret")).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(admin_listen).await;

    let client = reqwest::Client::new();

    for path in ["/metrics", "/healthz", "/ready", "/backends"] {
        let resp = client
            .get(format!("http://{admin_listen}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "path {path} should require a token"
        );

        let resp = client
            .get(format!("http://{admin_listen}{path}"))
            .header("Authorization", "Bearer wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "path {path} should reject a wrong token"
        );

        let resp = client
            .get(format!("http://{admin_listen}{path}"))
            .header("Authorization", "Bearer s3cret")
            .send()
            .await
            .unwrap();
        // Not necessarily 200 (e.g. `/ready` is 503 with no reachable
        // backend, which this fixture deliberately has none of) -- the
        // thing under test is that the correct token isn't rejected.
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "path {path} should accept the correct token"
        );
    }
}

/// Without `[admin] token`/`token_env` at all, every endpoint stays exactly
/// as open as it was before this feature existed -- the golden path for
/// every config that predates it.
#[tokio::test]
async fn admin_endpoints_stay_open_when_no_token_is_configured() {
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(
        &admin_config_toml(admin_listen, traffic_listen, "s3cret")
            .replace("token = \"s3cret\"\n", ""),
    )
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(admin_listen).await;

    let resp = reqwest::get(format!("http://{admin_listen}/healthz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
