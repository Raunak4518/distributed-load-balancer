mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use support::spawn_large_body_backend;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn compression_config_toml(listen: SocketAddr, backend: SocketAddr, compression: bool) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
compression = {compression}

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
"#
    )
}

/// A large, trivially-compressible (all-zero) body, requested with
/// `Accept-Encoding: gzip`, comes back gzip-encoded and much smaller than
/// the original -- the direct proof compression actually ran, not just that
/// the config parsed.
#[tokio::test]
async fn a_compressible_response_is_gzip_encoded_when_requested() {
    let body_len = 64 * 1024;
    let backend = spawn_large_body_backend(body_len).await;
    let listen = free_addr().await;
    let config = Config::parse(&compression_config_toml(listen, backend, true)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap()),
        Some("gzip"),
        "response was not marked as gzip-encoded"
    );
    let compressed = resp.bytes().await.unwrap();
    assert!(
        compressed.len() < body_len / 4,
        "gzip'd all-zero bytes should compress to a small fraction of {body_len}, got {}",
        compressed.len()
    );
}

/// A client that never asked for compression (no `Accept-Encoding`) must
/// get the body back unencoded, even on a listener with `compression =
/// true` -- negotiation, not something imposed on every response.
#[tokio::test]
async fn a_client_with_no_accept_encoding_gets_the_body_unencoded() {
    let body_len = 64 * 1024;
    let backend = spawn_large_body_backend(body_len).await;
    let listen = free_addr().await;
    let config = Config::parse(&compression_config_toml(listen, backend, true)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("content-encoding").is_none());
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), body_len);
}

/// `compression = false` (the default) never encodes, even for a client
/// that explicitly asks for it -- the operator's off switch actually turns
/// it off.
#[tokio::test]
async fn compression_disabled_never_encodes_even_if_the_client_asks() {
    let body_len = 64 * 1024;
    let backend = spawn_large_body_backend(body_len).await;
    let listen = free_addr().await;
    let config = Config::parse(&compression_config_toml(listen, backend, false)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("content-encoding").is_none());
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), body_len);
}
