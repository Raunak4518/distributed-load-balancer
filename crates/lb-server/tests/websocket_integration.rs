mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// A real running listener, a real backend that speaks the HTTP/1.1
/// upgrade handshake, and a raw TCP client sending a WebSocket-shaped
/// handshake straight through `lb_server::run` -- the same path a browser's
/// WebSocket client would take. Proves the `101` arrives with
/// `Connection`/`Upgrade` intact and that bytes sent after it are echoed
/// back through the full proxy round trip, not just that `handle_inner`'s
/// own unit/integration-level tests (which bypass `lb-server`'s real accept
/// loop and connection builder) agree with the design.
#[tokio::test]
async fn a_websocket_handshake_is_proxied_end_to_end() {
    let backend = support::spawn_upgrade_backend(true).await;
    let listen = free_addr().await;

    let config = Config::parse(&support::config_toml(
        &listen.to_string(),
        &[("b1", backend)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();

    let (head, mut leftover) = support::read_response_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101, got:\n{head}"
    );
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("connection: upgrade"), "got:\n{head}");
    assert!(lower.contains("upgrade: websocket"), "got:\n{head}");

    client.write_all(b"ping").await.unwrap();
    while leftover.len() < 4 {
        let mut chunk = [0u8; 64];
        let n = client.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before the echo arrived");
        leftover.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(&leftover[..4], b"ping");
}

/// An ordinary (non-upgrade) request on the same listener, same backend, is
/// completely unaffected by any of the upgrade-handling code added for the
/// test above.
#[tokio::test]
async fn an_ordinary_request_is_unaffected_by_upgrade_support() {
    let backend = support::spawn_upgrade_backend(true).await;
    let listen = free_addr().await;

    let config = Config::parse(&support::config_toml(
        &listen.to_string(),
        &[("b1", backend)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .header("X-Client", "plain")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A backend that declines the upgrade (answers an ordinary `200` instead
/// of `101`) is relayed as such through the full stack, not treated as a
/// successful upgrade.
#[tokio::test]
async fn a_declined_upgrade_is_relayed_as_an_ordinary_response() {
    let backend = support::spawn_upgrade_backend(false).await;
    let listen = free_addr().await;

    let config = Config::parse(&support::config_toml(
        &listen.to_string(),
        &[("b1", backend)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();

    let (head, _leftover) = support::read_response_head(&mut client).await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected 200, got:\n{head}"
    );
}
