mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Wire = Arc<Mutex<String>>;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_backend(answer: bool) -> (SocketAddr, Wire) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let wire: Wire = Arc::default();
    let recorded = Arc::clone(&wire);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    let is_health = chunk.starts_with("GET /health");
                    if !is_health {
                        recorded
                            .lock()
                            .unwrap()
                            .push_str(&chunk.to_ascii_lowercase());
                    }
                    if answer || is_health {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nprimary")
                            .await;
                    }
                }
            });
        }
    });
    (addr, wire)
}

async fn start(shadow: SocketAddr) -> (SocketAddr, Wire) {
    let (primary, primary_wire) = spawn_backend(true).await;
    let listen = free_addr().await;
    let text = support::config_toml(&listen.to_string(), &[("b1", primary)], 1000.0, 1000)
        .replace(
            "  [listeners.load_balancing]",
            &format!("  [listeners.mirror]\n  address = \"{shadow}\"\n  timeout_ms = 5000\n\n  [listeners.load_balancing]"),
        );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;
    (listen, primary_wire)
}

async fn post(listen: SocketAddr) -> String {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(
            b"POST /orders?id=7 HTTP/1.1\r\nHost: shop.example\r\nX-Client: c\r\nContent-Length: 11\r\nConnection: close\r\n\r\norder-body!",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).to_string()
}

async fn wait_for(wire: &Wire, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !wire.lock().unwrap().contains(needle) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wire.lock().unwrap().clone()
}

#[tokio::test]
async fn the_shadow_receives_a_marked_copy_of_each_request() {
    let (shadow, shadow_wire) = spawn_backend(true).await;
    let (listen, primary_wire) = start(shadow).await;

    let response = post(listen).await;
    assert!(response.ends_with("primary"), "{response}");

    let seen = wait_for(&shadow_wire, "order-body!").await;
    assert!(seen.starts_with("post /orders?id=7 http/1.1"), "{seen}");
    assert!(seen.contains("host: shop.example-shadow"), "{seen}");
    assert!(seen.contains("order-body!"), "{seen}");
    assert!(
        primary_wire
            .lock()
            .unwrap()
            .contains("host: shop.example\r\n"),
        "the primary must see the original host"
    );
}

#[tokio::test]
async fn a_stalled_shadow_does_not_delay_the_client() {
    let (shadow, shadow_wire) = spawn_backend(false).await;
    let (listen, _) = start(shadow).await;

    let started = Instant::now();
    let response = post(listen).await;
    assert!(response.ends_with("primary"), "{response}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the client waited {:?} on a shadow that never answers",
        started.elapsed()
    );
    let seen = wait_for(&shadow_wire, "order-body!").await;
    assert!(seen.contains("order-body!"), "{seen}");
}
