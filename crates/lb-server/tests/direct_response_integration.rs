mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

async fn spawn_backend() -> (SocketAddr, Wire) {
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
                let mut pending = String::new();
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                    while let Some(end) = pending.find("\r\n\r\n") {
                        let head: String = pending.drain(..end + 4).collect();
                        if !head.starts_with("GET /health") {
                            recorded.lock().unwrap().push_str(&head);
                        }
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nbackend")
                            .await;
                    }
                }
            });
        }
    });
    (addr, wire)
}

async fn get(listen: SocketAddr, path: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Client: c\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).to_ascii_lowercase()
}

#[tokio::test]
async fn redirects_and_maintenance_pages_are_answered_without_the_backend() {
    let (backend, wire) = spawn_backend().await;
    let listen = free_addr().await;
    let text = support::config_toml(&listen.to_string(), &[("b1", backend)], 1000.0, 1000)
        .replace(
            "  [listeners.load_balancing]",
            "  [[listeners.direct_responses]]\n  path_prefix = \"/old\"\n  status = 308\n  redirect = \"https://new.example\"\n  keep_path = true\n\n  [[listeners.direct_responses]]\n  host = \"maint.example\"\n  status = 503\n  body = \"down for maintenance\"\n\n  [listeners.load_balancing]",
        );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;

    let redirect = get(listen, "/old/page?x=1", "shop.example").await;
    assert!(redirect.starts_with("http/1.1 308"), "{redirect}");
    assert!(
        redirect.contains("location: https://new.example/old/page?x=1"),
        "{redirect}"
    );

    let maintenance = get(listen, "/anything", "maint.example").await;
    assert!(maintenance.starts_with("http/1.1 503"), "{maintenance}");
    assert!(
        maintenance.ends_with("down for maintenance"),
        "{maintenance}"
    );

    let proxied = get(listen, "/older", "shop.example").await;
    assert!(proxied.ends_with("backend"), "{proxied}");

    let seen = wire.lock().unwrap().clone();
    assert!(seen.contains("GET /older"), "{seen}");
    assert!(!seen.contains("/old/page"), "{seen}");
    assert!(!seen.contains("/anything"), "{seen}");
}
