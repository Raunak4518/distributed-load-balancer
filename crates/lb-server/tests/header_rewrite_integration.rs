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
                            recorded
                                .lock()
                                .unwrap()
                                .push_str(&head.to_ascii_lowercase());
                        }
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nServer: backend/1.0\r\nX-Debug: secret\r\nContent-Length: 2\r\n\r\nok",
                            )
                            .await;
                    }
                }
            });
        }
    });
    (addr, wire)
}

#[tokio::test]
async fn configured_request_and_response_headers_are_rewritten() {
    let (backend, wire) = spawn_backend().await;
    let listen = free_addr().await;
    let text = support::config_toml(&listen.to_string(), &[("b1", backend)], 1000.0, 1000)
        .replace(
            "  [listeners.load_balancing]",
            "  [listeners.headers]\n  request_set = { \"x-env\" = \"prod\" }\n  request_remove = [\"x-internal\"]\n  response_set = { \"x-served-by\" = \"lb\" }\n  response_remove = [\"server\", \"x-debug\"]\n\n  [listeners.load_balancing]",
        );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;

    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(
            b"GET /page HTTP/1.1\r\nHost: x\r\nX-Client: c\r\nX-Internal: leak\r\nX-Env: dev\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    let seen = wire.lock().unwrap().clone();

    assert!(response.starts_with("http/1.1 200"), "{response}");
    assert!(response.contains("x-served-by: lb"), "{response}");
    assert!(!response.contains("server: backend"), "{response}");
    assert!(!response.contains("x-debug"), "{response}");
    assert!(seen.contains("x-env: prod"), "{seen}");
    assert!(!seen.contains("x-env: dev"), "{seen}");
    assert!(!seen.contains("x-internal"), "{seen}");
}
