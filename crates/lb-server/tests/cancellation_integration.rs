mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Flag = Arc<Mutex<Option<Instant>>>;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_backend(request_seen: Flag, upstream_closed: Flag) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let request_seen = Arc::clone(&request_seen);
            let upstream_closed = Arc::clone(&upstream_closed);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                if head.starts_with(b"GET /health") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                *request_seen.lock().unwrap() = Some(Instant::now());
                if head.starts_with(b"GET /stream") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .await;
                    loop {
                        if stream.write_all(b"5\r\nhello\r\n").await.is_err() {
                            *upstream_closed.lock().unwrap() = Some(Instant::now());
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            *upstream_closed.lock().unwrap() = Some(Instant::now());
                            return;
                        }
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

async fn start(request_seen: &Flag, upstream_closed: &Flag) -> SocketAddr {
    let backend = spawn_backend(Arc::clone(request_seen), Arc::clone(upstream_closed)).await;
    let listen = free_addr().await;
    let text = support::config_toml(&listen.to_string(), &[("b1", backend)], 1000.0, 1000)
        .replacen(
            &format!("listen = \"{listen}\""),
            &format!("listen = \"{listen}\"\nforward_timeout_ms = 30000"),
            1,
        );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;
    listen
}

async fn wait_for(flag: &Flag) -> Option<Instant> {
    for _ in 0..150 {
        if let Some(at) = *flag.lock().unwrap() {
            return Some(at);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

#[tokio::test]
async fn a_client_that_disconnects_cancels_its_upstream_request() {
    let request_seen = Flag::default();
    let upstream_closed = Flag::default();
    let listen = start(&request_seen, &upstream_closed).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nX-Client: c1\r\n\r\n")
        .await
        .unwrap();
    assert!(
        wait_for(&request_seen).await.is_some(),
        "the request never reached the backend"
    );

    drop(client);
    let dropped_at = Instant::now();
    let closed_at = wait_for(&upstream_closed)
        .await
        .expect("the upstream request must be cancelled when its client goes away");
    assert!(
        closed_at.duration_since(dropped_at) < Duration::from_secs(2),
        "the upstream request outlived its client by {:?}",
        closed_at.duration_since(dropped_at)
    );
}

#[tokio::test]
async fn a_client_that_disconnects_mid_body_cancels_the_upstream_stream() {
    let request_seen = Flag::default();
    let upstream_closed = Flag::default();
    let listen = start(&request_seen, &upstream_closed).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"GET /stream HTTP/1.1\r\nHost: x\r\nX-Client: c1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&buf[..n])
    );

    drop(client);
    let dropped_at = Instant::now();
    let closed_at = wait_for(&upstream_closed)
        .await
        .expect("the upstream body must stop when its client goes away");
    assert!(
        closed_at.duration_since(dropped_at) < Duration::from_secs(2),
        "the upstream stream outlived its client by {:?}",
        closed_at.duration_since(dropped_at)
    );
}
