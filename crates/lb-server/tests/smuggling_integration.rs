mod support;

use lb_core::Config;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

type Wire = Arc<Mutex<Vec<u8>>>;

async fn spawn_recording_backend() -> (SocketAddr, Wire) {
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
                    let n = match tokio::time::timeout(
                        Duration::from_millis(300),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(0)) | Ok(Err(_)) => return,
                        Ok(Ok(n)) => n,
                        Err(_) => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                                .await;
                            continue;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    recorded.lock().unwrap().extend_from_slice(&buf[..n]);
                    if head.starts_with("GET /health") {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                }
            });
        }
    });
    (addr, wire)
}

async fn start() -> (SocketAddr, Wire) {
    let (backend, wire) = spawn_recording_backend().await;
    let listen = free_addr().await;
    let text = support::config_toml(&listen.to_string(), &[("b1", backend)], 1000.0, 1000);
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    wire.lock().unwrap().clear();
    (listen, wire)
}

async fn send_raw(listen: SocketAddr, raw: &[u8]) -> String {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(raw).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).to_string()
}

fn backend_saw(wire: &Wire) -> String {
    String::from_utf8_lossy(&wire.lock().unwrap())
        .split("\r\n\r\n")
        .filter(|chunk| !chunk.is_empty() && !chunk.starts_with("GET /health"))
        .collect::<Vec<_>>()
        .join("\n---\n")
        .to_ascii_lowercase()
}

#[tokio::test]
async fn content_length_with_chunked_is_framed_by_chunked_and_the_connection_closed() {
    let (listen, wire) = start().await;
    let response = send_raw(
        listen,
        b"POST / HTTP/1.1\r\nHost: x\r\nX-Client: c\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await
    .to_ascii_lowercase();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = backend_saw(&wire);
    assert!(
        response.starts_with("http/1.1 400") || response.contains("connection: close"),
        "an ambiguously framed request must be refused or end its connection: {response}"
    );
    assert!(!seen.contains("/smuggled"), "{seen}");
    assert!(!seen.contains("content-length: 4"), "{seen}");
}

#[tokio::test]
async fn conflicting_content_lengths_are_refused() {
    let (listen, wire) = start().await;
    let response = send_raw(
        listen,
        b"POST / HTTP/1.1\r\nHost: x\r\nX-Client: c\r\nContent-Length: 4\r\nContent-Length: 20\r\n\r\nabcdGET /smuggled HTTP/1.1\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(backend_saw(&wire).is_empty());
}

#[tokio::test]
async fn a_request_with_two_host_headers_is_refused() {
    let (listen, wire) = start().await;
    let response = send_raw(
        listen,
        b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nX-Client: c\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(backend_saw(&wire).is_empty(), "{}", backend_saw(&wire));
}

#[tokio::test]
async fn an_http11_request_without_a_host_is_refused() {
    let (listen, wire) = start().await;
    let response = send_raw(listen, b"GET / HTTP/1.1\r\nX-Client: c\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(backend_saw(&wire).is_empty());
}

#[tokio::test]
async fn an_absolute_form_target_decides_the_host_the_backend_sees() {
    let (listen, wire) = start().await;
    let response = send_raw(
        listen,
        b"GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\nX-Client: c\r\nConnection: close\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = backend_saw(&wire);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(seen.contains("host: a.example"), "{seen}");
    assert!(!seen.contains("b.example"), "{seen}");
}

#[tokio::test]
async fn a_chunked_body_reaches_the_backend_with_one_consistent_framing() {
    let (listen, wire) = start().await;
    let response = send_raw(
        listen,
        b"POST / HTTP/1.1\r\nHost: x\r\nX-Client: c\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = backend_saw(&wire);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let has_cl = seen.contains("content-length:");
    let has_te = seen.contains("transfer-encoding:");
    assert!(
        has_cl != has_te,
        "exactly one framing header must reach the backend: {seen}"
    );
}
