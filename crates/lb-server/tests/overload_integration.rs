mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
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

async fn get(listen: SocketAddr) -> String {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Client: c1\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("a response must arrive")
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase()
}

async fn hold(listen: SocketAddr, count: usize) -> Vec<TcpStream> {
    let mut held = Vec::new();
    for _ in 0..count {
        held.push(TcpStream::connect(listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    held
}

#[tokio::test]
async fn connection_pressure_sheds_keepalive_then_rejects_and_recovers() {
    let (backend, _) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let text = format!(
        "[server.overload]\nshed_keepalive_at = 0.3\nreject_at = 0.6\ncheck_interval_ms = 50\n[admin]\nlisten = \"{admin}\"\n{}",
        support::config_toml(&listen.to_string(), &[("b1", backend)], 1000.0, 1000).replacen(
            &format!("listen = \"{listen}\""),
            &format!("listen = \"{listen}\"\nmax_connections = 10\nmax_connections_per_ip = 10"),
            1,
        )
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let normal = get(listen).await;
    assert!(normal.starts_with("http/1.1 200"), "{normal}");
    assert!(!normal.contains("connection: close"), "{normal}");

    let three = hold(listen, 3).await;
    let shedding = get(listen).await;
    assert!(shedding.starts_with("http/1.1 200"), "{shedding}");
    assert!(
        shedding.contains("connection: close"),
        "at 30% of max_connections keep-alive must be shed: {shedding}"
    );

    let three_more = hold(listen, 3).await;
    let rejected = get(listen).await;
    assert!(
        rejected.starts_with("http/1.1 503"),
        "at 60% of max_connections new requests must be refused: {rejected}"
    );
    assert!(rejected.contains("retry-after: 1"), "{rejected}");
    assert_eq!(
        ready(admin).await,
        503,
        "an instance refusing work must leave rotation"
    );

    drop(three);
    drop(three_more);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let recovered = get(listen).await;
    assert!(recovered.starts_with("http/1.1 200"), "{recovered}");
    assert!(!recovered.contains("connection: close"), "{recovered}");
    assert_eq!(ready(admin).await, 200);
}

async fn ready(admin: SocketAddr) -> u16 {
    reqwest::get(format!("http://{admin}/ready"))
        .await
        .unwrap()
        .status()
        .as_u16()
}
