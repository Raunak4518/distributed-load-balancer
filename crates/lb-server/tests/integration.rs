mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::{config_toml, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn distributes_requests_round_robin_across_backends() {
    let (addr1, count1) = spawn_counting_backend(StatusCode::OK).await;
    let (addr2, count2) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("b1", addr1), ("b2", addr2)], 1000.0, 1000)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await; // let the listener bind

    let client = reqwest::Client::new();
    for i in 0..4 {
        client
            .get(format!("http://{listen}/"))
            .header("X-Client", format!("client-{i}"))
            .send()
            .await
            .unwrap();
    }

    assert_eq!(count1.load(Ordering::SeqCst) + count2.load(Ordering::SeqCst), 4);
    assert_eq!(count1.load(Ordering::SeqCst), 2);
    assert_eq!(count2.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rate_limits_a_bursty_client_with_429() {
    let (addr, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("b1", addr)], 2.0, 2)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let mut statuses = vec![];
    for _ in 0..4 {
        let resp = client.get(format!("http://{listen}/")).header("X-Client", "same-client").send().await.unwrap();
        statuses.push(resp.status());
    }

    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(statuses[1], StatusCode::OK);
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn fails_over_when_a_backend_stops_responding() {
    let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // nothing listens here
    let (healthy_addr, healthy_count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("dead", dead_addr), ("alive", healthy_addr)], 1000.0, 1000)).unwrap();
    tokio::spawn(lb_server::run(config));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let mut ok_count = 0;
    for i in 0..6 {
        let resp = client
            .get(format!("http://{listen}/"))
            .header("X-Client", format!("client-{i}"))
            .send()
            .await
            .unwrap();
        if resp.status() == StatusCode::OK {
            ok_count += 1;
        }
    }

    // Every request either lands on the healthy backend directly, or gets
    // retried onto it after the dead one fails — none should hard-fail.
    assert_eq!(ok_count, 6);
    assert_eq!(healthy_count.load(Ordering::SeqCst), 6);
}
