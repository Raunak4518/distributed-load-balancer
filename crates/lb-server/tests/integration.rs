mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::{
    config_toml, least_connections_config_toml, spawn_counting_backend, spawn_slow_counting_backend,
};
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

    let config = Config::parse(&config_toml(
        &listen.to_string(),
        &[("b1", addr1), ("b2", addr2)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await; // let the listener bind

    let client = reqwest::Client::new();
    for i in 0..4 {
        client
            .get(format!("http://{listen}/"))
            .header("X-Client", format!("client-{i}"))
            .send()
            .await
            .unwrap();
    }

    assert_eq!(
        count1.load(Ordering::SeqCst) + count2.load(Ordering::SeqCst),
        4
    );
    assert_eq!(count1.load(Ordering::SeqCst), 2);
    assert_eq!(count2.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rate_limits_a_bursty_client_with_429() {
    let (addr, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let config = Config::parse(&config_toml(&listen.to_string(), &[("b1", addr)], 2.0, 2)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();
    let mut statuses = vec![];
    for _ in 0..4 {
        let resp = client
            .get(format!("http://{listen}/"))
            .header("X-Client", "same-client")
            .send()
            .await
            .unwrap();
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

    let config = Config::parse(&config_toml(
        &listen.to_string(),
        &[("dead", dead_addr), ("alive", healthy_addr)],
        1000.0,
        1000,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

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

#[tokio::test]
async fn least_connections_routes_around_a_backend_still_mid_flight() {
    let (slow_addr, slow_count) =
        spawn_slow_counting_backend(StatusCode::OK, Duration::from_millis(400)).await;
    let (fast_addr, fast_count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    // "slow" listed first so the very first request (both backends at zero
    // active connections) lands on it via the stable tie-break -- that
    // request is what puts it mid-flight for the rest of this test.
    let config = Config::parse(&least_connections_config_toml(
        &listen.to_string(),
        &[("slow", slow_addr), ("fast", fast_addr)],
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::new();

    // Kicks off the request that will occupy "slow" for the next second;
    // deliberately not awaited yet.
    let occupying = {
        let client = client.clone();
        let url = format!("http://{listen}/");
        tokio::spawn(async move { client.get(url).send().await.unwrap() })
    };
    // Give it time to be accepted, picked, and dialed before the sequential
    // requests below start, so its active-connection guard is reliably held
    // first. Each of the five below is awaited to completion before the next
    // starts (unlike a concurrent burst), so its own pick only ever
    // competes against "slow" still mid-flight, not against a sibling
    // request racing the same tie.
    tokio::time::sleep(Duration::from_millis(50)).await;

    for _ in 0..5 {
        let resp = client
            .get(format!("http://{listen}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(occupying.await.unwrap().status(), StatusCode::OK);

    // "slow" was busy for the whole run, so every one of those 5 requests
    // must have gone to "fast" instead -- the property that distinguishes
    // this from round-robin, which would have split them evenly.
    assert_eq!(fast_count.load(Ordering::SeqCst), 5);
    assert_eq!(slow_count.load(Ordering::SeqCst), 1);
}
