mod support;

use hyper::StatusCode;
use lb_core::Config;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use support::{admin_config_toml_two_backends, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn get_json(url: &str) -> (StatusCode, Value) {
    let resp = reqwest::get(url).await.unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap())
}

/// `GET /backends` reports real, current state -- not just that the
/// endpoint exists.
#[tokio::test]
async fn lists_every_listeners_backends_with_live_state() {
    let (backend_a, _count_a) = spawn_counting_backend(StatusCode::OK).await;
    let (backend_b, _count_b) = spawn_counting_backend(StatusCode::OK).await;
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(&admin_config_toml_two_backends(
        admin_listen,
        traffic_listen,
        backend_a,
        backend_b,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(traffic_listen).await;
    support::wait_until_listening(admin_listen).await;

    let (status, body) = get_json(&format!("http://{admin_listen}/backends")).await;
    assert_eq!(status, StatusCode::OK);

    let web = body
        .get("web")
        .and_then(Value::as_array)
        .expect("listing should have a 'web' listener with an array of backends");
    assert_eq!(web.len(), 2);
    for backend in web {
        assert!(backend.get("id").is_some());
        assert!(backend.get("address").is_some());
        assert_eq!(backend["active_healthy"], Value::Bool(true));
        assert_eq!(backend["circuit_open"], Value::Bool(false));
        assert_eq!(backend["manually_drained"], Value::Bool(false));
        assert_eq!(backend["outlier_ejected"], Value::Bool(false));
        assert_eq!(backend["awaiting_first_probe"], Value::Bool(false));
        assert_eq!(backend["eligible"], Value::Bool(true));
    }
}

/// The direct proof: draining a backend removes it from rotation for *new*
/// traffic, and undraining puts it back -- not just that the listing
/// reflects a flag, but that real requests actually change destination.
#[tokio::test]
async fn drain_and_undrain_change_where_traffic_goes() {
    let (backend_a, count_a) = spawn_counting_backend(StatusCode::OK).await;
    let (backend_b, count_b) = spawn_counting_backend(StatusCode::OK).await;
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(&admin_config_toml_two_backends(
        admin_listen,
        traffic_listen,
        backend_a,
        backend_b,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(traffic_listen).await;
    support::wait_until_listening(admin_listen).await;

    let client = reqwest::Client::new();

    // Drain "a": every subsequent request must land on "b" alone.
    let drain = client
        .post(format!("http://{admin_listen}/backends/web/a/drain"))
        .send()
        .await
        .unwrap();
    assert_eq!(drain.status(), StatusCode::OK);

    for _ in 0..6 {
        let status = reqwest::get(format!("http://{traffic_listen}/"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        count_a.load(Ordering::SeqCst),
        0,
        "drained backend received traffic"
    );
    assert_eq!(count_b.load(Ordering::SeqCst), 6);

    // Undrain "a": round-robin resumes across both.
    let undrain = client
        .post(format!("http://{admin_listen}/backends/web/a/undrain"))
        .send()
        .await
        .unwrap();
    assert_eq!(undrain.status(), StatusCode::OK);

    for _ in 0..6 {
        let status = reqwest::get(format!("http://{traffic_listen}/"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        count_a.load(Ordering::SeqCst),
        3,
        "undrained backend never resumed receiving its share"
    );
    assert_eq!(count_b.load(Ordering::SeqCst), 9);
}

#[tokio::test]
async fn draining_an_unknown_backend_is_a_404_not_a_silent_no_op() {
    let (backend_a, _count) = spawn_counting_backend(StatusCode::OK).await;
    let (backend_b, _count) = spawn_counting_backend(StatusCode::OK).await;
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(&admin_config_toml_two_backends(
        admin_listen,
        traffic_listen,
        backend_a,
        backend_b,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(admin_listen).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{admin_listen}/backends/web/ghost/drain"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn draining_on_an_unknown_listener_is_a_404() {
    let (backend_a, _count) = spawn_counting_backend(StatusCode::OK).await;
    let (backend_b, _count) = spawn_counting_backend(StatusCode::OK).await;
    let admin_listen = free_addr().await;
    let traffic_listen = free_addr().await;
    let config = Config::parse(&admin_config_toml_two_backends(
        admin_listen,
        traffic_listen,
        backend_a,
        backend_b,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(admin_listen).await;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{admin_listen}/backends/ghost-listener/a/drain"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
