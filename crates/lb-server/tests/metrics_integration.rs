mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::Duration;
use support::{admin_config_toml, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn scrape(admin: SocketAddr) -> String {
    reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

/// Start a server and return (traffic addr, admin addr).
async fn start(rate_per_sec: f64, burst: u32) -> (SocketAddr, SocketAddr) {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let traffic = free_addr().await;

    let config = Config::parse(&admin_config_toml(
        admin,
        traffic,
        backend,
        rate_per_sec,
        burst,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(traffic).await;

    (traffic, admin)
}

#[tokio::test]
async fn successful_requests_are_counted_as_2xx() {
    let (traffic, admin) = start(1000.0, 1000).await;

    for _ in 0..3 {
        let status = reqwest::get(format!("http://{traffic}/"))
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }

    let body = scrape(admin).await;
    assert!(
        body.contains(r#"status="2xx"} 3"#),
        "expected three 2xx requests recorded, got:\n{body}"
    );
}

#[tokio::test]
async fn rate_limited_requests_are_counted_against_the_local_layer() {
    // burst 2 so the third request is rejected by the local GCRA.
    let (traffic, admin) = start(2.0, 2).await;

    let mut statuses = vec![];
    for _ in 0..4 {
        statuses.push(
            reqwest::get(format!("http://{traffic}/"))
                .await
                .unwrap()
                .status(),
        );
    }
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS);

    let body = scrape(admin).await;
    assert!(
        body.contains(r#"lb_ratelimit_rejected_total{layer="local",listener="web"}"#),
        "expected a local rate-limit rejection counter, got:\n{body}"
    );
    // The cluster layer is not configured here, so it must stay at zero.
    assert!(
        body.contains(r#"lb_ratelimit_rejected_total{layer="cluster",listener="web"} 0"#),
        "cluster layer should be zero when clustering is disabled, got:\n{body}"
    );
}

#[tokio::test]
async fn request_latency_is_observed() {
    let (traffic, admin) = start(1000.0, 1000).await;
    reqwest::get(format!("http://{traffic}/")).await.unwrap();

    let body = scrape(admin).await;
    assert!(body.contains("lb_request_duration_seconds_count{listener=\"web\"} 1"));
    assert!(body.contains("lb_request_duration_seconds_bucket"));
}

#[tokio::test]
async fn backend_outcomes_and_health_are_recorded() {
    let (traffic, admin) = start(1000.0, 1000).await;
    reqwest::get(format!("http://{traffic}/")).await.unwrap();
    // Give the active health checker a tick to publish the gauge.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let body = scrape(admin).await;
    assert!(
        body.contains(
            r#"lb_backend_requests_total{backend="b1",listener="web",outcome="success"} 1"#
        ),
        "expected one successful backend request, got:\n{body}"
    );
    assert!(
        body.contains(r#"lb_backend_healthy{backend="b1",listener="web"} 1"#),
        "expected the backend to be marked healthy, got:\n{body}"
    );
}

/// The admin surface must not be reachable through the traffic port. A
/// request for /metrics there is just another path to proxy — otherwise an
/// edge-facing listener would hand out internal topology.
#[tokio::test]
async fn metrics_are_not_exposed_on_the_traffic_listener() {
    let (traffic, admin) = start(1000.0, 1000).await;

    let proxied = reqwest::get(format!("http://{traffic}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !proxied.contains("lb_requests_total"),
        "metrics leaked on the public traffic listener: {proxied}"
    );

    // Same path on the admin listener does serve them.
    assert!(scrape(admin).await.contains("lb_requests_total"));
}

#[tokio::test]
async fn health_endpoints_reflect_liveness_and_readiness() {
    let (_traffic, admin) = start(1000.0, 1000).await;

    assert_eq!(
        reqwest::get(format!("http://{admin}/healthz"))
            .await
            .unwrap()
            .status(),
        200
    );
    // The backend is up, so this instance is ready to take traffic.
    assert_eq!(
        reqwest::get(format!("http://{admin}/ready"))
            .await
            .unwrap()
            .status(),
        200
    );
}
