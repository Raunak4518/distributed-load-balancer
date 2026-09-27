mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(
    listen: SocketAddr,
    local_zone: &str,
    backends: &[(&str, SocketAddr, u32, &str)],
) -> String {
    let backends: String = backends
        .iter()
        .map(|(id, addr, priority, zone)| {
            format!(
                "  [[listeners.backends]]\n  id = \"{id}\"\n  address = \"{addr}\"\n  priority = {priority}\n  zone = \"{zone}\"\n\n"
            )
        })
        .collect();
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
local_zone = "{local_zone}"

{backends}
  [listeners.health_check]
  path = "/health"
  interval_ms = 50
  timeout_ms = 200
  failure_threshold = 2
  unhealthy_threshold = 1
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

async fn get(listen: SocketAddr) -> StatusCode {
    reqwest::get(format!("http://{listen}/"))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn same_zone_backends_take_all_traffic_while_they_are_healthy() {
    let (near, near_hits) = support::spawn_counting_backend(StatusCode::OK).await;
    let (far, far_hits) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let text = config(
        listen,
        "eu-1",
        &[("near", near, 0, "eu-1"), ("far", far, 0, "us-1")],
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;

    for _ in 0..10 {
        assert_eq!(get(listen).await, StatusCode::OK);
    }
    assert_eq!(near_hits.load(Ordering::SeqCst), 10);
    assert_eq!(far_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_backup_idles_while_the_primary_is_healthy() {
    let (primary, primary_hits) = support::spawn_counting_backend(StatusCode::OK).await;
    let (backup, backup_hits) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let text = config(
        listen,
        "eu-1",
        &[
            ("primary", primary, 0, "eu-1"),
            ("backup", backup, 1, "eu-1"),
        ],
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;

    for _ in 0..10 {
        assert_eq!(get(listen).await, StatusCode::OK);
    }
    assert_eq!(primary_hits.load(Ordering::SeqCst), 10);
    assert_eq!(backup_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_backup_takes_over_when_the_primary_fails_its_health_checks() {
    let primary = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (backup, backup_hits) = support::spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let text = config(
        listen,
        "eu-1",
        &[
            ("primary", primary, 0, "eu-1"),
            ("backup", backup, 1, "eu-1"),
        ],
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    for _ in 0..10 {
        assert_eq!(get(listen).await, StatusCode::OK);
    }
    assert_eq!(backup_hits.load(Ordering::SeqCst), 10);
}
