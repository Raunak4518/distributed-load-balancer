mod support;

use hyper::StatusCode;
use lb_core::Config;
use lb_server::reload::apply_reload;
use std::net::SocketAddr;
use std::time::Duration;
use support::spawn_counting_backend;
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config_text(listen: SocketAddr, backend: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 200
  timeout_ms = 200
  failure_threshold = 2
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

/// The real proof for config hot-reload: a *running* `lb_server::run`
/// instance, started from a config file on disk (reload re-reads from disk,
/// unlike every other integration test's inline-string config), serving a
/// real request against the original backend, then reloading to point at a
/// second one and serving a real request that reaches it -- all without the
/// listener's bound socket ever being touched. SIGHUP itself is untested
/// here (Unix-only, unavailable on this project's Windows dev environment —
/// see `lb_server::reload`'s module docs); `apply_reload` is called
/// directly, which is the entire portable part of the mechanism.
#[tokio::test]
async fn a_running_server_reloads_its_backend_list_without_dropping_the_listener() {
    let (backend1, count1) = spawn_counting_backend(StatusCode::OK).await;
    let (backend2, count2) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let dir = std::env::temp_dir().join(format!(
        "lb-reload-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, config_text(listen, backend1)).unwrap();

    let config = Config::load(&config_path).unwrap();
    let (report_tx, report_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(lb_server::run_and_report_reload_handle(
        config,
        Some(config_path.clone()),
        Some(report_tx),
    ));
    support::wait_until_listening(listen).await;
    let reload_state = report_rx.await.unwrap();

    // Give the health checker a moment to confirm backend1 up.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let resp = reqwest::get(format!("http://{listen}/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(count1.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(count2.load(std::sync::atomic::Ordering::SeqCst), 0);

    // Edit the config file on disk, then reload it -- exactly what the
    // SIGHUP handler does, minus the signal itself.
    let old_config = Config::load(&config_path).unwrap();
    std::fs::write(&config_path, config_text(listen, backend2)).unwrap();
    let new_config = Config::load(&config_path).unwrap();
    let outcome = apply_reload(&new_config, &old_config, &reload_state).await;
    assert!(
        matches!(outcome, lb_server::reload::ReloadOutcome::Applied { .. }),
        "expected the reload to apply, got {outcome:?}"
    );

    // Give the new health checker a moment to confirm backend2 up.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let resp = reqwest::get(format!("http://{listen}/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        count2.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the second request should have reached the newly configured backend"
    );
    assert_eq!(
        count1.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the first backend should not have received a second request after reload"
    );
}
