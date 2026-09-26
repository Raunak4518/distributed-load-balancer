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
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(traffic).await;
    // The traffic and admin listeners bind independently inside `run` --
    // waiting on one is no guarantee the other is up yet. Every test in
    // this file scrapes `admin` right after `start()` returns, so without
    // this a slow/contended CI runner can still see a connection refused on
    // the admin port even though the traffic port answered fine.
    support::wait_until_listening(admin).await;

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

fn metric_value(body: &str, series: &str) -> f64 {
    body.lines()
        .find(|line| line.starts_with(series))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("series {series} missing from:\n{body}"))
}

async fn start_with_header_timeout(header_read_timeout_ms: u64) -> (SocketAddr, SocketAddr) {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let traffic = free_addr().await;
    let text = admin_config_toml(admin, traffic, backend, 1000.0, 1000).replacen(
        &format!("listen = \"{traffic}\""),
        &format!("listen = \"{traffic}\"\nheader_read_timeout_ms = {header_read_timeout_ms}"),
        1,
    );
    let config = Config::parse(&text).unwrap();
    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(traffic).await;
    support::wait_until_listening(admin).await;
    (traffic, admin)
}

#[tokio::test]
async fn http_connections_are_counted_while_open_and_released_after() {
    let (traffic, admin) = start(1000.0, 1000).await;
    let held = tokio::net::TcpStream::connect(traffic).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let body = scrape(admin).await;
    assert!(metric_value(&body, r#"lb_active_connections{listener="web"}"#) >= 1.0);
    assert!(metric_value(&body, r#"lb_connections_total{listener="web"}"#) >= 1.0);

    drop(held);
    let mut released = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let body = scrape(admin).await;
        if metric_value(&body, r#"lb_active_connections{listener="web"}"#) == 0.0 {
            released = true;
            break;
        }
    }
    assert!(released, "the active-connection gauge must return to zero");
}

#[tokio::test]
async fn a_stalled_request_head_is_counted_as_a_header_timeout() {
    use tokio::io::AsyncWriteExt;
    let (traffic, admin) = start_with_header_timeout(200).await;
    let mut slow = tokio::net::TcpStream::connect(traffic).await.unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;

    let body = scrape(admin).await;
    assert_eq!(
        metric_value(
            &body,
            r#"lb_request_timeouts_total{listener="web",phase="header"}"#
        ),
        1.0
    );
}

fn listener_toml(name: &str, listen: SocketAddr, backend: SocketAddr, tls: &str) -> String {
    format!(
        r#"
[[listeners]]
name = "{name}"
protocol = "http"
listen = "{listen}"
{tls}
  [[listeners.backends]]
  id = "{name}-1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 200
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

async fn ready_status(admin: SocketAddr) -> u16 {
    reqwest::get(format!("http://{admin}/ready"))
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn admin_post(admin: SocketAddr, path: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("http://{admin}{path}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn ready_fails_when_any_one_listener_has_nowhere_to_forward() {
    let (web_backend, _) = spawn_counting_backend(StatusCode::OK).await;
    let (api_backend, _) = spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let web = free_addr().await;
    let api = free_addr().await;
    let text = format!(
        "[admin]\nlisten = \"{admin}\"\n{}{}",
        listener_toml("web", web, web_backend, ""),
        listener_toml("api", api, api_backend, "")
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(web).await;
    support::wait_until_listening(api).await;
    support::wait_until_listening(admin).await;

    assert_eq!(ready_status(admin).await, 200);
    assert_eq!(admin_post(admin, "/backends/api/api-1/drain").await, 200);
    assert_eq!(
        ready_status(admin).await,
        503,
        "a listener with every backend drained cannot serve, even though another listener can"
    );
    assert_eq!(admin_post(admin, "/backends/api/api-1/undrain").await, 200);
    assert_eq!(ready_status(admin).await, 200);
}

#[tokio::test]
async fn ready_reads_the_pools_a_reload_swapped_in() {
    let (first, _) = spawn_counting_backend(StatusCode::OK).await;
    let (second, _) = spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let web = free_addr().await;
    let config_for = |backend| {
        Config::parse(&format!(
            "[admin]\nlisten = \"{admin}\"\n{}",
            listener_toml("web", web, backend, "")
        ))
        .unwrap()
    };
    let (report_tx, report_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(lb_server::run_and_report_reload_handle(
        config_for(first),
        None,
        Some(report_tx),
    ));
    support::wait_until_listening(web).await;
    support::wait_until_listening(admin).await;
    let reload_state = report_rx.await.unwrap();

    let outcome =
        lb_server::reload::apply_reload(&config_for(second), &config_for(first), &reload_state)
            .await;
    assert!(
        matches!(outcome, lb_server::reload::ReloadOutcome::Applied { .. }),
        "expected the reload to apply, got {outcome:?}"
    );
    assert_eq!(admin_post(admin, "/backends/web/web-1/drain").await, 200);
    assert_eq!(
        ready_status(admin).await,
        503,
        "readiness must judge the live pool, not the one built at startup"
    );
}

#[tokio::test]
async fn ready_fails_while_a_listener_serves_an_expired_certificate() {
    let (backend, _) = spawn_counting_backend(StatusCode::OK).await;
    let admin = free_addr().await;
    let web = free_addr().await;
    let dir = std::env::temp_dir().join(format!(
        "lb-ready-cert-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    lb_tls::ensure_bootstrap_certificate(&cert, &key, "localhost").unwrap();
    let tls = format!(
        "\n  [listeners.tls]\n  reload_interval_secs = 1\n    [[listeners.tls.certificates]]\n    name = \"primary\"\n    cert_file = \"{}\"\n    key_file = \"{}\"\n    hostnames = [\"localhost\"]\n",
        cert.display().to_string().replace('\\', "\\\\"),
        key.display().to_string().replace('\\', "\\\\"),
    );
    let text = format!(
        "[admin]\nlisten = \"{admin}\"\n{}",
        listener_toml("web", web, backend, &tls)
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(web).await;
    support::wait_until_listening(admin).await;

    assert_eq!(
        ready_status(admin).await,
        503,
        "an instance serving an expired certificate must not take traffic"
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let renewed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(&key, renewed.key_pair.serialize_pem()).unwrap();
    std::fs::write(&cert, renewed.cert.pem()).unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(15), async {
        while ready_status(admin).await != 200 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "readiness must return once a valid certificate is loaded"
    );
    let _ = std::fs::remove_dir_all(dir);
}
