mod support;

use hyper::StatusCode;
use lb_core::Config;
use lb_server::reload::{apply_reload, ReloadOutcome};
use serde_json::Value;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::{spawn_counting_backend, spawn_slow_counting_backend, wait_until_listening};
use tokio::net::TcpListener;
use tokio::process::Command;

#[cfg(windows)]
mod shutdown_signal {
    pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    #[link(name = "kernel32")]
    extern "system" {
        fn GenerateConsoleCtrlEvent(dw_ctrl_event: u32, dw_process_group_id: u32) -> i32;
    }

    const CTRL_BREAK_EVENT: u32 = 1;

    pub fn send_graceful_shutdown(pid: u32) {
        unsafe {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
        }
    }
}

#[cfg(unix)]
mod shutdown_signal {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    const SIGTERM: i32 = 15;

    pub fn send_graceful_shutdown(pid: u32) {
        unsafe {
            kill(pid as i32, SIGTERM);
        }
    }
}

use shutdown_signal::send_graceful_shutdown;

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_abortable_backend(status: StatusCode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (addr, handle)
}

#[derive(Debug)]
struct Sample {
    at_ms: f64,
    ok: bool,
    latency_ms: f64,
}

fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder().timeout(timeout).build().unwrap()
}

async fn closed_loop(
    client: reqwest::Client,
    url: String,
    concurrency: usize,
    start: Instant,
    stop_at: Instant,
) -> Vec<Sample> {
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let samples = Arc::clone(&samples);
        handles.push(tokio::spawn(async move {
            let mut local = Vec::new();
            while Instant::now() < stop_at {
                let req_started = Instant::now();
                let ok = match client.get(&url).send().await {
                    Ok(resp) => resp.status().is_success(),
                    Err(_) => false,
                };
                local.push(Sample {
                    at_ms: req_started.duration_since(start).as_secs_f64() * 1000.0,
                    ok,
                    latency_ms: req_started.elapsed().as_secs_f64() * 1000.0,
                });
            }
            samples.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Arc::try_unwrap(samples).unwrap().into_inner().unwrap()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn window_stats(samples: &[Sample], from_ms: f64, to_ms: f64) -> (usize, usize, f64, f64) {
    let mut lat: Vec<f64> = samples
        .iter()
        .filter(|s| s.at_ms >= from_ms && s.at_ms < to_ms)
        .map(|s| s.latency_ms)
        .collect();
    let total = lat.len();
    let errors = samples
        .iter()
        .filter(|s| s.at_ms >= from_ms && s.at_ms < to_ms && !s.ok)
        .count();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&lat, 0.50);
    let p99 = percentile(&lat, 0.99);
    (total, errors, p50, p99)
}

fn shutdown_config_text(
    listen: SocketAddr,
    backends: &[SocketAddr],
    drain_timeout_ms: u64,
) -> String {
    let backends_toml: String = backends
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            format!("  [[listeners.backends]]\n  id = \"b{i}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    format!(
        r#"
[server]
drain_timeout_ms = {drain_timeout_ms}

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

{backends_toml}
  [listeners.health_check]
  path = "/health"
  interval_ms = 100
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 2000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

#[tokio::test]
async fn graceful_shutdown_drains_in_flight_requests_under_load() {
    let mut backend_addrs = Vec::new();
    for _ in 0..3 {
        let (addr, _count) =
            spawn_slow_counting_backend(StatusCode::OK, Duration::from_millis(120)).await;
        backend_addrs.push(addr);
    }
    let listen = free_addr().await;
    let drain_timeout_ms = 2500u64;

    let dir = std::env::temp_dir().join(format!(
        "lb-lifecycle-shutdown-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        shutdown_config_text(listen, &backend_addrs, drain_timeout_ms),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_lb-server"));
    command
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        command.creation_flags(shutdown_signal::CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = command.spawn().expect("failed to spawn lb-server");
    let pid = child.id().expect("child has a pid");
    wait_until_listening(listen).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = build_client(Duration::from_secs(2));
    let url = format!("http://{listen}/");

    let start = Instant::now();
    let pre_window = Duration::from_millis(1500);
    let post_window = Duration::from_millis(5500);
    let stop_at = start + pre_window + post_window;
    let concurrency = 48;

    let load = closed_loop(client.clone(), url.clone(), concurrency, start, stop_at);
    let signal_sent: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let signal_sent_writer = Arc::clone(&signal_sent);
    let signaller = async move {
        tokio::time::sleep(pre_window).await;
        let at = Instant::now();
        send_graceful_shutdown(pid);
        *signal_sent_writer.lock().unwrap() = Some(at);
    };
    let exit_deadline = Duration::from_millis(drain_timeout_ms) + Duration::from_secs(3);
    let waiter = async {
        let res = tokio::time::timeout(exit_deadline, child.wait()).await;
        (Instant::now(), res)
    };

    let (samples, _, (exit_at, exit_res)) = tokio::join!(load, signaller, waiter);

    let signal_sent_at = signal_sent.lock().unwrap().expect("signal was sent");
    let signal_at_ms = signal_sent_at.duration_since(start).as_secs_f64() * 1000.0;

    let (pre_total, pre_errors, pre_p50, pre_p99) = window_stats(&samples, 0.0, signal_at_ms);
    let (during_total, during_errors, during_p50, during_p99) = window_stats(
        &samples,
        signal_at_ms,
        signal_at_ms + drain_timeout_ms as f64 + 500.0,
    );
    let (post_total, post_errors, post_p50, post_p99) = window_stats(
        &samples,
        signal_at_ms + drain_timeout_ms as f64 + 500.0,
        f64::MAX,
    );

    let first_bad_after_signal = samples
        .iter()
        .filter(|s| s.at_ms >= signal_at_ms)
        .find(|s| !s.ok || s.latency_ms > 500.0)
        .map(|s| s.at_ms - signal_at_ms);

    println!("=== Graceful shutdown under load (drain_timeout_ms={drain_timeout_ms}, concurrency={concurrency}) ===");
    println!(
        "baseline   : n={pre_total:>5} errors={pre_errors:>4} p50={pre_p50:>7.1}ms p99={pre_p99:>7.1}ms"
    );
    println!(
        "during     : n={during_total:>5} errors={during_errors:>4} p50={during_p50:>7.1}ms p99={during_p99:>7.1}ms"
    );
    println!(
        "post-drain : n={post_total:>5} errors={post_errors:>4} p50={post_p50:>7.1}ms p99={post_p99:>7.1}ms"
    );
    println!(
        "reaction time (first failed/slow request after signal): {}",
        first_bad_after_signal
            .map(|v| format!("{v:.1}ms"))
            .unwrap_or_else(|| "none observed".to_string())
    );

    let exited = matches!(exit_res, Ok(Ok(_)));
    let exit_delta_ms = exit_at.duration_since(signal_sent_at).as_secs_f64() * 1000.0;
    if exited {
        println!(
            "process exit: {exit_delta_ms:.1}ms after signal (drain_timeout_ms={drain_timeout_ms})"
        );
    } else {
        println!("process exit: did NOT exit within {exit_deadline:?}, forcing kill");
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    assert!(
        (pre_errors as f64 / pre_total.max(1) as f64) < 0.05,
        "baseline error rate should be near zero before shutdown: {pre_errors}/{pre_total}"
    );
    assert!(
        exited,
        "lb-server did not exit within drain_timeout_ms + 3s buffer"
    );
    assert!(
        exit_delta_ms <= drain_timeout_ms as f64 + 1500.0,
        "process exit took {exit_delta_ms:.1}ms, expected within drain_timeout_ms ({drain_timeout_ms}ms) + slack"
    );
}

fn reload_config_text(
    listen: SocketAddr,
    admin_listen: SocketAddr,
    b1: SocketAddr,
    b2: SocketAddr,
    b3_dead: SocketAddr,
) -> String {
    format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
forward_timeout_ms = 300

  [[listeners.backends]]
  id = "b1"
  address = "{b1}"

  [[listeners.backends]]
  id = "b2"
  address = "{b2}"

  [[listeners.backends]]
  id = "b3"
  address = "{b3_dead}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 100
  timeout_ms = 200
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

fn reload_config_text_with_b4(
    listen: SocketAddr,
    admin_listen: SocketAddr,
    b1: SocketAddr,
    b2: SocketAddr,
    b3_dead: SocketAddr,
    b4: SocketAddr,
) -> String {
    format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
forward_timeout_ms = 300

  [[listeners.backends]]
  id = "b1"
  address = "{b1}"

  [[listeners.backends]]
  id = "b2"
  address = "{b2}"

  [[listeners.backends]]
  id = "b3"
  address = "{b3_dead}"

  [[listeners.backends]]
  id = "b4"
  address = "{b4}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 100
  timeout_ms = 200
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

async fn admin_backends(client: &reqwest::Client, admin_listen: SocketAddr) -> Value {
    let resp = client
        .get(format!("http://{admin_listen}/backends"))
        .send()
        .await
        .unwrap();
    let text = resp.text().await.unwrap();
    serde_json::from_str(&text).unwrap()
}

fn backend_entry<'a>(body: &'a Value, listener: &str, id: &str) -> &'a Value {
    body[listener]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == id)
        .unwrap_or_else(|| panic!("no backend '{id}' in listener '{listener}'"))
}

#[tokio::test]
async fn reload_preserves_manual_drain_and_open_circuit_under_load() {
    let (b1, _c1) = spawn_counting_backend(StatusCode::OK).await;
    let (b2, _c2) = spawn_counting_backend(StatusCode::OK).await;
    let (b3_addr, b3_handle) = spawn_abortable_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let admin_listen = free_addr().await;

    let dir = std::env::temp_dir().join(format!(
        "lb-lifecycle-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        reload_config_text(listen, admin_listen, b1, b2, b3_addr),
    )
    .unwrap();

    let config = Config::load(&config_path).unwrap();
    let (report_tx, report_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(lb_server::run_and_report_reload_handle(
        config,
        Some(config_path.clone()),
        Some(report_tx),
    ));
    wait_until_listening(listen).await;
    wait_until_listening(admin_listen).await;
    let reload_state = report_rx.await.unwrap();

    let client = build_client(Duration::from_secs(2));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let initial = admin_backends(&client, admin_listen).await;
    assert_eq!(
        backend_entry(&initial, "web", "b3")["active_healthy"],
        Value::Bool(true),
        "b3 must be genuinely healthy and in rotation before it is killed"
    );
    b3_handle.abort();
    let url = format!("http://{listen}/");
    let start = Instant::now();
    let stop_at = start + Duration::from_secs(5);
    let concurrency = 48;

    let load = closed_loop(client.clone(), url.clone(), concurrency, start, stop_at);

    let admin_client = client.clone();
    let control = async move {
        let circuit_open_at = {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let body = admin_backends(&admin_client, admin_listen).await;
                if backend_entry(&body, "web", "b3")["circuit_open"] == Value::Bool(true) {
                    break Some(Instant::now());
                }
                if Instant::now() >= deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        };

        admin_client
            .post(format!("http://{admin_listen}/backends/web/b2/drain"))
            .send()
            .await
            .unwrap();
        let after_drain = admin_backends(&admin_client, admin_listen).await;
        assert_eq!(
            backend_entry(&after_drain, "web", "b2")["manually_drained"],
            Value::Bool(true)
        );

        let old_config = Config::load(&config_path).unwrap();
        let (b4_addr, _c4) = spawn_counting_backend(StatusCode::OK).await;
        std::fs::write(
            &config_path,
            reload_config_text_with_b4(listen, admin_listen, b1, b2, b3_addr, b4_addr),
        )
        .unwrap();
        let new_config = Config::load(&config_path).unwrap();

        let reload_started = Instant::now();
        let outcome = apply_reload(&new_config, &old_config, &reload_state).await;
        let reload_elapsed = reload_started.elapsed();

        let fresh_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let _ = fresh_client.get(&url).send().await;

        let settle_deadline = Instant::now() + Duration::from_millis(500);
        let mut after_reload = admin_backends(&admin_client, admin_listen).await;
        while backend_entry(&after_reload, "web", "b3")["circuit_open"] != Value::Bool(true)
            && Instant::now() < settle_deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
            after_reload = admin_backends(&admin_client, admin_listen).await;
        }
        (
            circuit_open_at,
            outcome,
            reload_started,
            reload_elapsed,
            after_reload,
        )
    };

    let (samples, (circuit_open_at, outcome, reload_started, reload_elapsed, after_reload)) =
        tokio::join!(load, control);

    let circuit_open_at = circuit_open_at
        .expect("backend b3's circuit should have opened under real failing load within 3s");
    let reload_start_ms = reload_started.duration_since(start).as_secs_f64() * 1000.0;
    let (reload_total, reload_errors, reload_p50, reload_p99) = window_stats(
        &samples,
        reload_start_ms - 100.0,
        reload_start_ms + reload_elapsed.as_secs_f64() * 1000.0 + 200.0,
    );
    let (overall_total, overall_errors, overall_p50, overall_p99) =
        window_stats(&samples, 0.0, f64::MAX);

    println!("=== Config reload under load (manual drain + open circuit must survive) ===");
    println!(
        "circuit on b3 opened {:.0}ms after start under real failing traffic",
        circuit_open_at.duration_since(start).as_secs_f64() * 1000.0
    );
    println!(
        "reload applied in {:.2}ms",
        reload_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "around reload: n={reload_total:>4} errors={reload_errors:>3} p50={reload_p50:>7.1}ms p99={reload_p99:>7.1}ms"
    );
    println!(
        "overall      : n={overall_total:>4} errors={overall_errors:>3} p50={overall_p50:>7.1}ms p99={overall_p99:>7.1}ms"
    );

    assert!(
        matches!(&outcome, ReloadOutcome::Applied { changed } if changed == &vec!["web".to_string()]),
        "expected the backend-list reload to apply to listener 'web', got {outcome:?}"
    );
    assert_eq!(
        after_reload["web"].as_array().unwrap().len(),
        4,
        "expected 4 backends on 'web' after adding b4"
    );
    assert_eq!(
        backend_entry(&after_reload, "web", "b2")["manually_drained"],
        Value::Bool(true),
        "b2's manual drain must survive an unrelated backend-list reload"
    );
    assert_eq!(
        backend_entry(&after_reload, "web", "b3")["circuit_open"],
        Value::Bool(true),
        "b3's open circuit must survive an unrelated backend-list reload"
    );
}

fn refused_reload_config_text(listen: SocketAddr, b1: SocketAddr, b2: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{b1}"

  [[listeners.backends]]
  id = "b2"
  address = "{b2}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 200
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000000
  burst = 10000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

#[tokio::test]
async fn restart_required_reload_is_refused_without_dropping_traffic() {
    let (b1, _c1) = spawn_counting_backend(StatusCode::OK).await;
    let (b2, _c2) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;

    let dir = std::env::temp_dir().join(format!(
        "lb-lifecycle-refuse-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, refused_reload_config_text(listen, b1, b2)).unwrap();

    let config = Config::load(&config_path).unwrap();
    let (report_tx, report_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(lb_server::run_and_report_reload_handle(
        config,
        Some(config_path.clone()),
        Some(report_tx),
    ));
    wait_until_listening(listen).await;
    let reload_state = report_rx.await.unwrap();

    let client = build_client(Duration::from_secs(2));
    let url = format!("http://{listen}/");
    let start = Instant::now();
    let pre_window = Duration::from_millis(1500);
    let stop_at = start + pre_window + Duration::from_millis(2000);
    let concurrency = 48;

    let load = closed_loop(client.clone(), url.clone(), concurrency, start, stop_at);

    let old_config = Config::load(&config_path).unwrap();
    let attempt = async move {
        tokio::time::sleep(pre_window).await;
        let new_listen = free_addr().await;
        let new_config = Config::parse(&refused_reload_config_text(new_listen, b1, b2)).unwrap();
        let attempted_at = Instant::now();
        let outcome = apply_reload(&new_config, &old_config, &reload_state).await;
        (attempted_at, outcome)
    };

    let (samples, (attempted_at, outcome)) = tokio::join!(load, attempt);

    let attempt_at_ms = attempted_at.duration_since(start).as_secs_f64() * 1000.0;
    let (around_total, around_errors, around_p50, around_p99) =
        window_stats(&samples, attempt_at_ms - 300.0, attempt_at_ms + 300.0);
    let (overall_total, overall_errors, overall_p50, overall_p99) =
        window_stats(&samples, 0.0, f64::MAX);

    println!("=== Restart-required reload attempted under load (must be refused) ===");
    println!("outcome: {outcome:?}");
    println!(
        "around attempt: n={around_total:>4} errors={around_errors:>3} p50={around_p50:>7.1}ms p99={around_p99:>7.1}ms"
    );
    println!(
        "overall       : n={overall_total:>4} errors={overall_errors:>3} p50={overall_p50:>7.1}ms p99={overall_p99:>7.1}ms"
    );

    match &outcome {
        ReloadOutcome::Refused(reason) => {
            assert!(
                reason.contains("restart"),
                "refusal reason should mention 'restart': {reason}"
            );
        }
        other => panic!("expected the re-addressed listener reload to be refused, got {other:?}"),
    }

    assert!(
        overall_errors as f64 / overall_total.max(1) as f64 <= 0.03,
        "no requests should be lost to a refused reload attempt: {overall_errors}/{overall_total} errors"
    );
    wait_until_listening(listen).await;
}
