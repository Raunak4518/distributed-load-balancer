mod support;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lb_core::Config;
use serde_json::Value;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::wait_until_listening;
use tokio::net::TcpListener;

const NUM_BACKENDS: usize = 10;
const LISTENER: &str = "web";

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

struct KillableBackend {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    accept_handle: tokio::task::JoinHandle<()>,
    conn_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl KillableBackend {
    fn kill(&self) {
        self.accept_handle.abort();
        for h in self.conn_handles.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

async fn spawn_killable_backend(status: StatusCode) -> KillableBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    let conn_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));
    let conn_handles_for_accept = Arc::clone(&conn_handles);
    let accept_handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let count = count_clone.clone();
            let conn_handle = tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let count = count.clone();
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
            conn_handles_for_accept.lock().unwrap().push(conn_handle);
        }
    });
    KillableBackend {
        addr,
        count,
        accept_handle,
        conn_handles,
    }
}

fn matrix_config_toml(
    admin_listen: SocketAddr,
    traffic_listen: SocketAddr,
    backends: &[(String, SocketAddr)],
) -> String {
    let backends_toml: String = backends
        .iter()
        .map(|(id, addr)| {
            format!("  [[listeners.backends]]\n  id = \"{id}\"\n  address = \"{addr}\"\n\n")
        })
        .collect();
    format!(
        r#"
[admin]
listen = "{admin_listen}"

[[listeners]]
name = "{LISTENER}"
protocol = "http"
listen = "{traffic_listen}"
forward_timeout_ms = 200

{backends_toml}
  [listeners.health_check]
  path = "/health"
  interval_ms = 2000
  timeout_ms = 300
  failure_threshold = 1
  cooldown_ms = 10000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000000
  burst = 1000000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder().timeout(timeout).build().unwrap()
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

async fn ready_status(client: &reqwest::Client, admin_listen: SocketAddr) -> StatusCode {
    client
        .get(format!("http://{admin_listen}/ready"))
        .send()
        .await
        .unwrap()
        .status()
}

fn sum_backend_attempts(text: &str, listener: &str) -> u64 {
    let marker = format!("listener=\"{listener}\"");
    text.lines()
        .filter(|l| l.starts_with("lb_backend_requests_total{") && l.contains(&marker))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.parse::<u64>().ok())
        .sum()
}

async fn scrape_metrics(client: &reqwest::Client, admin_listen: SocketAddr) -> String {
    client
        .get(format!("http://{admin_listen}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

struct Attempt {
    status: u16,
    elapsed_ms: f64,
}

async fn run_sequential_burst(client: &reqwest::Client, url: &str, n: usize) -> Vec<Attempt> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        let result = client.get(url).send().await;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let status = result
            .unwrap_or_else(|e| panic!("request errored instead of returning a response: {e}"))
            .status()
            .as_u16();
        out.push(Attempt { status, elapsed_ms });
    }
    out
}

async fn drive_until_dead_circuits_open(
    client: &reqwest::Client,
    url: &str,
    admin_client: &reqwest::Client,
    admin_listen: SocketAddr,
    dead_ids: &[String],
    deadline: Instant,
) -> (Value, Vec<Attempt>) {
    let mut attempts = Vec::new();
    loop {
        let started = Instant::now();
        let result = client.get(url).send().await;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let status = result
            .unwrap_or_else(|e| panic!("request errored instead of returning a response: {e}"))
            .status()
            .as_u16();
        attempts.push(Attempt { status, elapsed_ms });
        let body = admin_backends(admin_client, admin_listen).await;
        let all_open = dead_ids
            .iter()
            .all(|id| backend_entry(&body, LISTENER, id)["circuit_open"] == Value::Bool(true));
        if all_open {
            return (body, attempts);
        }
        assert!(
            Instant::now() < deadline,
            "not every dead backend's circuit opened before the deadline: {body}"
        );
    }
}

async fn drive_until_backends_ineligible(
    client: &reqwest::Client,
    url: &str,
    admin_client: &reqwest::Client,
    admin_listen: SocketAddr,
    ids: &[String],
    deadline: Instant,
) -> (Value, Vec<Attempt>) {
    let mut attempts = Vec::new();
    loop {
        let started = Instant::now();
        let result = client.get(url).send().await;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        let status = result
            .unwrap_or_else(|e| panic!("request errored instead of returning a response: {e}"))
            .status()
            .as_u16();
        attempts.push(Attempt { status, elapsed_ms });
        let body = admin_backends(admin_client, admin_listen).await;
        let all_ineligible = ids
            .iter()
            .all(|id| backend_entry(&body, LISTENER, id)["eligible"] == Value::Bool(false));
        if all_ineligible {
            return (body, attempts);
        }
        assert!(
            Instant::now() < deadline,
            "not every backend became ineligible before the deadline: {body}"
        );
    }
}

async fn wait_for_backends_ineligible(
    admin_client: &reqwest::Client,
    admin_listen: SocketAddr,
    ids: &[String],
    deadline: Instant,
) -> Value {
    loop {
        let body = admin_backends(admin_client, admin_listen).await;
        let all_ineligible = ids
            .iter()
            .all(|id| backend_entry(&body, LISTENER, id)["eligible"] == Value::Bool(false));
        if all_ineligible {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "not every backend became ineligible before the deadline: {body}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Debug)]
struct TimedAttempt {
    at_ms: f64,
    elapsed_ms: f64,
    status: u16,
}

async fn closed_loop_for(
    client: reqwest::Client,
    url: String,
    concurrency: usize,
    duration: Duration,
) -> Vec<TimedAttempt> {
    let start = Instant::now();
    let stop_at = start + duration;
    let samples: Arc<Mutex<Vec<TimedAttempt>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let samples = Arc::clone(&samples);
        handles.push(tokio::spawn(async move {
            let mut local = Vec::new();
            while Instant::now() < stop_at {
                let req_started = Instant::now();
                let status = match client.get(&url).send().await {
                    Ok(resp) => resp.status().as_u16(),
                    Err(_) => 0,
                };
                local.push(TimedAttempt {
                    at_ms: req_started.duration_since(start).as_secs_f64() * 1000.0,
                    elapsed_ms: req_started.elapsed().as_secs_f64() * 1000.0,
                    status,
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

fn max_latency(attempts: &[Attempt]) -> f64 {
    attempts.iter().map(|a| a.elapsed_ms).fold(0.0, f64::max)
}

struct Setup {
    traffic: SocketAddr,
    admin: SocketAddr,
    backends: Vec<(String, KillableBackend)>,
}

async fn start_matrix_server() -> Setup {
    let mut backends = Vec::with_capacity(NUM_BACKENDS);
    for i in 0..NUM_BACKENDS {
        let backend = spawn_killable_backend(StatusCode::OK).await;
        backends.push((format!("b{i}"), backend));
    }
    let traffic = free_addr().await;
    let admin = free_addr().await;
    let backend_list: Vec<(String, SocketAddr)> = backends
        .iter()
        .map(|(id, backend)| (id.clone(), backend.addr))
        .collect();
    let config = Config::parse(&matrix_config_toml(admin, traffic, &backend_list)).unwrap();
    tokio::spawn(lb_server::run(config, None));
    wait_until_listening(traffic).await;
    wait_until_listening(admin).await;
    Setup {
        traffic,
        admin,
        backends,
    }
}

async fn failure_fraction_case(dead_count: usize, check_active_health_probe: bool) {
    let setup = start_matrix_server().await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    let warm_up = run_sequential_burst(&client, &url, NUM_BACKENDS * 2).await;
    assert!(
        warm_up.iter().all(|a| a.status == 200),
        "every backend must be healthy and answering before any are killed"
    );
    for (id, backend) in &setup.backends {
        assert!(
            backend.count.load(Ordering::SeqCst) > 0,
            "backend {id} never received warm-up traffic"
        );
    }

    let dead_ids: Vec<String> = (0..dead_count).map(|i| format!("b{i}")).collect();
    let survivor_ids: Vec<String> = (dead_count..NUM_BACKENDS)
        .map(|i| format!("b{i}"))
        .collect();
    for (id, backend) in &setup.backends {
        if dead_ids.contains(id) {
            backend.kill();
        }
    }
    let dead_baseline: Vec<usize> = setup
        .backends
        .iter()
        .filter(|(id, ..)| dead_ids.contains(id))
        .map(|(_, backend)| backend.count.load(Ordering::SeqCst))
        .collect();

    let settle_deadline = Instant::now() + Duration::from_secs(8);
    let (settled, detection) = drive_until_dead_circuits_open(
        &client,
        &url,
        &admin_client,
        setup.admin,
        &dead_ids,
        settle_deadline,
    )
    .await;
    assert!(
        max_latency(&detection) < 1500.0,
        "a request during the failure took {:.1}ms, far more than the ~{}ms two-attempt bound",
        max_latency(&detection),
        200 * 2
    );
    assert!(
        detection
            .iter()
            .all(|a| a.status == 200 || a.status == 502 || a.status == 503),
        "every request during the failure must be a real response, not a hang or a protocol error"
    );

    for (id, before) in dead_ids.iter().zip(dead_baseline.iter()) {
        let (_, backend) = setup.backends.iter().find(|(bid, ..)| bid == id).unwrap();
        assert_eq!(
            backend.count.load(Ordering::SeqCst),
            *before,
            "dead backend {id} received traffic after it was killed"
        );
        assert_eq!(
            backend_entry(&settled, LISTENER, id)["eligible"],
            Value::Bool(false),
            "dead backend {id} should no longer be eligible"
        );
    }
    for id in &survivor_ids {
        assert_eq!(
            backend_entry(&settled, LISTENER, id)["eligible"],
            Value::Bool(true),
            "surviving backend {id} should still be eligible"
        );
    }

    if dead_count < NUM_BACKENDS {
        assert_eq!(
            ready_status(&admin_client, setup.admin).await,
            StatusCode::OK,
            "/ready must stay 200 while at least one backend is eligible"
        );
    }

    let survivor_hits_before_clean: usize = setup
        .backends
        .iter()
        .filter(|(id, ..)| survivor_ids.contains(id))
        .map(|(_, backend)| backend.count.load(Ordering::SeqCst))
        .sum();

    let clean_load =
        closed_loop_for(client.clone(), url.clone(), 16, Duration::from_millis(800)).await;
    assert!(
        !clean_load.is_empty(),
        "the steady-state load phase sent no requests"
    );
    assert!(
        clean_load.iter().all(|a| a.status == 200),
        "once settled, every request must succeed from a surviving backend: {:?}",
        clean_load
            .iter()
            .filter(|a| a.status != 200)
            .map(|a| a.status)
            .collect::<Vec<_>>()
    );
    let clean_max = clean_load.iter().map(|a| a.elapsed_ms).fold(0.0, f64::max);
    assert!(
        clean_max < 800.0,
        "steady-state requests should be fast, got a max of {clean_max:.1}ms"
    );

    for (id, backend) in &setup.backends {
        if dead_ids.contains(id) {
            assert_eq!(
                backend.count.load(Ordering::SeqCst),
                *dead_baseline
                    .get(dead_ids.iter().position(|d| d == id).unwrap())
                    .unwrap(),
                "dead backend {id} received traffic during the steady-state phase"
            );
        }
    }
    let survivor_hits_after_clean: usize = setup
        .backends
        .iter()
        .filter(|(id, ..)| survivor_ids.contains(id))
        .map(|(_, backend)| backend.count.load(Ordering::SeqCst))
        .sum();
    assert_eq!(
        survivor_hits_after_clean - survivor_hits_before_clean,
        clean_load.len(),
        "every steady-state 200 must have been served by exactly one surviving backend"
    );

    if check_active_health_probe {
        let probe_deadline = Instant::now() + Duration::from_millis(3000);
        loop {
            let body = admin_backends(&admin_client, setup.admin).await;
            let all_unhealthy = dead_ids.iter().all(|id| {
                backend_entry(&body, LISTENER, id)["active_healthy"] == Value::Bool(false)
            });
            if all_unhealthy {
                break;
            }
            assert!(
                Instant::now() < probe_deadline,
                "the active health checker never independently marked the dead backends unhealthy"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[tokio::test]
async fn one_of_ten_backends_down() {
    failure_fraction_case(1, false).await;
}

#[tokio::test]
async fn five_of_ten_backends_down() {
    failure_fraction_case(5, true).await;
}

#[tokio::test]
async fn nine_of_ten_backends_down() {
    failure_fraction_case(9, false).await;
}

#[tokio::test]
async fn ready_flips_to_unavailable_exactly_when_the_last_backend_dies() {
    let setup = start_matrix_server().await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    let warm_up = run_sequential_burst(&client, &url, NUM_BACKENDS * 2).await;
    assert!(warm_up.iter().all(|a| a.status == 200));

    for (id, backend) in &setup.backends {
        if id != "b9" {
            backend.kill();
        }
    }
    let settle_deadline = Instant::now() + Duration::from_secs(8);
    wait_for_backends_ineligible(
        &admin_client,
        setup.admin,
        &(0..9).map(|i| format!("b{i}")).collect::<Vec<_>>(),
        settle_deadline,
    )
    .await;
    assert_eq!(
        ready_status(&admin_client, setup.admin).await,
        StatusCode::OK,
        "/ready must still be 200 with one survivor left"
    );

    let (_, last_backend) = setup.backends.iter().find(|(id, ..)| id == "b9").unwrap();
    last_backend.kill();

    let flip_started = Instant::now();
    let flip_deadline = flip_started + Duration::from_secs(3);
    loop {
        let _ = client.get(&url).send().await;
        if ready_status(&admin_client, setup.admin).await == StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
        assert!(
            Instant::now() < flip_deadline,
            "/ready never flipped to 503 after the last backend died"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let flip_elapsed = flip_started.elapsed();
    assert!(
        flip_elapsed < Duration::from_secs(3),
        "readiness took {flip_elapsed:?} to flip after the last backend died"
    );
    assert_eq!(
        ready_status(&admin_client, setup.admin).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "/ready must stay 503 once every backend is down"
    );
}

#[tokio::test]
async fn all_backends_down_fails_fast_without_amplification_or_resource_leaks() {
    let setup = start_matrix_server().await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    let warm_up = run_sequential_burst(&client, &url, NUM_BACKENDS * 2).await;
    assert!(warm_up.iter().all(|a| a.status == 200));

    let before_baseline = admin_backends(&admin_client, setup.admin).await;
    for (id, _) in &setup.backends {
        assert_eq!(
            backend_entry(&before_baseline, LISTENER, id)["active_conns"],
            Value::from(0),
            "backend {id} has leftover active connections before the outage even starts"
        );
    }

    for (_, backend) in &setup.backends {
        backend.kill();
    }
    let all_ids: Vec<String> = (0..NUM_BACKENDS).map(|i| format!("b{i}")).collect();

    let attempts_before =
        sum_backend_attempts(&scrape_metrics(&admin_client, setup.admin).await, LISTENER);
    let settle_deadline = Instant::now() + Duration::from_secs(8);
    let (settled, detection) = drive_until_backends_ineligible(
        &client,
        &url,
        &admin_client,
        setup.admin,
        &all_ids,
        settle_deadline,
    )
    .await;
    assert!(
        detection.iter().all(|a| a.status == 502 || a.status == 503),
        "every request while all backends are down must be a real 502/503, never 200"
    );
    assert!(
        max_latency(&detection) < 1500.0,
        "a request during the outage took {:.1}ms",
        max_latency(&detection)
    );
    let attempts_after_detection =
        sum_backend_attempts(&scrape_metrics(&admin_client, setup.admin).await, LISTENER);
    let attempts_during_detection = attempts_after_detection - attempts_before;
    assert!(
        attempts_during_detection <= 2 * detection.len() as u64,
        "backend connection attempts ({attempts_during_detection}) exceeded the documented \
         one-retry bound of 2 attempts per request over {} requests",
        detection.len()
    );
    let real_traffic_trips = all_ids
        .iter()
        .filter(|id| backend_entry(&settled, LISTENER, id)["circuit_open"] == Value::Bool(true))
        .count();
    assert!(
        real_traffic_trips >= NUM_BACKENDS - 1,
        "expected real traffic to have tripped at least {} of {NUM_BACKENDS} circuits directly, \
         only {real_traffic_trips} opened that way (the rest were excluded by the active health \
         checker's own independent probe instead): {settled}",
        NUM_BACKENDS - 1
    );

    assert_eq!(
        ready_status(&admin_client, setup.admin).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "/ready must be 503 once every backend is down"
    );

    let attempts_before_settled =
        sum_backend_attempts(&scrape_metrics(&admin_client, setup.admin).await, LISTENER);
    let sustained =
        closed_loop_for(client.clone(), url.clone(), 12, Duration::from_millis(1500)).await;
    assert!(
        sustained.len() > 50,
        "the sustained load phase only sent {} requests, too few to draw conclusions from",
        sustained.len()
    );
    assert!(
        sustained.iter().all(|a| a.status == 503),
        "once every backend's circuit is open, every request must fail immediately with 503"
    );
    let attempts_after_settled =
        sum_backend_attempts(&scrape_metrics(&admin_client, setup.admin).await, LISTENER);
    assert_eq!(
        attempts_after_settled, attempts_before_settled,
        "no backend connection attempts should happen once every backend is excluded from rotation"
    );

    let sustained_max = sustained.iter().map(|a| a.elapsed_ms).fold(0.0, f64::max);
    assert!(
        sustained_max < 400.0,
        "a fully-settled outage response took {sustained_max:.1}ms; it should fail locally, \
         without touching the network"
    );

    let third = sustained.len() / 3;
    let mut sorted_all: Vec<f64> = sustained.iter().map(|a| a.elapsed_ms).collect();
    sorted_all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let overall_p99 = percentile(&sorted_all, 0.99);
    assert!(
        overall_p99 < 250.0,
        "overall p99 latency while fully down was {overall_p99:.1}ms"
    );

    let mut first_window: Vec<f64> = sustained[..third].iter().map(|a| a.elapsed_ms).collect();
    let mut last_window: Vec<f64> = sustained[sustained.len() - third..]
        .iter()
        .map(|a| a.elapsed_ms)
        .collect();
    first_window.sort_by(|a, b| a.partial_cmp(b).unwrap());
    last_window.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let first_p99 = percentile(&first_window, 0.99);
    let last_p99 = percentile(&last_window, 0.99);
    assert!(
        last_p99 <= first_p99 * 3.0 + 50.0,
        "latency climbed from {first_p99:.1}ms to {last_p99:.1}ms over the sustained outage, \
         which looks like a growing backlog rather than a flat fast-fail path"
    );

    let first_window_count = sustained
        .iter()
        .filter(|a| a.at_ms < sustained.last().unwrap().at_ms / 3.0)
        .count();
    let last_window_count = sustained
        .iter()
        .filter(|a| a.at_ms >= sustained.last().unwrap().at_ms * 2.0 / 3.0)
        .count();
    assert!(
        first_window_count > 0 && last_window_count > 0,
        "throughput dropped to zero during the sustained outage window: first={first_window_count} last={last_window_count}"
    );
    assert!(
        (last_window_count as f64) >= (first_window_count as f64) * 0.4,
        "throughput collapsed over the sustained outage (first={first_window_count}, last={last_window_count}), \
         suggesting the server is falling behind rather than staying flat"
    );

    let after = admin_backends(&admin_client, setup.admin).await;
    for id in &all_ids {
        assert_eq!(
            backend_entry(&after, LISTENER, id)["active_conns"],
            Value::from(0),
            "backend {id} still shows in-flight connections after every request completed"
        );
    }
}
