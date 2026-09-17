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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::wait_until_listening;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const LISTENER: &str = "web";

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder().timeout(timeout).build().unwrap()
}

struct RecoverableBackend {
    addr: SocketAddr,
    hits: Arc<Mutex<Vec<Instant>>>,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
    conn_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

fn spawn_accept_loop(
    listener: TcpListener,
    hits: Arc<Mutex<Vec<Instant>>>,
    conn_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    let conn_handles_for_accept = Arc::clone(&conn_handles);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let hits = Arc::clone(&hits);
            let conn_handle = tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        hits.lock().unwrap().push(Instant::now());
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
            conn_handles_for_accept.lock().unwrap().push(conn_handle);
        }
    })
}

impl RecoverableBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let conn_handles: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let accept_handle =
            spawn_accept_loop(listener, Arc::clone(&hits), Arc::clone(&conn_handles));
        RecoverableBackend {
            addr,
            hits,
            accept_handle: Mutex::new(Some(accept_handle)),
            conn_handles,
        }
    }

    fn kill(&self) {
        if let Some(h) = self.accept_handle.lock().unwrap().take() {
            h.abort();
        }
        for h in self.conn_handles.lock().unwrap().drain(..) {
            h.abort();
        }
    }

    async fn revive(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = loop {
            match TcpListener::bind(self.addr).await {
                Ok(l) => break l,
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "could not rebind recovered backend at {}: {e}",
                        self.addr
                    );
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
        };
        let handle = spawn_accept_loop(
            listener,
            Arc::clone(&self.hits),
            Arc::clone(&self.conn_handles),
        );
        *self.accept_handle.lock().unwrap() = Some(handle);
    }

    fn hit_count(&self) -> usize {
        self.hits.lock().unwrap().len()
    }

    fn hits_snapshot(&self) -> Vec<Instant> {
        self.hits.lock().unwrap().clone()
    }
}

#[allow(clippy::too_many_arguments)]
fn recovery_config_toml(
    admin_listen: SocketAddr,
    traffic_listen: SocketAddr,
    backends: &[(String, SocketAddr)],
    strategy: &str,
    interval_ms: u64,
    timeout_ms: u64,
    failure_threshold: u32,
    cooldown_ms: u64,
    half_open_successes_required: u32,
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
  interval_ms = {interval_ms}
  timeout_ms = {timeout_ms}
  failure_threshold = {failure_threshold}
  cooldown_ms = {cooldown_ms}
  half_open_successes_required = {half_open_successes_required}

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000000
  burst = 1000000

  [listeners.load_balancing]
  strategy = "{strategy}"
"#
    )
}

struct Setup {
    traffic: SocketAddr,
    admin: SocketAddr,
    backends: Vec<(String, RecoverableBackend)>,
}

#[allow(clippy::too_many_arguments)]
async fn start_recovery_server(
    num_backends: usize,
    strategy: &str,
    interval_ms: u64,
    timeout_ms: u64,
    failure_threshold: u32,
    cooldown_ms: u64,
    half_open_successes_required: u32,
) -> Setup {
    let mut backends = Vec::with_capacity(num_backends);
    for i in 0..num_backends {
        let backend = RecoverableBackend::spawn().await;
        backends.push((format!("b{i}"), backend));
    }
    let traffic = free_addr().await;
    let admin = free_addr().await;
    let backend_list: Vec<(String, SocketAddr)> = backends
        .iter()
        .map(|(id, backend)| (id.clone(), backend.addr))
        .collect();
    let config = Config::parse(&recovery_config_toml(
        admin,
        traffic,
        &backend_list,
        strategy,
        interval_ms,
        timeout_ms,
        failure_threshold,
        cooldown_ms,
        half_open_successes_required,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config, None));
    wait_until_listening(traffic).await;
    wait_until_listening(admin).await;
    Setup {
        traffic,
        admin,
        backends,
    }
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

fn backend_circuit_state(text: &str, listener: &str, backend: &str) -> Option<i64> {
    let marker_backend = format!("backend=\"{backend}\"");
    let marker_listener = format!("listener=\"{listener}\"");
    text.lines()
        .find(|l| {
            l.starts_with("lb_backend_circuit_state{")
                && l.contains(&marker_backend)
                && l.contains(&marker_listener)
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse::<i64>().ok())
}

async fn warm_up_all(
    client: &reqwest::Client,
    url: &str,
    backends: &[(String, RecoverableBackend)],
) {
    for _ in 0..backends.len() * 4 {
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    for (id, backend) in backends {
        assert!(
            backend.hit_count() > 0,
            "backend {id} never received warm-up traffic"
        );
    }
}

fn spawn_background_traffic(
    client: reqwest::Client,
    url: String,
    concurrency: usize,
) -> Vec<JoinHandle<()>> {
    (0..concurrency)
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                loop {
                    let _ = client.get(&url).send().await;
                }
            })
        })
        .collect()
}

fn abort_all(handles: Vec<JoinHandle<()>>) {
    for h in handles {
        h.abort();
    }
}

#[tokio::test]
async fn a_recovered_backend_starts_receiving_traffic_quickly() {
    let setup = start_recovery_server(4, "round_robin", 50, 100, 1, 80, 1).await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    warm_up_all(&client, &url, &setup.backends).await;

    let dead_id = "b0";
    let (_, dead) = setup.backends.iter().find(|(id, _)| id == dead_id).unwrap();
    dead.kill();

    let exclude_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = client.get(&url).send().await;
        let body = admin_backends(&admin_client, setup.admin).await;
        let entry = backend_entry(&body, LISTENER, dead_id);
        if entry["eligible"] == Value::Bool(false) {
            assert!(
                entry["circuit_open"] == Value::Bool(true)
                    || entry["active_healthy"] == Value::Bool(false),
                "backend excluded from rotation without either signal explaining why: {entry}"
            );
            break;
        }
        assert!(
            Instant::now() < exclude_deadline,
            "killed backend never became ineligible"
        );
    }

    let baseline_hits = dead.hit_count();
    dead.revive().await;
    let revived_at = Instant::now();

    let bg = spawn_background_traffic(client.clone(), url.clone(), 8);

    let first_hit_deadline = Instant::now() + Duration::from_secs(3);
    let first_hit = loop {
        let hits = dead.hits_snapshot();
        if hits.len() > baseline_hits {
            break hits[baseline_hits];
        }
        assert!(
            Instant::now() < first_hit_deadline,
            "recovered backend never received traffic after coming back up"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    abort_all(bg);

    let time_to_first_traffic = first_hit.duration_since(revived_at);
    println!(
        "scenario 1: recovered backend received its first real request {:.1}ms after coming back up",
        time_to_first_traffic.as_secs_f64() * 1000.0
    );
    assert!(
        time_to_first_traffic < Duration::from_secs(2),
        "recovered backend took {time_to_first_traffic:?} to receive its first request"
    );
}

#[tokio::test]
async fn active_healthy_flips_true_only_after_a_probe_succeeds() {
    let setup = start_recovery_server(2, "round_robin", 200, 150, 1, 100, 1).await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    warm_up_all(&client, &url, &setup.backends).await;

    let dead_id = "b0";
    let (_, dead) = setup.backends.iter().find(|(id, _)| id == dead_id).unwrap();
    dead.kill();

    let unhealthy_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let _ = client.get(&url).send().await;
        let body = admin_backends(&admin_client, setup.admin).await;
        if backend_entry(&body, LISTENER, dead_id)["active_healthy"] == Value::Bool(false) {
            break;
        }
        assert!(
            Instant::now() < unhealthy_deadline,
            "the active health checker never marked the killed backend unhealthy"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    dead.revive().await;
    let revived_at = Instant::now();

    let just_after_revive = admin_backends(&admin_client, setup.admin).await;
    assert_eq!(
        backend_entry(&just_after_revive, LISTENER, dead_id)["active_healthy"],
        Value::Bool(false),
        "active_healthy flipped true before any health probe could have run against the revived backend"
    );

    let flip_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let body = admin_backends(&admin_client, setup.admin).await;
        if backend_entry(&body, LISTENER, dead_id)["active_healthy"] == Value::Bool(true) {
            break;
        }
        assert!(
            Instant::now() < flip_deadline,
            "active_healthy never flipped back to true after the backend recovered"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let flip_elapsed = revived_at.elapsed();
    println!(
        "scenario 2: active_healthy flipped back to true {:.1}ms after the backend came back up \
         (health_check.interval_ms=200)",
        flip_elapsed.as_secs_f64() * 1000.0
    );
}

#[tokio::test]
async fn circuit_state_moves_through_half_open_before_closing_on_recovery() {
    let setup = start_recovery_server(2, "round_robin", 40, 100, 1, 300, 3).await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    warm_up_all(&client, &url, &setup.backends).await;

    let (_, b0) = setup.backends.iter().find(|(id, _)| id == "b0").unwrap();
    let (_, b1) = setup.backends.iter().find(|(id, _)| id == "b1").unwrap();
    b0.kill();

    let open_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let _ = client.get(&url).send().await;
        let text = scrape_metrics(&admin_client, setup.admin).await;
        if backend_circuit_state(&text, LISTENER, "b0") == Some(1) {
            break;
        }
        assert!(
            Instant::now() < open_deadline,
            "b0's circuit never tripped open from real traffic"
        );
    }

    b0.revive().await;

    let mut sequence: Vec<&'static str> = Vec::new();
    let mut states: Vec<i64> = Vec::new();
    let settle_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let before_b0 = b0.hit_count();
        let before_b1 = b1.hit_count();
        let resp = client.get(&url).send().await;
        if let Ok(resp) = resp {
            assert!(
                resp.status() == StatusCode::OK || resp.status() == StatusCode::SERVICE_UNAVAILABLE
            );
        }
        if b0.hit_count() > before_b0 {
            sequence.push("b0");
        } else if b1.hit_count() > before_b1 {
            sequence.push("b1");
        } else {
            sequence.push("neither");
        }
        let text = scrape_metrics(&admin_client, setup.admin).await;
        let state = backend_circuit_state(&text, LISTENER, "b0").unwrap_or(-1);
        states.push(state);
        if state == 0 && states.contains(&2) {
            break;
        }
        assert!(
            Instant::now() < settle_deadline,
            "b0's circuit never fully closed after recovery: states so far {states:?}"
        );
    }

    let open_hits = sequence
        .iter()
        .zip(states.iter())
        .take_while(|(_, state)| **state != 2)
        .filter(|(b, _)| **b == "b0")
        .count();
    assert_eq!(
        open_hits, 0,
        "b0 must receive zero real traffic while its circuit is fully Open: sequence={sequence:?} states={states:?}"
    );

    let half_open_start = states.iter().position(|s| *s == 2).unwrap();
    let closed_at = states[half_open_start..]
        .iter()
        .position(|s| *s == 0)
        .map(|i| i + half_open_start)
        .unwrap();
    let half_open_slice = &sequence[half_open_start..closed_at];
    let half_open_b0_hits = half_open_slice.iter().filter(|b| **b == "b0").count();
    let half_open_b1_hits = half_open_slice.iter().filter(|b| **b == "b1").count();
    println!(
        "scenario 3: while lb_backend_circuit_state reported HalfOpen for b0, it received {half_open_b0_hits} \
         requests against b1's {half_open_b1_hits} over {} total requests in that window -- this codebase's \
         HalfOpen state does not itself throttle concurrency/rate, it is eligible for normal load-balancer \
         selection identical to Closed; the only distinct behavior is that a single failure while HalfOpen \
         re-opens the circuit immediately instead of requiring failure_threshold consecutive failures",
        half_open_slice.len()
    );
    assert!(
        half_open_b0_hits > 0,
        "b0 must have received at least one request while nominally HalfOpen, since that is exactly what closes the circuit"
    );
    assert!(
        half_open_b1_hits > 0,
        "the survivor b1 must have kept receiving its own share of traffic during b0's HalfOpen window too"
    );

    let final_state = *states.last().unwrap();
    assert_eq!(
        final_state, 0,
        "the circuit must end fully Closed once enough consecutive successes landed"
    );
}

struct RecoveryTrafficMeasurement {
    recovery_instant: Instant,
    recovered_id: String,
    per_backend_hits: Vec<(String, Vec<Instant>)>,
}

async fn measure_recovery_traffic(
    strategy: &str,
    num_backends: usize,
    concurrency: usize,
    post_recovery_duration: Duration,
) -> RecoveryTrafficMeasurement {
    let setup = start_recovery_server(num_backends, strategy, 40, 100, 1, 80, 1).await;
    let client = build_client(Duration::from_secs(3));
    let admin_client = build_client(Duration::from_secs(3));
    let url = format!("http://{}/", setup.traffic);

    warm_up_all(&client, &url, &setup.backends).await;

    let dead_id = "b0".to_string();
    let (_, dead) = setup
        .backends
        .iter()
        .find(|(id, _)| *id == dead_id)
        .unwrap();
    dead.kill();

    let bg = spawn_background_traffic(client.clone(), url.clone(), concurrency);

    let exclude_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body = admin_backends(&admin_client, setup.admin).await;
        if backend_entry(&body, LISTENER, &dead_id)["eligible"] == Value::Bool(false) {
            break;
        }
        assert!(
            Instant::now() < exclude_deadline,
            "killed backend never became ineligible under background load"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    dead.revive().await;

    let eligible_deadline = Instant::now() + Duration::from_secs(3);
    let recovery_instant = loop {
        let body = admin_backends(&admin_client, setup.admin).await;
        if backend_entry(&body, LISTENER, &dead_id)["eligible"] == Value::Bool(true) {
            break Instant::now();
        }
        assert!(
            Instant::now() < eligible_deadline,
            "recovered backend never became eligible again under background load"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    tokio::time::sleep(post_recovery_duration).await;
    abort_all(bg);

    let per_backend_hits = setup
        .backends
        .iter()
        .map(|(id, backend)| (id.clone(), backend.hits_snapshot()))
        .collect();

    RecoveryTrafficMeasurement {
        recovery_instant,
        recovered_id: dead_id,
        per_backend_hits,
    }
}

fn bucket_shares(
    measurement: &RecoveryTrafficMeasurement,
    duration: Duration,
    bucket: Duration,
) -> Vec<(usize, usize)> {
    let num_buckets = (duration.as_secs_f64() / bucket.as_secs_f64()).ceil() as usize;
    let recovered_hits: &Vec<Instant> = &measurement
        .per_backend_hits
        .iter()
        .find(|(id, _)| *id == measurement.recovered_id)
        .unwrap()
        .1;
    (0..num_buckets)
        .map(|b| {
            let lo = measurement.recovery_instant + bucket * b as u32;
            let hi = measurement.recovery_instant + bucket * (b as u32 + 1);
            let recovered = recovered_hits
                .iter()
                .filter(|t| **t >= lo && **t < hi)
                .count();
            let total: usize = measurement
                .per_backend_hits
                .iter()
                .map(|(_, hits)| hits.iter().filter(|t| **t >= lo && **t < hi).count())
                .sum();
            (recovered, total)
        })
        .collect()
}

#[tokio::test]
async fn peak_ewma_recovered_backend_traffic_share_over_time() {
    let measurement =
        measure_recovery_traffic("peak_ewma_p2c", 4, 16, Duration::from_secs(2)).await;
    let bucket = Duration::from_millis(200);
    let buckets = bucket_shares(&measurement, Duration::from_secs(2), bucket);

    println!("scenario 4 (peak_ewma_p2c): recovered backend share per 200ms window after recovery");
    for (i, (recovered, total)) in buckets.iter().enumerate() {
        let share = if *total > 0 {
            *recovered as f64 / *total as f64
        } else {
            0.0
        };
        println!(
            "  window {:>2} [{:>4}ms..{:>4}ms): {recovered:>3}/{total:<3} requests, share={share:.3}",
            i,
            i * 200,
            (i + 1) * 200
        );
    }

    let total_recovered_hits: usize = buckets.iter().map(|(r, _)| r).sum();
    assert!(
        total_recovered_hits > 0,
        "the recovered backend never received any traffic at all over the {} windows measured after recovery",
        buckets.len()
    );

    let early_shares: Vec<f64> = buckets[..2]
        .iter()
        .map(|(r, t)| if *t > 0 { *r as f64 / *t as f64 } else { 0.0 })
        .collect();
    let late_shares: Vec<f64> = buckets[buckets.len() - 3..]
        .iter()
        .map(|(r, t)| if *t > 0 { *r as f64 / *t as f64 } else { 0.0 })
        .collect();
    let early_avg = early_shares.iter().sum::<f64>() / early_shares.len() as f64;
    let late_avg = late_shares.iter().sum::<f64>() / late_shares.len() as f64;
    println!(
        "scenario 4 summary: average share in the first 400ms = {early_avg:.3}, average share in the last \
         600ms = {late_avg:.3} (an even split across 4 backends would be {:.3})",
        1.0 / 4.0
    );
    if early_avg > late_avg * 1.5 {
        println!(
            "scenario 4 finding: peak_ewma_p2c gave the recovered backend a HIGHER share early on ({early_avg:.3}) \
             than its later steady-state share ({late_avg:.3}) -- traffic did not ramp up gradually, it started \
             elevated and settled down"
        );
    } else if late_avg > early_avg * 1.5 {
        println!(
            "scenario 4 finding: peak_ewma_p2c gave the recovered backend a LOWER share early on ({early_avg:.3}) \
             than its later steady-state share ({late_avg:.3}) -- traffic ramped up gradually rather than jumping \
             immediately to a full/equal share"
        );
    } else {
        println!(
            "scenario 4 finding: peak_ewma_p2c gave the recovered backend a roughly steady share throughout \
             (early={early_avg:.3}, late={late_avg:.3}) -- no strong gradual-ramp or immediate-jump pattern observed"
        );
    }
}

#[tokio::test]
async fn recovery_traffic_burst_ratio_round_robin_vs_peak_ewma() {
    for strategy in ["round_robin", "peak_ewma_p2c"] {
        let measurement = measure_recovery_traffic(strategy, 4, 16, Duration::from_secs(2)).await;
        let bucket = Duration::from_millis(200);
        let buckets = bucket_shares(&measurement, Duration::from_secs(2), bucket);

        let fair_share = 1.0 / 4.0;
        let steady_shares: Vec<f64> = buckets[buckets.len() - 3..]
            .iter()
            .map(|(r, t)| if *t > 0 { *r as f64 / *t as f64 } else { 0.0 })
            .collect();
        let steady_state = steady_shares.iter().sum::<f64>() / steady_shares.len() as f64;
        let steady_state = if steady_state > 0.0 {
            steady_state
        } else {
            fair_share
        };

        let early_windows: Vec<f64> = buckets[..5]
            .iter()
            .map(|(r, t)| if *t > 0 { *r as f64 / *t as f64 } else { 0.0 })
            .collect();
        let peak_early = early_windows.iter().cloned().fold(0.0_f64, f64::max);
        let ratio = peak_early / steady_state;

        println!(
            "scenario 5 ({strategy}): steady-state share={steady_state:.3} (fair share would be {fair_share:.3}), \
             peak share in any 200ms window during the first 1s after recovery={peak_early:.3}, ratio={ratio:.2}x"
        );

        let sustained_overload = early_windows
            .windows(2)
            .any(|w| w.iter().all(|s| *s > steady_state * 3.0));
        if sustained_overload {
            println!(
                "scenario 5 finding ({strategy}): OBSERVED a sustained recovery-storm spike -- at least two \
                 consecutive 200ms windows in the first second after recovery each exceeded 3x the steady-state \
                 share ({steady_state:.3})"
            );
        } else {
            println!(
                "scenario 5 finding ({strategy}): no sustained (>200ms) overload spike above 3x steady-state \
                 share observed in the first second after recovery"
            );
        }
    }
}
