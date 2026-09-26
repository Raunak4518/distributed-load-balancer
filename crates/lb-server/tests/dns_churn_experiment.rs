use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lb_core::{
    Backend, BackendId, BackendPool, Decision, HealthCheckConfig, RateLimitKeySource, RateLimiter,
    Resolve, SystemClock,
};
use lb_healthcheck::{spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe};
use lb_proxy::{build_client, handle, AccessLog, ProbeCapableClient, ProxyContext};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time;

struct AlwaysAllow;

impl RateLimiter for AlwaysAllow {
    fn check(&self, _key: &str) -> Decision {
        Decision::Allow
    }
}

fn test_metrics() -> Arc<lb_metrics::ListenerMetrics> {
    let registry = lb_metrics::Metrics::new().unwrap();
    Arc::new(registry.listener("dns-churn"))
}

struct ControlledResolver {
    addrs: Mutex<Vec<SocketAddr>>,
}

impl ControlledResolver {
    fn new(initial: Vec<SocketAddr>) -> Self {
        ControlledResolver {
            addrs: Mutex::new(initial),
        }
    }

    fn set(&self, addrs: Vec<SocketAddr>) {
        *self.addrs.lock().unwrap() = addrs;
    }
}

impl Resolve for ControlledResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(self.addrs.lock().unwrap().clone())
    }
}

struct GatedBackend {
    addr: SocketAddr,
    ready: Arc<AtomicBool>,
    hits: Arc<Mutex<Vec<Instant>>>,
    premature_hits: Arc<AtomicUsize>,
    health_probes_ok: Arc<AtomicUsize>,
    health_probes_failed: Arc<AtomicUsize>,
}

impl GatedBackend {
    fn hit_count(&self) -> usize {
        self.hits.lock().unwrap().len()
    }

    fn hits_after(&self, cutoff: Instant) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|t| **t >= cutoff)
            .count()
    }

    fn first_hit(&self) -> Option<Instant> {
        self.hits.lock().unwrap().first().copied()
    }
}

async fn spawn_gated_backend(initially_ready: bool) -> GatedBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ready = Arc::new(AtomicBool::new(initially_ready));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let premature_hits = Arc::new(AtomicUsize::new(0));
    let health_probes_ok = Arc::new(AtomicUsize::new(0));
    let health_probes_failed = Arc::new(AtomicUsize::new(0));

    let ready_task = Arc::clone(&ready);
    let hits_task = Arc::clone(&hits);
    let premature_task = Arc::clone(&premature_hits);
    let health_ok_task = Arc::clone(&health_probes_ok);
    let health_failed_task = Arc::clone(&health_probes_failed);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let ready = Arc::clone(&ready_task);
            let hits = Arc::clone(&hits_task);
            let premature = Arc::clone(&premature_task);
            let health_ok = Arc::clone(&health_ok_task);
            let health_failed = Arc::clone(&health_failed_task);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let ready = Arc::clone(&ready);
                    let hits = Arc::clone(&hits);
                    let premature = Arc::clone(&premature);
                    let health_ok = Arc::clone(&health_ok);
                    let health_failed = Arc::clone(&health_failed);
                    async move {
                        let is_ready = ready.load(Ordering::SeqCst);
                        if req.uri().path() == "/health" {
                            let status = if is_ready {
                                health_ok.fetch_add(1, Ordering::SeqCst);
                                StatusCode::OK
                            } else {
                                health_failed.fetch_add(1, Ordering::SeqCst);
                                StatusCode::SERVICE_UNAVAILABLE
                            };
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        if !is_ready {
                            premature.fetch_add(1, Ordering::SeqCst);
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        hits.lock().unwrap().push(Instant::now());
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"ok")))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    GatedBackend {
        addr,
        ready,
        hits,
        premature_hits,
        health_probes_ok,
        health_probes_failed,
    }
}

fn health_check_config() -> HealthCheckConfig {
    HealthCheckConfig {
        path: Some("/health".to_string()),
        interval_ms: 300,
        timeout_ms: 150,
        failure_threshold: 1,
        cooldown_ms: 500,
        half_open_successes_required: 1,
        flap_backoff_multiplier: 1.0,
        max_flap_cooldown_ms: u64::MAX,
        flap_streak_reset_ms: 60_000,
        unhealthy_latency_ms: None,
        unhealthy_request_count: None,
        outlier_detection: None,
        max_ejected_fraction: None,
    }
}

fn backend_id_for(addr: SocketAddr) -> BackendId {
    BackendId::new(format!("dns:{addr}"))
}

async fn run_poller(
    resolver: Arc<ControlledResolver>,
    poll_interval: Duration,
    pool: Arc<BackendPool>,
    health_check: HealthCheckConfig,
    probe_client: Arc<dyn lb_core::ProbeClient>,
) {
    let mut ticker = time::interval(poll_interval);
    let mut checkers: HashMap<BackendId, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        ticker.tick().await;
        let addrs = resolver.resolve("churn.experiment.test", 0).await.unwrap();
        let backends: Vec<Backend> = addrs
            .into_iter()
            .map(|addr| Backend::new(format!("dns:{addr}"), addr, 1, None))
            .collect();
        let ids: Vec<BackendId> = backends.iter().map(|b| b.id.clone()).collect();
        pool.apply_resolved(backends.clone());
        checkers.retain(|id, handle| {
            let keep = ids.contains(id);
            if !keep {
                handle.abort();
            }
            keep
        });
        for backend in &backends {
            let health_check = health_check.clone();
            let probe_client = Arc::clone(&probe_client);
            let pool = Arc::clone(&pool);
            checkers.entry(backend.id.clone()).or_insert_with(|| {
                spawn_active_checker(
                    backend.clone(),
                    pool,
                    ActiveCheckConfig {
                        interval: Duration::from_millis(health_check.interval_ms),
                        healthy_gauge: None,
                    },
                    HttpProbe::new(
                        probe_client,
                        health_check.path.clone().unwrap(),
                        Duration::from_millis(health_check.timeout_ms),
                        false,
                    ),
                )
            });
        }
    }
}

async fn spawn_lb_front(ctx: Arc<ProxyContext<AlwaysAllow, SystemClock>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let ctx = Arc::clone(&ctx);
                    async move { handle(req, ctx, peer.ip()).await }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

#[derive(Default)]
struct ClientTally {
    sent: AtomicUsize,
    ok_2xx: AtomicUsize,
    backend_not_ready_503: AtomicUsize,
    no_healthy_backend_503: AtomicUsize,
    other_status: AtomicUsize,
    transport_errors: AtomicUsize,
}

async fn closed_loop_worker(
    front_addr: SocketAddr,
    tally: Arc<ClientTally>,
    stop_at: Instant,
    pacing: Duration,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let url = format!("http://{front_addr}/");
    while Instant::now() < stop_at {
        tally.sent.fetch_add(1, Ordering::SeqCst);
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    tally.ok_2xx.fetch_add(1, Ordering::SeqCst);
                } else if status == StatusCode::SERVICE_UNAVAILABLE {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains("no healthy backend") {
                        tally.no_healthy_backend_503.fetch_add(1, Ordering::SeqCst);
                    } else {
                        tally.backend_not_ready_503.fetch_add(1, Ordering::SeqCst);
                    }
                } else {
                    tally.other_status.fetch_add(1, Ordering::SeqCst);
                }
            }
            Err(_) => {
                tally.transport_errors.fetch_add(1, Ordering::SeqCst);
            }
        }
        time::sleep(pacing).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_churn_experiment() {
    let poll_interval = Duration::from_secs(2);

    let a = spawn_gated_backend(true).await;
    let b = spawn_gated_backend(true).await;
    let c = spawn_gated_backend(true).await;
    let d = spawn_gated_backend(true).await;

    let resolver = Arc::new(ControlledResolver::new(vec![
        a.addr, b.addr, c.addr, d.addr,
    ]));
    let pool = Arc::new(BackendPool::new(Vec::new()));
    let client = build_client(None, HashMap::new(), false, None);
    let probe_client: Arc<dyn lb_core::ProbeClient> = Arc::new(ProbeCapableClient(client.clone()));

    tokio::spawn(run_poller(
        Arc::clone(&resolver),
        poll_interval,
        Arc::clone(&pool),
        health_check_config(),
        probe_client,
    ));

    let ctx: Arc<ProxyContext<AlwaysAllow, SystemClock>> = Arc::new(ProxyContext {
        rate_limiter: Arc::new(AlwaysAllow),
        balancer: Arc::new(lb_balancer::RoundRobin::new()),
        pool: Arc::clone(&pool),
        routes: Vec::new(),
        canary: Vec::new(),
        canary_cursor: std::sync::atomic::AtomicUsize::new(0),
        sticky: None,
        cache: None,
        waf: None,
        waf_inspect_headers: false,
        retry_budget: None,
        circuit_breakers: lb_core::BackendMap::<CircuitBreaker<SystemClock>>::new(),
        outlier: None,
        acme_challenges: None,
        client: client.clone(),
        per_backend_client: None,
        backend_tls: false,
        backend_tls_connector: None,
        websocket_idle_timeout: Duration::from_secs(300),
        backend_tcp_keepalive: None,
        rate_limit_key: RateLimitKeySource::SourceIp,
        forward_timeout: Duration::from_secs(2),
        max_request_body_bytes: 1024 * 1024,
        cluster: None,
        metrics: test_metrics(),
        backend_metrics: lb_core::BackendMap::new(),
        access_log: AccessLog::disabled(),
        body_read_timeout: Duration::from_secs(10),
        hsts_max_age_secs: None,
    });

    let front_addr = spawn_lb_front(Arc::clone(&ctx)).await;

    time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        pool.all_backend_ids().len(),
        4,
        "initial DNS resolution did not populate the pool with 4 backends"
    );

    let start = Instant::now();
    let run_for = Duration::from_secs(48);
    let stop_at = start + run_for;

    let tally = Arc::new(ClientTally::default());
    let mut workers = Vec::new();
    for _ in 0..6 {
        workers.push(tokio::spawn(closed_loop_worker(
            front_addr,
            Arc::clone(&tally),
            stop_at,
            Duration::from_millis(25),
        )));
    }

    time::sleep(Duration::from_secs(12)).await;
    let e = spawn_gated_backend(false).await;
    resolver.set(vec![a.addr, b.addr, c.addr, d.addr, e.addr]);
    let e_added_at = Instant::now();
    let e_ready_clone = Arc::clone(&e.ready);
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(5_000)).await;
        e_ready_clone.store(true, Ordering::SeqCst);
    });

    time::sleep(Duration::from_secs(12)).await;
    let f = spawn_gated_backend(true).await;
    resolver.set(vec![a.addr, c.addr, d.addr, e.addr, f.addr]);
    let b_removed_at = Instant::now();

    time::sleep(Duration::from_secs(12)).await;

    let remaining = stop_at.saturating_duration_since(Instant::now());
    if remaining > Duration::ZERO {
        time::sleep(remaining).await;
    }

    for w in workers {
        let _ = w.await;
    }

    let final_ids: std::collections::HashSet<BackendId> =
        pool.all_backend_ids().into_iter().collect();
    let expected_final: std::collections::HashSet<BackendId> =
        [a.addr, c.addr, d.addr, e.addr, f.addr]
            .into_iter()
            .map(backend_id_for)
            .collect();

    let b_grace_cutoff = b_removed_at + poll_interval + Duration::from_millis(1200);
    let b_hits_after_removal = b.hits_after(b_grace_cutoff);

    let e_first_hit_latency = e.first_hit().map(|t| t.duration_since(e_added_at));

    println!("==== DNS churn experiment report ====");
    println!("poll_interval = {poll_interval:?}, run_for = {run_for:?}");
    println!(
        "final pool membership matches expected [a,c,d,e,f]: {}",
        final_ids == expected_final
    );
    println!(
        "client requests sent = {}",
        tally.sent.load(Ordering::SeqCst)
    );
    println!("client 2xx = {}", tally.ok_2xx.load(Ordering::SeqCst));
    println!(
        "client 503 (backend not ready) = {}",
        tally.backend_not_ready_503.load(Ordering::SeqCst)
    );
    println!(
        "client 503 (no healthy backend in pool) = {}",
        tally.no_healthy_backend_503.load(Ordering::SeqCst)
    );
    println!(
        "client other non-2xx = {}",
        tally.other_status.load(Ordering::SeqCst)
    );
    println!(
        "client transport errors (timeout/refused) = {}",
        tally.transport_errors.load(Ordering::SeqCst)
    );
    println!("---- per-backend ----");
    println!("a (steady):    hits={}", a.hit_count());
    println!(
        "b (removed at +24s): hits_total={}, hits_after_removal_grace={}",
        b.hit_count(),
        b_hits_after_removal
    );
    println!("c (steady):    hits={}", c.hit_count());
    println!("d (steady):    hits={}", d.hit_count());
    println!(
        "e (added at +12s, ready after +5000ms): hits_total={}, premature_hits={}, \
         health_probes_ok={}, health_probes_failed={}, first_real_hit_latency={:?}",
        e.hit_count(),
        e.premature_hits.load(Ordering::SeqCst),
        e.health_probes_ok.load(Ordering::SeqCst),
        e.health_probes_failed.load(Ordering::SeqCst),
        e_first_hit_latency
    );
    println!(
        "f (added at +24s, ready immediately): hits_total={}, premature_hits={}",
        f.hit_count(),
        f.premature_hits.load(Ordering::SeqCst)
    );
    println!("======================================");

    assert!(
        final_ids == expected_final,
        "pool did not converge to the expected post-churn backend set: {final_ids:?} != {expected_final:?}"
    );
    assert_eq!(
        b_hits_after_removal, 0,
        "backend b kept receiving new requests well after being removed from DNS"
    );
    assert!(
        c.hit_count() > 0 && d.hit_count() > 0 && a.hit_count() > 0,
        "a steady backend received no traffic at all during the run"
    );
    assert!(
        f.hit_count() > 0,
        "backend f, added at +24s in place of the removed b, never received traffic"
    );
    assert!(
        e.hit_count() > 0,
        "backend e, added at +12s, never received traffic even after becoming ready"
    );
    assert!(
        tally.sent.load(Ordering::SeqCst) > 1000,
        "closed-loop load did not generate a meaningful request volume"
    );
}
