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

fn test_metrics(name: &str) -> Arc<lb_metrics::ListenerMetrics> {
    let registry = lb_metrics::Metrics::new().unwrap();
    Arc::new(registry.listener(name))
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

fn backend_id_for(addr: SocketAddr) -> BackendId {
    BackendId::new(format!("dns:{addr}"))
}

struct FlapBackend {
    addr: SocketAddr,
    ready: Arc<AtomicBool>,
    hits: Arc<Mutex<Vec<Instant>>>,
    health_probes_ok: Arc<AtomicUsize>,
    health_probes_failed: Arc<AtomicUsize>,
    held_started: Arc<AtomicBool>,
    release_gate: Arc<AtomicBool>,
}

impl FlapBackend {
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

    fn health_probe_count(&self) -> usize {
        self.health_probes_ok.load(Ordering::SeqCst)
            + self.health_probes_failed.load(Ordering::SeqCst)
    }
}

async fn spawn_flap_backend(initially_ready: bool) -> FlapBackend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ready = Arc::new(AtomicBool::new(initially_ready));
    let hits = Arc::new(Mutex::new(Vec::new()));
    let health_probes_ok = Arc::new(AtomicUsize::new(0));
    let health_probes_failed = Arc::new(AtomicUsize::new(0));
    let held_started = Arc::new(AtomicBool::new(false));
    let release_gate = Arc::new(AtomicBool::new(false));

    let ready_task = Arc::clone(&ready);
    let hits_task = Arc::clone(&hits);
    let ok_task = Arc::clone(&health_probes_ok);
    let failed_task = Arc::clone(&health_probes_failed);
    let held_task = Arc::clone(&held_started);
    let release_task = Arc::clone(&release_gate);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let ready = Arc::clone(&ready_task);
            let hits = Arc::clone(&hits_task);
            let health_ok = Arc::clone(&ok_task);
            let health_failed = Arc::clone(&failed_task);
            let held = Arc::clone(&held_task);
            let release = Arc::clone(&release_task);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let ready = Arc::clone(&ready);
                    let hits = Arc::clone(&hits);
                    let health_ok = Arc::clone(&health_ok);
                    let health_failed = Arc::clone(&health_failed);
                    let held = Arc::clone(&held);
                    let release = Arc::clone(&release);
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
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        if req.uri().path() == "/slow" {
                            held.store(true, Ordering::SeqCst);
                            while !release.load(Ordering::SeqCst) {
                                time::sleep(Duration::from_millis(20)).await;
                            }
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from(addr.to_string())))
                                    .unwrap(),
                            );
                        }
                        hits.lock().unwrap().push(Instant::now());
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(addr.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    FlapBackend {
        addr,
        ready,
        hits,
        health_probes_ok,
        health_probes_failed,
        held_started,
        release_gate,
    }
}

fn health_check_config() -> HealthCheckConfig {
    HealthCheckConfig {
        path: Some("/health".to_string()),
        interval_ms: 150,
        timeout_ms: 100,
        failure_threshold: 1,
        cooldown_ms: 300,
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

#[derive(Default)]
struct CheckerStats {
    spawned: AtomicUsize,
    aborted: AtomicUsize,
}

impl CheckerStats {
    fn alive(&self) -> usize {
        self.spawned.load(Ordering::SeqCst) - self.aborted.load(Ordering::SeqCst)
    }
}

async fn run_poller(
    resolver: Arc<ControlledResolver>,
    poll_interval: Duration,
    pool: Arc<BackendPool>,
    health_check: HealthCheckConfig,
    probe_client: Arc<dyn lb_core::ProbeClient>,
    stats: Arc<CheckerStats>,
) {
    let mut ticker = time::interval(poll_interval);
    let mut checkers: HashMap<BackendId, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        ticker.tick().await;
        let addrs = resolver.resolve("flap.experiment.test", 0).await.unwrap();
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
                stats.aborted.fetch_add(1, Ordering::SeqCst);
            }
            keep
        });
        for backend in &backends {
            let health_check = health_check.clone();
            let probe_client = Arc::clone(&probe_client);
            let pool = Arc::clone(&pool);
            let stats = Arc::clone(&stats);
            checkers.entry(backend.id.clone()).or_insert_with(|| {
                stats.spawned.fetch_add(1, Ordering::SeqCst);
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

fn build_ctx(
    pool: Arc<BackendPool>,
    client: lb_proxy::ProxyClient,
    listener_name: &str,
) -> Arc<ProxyContext<AlwaysAllow, SystemClock>> {
    Arc::new(ProxyContext {
        rate_limiter: Arc::new(AlwaysAllow),
        balancer: Arc::new(lb_balancer::RoundRobin::new()),
        pool,
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
        forward_timeout: Duration::from_secs(30),
        max_request_body_bytes: 1024 * 1024,
        cluster: None,
        metrics: test_metrics(listener_name),
        backend_metrics: lb_core::BackendMap::new(),
        access_log: AccessLog::disabled(),
        body_read_timeout: Duration::from_secs(10),
        hsts_max_age_secs: None,
    })
}

async fn get_body(front_addr: SocketAddr, path: &str, timeout: Duration) -> (StatusCode, String) {
    let client = reqwest::Client::builder().timeout(timeout).build().unwrap();
    let url = format!("http://{front_addr}{path}");
    let resp = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

async fn sample_ok_bodies(
    front_addr: SocketAddr,
    n: usize,
    pacing: Duration,
) -> (Vec<String>, usize) {
    let mut bodies = Vec::new();
    let mut non_2xx = 0usize;
    for _ in 0..n {
        let (status, body) = get_body(front_addr, "/", Duration::from_secs(2)).await;
        if status.is_success() {
            bodies.push(body);
        } else {
            non_2xx += 1;
        }
        time::sleep(pacing).await;
    }
    (bodies, non_2xx)
}

async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !cond() {
        if Instant::now() >= deadline {
            panic!("condition not met within {timeout:?}");
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_1_appear_disappear_reappear_same_address() {
    let poll_interval = Duration::from_secs(2);
    let margin = Duration::from_millis(500);

    let a = spawn_flap_backend(true).await;
    let id_a = backend_id_for(a.addr);

    let resolver = Arc::new(ControlledResolver::new(vec![a.addr]));
    let pool = Arc::new(BackendPool::new(Vec::new()));
    let client = build_client(None, HashMap::new(), false, None);
    let probe_client: Arc<dyn lb_core::ProbeClient> = Arc::new(ProbeCapableClient(client.clone()));
    let stats = Arc::new(CheckerStats::default());

    tokio::spawn(run_poller(
        Arc::clone(&resolver),
        poll_interval,
        Arc::clone(&pool),
        health_check_config(),
        probe_client,
        Arc::clone(&stats),
    ));

    let ctx = build_ctx(Arc::clone(&pool), client, "scenario1");
    let front_addr = spawn_lb_front(ctx).await;

    time::sleep(poll_interval + margin).await;
    assert_eq!(pool.all_backend_ids(), vec![id_a.clone()]);
    assert!(pool.is_eligible(&id_a));

    let (status, body) = get_body(front_addr, "/", Duration::from_secs(2)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, a.addr.to_string());

    pool.set_circuit_open(&id_a, true);
    pool.set_outlier_ejected(&id_a, true);
    pool.set_manually_drained(&id_a, true);
    a.ready.store(false, Ordering::SeqCst);
    wait_until(|| !pool.is_active_healthy(&id_a), Duration::from_secs(3)).await;
    assert!(!pool.is_eligible(&id_a));

    let probes_before_removal = a.health_probe_count();

    resolver.set(vec![]);
    let removed_at = Instant::now();
    time::sleep(poll_interval + margin).await;

    assert!(
        pool.all_backend_ids().is_empty(),
        "backend should be fully removed from the pool while absent from DNS"
    );
    assert!(!pool.is_eligible(&id_a));
    assert_eq!(stats.alive(), 0);

    let (status, body) = get_body(front_addr, "/", Duration::from_secs(2)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("no healthy backend"));
    assert_eq!(
        a.hits_after(removed_at),
        0,
        "backend received traffic while absent from DNS"
    );

    a.ready.store(true, Ordering::SeqCst);
    resolver.set(vec![a.addr]);
    time::sleep(poll_interval + margin).await;

    assert_eq!(pool.all_backend_ids(), vec![id_a.clone()]);
    assert!(
        !pool.is_circuit_open(&id_a),
        "stale circuit-open flag carried over a disappear/reappear cycle at the same address"
    );
    assert!(
        !pool.is_outlier_ejected(&id_a),
        "stale outlier-ejected flag carried over a disappear/reappear cycle at the same address"
    );
    assert!(
        !pool.is_manually_drained(&id_a),
        "stale manual-drain flag carried over a disappear/reappear cycle at the same address"
    );
    assert!(pool.is_active_healthy(&id_a));
    assert!(pool.is_eligible(&id_a));
    assert_eq!(stats.spawned.load(Ordering::SeqCst), 2);
    assert_eq!(stats.aborted.load(Ordering::SeqCst), 1);
    assert_eq!(stats.alive(), 1);

    time::sleep(Duration::from_millis(150 * 4)).await;
    assert!(
        a.health_probe_count() > probes_before_removal,
        "health checker did not resume probing the reappeared backend from scratch"
    );

    let (status, body) = get_body(front_addr, "/", Duration::from_secs(2)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, a.addr.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_2_address_change_inflight_and_checker_teardown() {
    let poll_interval = Duration::from_secs(2);
    let margin = Duration::from_millis(500);

    let old = spawn_flap_backend(true).await;
    let new = spawn_flap_backend(true).await;
    let id_old = backend_id_for(old.addr);
    let id_new = backend_id_for(new.addr);

    let resolver = Arc::new(ControlledResolver::new(vec![old.addr]));
    let pool = Arc::new(BackendPool::new(Vec::new()));
    let client = build_client(None, HashMap::new(), false, None);
    let probe_client: Arc<dyn lb_core::ProbeClient> = Arc::new(ProbeCapableClient(client.clone()));
    let stats = Arc::new(CheckerStats::default());

    tokio::spawn(run_poller(
        Arc::clone(&resolver),
        poll_interval,
        Arc::clone(&pool),
        health_check_config(),
        probe_client,
        Arc::clone(&stats),
    ));

    let ctx = build_ctx(Arc::clone(&pool), client, "scenario2");
    let front_addr = spawn_lb_front(ctx).await;

    time::sleep(poll_interval + margin).await;
    assert_eq!(pool.all_backend_ids(), vec![id_old.clone()]);
    assert_eq!(stats.spawned.load(Ordering::SeqCst), 1);
    assert_eq!(stats.alive(), 1);

    let held = tokio::spawn(get_body(front_addr, "/slow", Duration::from_secs(25)));
    wait_until(
        || old.held_started.load(Ordering::SeqCst),
        Duration::from_secs(5),
    )
    .await;

    resolver.set(vec![new.addr]);
    time::sleep(poll_interval + margin).await;

    assert_eq!(pool.all_backend_ids(), vec![id_new.clone()]);
    assert!(!pool.is_eligible(&id_old));
    assert_eq!(stats.spawned.load(Ordering::SeqCst), 2);
    assert_eq!(stats.aborted.load(Ordering::SeqCst), 1);
    assert_eq!(stats.alive(), 1);

    let old_probes_after_teardown = old.health_probe_count();
    time::sleep(Duration::from_millis(150 * 4)).await;
    assert_eq!(
        old.health_probe_count(),
        old_probes_after_teardown,
        "old address kept receiving health probes after its checker was reported torn down -- leaked task"
    );

    old.release_gate.store(true, Ordering::SeqCst);
    let (status, body) = held.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        old.addr.to_string(),
        "in-flight request to the old address was not allowed to complete cleanly"
    );

    let (bodies, non_2xx) = sample_ok_bodies(front_addr, 8, Duration::from_millis(50)).await;
    assert_eq!(non_2xx, 0);
    for body in &bodies {
        assert_eq!(body, &new.addr.to_string());
    }
    assert_eq!(
        old.hit_count(),
        0,
        "old address received ordinary traffic after its address changed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_3_rapid_repeated_address_changes() {
    let poll_interval = Duration::from_secs(2);
    let margin = Duration::from_millis(500);

    let b0 = spawn_flap_backend(true).await;
    let b1 = spawn_flap_backend(false).await;
    let b2 = spawn_flap_backend(true).await;
    let b3 = spawn_flap_backend(true).await;
    let ghost_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    let resolver = Arc::new(ControlledResolver::new(vec![b0.addr]));
    let pool = Arc::new(BackendPool::new(Vec::new()));
    let client = build_client(None, HashMap::new(), false, None);
    let probe_client: Arc<dyn lb_core::ProbeClient> = Arc::new(ProbeCapableClient(client.clone()));
    let stats = Arc::new(CheckerStats::default());

    tokio::spawn(run_poller(
        Arc::clone(&resolver),
        poll_interval,
        Arc::clone(&pool),
        health_check_config(),
        probe_client,
        Arc::clone(&stats),
    ));

    let ctx = build_ctx(Arc::clone(&pool), client, "scenario3");
    let front_addr = spawn_lb_front(ctx).await;

    time::sleep(poll_interval + margin).await;
    let id_b0 = backend_id_for(b0.addr);
    assert_eq!(pool.all_backend_ids(), vec![id_b0.clone()]);
    let (bodies, non_2xx) = sample_ok_bodies(front_addr, 6, Duration::from_millis(50)).await;
    assert_eq!(non_2xx, 0);
    for body in &bodies {
        assert_eq!(body, &b0.addr.to_string());
    }

    resolver.set(vec![b1.addr]);
    let b0_replaced_at = Instant::now();
    time::sleep(poll_interval + margin).await;

    let id_b1 = backend_id_for(b1.addr);
    assert_eq!(pool.all_backend_ids(), vec![id_b1.clone()]);
    assert!(!pool.is_active_healthy(&id_b1));
    assert!(!pool.is_eligible(&id_b1));
    let (_, non_2xx) = sample_ok_bodies(front_addr, 6, Duration::from_millis(50)).await;
    assert_eq!(
        non_2xx, 6,
        "unhealthy current backend should refuse all traffic"
    );
    let probed_while_b1_current = b1.health_probe_count();
    assert!(probed_while_b1_current > 0);

    resolver.set(vec![b2.addr]);
    time::sleep(poll_interval + margin).await;

    let id_b2 = backend_id_for(b2.addr);
    assert_eq!(pool.all_backend_ids(), vec![id_b2.clone()]);
    assert!(
        pool.is_active_healthy(&id_b2),
        "backend's health state was contaminated by the previous address's failing history"
    );
    assert!(pool.is_eligible(&id_b2));
    let b1_probes_after_teardown = b1.health_probe_count();
    let (bodies, non_2xx) = sample_ok_bodies(front_addr, 6, Duration::from_millis(50)).await;
    assert_eq!(non_2xx, 0);
    for body in &bodies {
        assert_eq!(body, &b2.addr.to_string());
    }

    let b2_replaced_at = Instant::now();
    resolver.set(vec![ghost_addr]);
    time::sleep(Duration::from_millis(150)).await;
    resolver.set(vec![b3.addr]);
    time::sleep(poll_interval + margin).await;

    let id_b3 = backend_id_for(b3.addr);
    let id_ghost = backend_id_for(ghost_addr);
    assert_eq!(
        pool.all_backend_ids(),
        vec![id_b3.clone()],
        "pool did not converge to the final address, or briefly exposed the sub-poll-interval ghost address"
    );
    assert!(!pool.is_eligible(&id_ghost));
    let (bodies, non_2xx) = sample_ok_bodies(front_addr, 6, Duration::from_millis(50)).await;
    assert_eq!(non_2xx, 0);
    for body in &bodies {
        assert_eq!(body, &b3.addr.to_string());
    }

    assert_eq!(
        stats.spawned.load(Ordering::SeqCst),
        4,
        "a checker was spawned for an address that never should have been observed"
    );
    assert_eq!(stats.aborted.load(Ordering::SeqCst), 3);
    assert_eq!(stats.alive(), 1);

    let grace = poll_interval + Duration::from_millis(700);
    assert_eq!(b0.hits_after(b0_replaced_at + grace), 0);
    assert_eq!(
        b1.hit_count(),
        0,
        "unhealthy backend should never have served traffic"
    );
    assert_eq!(
        b1.health_probe_count(),
        b1_probes_after_teardown,
        "backend kept being probed after its checker was reported torn down -- leaked task"
    );
    assert_eq!(b2.hits_after(b2_replaced_at + grace), 0);
}
