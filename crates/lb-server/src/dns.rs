use crate::wiring::ProbeTransport;
use lb_core::{
    Backend, BackendId, BackendMap, BackendPool, DnsDiscoveryConfig, HealthCheckConfig, Resolve,
    SystemClock,
};
use lb_healthcheck::{
    spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe, OutlierDetector,
    TcpConnectProbe,
};
use lb_metrics::{BackendMetrics, Metrics};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub struct TokioResolver;

impl Resolve for TokioResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        Ok(addrs.collect())
    }
}

/// Aborts the wrapped checker task when dropped -- the only way to actually
/// stop it: a `JoinHandle` alone just detaches on drop, it does not cancel
/// the task. This is what lets `spawn_dns_poller` react to a backend leaving
/// DNS by simply removing its entry from `checkers` below, and what lets
/// every backend's checker get cleaned up automatically if the poller itself
/// is ever aborted (its local `checkers` map is dropped like any other local
/// when a task is cancelled at its next await point).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct DnsBackendRuntime {
    pub(crate) listener_name: String,
    pub(crate) health_check: HealthCheckConfig,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) breakers: BackendMap<CircuitBreaker<SystemClock>>,
    pub(crate) backend_metrics: BackendMap<BackendMetrics>,
    pub(crate) outlier: Option<Arc<OutlierDetector>>,
}

impl DnsBackendRuntime {
    fn reconcile(&self, live: &[BackendId]) {
        let live_set: HashSet<&BackendId> = live.iter().collect();
        let departed: Vec<BackendId> = self
            .backend_metrics
            .snapshot()
            .keys()
            .filter(|id| !live_set.contains(id))
            .cloned()
            .collect();
        self.breakers.reconcile(live, |_| {
            crate::wiring::breaker_for(&self.health_check, None)
        });
        self.backend_metrics
            .reconcile(live, |id| self.metrics.backend(&self.listener_name, &id.0));
        if let Some(outlier) = &self.outlier {
            outlier.reconcile(live);
        }
        for id in departed {
            self.metrics.remove_backend(&self.listener_name, &id.0);
        }
    }
}

fn retain_live_checkers(checkers: &mut HashMap<BackendId, AbortOnDrop>, ids: &[BackendId]) {
    let id_set: std::collections::HashSet<&BackendId> = ids.iter().collect();
    checkers.retain(|id, _| id_set.contains(id));
}

fn spawn_checker_for(
    backend: &Backend,
    pool: &Arc<BackendPool>,
    health_check: &HealthCheckConfig,
    transport: &ProbeTransport,
    metrics: &Metrics,
    listener_name: &str,
) -> AbortOnDrop {
    let config = ActiveCheckConfig {
        interval: Duration::from_millis(health_check.interval_ms),
        healthy_gauge: Some(metrics.backend(listener_name, &backend.id.0).healthy),
    };
    let timeout = Duration::from_millis(health_check.timeout_ms);
    let handle = match transport {
        ProbeTransport::Http {
            client,
            backend_tls,
        } => {
            let path = health_check
                .path
                .clone()
                .expect("config validation guarantees http listeners have a health_check.path");
            spawn_active_checker(
                backend.clone(),
                Arc::clone(pool),
                config,
                HttpProbe::new(Arc::clone(client), path, timeout, *backend_tls),
            )
        }
        ProbeTransport::Tcp(outbound) => spawn_active_checker(
            backend.clone(),
            Arc::clone(pool),
            config,
            TcpConnectProbe::new(timeout, outbound.clone()),
        ),
    };
    AbortOnDrop(handle)
}

/// Polls `cfg.name` on `cfg.poll_interval()`, applying whatever it resolves
/// to `pool`. Also keeps this listener's active health checking and (for an
/// HTTP listener with `backend_tls`) per-backend client pool in step with
/// DNS churn -- neither of those exists ahead of time the way a static
/// `[[listeners.backends]]` list's does, since a DNS-resolved backend's very
/// identity (and whether it exists at all) is only known once a poll
/// resolves it.
pub(crate) fn spawn_dns_poller<R: Resolve + 'static>(
    resolver: R,
    cfg: DnsDiscoveryConfig,
    pool: Arc<BackendPool>,
    per_backend_client: Option<Arc<lb_proxy::PerBackendClients>>,
    transport: ProbeTransport,
    runtime: DnsBackendRuntime,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(cfg.poll_interval());
        let mut checkers: HashMap<BackendId, AbortOnDrop> = HashMap::new();
        for id in pool.all_backend_ids() {
            if let Some(backend) = pool.backend(&id) {
                checkers.insert(
                    id,
                    spawn_checker_for(
                        &backend,
                        &pool,
                        &runtime.health_check,
                        &transport,
                        &runtime.metrics,
                        &runtime.listener_name,
                    ),
                );
            }
        }
        loop {
            ticker.tick().await;
            match resolver.resolve(&cfg.name, cfg.port).await {
                Ok(addrs) => {
                    let backends: Vec<Backend> = addrs
                        .into_iter()
                        .map(|addr| {
                            Backend::new(format!("dns:{addr}"), addr, 1, cfg.server_name.clone())
                        })
                        .collect();
                    let ids: Vec<BackendId> = backends.iter().map(|b| b.id.clone()).collect();
                    runtime.reconcile(&ids);
                    pool.apply_resolved(backends.clone());
                    if let Some(per_backend) = &per_backend_client {
                        per_backend.evict_missing(&ids);
                    }
                    retain_live_checkers(&mut checkers, &ids);
                    for backend in &backends {
                        checkers.entry(backend.id.clone()).or_insert_with(|| {
                            spawn_checker_for(
                                backend,
                                &pool,
                                &runtime.health_check,
                                &transport,
                                &runtime.metrics,
                                &runtime.listener_name,
                            )
                        });
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        listener = %runtime.listener_name,
                        dns_name = %cfg.name,
                        error = %err,
                        "dns discovery lookup failed; keeping the previous backend set"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId;
    use std::time::Duration as StdDuration;

    struct FakeResolver {
        addrs: Vec<SocketAddr>,
    }

    impl Resolve for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(self.addrs.clone())
        }
    }

    struct FailingResolver;

    impl Resolve for FailingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Err(io::Error::other("lookup failed"))
        }
    }

    fn cfg() -> DnsDiscoveryConfig {
        DnsDiscoveryConfig {
            name: "svc.internal".to_string(),
            port: 9001,
            poll_interval_secs: Some(10),
            server_name: None,
        }
    }

    fn health_check() -> HealthCheckConfig {
        HealthCheckConfig {
            path: None,
            interval_ms: 50,
            timeout_ms: 200,
            failure_threshold: 2,
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

    fn no_op_transport() -> ProbeTransport {
        ProbeTransport::Tcp(None)
    }

    fn test_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new().unwrap())
    }

    fn runtime_with(health_check: HealthCheckConfig) -> DnsBackendRuntime {
        DnsBackendRuntime {
            listener_name: "web".to_string(),
            health_check,
            metrics: test_metrics(),
            breakers: BackendMap::new(),
            backend_metrics: BackendMap::new(),
            outlier: None,
        }
    }

    fn spawn(
        resolver: impl Resolve + 'static,
        pool: Arc<BackendPool>,
        per_backend_client: Option<Arc<lb_proxy::PerBackendClients>>,
    ) -> tokio::task::JoinHandle<()> {
        spawn_dns_poller(
            resolver,
            cfg(),
            pool,
            per_backend_client,
            no_op_transport(),
            runtime_with(health_check()),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_poll_populates_the_pool() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let pool = Arc::new(BackendPool::new(Vec::new()));

        let _handle = spawn(FakeResolver { addrs: vec![addr] }, Arc::clone(&pool), None);
        time::sleep(StdDuration::from_millis(1)).await; // yield so the spawned task runs

        let ids = pool.all_backend_ids();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], BackendId::new("dns:127.0.0.1:9001"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_poll_keeps_the_previous_backend_set() {
        let existing = Backend::new(
            "dns:127.0.0.1:9001",
            "127.0.0.1:9001".parse().unwrap(),
            1,
            None,
        );
        let pool = Arc::new(BackendPool::new(vec![existing]));

        let _handle = spawn(FailingResolver, Arc::clone(&pool), None);
        time::sleep(StdDuration::from_millis(1)).await; // yield so the spawned task runs

        assert_eq!(pool.all_backend_ids().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_leaves_dns_is_evicted_from_the_per_backend_client_cache() {
        let gone: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let staying: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let connector = Arc::new(
            lb_tls::BackendConnector::new(&lb_core::BackendTlsConfig {
                ca_file: None,
                danger_accept_invalid_certs: true,
            })
            .unwrap(),
        );
        let per_backend = Arc::new(lb_proxy::PerBackendClients::new(
            "svc.internal".into(),
            connector,
            false,
            None,
        ));
        per_backend.get_or_build(&Backend::new("dns:127.0.0.1:9001", gone, 1, None));
        per_backend.get_or_build(&Backend::new("dns:127.0.0.1:9002", staying, 1, None));

        let _handle = spawn(
            FakeResolver {
                addrs: vec![staying],
            },
            Arc::clone(&pool),
            Some(Arc::clone(&per_backend)),
        );
        time::sleep(StdDuration::from_millis(1)).await;

        let tracked = per_backend.tracked_ids();
        assert!(!tracked.contains(&BackendId::new("dns:127.0.0.1:9001")));
        assert!(tracked.contains(&BackendId::new("dns:127.0.0.1:9002")));
    }

    /// The core of this fix: a backend that appears in DNS gets a real
    /// active health checker, proven here by a TCP-connect probe against an
    /// address nothing listens on actually marking it unhealthy -- before
    /// this fix, `pool.is_active_healthy` never moved off its initial
    /// `true` for a `dns_discovery` backend, no matter what it did.
    #[tokio::test]
    async fn a_resolved_backend_gets_a_real_health_checker() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // nothing listens here
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let id = BackendId::new(format!("dns:{addr}"));

        let handle = spawn_dns_poller(
            FakeResolver { addrs: vec![addr] },
            DnsDiscoveryConfig {
                poll_interval_secs: Some(1),
                ..cfg()
            },
            Arc::clone(&pool),
            None,
            no_op_transport(),
            runtime_with(HealthCheckConfig {
                path: None,
                interval_ms: 10,
                timeout_ms: 50,
                failure_threshold: 1,
                cooldown_ms: 100,
                half_open_successes_required: 1,
                flap_backoff_multiplier: 1.0,
                max_flap_cooldown_ms: u64::MAX,
                flap_streak_reset_ms: 60_000,
                unhealthy_latency_ms: None,
                unhealthy_request_count: None,
                outlier_detection: None,
                max_ejected_fraction: None,
            }),
        );

        // Real timers, since the checker itself runs on a real interval
        // this test doesn't control: give it a few cycles to mark the
        // backend unhealthy.
        for _ in 0..20 {
            time::sleep(StdDuration::from_millis(20)).await;
            if !pool.is_active_healthy(&id) {
                break;
            }
        }
        assert!(
            !pool.is_active_healthy(&id),
            "a checker should have marked the unreachable backend unhealthy"
        );

        handle.abort();
    }

    struct SwitchableResolver {
        addrs: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    }

    impl Resolve for SwitchableResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(self.addrs.lock().unwrap().clone())
        }
    }

    fn outlier_runtime() -> DnsBackendRuntime {
        DnsBackendRuntime {
            outlier: Some(Arc::new(OutlierDetector::new(
                Vec::new(),
                lb_healthcheck::OutlierConfig {
                    min_volume: 1,
                    min_hosts: 2,
                    stddev_factor: 1.0,
                    eject_ticks: 1,
                },
            ))),
            ..runtime_with(health_check())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolved_backend_gets_a_circuit_breaker_metrics_and_outlier_tracking() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let id = BackendId::new(format!("dns:{addr}"));
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let runtime = outlier_runtime();
        let breakers = runtime.breakers.clone();
        let backend_metrics = runtime.backend_metrics.clone();
        let outlier = runtime.outlier.clone().unwrap();

        let _handle = spawn_dns_poller(
            FakeResolver { addrs: vec![addr] },
            cfg(),
            Arc::clone(&pool),
            None,
            no_op_transport(),
            runtime,
        );
        time::sleep(StdDuration::from_millis(1)).await;

        let breaker = breakers
            .get(&id)
            .expect("a resolved backend must get a circuit breaker");
        breaker.record_failure();
        breaker.record_failure();
        assert!(breaker.is_open());
        assert!(backend_metrics.contains(&id));
        assert!(outlier.tracks(&id));
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_leaves_dns_loses_its_breaker_metrics_and_outlier_tracking() {
        let gone: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let staying: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let gone_id = BackendId::new(format!("dns:{gone}"));
        let staying_id = BackendId::new(format!("dns:{staying}"));
        let addrs = Arc::new(std::sync::Mutex::new(vec![gone, staying]));
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let runtime = outlier_runtime();
        let breakers = runtime.breakers.clone();
        let backend_metrics = runtime.backend_metrics.clone();
        let outlier = runtime.outlier.clone().unwrap();
        let metrics = Arc::clone(&runtime.metrics);

        let _handle = spawn_dns_poller(
            SwitchableResolver {
                addrs: Arc::clone(&addrs),
            },
            cfg(),
            Arc::clone(&pool),
            None,
            no_op_transport(),
            runtime,
        );
        time::sleep(StdDuration::from_millis(1)).await;
        backend_metrics
            .get(&gone_id)
            .unwrap()
            .requests_success
            .inc();
        let staying_breaker = breakers.get(&staying_id).unwrap();
        assert!(metrics.gather_text().contains(&*gone_id.0));

        *addrs.lock().unwrap() = vec![staying];
        time::sleep(StdDuration::from_secs(11)).await;

        assert!(breakers.get(&gone_id).is_none());
        assert!(!backend_metrics.contains(&gone_id));
        assert!(!outlier.tracks(&gone_id));
        assert!(!metrics.gather_text().contains(&*gone_id.0));
        assert!(Arc::ptr_eq(
            &breakers.get(&staying_id).unwrap(),
            &staying_breaker
        ));
    }

    #[tokio::test]
    async fn a_backend_added_by_a_later_poll_never_serves_before_a_successful_probe() {
        let listening = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first = listening.local_addr().unwrap();
        let second: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let first_id = BackendId::new(format!("dns:{first}"));
        let second_id = BackendId::new(format!("dns:{second}"));
        let addrs = Arc::new(std::sync::Mutex::new(vec![first]));
        let pool = Arc::new(BackendPool::new(Vec::new()));
        let handle = spawn_dns_poller(
            SwitchableResolver {
                addrs: Arc::clone(&addrs),
            },
            DnsDiscoveryConfig {
                poll_interval_secs: Some(1),
                ..cfg()
            },
            Arc::clone(&pool),
            None,
            no_op_transport(),
            runtime_with(health_check()),
        );
        for _ in 0..50 {
            time::sleep(StdDuration::from_millis(10)).await;
            if !pool.is_awaiting_first_probe(&first_id) && pool.backend(&first_id).is_some() {
                break;
            }
        }
        assert!(pool.is_active_healthy(&first_id));

        *addrs.lock().unwrap() = vec![first, second];
        let mut saw_second = false;
        for _ in 0..300 {
            time::sleep(StdDuration::from_millis(5)).await;
            if pool.backend(&second_id).is_some() {
                saw_second = true;
                assert!(
                    !pool.is_eligible(&second_id),
                    "a newly resolved backend must not be eligible before a successful probe"
                );
                assert_eq!(pool.eligible_backends(), vec![first_id.clone()]);
            }
        }
        assert!(
            saw_second,
            "the second poll should have added the new backend"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn a_backend_already_in_the_pool_is_health_checked_while_dns_is_failing() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let id = BackendId::new(format!("dns:{addr}"));
        let pool = Arc::new(BackendPool::new(vec![Backend::new(&*id.0, addr, 1, None)]));
        let handle = spawn_dns_poller(
            FailingResolver,
            cfg(),
            Arc::clone(&pool),
            None,
            no_op_transport(),
            runtime_with(health_check()),
        );
        for _ in 0..50 {
            time::sleep(StdDuration::from_millis(20)).await;
            if !pool.is_active_healthy(&id) {
                break;
            }
        }
        assert!(
            !pool.is_active_healthy(&id),
            "a carried-over backend must be probed even before DNS succeeds"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn retain_live_checkers_cost_does_not_scale_quadratically() {
        let small = fastest_retain_time(10).await;
        let large = fastest_retain_time(1000).await;
        assert!(
            large < small.max(StdDuration::from_micros(1)) * 500,
            "retain took {large:?} at 1000 tracked backends vs {small:?} at 10; \
             expected roughly linear growth (O(N+M)), not an O(N*M) blowup"
        );
        assert!(
            large < StdDuration::from_millis(50),
            "retain at 1000 tracked backends took {large:?}, too slow for an \
             O(N+M) HashSet-backed retain"
        );
    }

    async fn fastest_retain_time(n: usize) -> StdDuration {
        let mut fastest = StdDuration::MAX;
        for _ in 0..5 {
            let mut checkers: HashMap<BackendId, AbortOnDrop> = HashMap::new();
            for i in 0..n {
                let id = BackendId::new(format!("dns:127.0.0.1:{i}"));
                checkers.insert(id, AbortOnDrop(tokio::spawn(async {})));
            }
            let ids: Vec<BackendId> = (0..n)
                .filter(|i| i % 2 == 0)
                .map(|i| BackendId::new(format!("dns:127.0.0.1:{i}")))
                .collect();

            let start = std::time::Instant::now();
            retain_live_checkers(&mut checkers, &ids);
            let elapsed = start.elapsed();

            assert_eq!(checkers.len(), ids.len());
            fastest = fastest.min(elapsed);
        }
        fastest
    }
}
