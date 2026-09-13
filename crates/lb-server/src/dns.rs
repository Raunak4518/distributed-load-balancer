use crate::wiring::ProbeTransport;
use lb_core::{Backend, BackendId, BackendPool, DnsDiscoveryConfig, HealthCheckConfig, Resolve};
use lb_healthcheck::{spawn_active_checker, ActiveCheckConfig, HttpProbe, TcpConnectProbe};
use lb_metrics::Metrics;
use std::collections::HashMap;
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
#[allow(clippy::too_many_arguments)]
pub fn spawn_dns_poller<R: Resolve + 'static>(
    resolver: R,
    cfg: DnsDiscoveryConfig,
    pool: Arc<BackendPool>,
    listener_name: String,
    per_backend_client: Option<Arc<lb_proxy::PerBackendClients>>,
    health_check: HealthCheckConfig,
    transport: ProbeTransport,
    metrics: Arc<Metrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(cfg.poll_interval());
        let mut checkers: HashMap<BackendId, AbortOnDrop> = HashMap::new();
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
                    pool.apply_resolved(backends.clone());
                    if let Some(per_backend) = &per_backend_client {
                        per_backend.evict_missing(&ids);
                    }
                    checkers.retain(|id, _| ids.contains(id));
                    for backend in &backends {
                        checkers.entry(backend.id.clone()).or_insert_with(|| {
                            spawn_checker_for(
                                backend,
                                &pool,
                                &health_check,
                                &transport,
                                &metrics,
                                &listener_name,
                            )
                        });
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        listener = %listener_name,
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
        }
    }

    fn no_op_transport() -> ProbeTransport {
        ProbeTransport::Tcp(None)
    }

    fn test_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new().unwrap())
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
            "web".to_string(),
            per_backend_client,
            health_check(),
            no_op_transport(),
            test_metrics(),
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
            "web".to_string(),
            None,
            HealthCheckConfig {
                path: None,
                interval_ms: 10,
                timeout_ms: 50,
                failure_threshold: 1,
                cooldown_ms: 100,
            },
            no_op_transport(),
            test_metrics(),
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
}
