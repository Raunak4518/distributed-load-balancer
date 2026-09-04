use lb_balancer::RoundRobin;
use lb_cluster::{ClusterNode, ListenerCoordinator};
use lb_core::ClusterCoordinator;
use lb_core::{Backend, BackendPool, Config, ListenerConfig, Protocol, SystemClock};
use lb_healthcheck::{
    spawn_active_checker, ActiveCheckConfig, CircuitBreaker, HttpProbe, TcpConnectProbe,
};
use lb_metrics::Metrics;
use lb_proxy::ProxyContext;
use lb_ratelimit::{spawn_sweeper, Gcra, GcraConfig};
use lb_tcp::TcpContext;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub type HttpContext = ProxyContext<Gcra<SystemClock>, RoundRobin, SystemClock>;
pub type TcpAppContext = TcpContext<Gcra<SystemClock>, RoundRobin, SystemClock>;
pub type AppClusterNode = ClusterNode<SystemClock>;

/// One configured listener, ready to accept. An enum rather than a trait:
/// this is a genuinely closed set, and `serve_listener` must match on it
/// exhaustively to know which protocol driver to run.
pub enum ListenerRuntime {
    Http {
        name: String,
        listen: SocketAddr,
        ctx: Arc<HttpContext>,
        limits: ConnectionLimits,
        metrics: Arc<lb_metrics::ListenerMetrics>,
        header_read_timeout: Duration,
    },
    Tcp {
        name: String,
        listen: SocketAddr,
        ctx: Arc<TcpAppContext>,
        limits: ConnectionLimits,
        metrics: Arc<lb_metrics::ListenerMetrics>,
    },
}

impl ListenerRuntime {
    pub fn name(&self) -> &str {
        match self {
            ListenerRuntime::Http { name, .. } | ListenerRuntime::Tcp { name, .. } => name,
        }
    }

    pub fn limits(&self) -> &ConnectionLimits {
        match self {
            ListenerRuntime::Http { limits, .. } | ListenerRuntime::Tcp { limits, .. } => limits,
        }
    }

    pub fn metrics(&self) -> &Arc<lb_metrics::ListenerMetrics> {
        match self {
            ListenerRuntime::Http { metrics, .. } | ListenerRuntime::Tcp { metrics, .. } => metrics,
        }
    }

    pub fn listen(&self) -> SocketAddr {
        match self {
            ListenerRuntime::Http { listen, .. } | ListenerRuntime::Tcp { listen, .. } => *listen,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            ListenerRuntime::Http { .. } => "http",
            ListenerRuntime::Tcp { .. } => "tcp",
        }
    }
}

/// Per-listener connection caps.
pub struct ConnectionLimits {
    /// Global cap. Acquired *before* `accept()` so that at capacity we stop
    /// accepting and the kernel refuses on our behalf.
    pub global: Arc<tokio::sync::Semaphore>,
    /// Per-source cap, checked after `accept()` — the peer address is not
    /// knowable before then.
    pub per_ip: Arc<crate::limits::PerIpLimiter>,
}

pub struct WiredApp {
    pub listeners: Vec<ListenerRuntime>,
    pub background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub drain_timeout: Duration,
    /// Present only when `[cluster]` is configured.
    pub cluster: Option<ClusterSetup>,
    /// Always collected; `admin_listen` controls whether it is exposed.
    pub metrics: Arc<Metrics>,
    pub admin_listen: Option<SocketAddr>,
    /// Every listener's pool, for the readiness check.
    pub pools: Vec<Arc<BackendPool>>,
}

/// Everything `run` needs to start peer coordination, kept separate from the
/// per-listener wiring so binding can happen alongside the traffic listeners.
pub struct ClusterSetup {
    pub node: Arc<AppClusterNode>,
    pub listen: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub sync_interval: Duration,
}

/// Builds the runtime.
///
/// Takes the already-resolved cluster secret rather than reading it here:
/// `run` resolves it before anything binds, so a missing secret fails
/// startup instead of surfacing once traffic is flowing.
pub fn build_app(config: &Config, cluster_secret: Option<Vec<u8>>) -> WiredApp {
    let mut listeners = Vec::with_capacity(config.listeners.len());
    let mut background_tasks = Vec::new();
    let mut pools = Vec::with_capacity(config.listeners.len());

    // One registry per process. Handles are resolved from it once per
    // listener/backend below — never on the request path.
    let metrics = Arc::new(Metrics::new().expect("metric names are valid and unique"));

    // One cluster node per process, shared by every listener.
    let cluster_node = match (config.cluster.as_ref(), cluster_secret) {
        (Some(c), Some(secret)) => Some(Arc::new(ClusterNode::new(
            c.node_id.clone(),
            c.window_secs,
            SystemClock,
            secret,
        ))),
        _ => None,
    };

    for lc in &config.listeners {
        let backends: Vec<Backend> = lc
            .backends
            .iter()
            .map(|b| Backend::new(b.id.clone(), b.address, b.weight))
            .collect();
        let pool = Arc::new(BackendPool::new(backends.clone()));
        pools.push(Arc::clone(&pool));

        let protocol_name = match lc.protocol {
            Protocol::Http => "http",
            Protocol::Tcp => "tcp",
        };
        let listener_metrics = Arc::new(metrics.listener(&lc.name, protocol_name));
        let connection_limits = ConnectionLimits {
            global: Arc::new(tokio::sync::Semaphore::new(lc.max_connections())),
            per_ip: Arc::new(crate::limits::PerIpLimiter::new(
                lc.max_connections_per_ip(),
            )),
        };
        let backend_metrics: HashMap<_, _> = backends
            .iter()
            .map(|b| (b.id.clone(), metrics.backend(&lc.name, &b.id.0)))
            .collect();

        let mut circuit_breakers = HashMap::new();
        for b in &backends {
            circuit_breakers.insert(
                b.id.clone(),
                CircuitBreaker::new(
                    lc.health_check.failure_threshold,
                    Duration::from_millis(lc.health_check.cooldown_ms),
                    SystemClock,
                ),
            );
        }

        let rate_limiter = Arc::new(Gcra::new(
            GcraConfig {
                rate_per_sec: lc.rate_limit.rate_per_sec,
                burst: lc.rate_limit.burst,
                max_tracked_keys: lc.rate_limit.max_tracked_keys,
            },
            SystemClock,
        ));
        background_tasks.push(spawn_sweeper(
            rate_limiter.clone(),
            Duration::from_secs(30),
            Duration::from_secs(60),
        ));

        spawn_health_checkers(lc, &backends, &pool, &mut background_tasks, &metrics);

        // The global cap is the sustained rate over the whole window; the
        // local GCRA continues to shape bursts inside it.
        let cluster_coordinator: Option<Arc<dyn ClusterCoordinator>> =
            match (&cluster_node, &config.cluster) {
                (Some(node), Some(cc)) => {
                    let limit = (lc.rate_limit.rate_per_sec * cc.window_secs as f64).ceil() as u64;
                    Some(Arc::new(ListenerCoordinator::new(
                        Arc::clone(node),
                        lc.name.clone(),
                        limit.max(1),
                    )))
                }
                _ => None,
            };

        listeners.push(match lc.protocol {
            Protocol::Http => ListenerRuntime::Http {
                name: lc.name.clone(),
                listen: lc.listen,
                ctx: Arc::new(ProxyContext {
                    rate_limiter,
                    balancer: Arc::new(RoundRobin::new()),
                    pool,
                    circuit_breakers,
                    client: lb_proxy::build_client(),
                    rate_limit_key: lc.rate_limit.key.clone(),
                    forward_timeout: lc.forward_timeout(),
                    max_request_body_bytes: lc.max_request_body_bytes(),
                    cluster: cluster_coordinator,
                    metrics: Arc::clone(&listener_metrics),
                    backend_metrics,
                    access_log: lb_proxy::AccessLog::new(
                        config.logging.log_requests,
                        config.logging.sample_rate,
                    ),
                    body_read_timeout: lc.body_read_timeout(),
                }),
                limits: connection_limits,
                metrics: Arc::clone(&listener_metrics),
                header_read_timeout: lc.header_read_timeout(),
            },
            Protocol::Tcp => ListenerRuntime::Tcp {
                name: lc.name.clone(),
                listen: lc.listen,
                ctx: Arc::new(TcpContext {
                    rate_limiter,
                    balancer: Arc::new(RoundRobin::new()),
                    pool,
                    circuit_breakers,
                    connect_timeout: lc.connect_timeout(),
                    idle_timeout: lc.idle_timeout(),
                    cluster: cluster_coordinator,
                    metrics: Arc::clone(&listener_metrics),
                    backend_metrics,
                }),
                limits: connection_limits,
                metrics: Arc::clone(&listener_metrics),
            },
        });
    }

    let cluster = match (cluster_node, config.cluster.as_ref()) {
        (Some(node), Some(cc)) => Some(ClusterSetup {
            node,
            listen: cc.listen,
            peers: cc.peers.clone(),
            sync_interval: cc.sync_interval(),
        }),
        _ => None,
    };

    WiredApp {
        listeners,
        background_tasks,
        drain_timeout: Duration::from_millis(config.server.drain_timeout_ms),
        cluster,
        metrics,
        admin_listen: config.admin.as_ref().map(|a| a.listen),
        pools,
    }
}

/// The listener's protocol picks the probe — an HTTP listener always wants an
/// HTTP probe, so there is no config knob here to get wrong.
fn spawn_health_checkers(
    lc: &ListenerConfig,
    backends: &[Backend],
    pool: &Arc<BackendPool>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    metrics: &Metrics,
) {
    let interval = Duration::from_millis(lc.health_check.interval_ms);
    let timeout = Duration::from_millis(lc.health_check.timeout_ms);

    for b in backends {
        let config = ActiveCheckConfig {
            interval,
            healthy_gauge: Some(metrics.backend(&lc.name, &b.id.0).healthy),
        };
        match lc.protocol {
            Protocol::Http => {
                let path =
                    lc.health_check.path.clone().expect(
                        "config validation guarantees http listeners have a health_check.path",
                    );
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    HttpProbe::new(path, timeout),
                ));
            }
            Protocol::Tcp => {
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    TcpConnectProbe::new(timeout),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::BackendId;

    const CONFIG: &str = r#"
        [[listeners]]
        name = "web"
        protocol = "http"
        listen = "127.0.0.1:0"

          [[listeners.backends]]
          id = "w1"
          address = "127.0.0.1:9001"

          [[listeners.backends]]
          id = "w2"
          address = "127.0.0.1:9002"

          [listeners.health_check]
          path = "/health"
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 50
          burst = 100

          [listeners.load_balancing]
          strategy = "round_robin"

        [[listeners]]
        name = "db"
        protocol = "tcp"
        listen = "127.0.0.1:1"

          [[listeners.backends]]
          id = "pg1"
          address = "127.0.0.1:9003"

          [listeners.health_check]
          interval_ms = 2000
          timeout_ms = 500
          failure_threshold = 3
          cooldown_ms = 5000

          [listeners.rate_limit]
          key = "source_ip"
          rate_per_sec = 10
          burst = 20

          [listeners.load_balancing]
          strategy = "round_robin"
    "#;

    #[tokio::test]
    async fn builds_one_runtime_per_listener_with_the_right_protocol() {
        // build_app spawns background tasks, so this needs a Tokio runtime.
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None);

        assert_eq!(app.listeners.len(), 2);
        assert!(matches!(app.listeners[0], ListenerRuntime::Http { .. }));
        assert!(matches!(app.listeners[1], ListenerRuntime::Tcp { .. }));
        assert_eq!(app.listeners[0].name(), "web");
        assert_eq!(app.listeners[1].protocol_name(), "tcp");

        // 2 sweepers (one per listener) + 3 health checkers (2 http + 1 tcp)
        assert_eq!(app.background_tasks.len(), 5);

        match &app.listeners[0] {
            ListenerRuntime::Http { ctx, .. } => {
                assert_eq!(ctx.pool.all_backend_ids().len(), 2);
                assert!(ctx.pool.is_eligible(&BackendId::new("w1")));
            }
            _ => panic!("expected an http listener"),
        }

        for task in app.background_tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn applies_drain_timeout_default() {
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None);
        assert_eq!(app.drain_timeout, Duration::from_millis(10_000));
        for task in app.background_tasks {
            task.abort();
        }
    }
}
