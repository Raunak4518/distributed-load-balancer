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
        /// `None` means this listener speaks plaintext. Built once at startup
        /// so a bad certificate fails before the port is bound, rather than
        /// on the first client to arrive.
        tls: Option<Arc<lb_tls::TlsAcceptor>>,
    },
    Tcp {
        name: String,
        listen: SocketAddr,
        ctx: Arc<TcpAppContext>,
        limits: ConnectionLimits,
        metrics: Arc<lb_metrics::ListenerMetrics>,
        tls: Option<Arc<lb_tls::TlsAcceptor>>,
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

    pub fn tls(&self) -> Option<&Arc<lb_tls::TlsAcceptor>> {
        match self {
            ListenerRuntime::Http { tls, .. } | ListenerRuntime::Tcp { tls, .. } => tls.as_ref(),
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
///
/// Fails rather than panics on bad operator input — a certificate that will
/// not load is the same class of problem as a port that will not bind, and
/// deserves the same clean message. `Metrics::new()` still uses `expect`,
/// because it can only fail on a duplicate metric name, which is a
/// programming error and not something an operator can cause.
pub fn build_app(
    config: &Config,
    cluster_secret: Option<Vec<u8>>,
) -> Result<WiredApp, std::io::Error> {
    let mut listeners = Vec::with_capacity(config.listeners.len());
    let mut background_tasks = Vec::new();
    let mut pools = Vec::with_capacity(config.listeners.len());

    // Every acceptor is built before any background task is spawned,
    // mirroring how `run` binds every listener before serving any of them: a
    // certificate that will not load should fail startup outright, not
    // halfway through it with sweepers and health checkers already running.
    let mut tls_acceptors = Vec::with_capacity(config.listeners.len());
    for lc in &config.listeners {
        tls_acceptors.push(build_tls_acceptor(lc)?);
    }

    // One registry per process. Handles are resolved from it once per
    // listener/backend below — never on the request path.
    let metrics = Arc::new(Metrics::new().expect("metric names are valid and unique"));

    // Built here for the same reason as the acceptors above: an unreadable
    // `ca_file` is operator input, and must fail startup rather than turn
    // every backend request into a verification error. One connector per
    // listener, so the same trust roots and verification policy serve both
    // the L7 client and the L4 transport built from it below.
    let mut backend_connectors = Vec::with_capacity(config.listeners.len());
    for lc in &config.listeners {
        backend_connectors.push(build_backend_connector(lc, &metrics)?);
    }

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

    for ((lc, tls), backend_tls) in config
        .listeners
        .iter()
        .zip(tls_acceptors)
        .zip(backend_connectors)
    {
        let backends: Vec<Backend> = lc
            .backends
            .iter()
            .map(|b| Backend::new(b.id.clone(), b.address, b.weight, b.server_name.clone()))
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

        // Certificates expire on a fixed schedule (90 days under ACME), so a
        // TLS listener without a reload loop is an outage generator on a
        // timer. Pushed onto the same list the health checkers use, so it is
        // aborted on shutdown with everything else.
        if let (Some(acceptor), Some(tls_cfg)) = (tls.as_ref(), lc.tls.as_ref()) {
            background_tasks.push(lb_tls::spawn_reloader(
                lc.name.clone(),
                tls_cfg.certificates.clone(),
                Arc::clone(acceptor.resolver()),
                tls_cfg.reload_interval(),
                Arc::clone(&listener_metrics),
            ));
        }

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
                    client: lb_proxy::build_client(backend_tls.as_deref()),
                    backend_tls: backend_tls.is_some(),
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
                tls,
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
                    // The one place the L4 data plane's re-encryption is
                    // chosen. `lb-tcp` sees a trait object and never learns
                    // which TLS implementation is behind it.
                    backend_tls: backend_tls.map(|c| {
                        Arc::new(lb_tls::BackendTlsTransport::new(&c))
                            as Arc<dyn lb_core::OutboundTransport>
                    }),
                    cluster: cluster_coordinator,
                    metrics: Arc::clone(&listener_metrics),
                    backend_metrics,
                }),
                limits: connection_limits,
                metrics: Arc::clone(&listener_metrics),
                tls,
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

    Ok(WiredApp {
        listeners,
        background_tasks,
        drain_timeout: Duration::from_millis(config.server.drain_timeout_ms),
        cluster,
        metrics,
        admin_listen: config.admin.as_ref().map(|a| a.listen),
        pools,
    })
}

/// Builds one listener's TLS acceptor, if it has a `[listeners.tls]` section.
///
/// Done at startup rather than on first connection: an unreadable certificate
/// or an unusable key must fail startup outright rather than leave a bound
/// port that can never complete a handshake. A mistyped `cert_file` is the
/// commonest TLS misconfiguration there is, so the error names the listener.
fn build_tls_acceptor(
    lc: &ListenerConfig,
) -> Result<Option<Arc<lb_tls::TlsAcceptor>>, std::io::Error> {
    let Some(tls_cfg) = &lc.tls else {
        return Ok(None);
    };
    // The listener's protocol decides what we are willing to speak inside
    // the tunnel. Advertising `http/1.1` is the seam where Phase 8 adds
    // `h2`; at L4 we do not know the application protocol's name, so we
    // offer none.
    let alpn: &[&[u8]] = match lc.protocol {
        Protocol::Http => &[b"http/1.1"],
        Protocol::Tcp => &[],
    };
    let acceptor = lb_tls::TlsAcceptor::new(tls_cfg, alpn).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "listener '{}' could not load its TLS material: {err}",
                lc.name
            ),
        )
    })?;
    Ok(Some(Arc::new(acceptor)))
}

/// Builds one listener's backend connector, if it has a
/// `[listeners.backend_tls]` section, and makes the danger flag visible.
///
/// The warning and the gauge are here rather than at the config layer
/// because this is the moment the policy becomes real. `danger_accept_invalid_certs`
/// encrypts backend traffic without authenticating it, which does not address
/// the threat encryption is there for -- so it says so at every startup and
/// sets a series a dashboard can alert on, instead of living undiscovered in
/// a config file for two years.
fn build_backend_connector(
    lc: &ListenerConfig,
    metrics: &Metrics,
) -> Result<Option<Arc<lb_tls::BackendConnector>>, std::io::Error> {
    let Some(cfg) = &lc.backend_tls else {
        return Ok(None);
    };
    let connector = lb_tls::BackendConnector::new(cfg).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "listener '{}' could not load its backend TLS trust roots: {err}",
                lc.name
            ),
        )
    })?;

    let disabled = connector.verification_disabled();
    if disabled {
        tracing::warn!(
            listener = %lc.name,
            "backend TLS certificate verification is DISABLED — traffic to \
             backends is encrypted but NOT authenticated"
        );
    }
    // Set either way, so a listener that does verify publishes a flat zero
    // rather than a gap: to an alert those look identical.
    metrics
        .backend_tls_verification_disabled
        .with_label_values(&[&lc.name])
        .set(i64::from(disabled));

    Ok(Some(Arc::new(connector)))
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
        let app = build_app(&config, None).unwrap();

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
        let app = build_app(&config, None).unwrap();
        assert_eq!(app.drain_timeout, Duration::from_millis(10_000));
        for task in app.background_tasks {
            task.abort();
        }
    }
}
