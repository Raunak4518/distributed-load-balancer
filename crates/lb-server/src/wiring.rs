use lb_balancer::RoundRobin;
use lb_cluster::{ClusterNode, ListenerCoordinator};
use lb_core::ClusterCoordinator;
use lb_core::{Backend, BackendPool, Config, Http2Config, ListenerConfig, Protocol, SystemClock};
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
        /// `Some` exactly when this listener's acceptor advertises `h2`, and
        /// carrying defaults when the operator wrote no `[listeners.http2]`
        /// section. That equivalence is the point: `h2` is negotiated by the
        /// ALPN list built from `http2_enabled()`, so populating this from
        /// the same predicate makes "negotiated h2 without settings to serve
        /// it under" unrepresentable rather than merely unlikely.
        http2: Option<Arc<Http2Config>>,
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

    /// The HTTP/2 settings to serve an `h2` connection under, or `None` if
    /// this listener never advertises `h2`. A TCP listener is always `None`:
    /// HTTP/2 is an application protocol and the L4 data plane parses none.
    pub fn http2(&self) -> Option<&Arc<Http2Config>> {
        match self {
            ListenerRuntime::Http { http2, .. } => http2.as_ref(),
            ListenerRuntime::Tcp { .. } => None,
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

        if let Some(dns) = &lc.dns_discovery {
            background_tasks.push(crate::dns::spawn_dns_poller(
                crate::dns::TokioResolver,
                dns.clone(),
                Arc::clone(&pool),
                lc.name.clone(),
            ));
        }

        // Pins the L7 forwarding client's TCP dial to each backend's
        // configured `address`, even though the forwarding authority is that
        // backend's `server_name` (chosen so SNI and hostname verification
        // check the certificate's own name). Without this table, a
        // `backend_tls` listener's connector would resolve `server_name` via
        // real DNS to find something to dial -- silently reintroducing
        // DNS-based backend resolution and letting traffic follow whatever
        // that name resolves to instead of the pinned backend. Built for
        // every listener, not only `backend_tls` ones: a plaintext listener's
        // requests carry an IP-literal authority, so the table is simply
        // never consulted there. See `lb_proxy::resolver::PinnedResolver`.
        let server_name_addresses: HashMap<String, SocketAddr> = backends
            .iter()
            .filter_map(|b| b.server_name.clone().map(|name| (name, b.address)))
            .collect();

        let listener_metrics = Arc::new(metrics.listener(&lc.name));
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

        let runtime = match lc.protocol {
            Protocol::Http => {
                // Built exactly once per HTTP listener, and handed to both
                // consumers below. **This sharing is the whole mechanism**
                // behind "a probe validates what traffic validates": the
                // probe does not use a client like the data plane's, it uses
                // this one -- same connection pool, same trust roots, same
                // verification policy, same pinned resolver. A `Client` is an
                // `Arc`-backed handle, so a clone is the same client, not a
                // copy of one. Two `build_client` calls here would put two
                // TLS stacks in one listener and let them disagree.
                // Prior-knowledge h2c: plaintext backends only, and only
                // when the operator has said so -- a TLS backend negotiates
                // via ALPN regardless (see `lb_proxy::build_client`).
                let backend_h2c = lc.http2.as_ref().map(|h| h.backend_h2c()).unwrap_or(false);
                let client = lb_proxy::build_client(
                    backend_tls.as_deref(),
                    server_name_addresses,
                    backend_h2c,
                );
                // A `dns_discovery` + `backend_tls` listener puts several
                // backends behind one `server_name`, which `client` above
                // cannot serve correctly -- see `lb_proxy::per_backend`.
                // Each such backend gets its own client (and so its own
                // connection pool) instead, built lazily as backends are
                // first seen; `client` stays built but unused, its
                // dial-pinning table simply empty.
                let per_backend_client = match (&lc.dns_discovery, &backend_tls) {
                    (Some(dns), Some(connector)) => Some(Arc::new(lb_proxy::PerBackendClients::new(
                        dns.server_name
                            .clone()
                            .expect("validated: server_name is required when backend_tls is set"),
                        Arc::clone(connector),
                        backend_h2c,
                    ))),
                    _ => None,
                };
                let probe_client: Arc<dyn lb_core::ProbeClient> = match &per_backend_client {
                    Some(per_backend) => Arc::clone(per_backend) as Arc<dyn lb_core::ProbeClient>,
                    None => Arc::new(lb_proxy::ProbeCapableClient(client.clone())),
                };
                spawn_health_checkers(
                    lc,
                    &backends,
                    &pool,
                    &mut background_tasks,
                    &metrics,
                    ProbeTransport::Http {
                        client: probe_client,
                        backend_tls: backend_tls.is_some(),
                    },
                );
                ListenerRuntime::Http {
                    name: lc.name.clone(),
                    listen: lc.listen,
                    ctx: Arc::new(ProxyContext {
                        rate_limiter,
                        balancer: Arc::new(RoundRobin::new()),
                        pool,
                        circuit_breakers,
                        client,
                        per_backend_client,
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
                        // Both gating conditions collapse into this one
                        // `Option` here, at the one place that knows both
                        // facts: whether this listener terminates TLS at all
                        // (`lc.tls`) and whether HSTS was actually turned on
                        // (`hsts_max_age_secs() > 0`, since 0 is the default
                        // and must stay a no-op, not `max-age=0`). `handle`
                        // downstream cannot see either fact for itself.
                        hsts_max_age_secs: lc
                            .tls
                            .as_ref()
                            .map(|t| t.hsts_max_age_secs())
                            .filter(|&v| v > 0),
                    }),
                    limits: connection_limits,
                    metrics: Arc::clone(&listener_metrics),
                    header_read_timeout: lc.header_read_timeout(),
                    tls,
                    // Built from the same `http2_enabled()` that chose the
                    // ALPN list above, so the two cannot drift apart. The
                    // `unwrap_or_default` is load-bearing rather than
                    // defensive: `http2_enabled()` is true for a TLS
                    // listener with no `[listeners.http2]` section at all --
                    // the common case -- and that listener still advertises
                    // `h2` and so still needs settings to serve it under.
                    http2: lc
                        .http2_enabled()
                        .then(|| Arc::new(lc.http2.clone().unwrap_or_default())),
                }
            }
            Protocol::Tcp => {
                // The one place the L4 data plane's re-encryption is chosen.
                // `lb-tcp` sees a trait object and never learns which TLS
                // implementation is behind it -- and, for the same reason as
                // the HTTP client above, the probe is handed this same `Arc`
                // rather than a second transport built from the same config.
                let outbound: Option<Arc<dyn lb_core::OutboundTransport>> = backend_tls.map(|c| {
                    Arc::new(lb_tls::BackendTlsTransport::new(&c))
                        as Arc<dyn lb_core::OutboundTransport>
                });
                spawn_health_checkers(
                    lc,
                    &backends,
                    &pool,
                    &mut background_tasks,
                    &metrics,
                    ProbeTransport::Tcp(outbound.clone()),
                );
                ListenerRuntime::Tcp {
                    name: lc.name.clone(),
                    listen: lc.listen,
                    ctx: Arc::new(TcpContext {
                        rate_limiter,
                        balancer: Arc::new(RoundRobin::new()),
                        pool,
                        circuit_breakers,
                        connect_timeout: lc.connect_timeout(),
                        idle_timeout: lc.idle_timeout(),
                        backend_tls: outbound,
                        cluster: cluster_coordinator,
                        metrics: Arc::clone(&listener_metrics),
                        backend_metrics,
                    }),
                    limits: connection_limits,
                    metrics: Arc::clone(&listener_metrics),
                    tls,
                }
            }
        };
        listeners.push(runtime);
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
    // the tunnel. Order is preference: a client offering both gets HTTP/2.
    // TCP listeners advertise nothing -- at L4 we do not know the
    // application protocol's name.
    let alpn: &[&[u8]] = match (lc.protocol, lc.http2_enabled()) {
        (Protocol::Http, true) => &[b"h2", b"http/1.1"],
        (Protocol::Http, false) => &[b"http/1.1"],
        (Protocol::Tcp, _) => &[],
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

/// The outbound machinery a listener's probes must use: the *same* values its
/// data plane forwards through, not equivalents built from the same config.
///
/// An enum rather than two optional parameters because the two are mutually
/// exclusive by protocol, and because it is built at the one site that also
/// builds the data plane's copy -- which makes the sharing visible in the
/// wiring instead of being a convention someone has to remember.
enum ProbeTransport {
    Http {
        client: Arc<dyn lb_core::ProbeClient>,
        /// Whether this listener re-encrypts, exactly as `ProxyContext`
        /// carries it. The client owns the scheme/authority decision; this
        /// only tells it which kind of listener it is probing for.
        backend_tls: bool,
    },
    /// `None` inside means a plaintext outbound leg -- the same shape
    /// `TcpContext.backend_tls` holds.
    Tcp(Option<Arc<dyn lb_core::OutboundTransport>>),
}

/// Spawns one active checker per backend. `transport` picks the probe — an
/// HTTP listener always wants an HTTP probe, so there is still no config knob
/// here to get wrong.
///
/// Note what moved, though: this reads the *caller's* `ProbeTransport` rather
/// than `lc.protocol`, so keeping the two in agreement is now the caller's
/// obligation, not this function's. It is discharged in `build_app`, where
/// the enum is constructed inside the `match lc.protocol` arm that also
/// builds the data plane's copy — which is the point. Building it here from
/// `lc.protocol` instead would mean building the client and the transport
/// here too, and then they would be *this* function's, not the listener's,
/// which is precisely the divergence the whole design exists to prevent.
fn spawn_health_checkers(
    lc: &ListenerConfig,
    backends: &[Backend],
    pool: &Arc<BackendPool>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    metrics: &Metrics,
    transport: ProbeTransport,
) {
    let interval = Duration::from_millis(lc.health_check.interval_ms);
    let timeout = Duration::from_millis(lc.health_check.timeout_ms);

    for b in backends {
        let config = ActiveCheckConfig {
            interval,
            healthy_gauge: Some(metrics.backend(&lc.name, &b.id.0).healthy),
        };
        match &transport {
            ProbeTransport::Http {
                client,
                backend_tls,
            } => {
                let path =
                    lc.health_check.path.clone().expect(
                        "config validation guarantees http listeners have a health_check.path",
                    );
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    // `Arc::clone`, not a second client: every backend of this
                    // listener probes through the one the listener forwards
                    // with.
                    HttpProbe::new(Arc::clone(client), path, timeout, *backend_tls),
                ));
            }
            ProbeTransport::Tcp(outbound) => {
                tasks.push(spawn_active_checker(
                    b.clone(),
                    pool.clone(),
                    config,
                    TcpConnectProbe::new(timeout, outbound.clone()),
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

    /// The half of the h2 invariant that needs no certificate: a listener
    /// that cannot negotiate ALPN must carry no HTTP/2 settings, so `drive`'s
    /// `is_h2` branch is unreachable for it by construction. The other half --
    /// a TLS listener with no `[listeners.http2]` section still getting
    /// settings -- is covered end to end in `tests/http2_integration.rs`,
    /// where the `expect` in `drive` would fire if it did not hold.
    #[tokio::test]
    async fn a_listener_that_cannot_negotiate_alpn_carries_no_http2_settings() {
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None).unwrap();

        // Plaintext HTTP: no TLS handshake, so no ALPN, so no h2.
        assert!(app.listeners[0].http2().is_none());
        // TCP: HTTP/2 is an application protocol the L4 data plane never
        // parses, whatever the config says.
        assert!(app.listeners[1].http2().is_none());

        for task in app.background_tasks {
            task.abort();
        }
    }

    /// `dns_discovery` + `backend_tls` on an HTTP listener used to be
    /// rejected outright at config validation. Now that it's accepted, the
    /// listener must come up with a `per_backend_client` -- the shared
    /// `client` cannot serve several DNS-resolved addresses safely, since
    /// they'd all share one `server_name` authority. See
    /// `lb_proxy::per_backend`.
    #[tokio::test]
    async fn dns_discovery_with_backend_tls_on_http_gets_a_per_backend_client() {
        const CONFIG: &str = r#"
            [[listeners]]
            name = "web"
            protocol = "http"
            listen = "127.0.0.1:0"

              [listeners.dns_discovery]
              name = "backend.svc.cluster.local"
              port = 9001
              server_name = "backend.internal"

              [listeners.backend_tls]
              danger_accept_invalid_certs = true

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
        "#;
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None).unwrap();

        match &app.listeners[0] {
            ListenerRuntime::Http { ctx, .. } => {
                assert!(ctx.per_backend_client.is_some());
            }
            _ => panic!("expected an http listener"),
        }

        for task in app.background_tasks {
            task.abort();
        }
    }

    /// A static `backend_tls` listener (no `dns_discovery`) already gives
    /// each backend its own distinct `server_name`, so it never needs the
    /// per-backend client path -- confirming the new branch in `build_app`
    /// stays off for the case it was never meant to touch.
    #[tokio::test]
    async fn a_static_backend_tls_listener_has_no_per_backend_client() {
        const CONFIG: &str = r#"
            [[listeners]]
            name = "web"
            protocol = "http"
            listen = "127.0.0.1:0"

              [listeners.backend_tls]
              danger_accept_invalid_certs = true

              [[listeners.backends]]
              id = "b1"
              address = "127.0.0.1:9001"
              server_name = "b1.internal"

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
        "#;
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None).unwrap();

        match &app.listeners[0] {
            ListenerRuntime::Http { ctx, .. } => {
                assert!(ctx.per_backend_client.is_none());
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
