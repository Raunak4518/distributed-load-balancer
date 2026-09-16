use arc_swap::ArcSwap;
use lb_balancer::{ConsistentHash, LeastConnections, PeakEwmaP2c, RoundRobin, WeightedRoundRobin};
use lb_cluster::{ClusterNode, ListenerCoordinator};
use lb_core::ClusterCoordinator;
use lb_core::{
    Backend, BackendId, BackendPool, ClusterConfig, Config, HealthCheckConfig, Http2Config,
    ListenerConfig, LoadBalancer, LoadBalancingStrategy, LoggingConfig, Protocol, SystemClock,
};
use lb_healthcheck::{
    spawn_active_checker, spawn_outlier_detector, ActiveCheckConfig, CircuitBreaker, HttpProbe,
    OutlierConfig, OutlierDetector, TcpConnectProbe,
};
use lb_metrics::Metrics;
use lb_proxy::{spawn_cache_sweeper, CompiledRoute, ProxyContext, ResponseCache, StickyRuntime};
use lb_ratelimit::{spawn_sweeper, Gcra, GcraConfig};
use lb_tcp::TcpContext;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub type HttpContext = ProxyContext<Gcra<SystemClock>, SystemClock>;
pub type TcpAppContext = TcpContext<Gcra<SystemClock>, SystemClock>;
pub type AppClusterNode = ClusterNode<SystemClock>;

/// Builds the operator-chosen balancer for one listener. A `match` rather
/// than a registry: this is a closed set the same way `Protocol` is, and
/// every arm just needs a `Default`-ish constructor -- no per-strategy
/// config to thread through yet.
fn build_balancer(strategy: &LoadBalancingStrategy) -> Arc<dyn LoadBalancer> {
    match strategy {
        LoadBalancingStrategy::RoundRobin => Arc::new(RoundRobin::new()),
        LoadBalancingStrategy::LeastConnections => Arc::new(LeastConnections::new()),
        LoadBalancingStrategy::WeightedRoundRobin => Arc::new(WeightedRoundRobin::new()),
        LoadBalancingStrategy::ConsistentHash => Arc::new(ConsistentHash::new()),
        LoadBalancingStrategy::PeakEwmaP2c => Arc::new(PeakEwmaP2c::new(SystemClock)),
    }
}

/// One configured listener, ready to accept. An enum rather than a trait:
/// this is a genuinely closed set, and `serve_listener` must match on it
/// exhaustively to know which protocol driver to run.
///
/// `ctx` is behind an `ArcSwap`, not a plain `Arc`, so that config hot-reload
/// (`reload::apply_reload`) can replace it atomically while connections are
/// in flight: each newly accepted connection reads whatever is current at
/// the moment it starts (`drive`, in `lib.rs`, loads fresh per connection),
/// while a connection already running keeps whichever snapshot it loaded.
/// Nothing else on this enum is reloadable -- `tls`, `http2`, and `limits`
/// require a restart to change; see `reload`'s module docs for why.
pub enum ListenerRuntime {
    Http {
        name: String,
        listen: SocketAddr,
        ctx: Arc<ArcSwap<HttpContext>>,
        limits: ConnectionLimits,
        metrics: Arc<lb_metrics::ListenerMetrics>,
        header_read_timeout: Duration,
        write_timeout: Duration,
        /// Whether this listener expects a PROXY protocol header ahead of
        /// everything else on the connection -- see `proxy_protocol`'s
        /// module docs for the trust model this implies.
        proxy_protocol: bool,
        /// Whether responses get gzip/brotli/deflate/zstd compression --
        /// see `compression`'s module docs.
        compression: bool,
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
        /// See `lb_core::TcpKeepaliveConfig`. Restart-only, same as `tls`/
        /// `http2` above -- applied once, in `spawn_connection`, to the
        /// freshly accepted socket.
        client_tcp_keepalive: Option<lb_core::TcpKeepaliveConfig>,
    },
    Tcp {
        name: String,
        listen: SocketAddr,
        ctx: Arc<ArcSwap<TcpAppContext>>,
        limits: ConnectionLimits,
        metrics: Arc<lb_metrics::ListenerMetrics>,
        proxy_protocol: bool,
        tls: Option<Arc<lb_tls::TlsAcceptor>>,
        client_tcp_keepalive: Option<lb_core::TcpKeepaliveConfig>,
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

    pub fn proxy_protocol(&self) -> bool {
        match self {
            ListenerRuntime::Http { proxy_protocol, .. }
            | ListenerRuntime::Tcp { proxy_protocol, .. } => *proxy_protocol,
        }
    }

    pub fn client_tcp_keepalive(&self) -> Option<&lb_core::TcpKeepaliveConfig> {
        match self {
            ListenerRuntime::Http {
                client_tcp_keepalive,
                ..
            }
            | ListenerRuntime::Tcp {
                client_tcp_keepalive,
                ..
            } => client_tcp_keepalive.as_ref(),
        }
    }

    /// Always `false` for a TCP listener: HTTP/2's `http2()` accessor above
    /// follows the same shape, for the same reason -- there is no response
    /// to compress at L4.
    pub fn compression(&self) -> bool {
        match self {
            ListenerRuntime::Http { compression, .. } => *compression,
            ListenerRuntime::Tcp { .. } => false,
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
    /// TLS cert-reload tasks only — see `WiredApp::reload` for why they are
    /// kept apart from everything else: config hot-reload never touches
    /// them, so they are never candidates for the abort-and-respawn dance
    /// `reload::apply_reload` does to the tasks in `reload.tasks`.
    pub tls_reload_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub drain_timeout: Duration,
    /// Present only when `[cluster]` is configured.
    pub cluster: Option<ClusterSetup>,
    /// Always collected; `admin_listen` controls whether it is exposed.
    pub metrics: Arc<Metrics>,
    pub admin_listen: Option<SocketAddr>,
    /// Every listener's pool, for the readiness check.
    pub pools: Vec<Arc<BackendPool>>,
    /// Everything `reload::apply_reload` needs to reach a running listener's
    /// swappable context and replace its health-checker/DNS-poller/sweeper
    /// tasks. Kept on `WiredApp` (built once, alongside everything else)
    /// rather than reconstructed later, so a listener's `ArcSwap` here is
    /// *the same* `Arc` `ListenerRuntime::ctx` holds -- a store into one is
    /// visible through the other, which is the entire mechanism. `Arc`-
    /// wrapped so `run` can hand a clone to the SIGHUP task independently of
    /// its own use of it (draining tasks at shutdown).
    pub reload: Arc<ReloadState>,
}

/// The subset of build state a config reload needs, later, to touch a
/// *running* listener without rebuilding everything from scratch. See
/// `reload::apply_reload`.
pub struct ReloadState {
    pub metrics: Arc<Metrics>,
    pub acme_challenges: Arc<lb_tls::AcmeChallengeStore>,
    pub cluster_node: Option<Arc<AppClusterNode>>,
    pub listeners: HashMap<String, ListenerReloadHandle>,
    /// This listener's health checkers, DNS poller, and rate-limit sweeper —
    /// the tasks a ctx rebuild makes stale, since they check/resolve/sweep
    /// against the *old* pool and rate limiter. Replaced as a whole on
    /// reload: the old set is aborted, a fresh set spawned against the new
    /// ctx, under one lock so nothing observes a listener with neither set
    /// running. Never contains the TLS cert-reload task -- see
    /// `WiredApp::tls_reload_tasks`.
    pub tasks: Arc<tokio::sync::Mutex<HashMap<String, Vec<tokio::task::JoinHandle<()>>>>>,
    /// The config as of the last successful reload (or the one `build_app`
    /// was called with, before the first). What the *next* reload diffs
    /// against -- not the original startup config forever, and not
    /// re-derived from `ListenerRuntime`, which no longer carries most of
    /// a `ListenerConfig`'s fields once built.
    pub config: tokio::sync::Mutex<Config>,
}

/// One listener's swappable context, keyed by name in `ReloadState.listeners`
/// so the reload path can reach it without holding (or matching on) the
/// whole `ListenerRuntime` enum. Always the *same* `Arc<ArcSwap<_>>` that
/// listener's `ListenerRuntime::ctx` holds — cloned, not a second one — so a
/// `store` here is a store there too.
#[derive(Clone)]
pub enum ListenerReloadHandle {
    Http(Arc<ArcSwap<HttpContext>>),
    Tcp(Arc<ArcSwap<TcpAppContext>>),
}

/// Everything `run` needs to start peer coordination, kept separate from the
/// per-listener wiring so binding can happen alongside the traffic listeners.
pub struct ClusterSetup {
    pub node: Arc<AppClusterNode>,
    pub listen: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub sync_interval: Duration,
    /// `None` keeps the peer channel HMAC-authenticated but unencrypted, as
    /// it always was before `[cluster.tls]` existed.
    pub peer_tls: Option<Arc<lb_tls::PeerTls>>,
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
    let mut tls_reload_tasks = Vec::new();
    let mut pools = Vec::with_capacity(config.listeners.len());
    let mut reload_listeners = HashMap::with_capacity(config.listeners.len());
    let mut reload_tasks = HashMap::with_capacity(config.listeners.len());

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
    let acme_challenges = Arc::new(lb_tls::AcmeChallengeStore::new());

    // Built here for the same reason as the acceptors above: an unreadable
    // `ca_file` is operator input, and must fail startup rather than turn
    // every backend request into a verification error. One connector per
    // listener, so the same trust roots and verification policy serve both
    // the L7 client and the L4 transport built from it below.
    let mut backend_connectors = Vec::with_capacity(config.listeners.len());
    for lc in &config.listeners {
        backend_connectors.push(build_backend_connector(lc, &metrics)?);
    }

    // One cluster node per process, shared by every listener. Not reloadable
    // (`reload::apply_reload` refuses a reload that would change `[cluster]`),
    // so this is the one and only place it is ever constructed.
    let cluster_node = match (config.cluster.as_ref(), cluster_secret) {
        (Some(c), Some(secret)) => Some(Arc::new(ClusterNode::new(
            c.node_id.clone(),
            c.window_secs,
            SystemClock,
            secret,
        ))),
        _ => None,
    };

    // Built alongside every other TLS acceptor/connector above, for the same
    // reason: a bad peer certificate should fail startup outright, before
    // anything binds, not surface once the sync loop is already running.
    let peer_tls = match config.cluster.as_ref().and_then(|c| c.tls.as_ref()) {
        Some(cfg) => Some(Arc::new(lb_tls::PeerTls::new(cfg).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cluster could not load its peer TLS material: {err}"),
            )
        })?)),
        None => None,
    };

    for ((lc, tls), backend_tls) in config
        .listeners
        .iter()
        .zip(tls_acceptors)
        .zip(backend_connectors)
    {
        let core = build_listener_core(
            lc,
            backend_tls,
            cluster_node.as_ref(),
            config.cluster.as_ref(),
            &config.logging,
            &metrics,
            &acme_challenges,
            None,
        );
        pools.push(Arc::clone(&core.pool));
        for route in &core.routes {
            pools.push(Arc::clone(&route.pool));
        }
        for pool in &core.canary {
            pools.push(Arc::clone(&pool.pool));
        }
        let tasks = spawn_listener_tasks(lc, &core, &metrics);
        reload_tasks.insert(lc.name.clone(), tasks);

        let listener_metrics = Arc::new(metrics.listener(&lc.name));
        let connection_limits = ConnectionLimits {
            global: Arc::new(tokio::sync::Semaphore::new(lc.max_connections())),
            per_ip: Arc::new(crate::limits::PerIpLimiter::new(
                lc.max_connections_per_ip(),
            )),
        };

        // Certificates expire on a fixed schedule (90 days under ACME), so a
        // TLS listener without a reload loop is an outage generator on a
        // timer. Kept apart from `reload_tasks`: config hot-reload never
        // touches TLS (see `reload`'s module docs), so this must never be
        // among the tasks a ctx reload aborts and respawns.
        if let (Some(acceptor), Some(tls_cfg)) = (tls.as_ref(), lc.tls.as_ref()) {
            tls_reload_tasks.push(lb_tls::spawn_reloader(
                lc.name.clone(),
                tls_cfg.certificates.clone(),
                Arc::clone(acceptor.resolver()),
                tls_cfg.reload_interval(),
                Arc::clone(&listener_metrics),
            ));
            for cert in &tls_cfg.certificates {
                if let Some(acme) = &cert.acme {
                    tls_reload_tasks.push(lb_tls::spawn_acme_renewer(
                        acme.directory_url.clone(),
                        acme.contact_email.clone(),
                        acme.account_key_file.clone(),
                        cert.hostnames[0].clone(),
                        cert.cert_file.clone(),
                        cert.key_file.clone(),
                        Duration::from_secs(acme.renew_before_days as u64 * 86_400),
                        Duration::from_secs(acme.check_interval_secs),
                        acme.ca_bundle_file.clone(),
                        lb_tls::AcmeRetryPolicy {
                            fallback_directory_url: acme.fallback_directory_url.clone(),
                            staging_directory_url: acme.staging_directory_url.clone(),
                            ..Default::default()
                        },
                        Arc::clone(&acme_challenges),
                    ));
                }
            }
        }

        let runtime = match core.kind {
            ListenerCoreKind::Http(ctx) => {
                let ctx = Arc::new(ArcSwap::from_pointee(*ctx));
                reload_listeners.insert(
                    lc.name.clone(),
                    ListenerReloadHandle::Http(Arc::clone(&ctx)),
                );
                ListenerRuntime::Http {
                    name: lc.name.clone(),
                    listen: lc.listen,
                    ctx,
                    limits: connection_limits,
                    metrics: Arc::clone(&listener_metrics),
                    header_read_timeout: lc.header_read_timeout(),
                    write_timeout: lc.write_timeout(),
                    proxy_protocol: lc.proxy_protocol,
                    compression: lc.compression,
                    tls,
                    // Built from the same `http2_enabled()` the TLS acceptor's
                    // ALPN list is chosen from, so the two cannot drift apart.
                    // The `unwrap_or_default` is load-bearing rather than
                    // defensive: `http2_enabled()` is true for a TLS listener
                    // with no `[listeners.http2]` section at all -- the common
                    // case -- and that listener still advertises `h2` and so
                    // still needs settings to serve it under.
                    http2: lc
                        .http2_enabled()
                        .then(|| Arc::new(lc.http2.clone().unwrap_or_default())),
                    client_tcp_keepalive: lc.client_tcp_keepalive.clone(),
                }
            }
            ListenerCoreKind::Tcp(ctx) => {
                let ctx = Arc::new(ArcSwap::from_pointee(*ctx));
                reload_listeners
                    .insert(lc.name.clone(), ListenerReloadHandle::Tcp(Arc::clone(&ctx)));
                ListenerRuntime::Tcp {
                    name: lc.name.clone(),
                    listen: lc.listen,
                    ctx,
                    limits: connection_limits,
                    metrics: Arc::clone(&listener_metrics),
                    proxy_protocol: lc.proxy_protocol,
                    tls,
                    client_tcp_keepalive: lc.client_tcp_keepalive.clone(),
                }
            }
        };
        listeners.push(runtime);
    }

    let cluster = match (&cluster_node, config.cluster.as_ref()) {
        (Some(node), Some(cc)) => Some(ClusterSetup {
            node: Arc::clone(node),
            listen: cc.listen,
            peers: cc.peers.clone(),
            sync_interval: cc.sync_interval(),
            peer_tls: peer_tls.clone(),
        }),
        _ => None,
    };

    Ok(WiredApp {
        listeners,
        tls_reload_tasks,
        drain_timeout: Duration::from_millis(config.server.drain_timeout_ms),
        cluster,
        metrics: Arc::clone(&metrics),
        admin_listen: config.admin.as_ref().map(|a| a.listen),
        pools,
        reload: Arc::new(ReloadState {
            metrics,
            acme_challenges,
            cluster_node,
            listeners: reload_listeners,
            tasks: Arc::new(tokio::sync::Mutex::new(reload_tasks)),
            config: tokio::sync::Mutex::new(config.clone()),
        }),
    })
}

/// One listener's fully-built runtime pieces, minus everything that never
/// changes on a config reload (`tls`, `http2`, `limits`, its name/address).
/// Kept separate from `ListenerRuntime` so `reload::apply_reload` can build
/// exactly this — and nothing else — for a listener whose config changed,
/// without touching the parts that require a restart to change at all.
pub(crate) struct ListenerCore {
    pub(crate) backends: Vec<Backend>,
    pub(crate) pool: Arc<BackendPool>,
    /// `Some` exactly when `lc.health_check.outlier_detection` is set --
    /// the same instance already living inside `kind`'s `ProxyContext`/
    /// `TcpContext`, kept here too so `spawn_listener_tasks` can spawn its
    /// periodic recompute task without reaching into `kind`.
    pub(crate) outlier: Option<Arc<OutlierDetector>>,
    pub(crate) kind: ListenerCoreKind,
    /// One entry per `[[listeners.routes]]` rule, in declaration order --
    /// always empty for a TCP listener (routes are HTTP-only, rejected at
    /// config validation for `Protocol::Tcp`). Kept alongside the default
    /// `backends`/`pool` above so `spawn_listener_tasks` can spawn health
    /// checkers for every route's backends the same way it does for the
    /// default set, and so `build_app` can add every route's pool to the
    /// readiness check.
    pub(crate) routes: Vec<RoutePool>,
    /// One entry per `[[listeners.canary]]` pool, in declaration order --
    /// always empty for a TCP listener (canary is HTTP-only, rejected at
    /// config validation for `Protocol::Tcp`). Same role as `routes` above:
    /// lets `spawn_listener_tasks` spawn each pool's own health checkers and
    /// `build_app` add each pool to the readiness check.
    pub(crate) canary: Vec<CanaryPool>,
}

/// One `[[listeners.routes]]` rule's built pool -- see `ListenerCore::routes`.
/// Mirrors `CompiledRoute` (`lb_proxy`), minus the balancer: that is built
/// directly into `ProxyContext::routes` below, since nothing outside the
/// request path ever needs to pick through a route's pool.
pub(crate) struct RoutePool {
    pub(crate) backends: Vec<Backend>,
    pub(crate) pool: Arc<BackendPool>,
    /// See `ListenerCore::outlier` -- this route's own, independent instance.
    pub(crate) outlier: Option<Arc<OutlierDetector>>,
    /// A route's own `health_check`, independent of the listener's default
    /// one -- a route may probe a different path/interval than the backends
    /// it falls back to.
    pub(crate) health_check: HealthCheckConfig,
}

/// One `[[listeners.canary]]` pool's built pool -- see `ListenerCore::canary`.
/// Mirrors `RoutePool` exactly: no `percent` here, for the same reason
/// `RoutePool` carries no `path_prefix`/`host` -- this struct exists only for
/// health-checker spawning and the readiness check, neither of which needs
/// it. `percent` lives on `lb_proxy::CompiledCanaryPool` instead, the only
/// place it's ever consulted (request-time pool selection, and the admin
/// API's label, which reads it from the same live `ProxyContext`).
pub(crate) struct CanaryPool {
    pub(crate) backends: Vec<Backend>,
    pub(crate) pool: Arc<BackendPool>,
    /// See `ListenerCore::outlier` -- this canary pool's own, independent
    /// instance.
    pub(crate) outlier: Option<Arc<OutlierDetector>>,
    pub(crate) health_check: HealthCheckConfig,
}

pub(crate) enum ListenerCoreKind {
    // Both boxed: clippy's `large_enum_variant` is right that leaving either
    // unboxed would size every `ListenerCoreKind` to the bigger of the two.
    Http(Box<HttpContext>),
    Tcp(Box<TcpAppContext>),
}

/// A running listener's live, non-config-derived state, carried across a
/// config reload so that changing one field (a rate limit, a WAF mode) does
/// not also hand every backend a clean bill of health -- an operator's
/// manual drain and a breaker mid-cooldown are not things `build_app`'s
/// startup path has any state for, but `apply_reload` does.
pub(crate) struct PreviousListenerState {
    manually_drained: HashSet<BackendId>,
    circuit_breakers: HashMap<BackendId, lb_healthcheck::CircuitBreakerSnapshot>,
}

impl PreviousListenerState {
    pub(crate) fn from_http(ctx: &HttpContext) -> Self {
        let mut manually_drained = HashSet::new();
        Self::collect_drained(&ctx.pool, &mut manually_drained);
        for route in &ctx.routes {
            Self::collect_drained(&route.pool, &mut manually_drained);
        }
        for canary in &ctx.canary {
            Self::collect_drained(&canary.pool, &mut manually_drained);
        }
        PreviousListenerState {
            manually_drained,
            circuit_breakers: Self::snapshot_breakers(&ctx.circuit_breakers),
        }
    }

    pub(crate) fn from_tcp(ctx: &TcpAppContext) -> Self {
        let mut manually_drained = HashSet::new();
        Self::collect_drained(&ctx.pool, &mut manually_drained);
        PreviousListenerState {
            manually_drained,
            circuit_breakers: Self::snapshot_breakers(&ctx.circuit_breakers),
        }
    }

    fn collect_drained(pool: &BackendPool, into: &mut HashSet<BackendId>) {
        for id in pool.all_backend_ids() {
            if pool.is_manually_drained(&id) {
                into.insert(id);
            }
        }
    }

    fn snapshot_breakers(
        breakers: &HashMap<BackendId, CircuitBreaker<SystemClock>>,
    ) -> HashMap<BackendId, lb_healthcheck::CircuitBreakerSnapshot> {
        breakers
            .iter()
            .map(|(id, cb)| (id.clone(), cb.snapshot()))
            .collect()
    }

    fn is_drained(&self, id: &BackendId) -> bool {
        self.manually_drained.contains(id)
    }

    fn breaker_snapshot(&self, id: &BackendId) -> Option<lb_healthcheck::CircuitBreakerSnapshot> {
        self.circuit_breakers.get(id).copied()
    }
}

fn seed_drained(
    pool: &BackendPool,
    backends: &[Backend],
    previous: Option<&PreviousListenerState>,
) {
    let Some(previous) = previous else {
        return;
    };
    for b in backends {
        if previous.is_drained(&b.id) {
            pool.set_manually_drained(&b.id, true);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn new_or_migrated_breaker(
    previous: Option<&PreviousListenerState>,
    id: &BackendId,
    failure_threshold: u32,
    cooldown: Duration,
    half_open_successes_required: u32,
    flap_backoff_multiplier: f64,
    max_flap_cooldown: Duration,
    flap_streak_reset: Duration,
    unhealthy_latency: Option<Duration>,
    unhealthy_request_count: Option<usize>,
) -> CircuitBreaker<SystemClock> {
    match previous.and_then(|p| p.breaker_snapshot(id)) {
        Some(snapshot) => CircuitBreaker::from_snapshot(
            failure_threshold,
            cooldown,
            half_open_successes_required,
            flap_backoff_multiplier,
            max_flap_cooldown,
            flap_streak_reset,
            unhealthy_latency,
            unhealthy_request_count,
            SystemClock,
            snapshot,
        ),
        None => CircuitBreaker::new(
            failure_threshold,
            cooldown,
            half_open_successes_required,
            flap_backoff_multiplier,
            max_flap_cooldown,
            flap_streak_reset,
            unhealthy_latency,
            unhealthy_request_count,
            SystemClock,
        ),
    }
}

/// `None` when `health_check.outlier_detection` is unset (the default) --
/// the ordinary case, costing nothing beyond this one check.
///
/// `eject_ticks` is derived from the *existing* `cooldown_ms`/`interval_ms`
/// (rounded up, floored at 1 recompute round) rather than a new config
/// field: an ejected backend staying out for roughly the same duration the
/// circuit breaker's own cooldown already uses is the least surprising
/// default, and it keeps outlier detection's entire config surface to the
/// one `[listeners.health_check.outlier_detection]` section.
fn build_outlier_detector(
    backends: &[Backend],
    health_check: &HealthCheckConfig,
) -> Option<Arc<OutlierDetector>> {
    let od = health_check.outlier_detection.as_ref()?;
    let eject_ticks = health_check
        .cooldown_ms
        .div_ceil(health_check.interval_ms.max(1))
        .max(1) as u32;
    Some(Arc::new(OutlierDetector::new(
        backends.iter().map(|b| b.id.clone()),
        OutlierConfig {
            min_volume: od.min_volume,
            min_hosts: od.min_hosts,
            stddev_factor: od.stddev_factor,
            eject_ticks,
        },
    )))
}

/// Builds one listener's pool, rate limiter, circuit breakers, and
/// protocol-specific context. Infallible: the one fallible step for a
/// listener (`build_backend_connector`, real file I/O) has already happened
/// by the time this is called, both at startup (`build_app`, above) and on
/// reload (`reload::apply_reload`, which must resolve every changed
/// listener's connector *before* rebuilding or swapping in any of them — see
/// its module docs for why that ordering is load-bearing).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_listener_core(
    lc: &ListenerConfig,
    backend_tls: Option<Arc<lb_tls::BackendConnector>>,
    cluster_node: Option<&Arc<AppClusterNode>>,
    cluster_cfg: Option<&ClusterConfig>,
    logging: &LoggingConfig,
    metrics: &Metrics,
    acme_challenges: &Arc<lb_tls::AcmeChallengeStore>,
    previous: Option<&PreviousListenerState>,
) -> ListenerCore {
    let backends: Vec<Backend> = lc
        .backends
        .iter()
        .map(|b| Backend::new(b.id.clone(), b.address, b.weight, b.server_name.clone()))
        .collect();
    let pool = Arc::new(BackendPool::with_max_ejected_fraction(
        backends.clone(),
        lc.health_check.max_ejected_fraction,
    ));
    seed_drained(&pool, &backends, previous);
    let outlier = build_outlier_detector(&backends, &lc.health_check);

    // Built once per route, the same way the default `backends`/`pool` above
    // are -- `Config::validate()` already guarantees every id here is unique
    // across the default backends and every route's, so the flat
    // `circuit_breakers`/`backend_metrics` maps built below stay correct with
    // no per-pool scoping key.
    #[allow(clippy::type_complexity)]
    let route_pools: Vec<(
        &lb_core::RouteConfig,
        Vec<Backend>,
        Arc<BackendPool>,
        Option<Arc<OutlierDetector>>,
    )> = lc
        .routes
        .iter()
        .map(|r| {
            let route_backends: Vec<Backend> = r
                .backends
                .iter()
                .map(|b| Backend::new(b.id.clone(), b.address, b.weight, b.server_name.clone()))
                .collect();
            let route_pool = Arc::new(BackendPool::with_max_ejected_fraction(
                route_backends.clone(),
                r.health_check.max_ejected_fraction,
            ));
            seed_drained(&route_pool, &route_backends, previous);
            let route_outlier = build_outlier_detector(&route_backends, &r.health_check);
            (r, route_backends, route_pool, route_outlier)
        })
        .collect();
    // Same construction as `route_pools` above, for `[[listeners.canary]]`.
    #[allow(clippy::type_complexity)]
    let canary_pools: Vec<(
        &lb_core::CanaryPoolConfig,
        Vec<Backend>,
        Arc<BackendPool>,
        Option<Arc<OutlierDetector>>,
    )> = lc
        .canary
        .iter()
        .map(|c| {
            let canary_backends: Vec<Backend> = c
                .backends
                .iter()
                .map(|b| Backend::new(b.id.clone(), b.address, b.weight, b.server_name.clone()))
                .collect();
            let canary_pool = Arc::new(BackendPool::with_max_ejected_fraction(
                canary_backends.clone(),
                c.health_check.max_ejected_fraction,
            ));
            seed_drained(&canary_pool, &canary_backends, previous);
            let canary_outlier = build_outlier_detector(&canary_backends, &c.health_check);
            (c, canary_backends, canary_pool, canary_outlier)
        })
        .collect();
    let all_backends = || {
        backends
            .iter()
            .chain(route_pools.iter().flat_map(|(_, bs, _, _)| bs.iter()))
            .chain(canary_pools.iter().flat_map(|(_, bs, _, _)| bs.iter()))
    };

    // Pins the L7 forwarding client's TCP dial to each backend's configured
    // `address`, even though the forwarding authority is that backend's
    // `server_name` (chosen so SNI and hostname verification check the
    // certificate's own name). Without this table, a `backend_tls` listener's
    // connector would resolve `server_name` via real DNS to find something to
    // dial -- silently reintroducing DNS-based backend resolution and letting
    // traffic follow whatever that name resolves to instead of the pinned
    // backend. Built for every listener, not only `backend_tls` ones: a
    // plaintext listener's requests carry an IP-literal authority, so the
    // table is simply never consulted there. See
    // `lb_proxy::resolver::PinnedResolver`.
    let server_name_addresses: HashMap<String, SocketAddr> = all_backends()
        .filter_map(|b| b.server_name.clone().map(|name| (name, b.address)))
        .collect();

    let listener_metrics = Arc::new(metrics.listener(&lc.name));
    let backend_metrics: HashMap<_, _> = all_backends()
        .map(|b| (b.id.clone(), metrics.backend(&lc.name, &b.id.0)))
        .collect();

    // Each route's own `health_check.failure_threshold`/`cooldown_ms` governs
    // its own backends' breakers; the default backends keep using the
    // listener's own `health_check` as they always have.
    let mut circuit_breakers = HashMap::new();
    for b in &backends {
        circuit_breakers.insert(
            b.id.clone(),
            new_or_migrated_breaker(
                previous,
                &b.id,
                lc.health_check.failure_threshold,
                Duration::from_millis(lc.health_check.cooldown_ms),
                lc.health_check.half_open_successes_required,
                lc.health_check.flap_backoff_multiplier,
                Duration::from_millis(lc.health_check.max_flap_cooldown_ms),
                Duration::from_millis(lc.health_check.flap_streak_reset_ms),
                lc.health_check
                    .unhealthy_latency_ms
                    .map(Duration::from_millis),
                lc.health_check.unhealthy_request_count,
            ),
        );
    }
    for (route, route_backends, _, _) in &route_pools {
        for b in route_backends {
            circuit_breakers.insert(
                b.id.clone(),
                new_or_migrated_breaker(
                    previous,
                    &b.id,
                    route.health_check.failure_threshold,
                    Duration::from_millis(route.health_check.cooldown_ms),
                    route.health_check.half_open_successes_required,
                    route.health_check.flap_backoff_multiplier,
                    Duration::from_millis(route.health_check.max_flap_cooldown_ms),
                    Duration::from_millis(route.health_check.flap_streak_reset_ms),
                    route
                        .health_check
                        .unhealthy_latency_ms
                        .map(Duration::from_millis),
                    route.health_check.unhealthy_request_count,
                ),
            );
        }
    }
    for (canary, canary_backends, _, _) in &canary_pools {
        for b in canary_backends {
            circuit_breakers.insert(
                b.id.clone(),
                new_or_migrated_breaker(
                    previous,
                    &b.id,
                    canary.health_check.failure_threshold,
                    Duration::from_millis(canary.health_check.cooldown_ms),
                    canary.health_check.half_open_successes_required,
                    canary.health_check.flap_backoff_multiplier,
                    Duration::from_millis(canary.health_check.max_flap_cooldown_ms),
                    Duration::from_millis(canary.health_check.flap_streak_reset_ms),
                    canary
                        .health_check
                        .unhealthy_latency_ms
                        .map(Duration::from_millis),
                    canary.health_check.unhealthy_request_count,
                ),
            );
        }
    }

    let rate_limiter = Arc::new(Gcra::new(
        GcraConfig {
            rate_per_sec: lc.rate_limit.rate_per_sec,
            burst: lc.rate_limit.burst,
            max_tracked_keys: lc.rate_limit.max_tracked_keys,
        },
        SystemClock,
    ));

    // The global cap is the sustained rate over the whole window; the local
    // GCRA continues to shape bursts inside it.
    let cluster_coordinator: Option<Arc<dyn ClusterCoordinator>> = match (cluster_node, cluster_cfg)
    {
        (Some(node), Some(cc)) => {
            let limit = (lc.rate_limit.rate_per_sec * cc.window_secs as f64).ceil() as u64;
            listener_metrics.cluster_convergence_bound.set(
                lb_cluster::convergence_over_admission_bound(
                    lc.rate_limit.rate_per_sec,
                    cc.sync_interval_ms,
                    cc.peers.len(),
                ) as i64,
            );
            Some(Arc::new(ListenerCoordinator::new(
                Arc::clone(node),
                lc.name.clone(),
                limit.max(1),
            )))
        }
        _ => None,
    };

    let kind = match lc.protocol {
        Protocol::Http => {
            // Built exactly once per HTTP listener, and handed to both
            // consumers below (real traffic and its health probe) -- see
            // `spawn_listener_tasks`. **This sharing is the whole mechanism**
            // behind "a probe validates what traffic validates": the probe
            // does not use a client like the data plane's, it uses this one --
            // same connection pool, same trust roots, same verification
            // policy, same pinned resolver. A `Client` is an `Arc`-backed
            // handle, so a clone is the same client, not a copy of one. Two
            // `build_client` calls here would put two TLS stacks in one
            // listener and let them disagree.
            // Prior-knowledge h2c: plaintext backends only, and only when the
            // operator has said so -- a TLS backend negotiates via ALPN
            // regardless (see `lb_proxy::build_client`).
            let backend_h2c = lc.http2.as_ref().map(|h| h.backend_h2c()).unwrap_or(false);
            let client = lb_proxy::build_client(
                backend_tls.as_deref(),
                server_name_addresses,
                backend_h2c,
                lc.backend_tcp_keepalive.as_ref(),
            );
            // A `dns_discovery` + `backend_tls` listener puts several backends
            // behind one `server_name`, which `client` above cannot serve
            // correctly -- see `lb_proxy::per_backend`. Each such backend gets
            // its own client (and so its own connection pool) instead, built
            // lazily as backends are first seen; `client` stays built but
            // unused, its dial-pinning table simply empty.
            let per_backend_client = match (&lc.dns_discovery, &backend_tls) {
                (Some(dns), Some(connector)) => Some(Arc::new(lb_proxy::PerBackendClients::new(
                    dns.server_name
                        .clone()
                        .expect("validated: server_name is required when backend_tls is set"),
                    Arc::clone(connector),
                    backend_h2c,
                    lc.backend_tcp_keepalive.clone(),
                ))),
                _ => None,
            };
            // One `CompiledRoute` per `[[listeners.routes]]` rule, in
            // declaration order -- `handle`'s `resolve_route` walks this
            // `Vec` and falls through to `pool`/`balancer` above when it's
            // empty or nothing matches.
            let compiled_routes: Vec<CompiledRoute> = route_pools
                .iter()
                .map(|(route, _, route_pool, route_outlier)| CompiledRoute {
                    path_prefix: route.path_prefix.clone(),
                    host: route.host.clone(),
                    pool: Arc::clone(route_pool),
                    balancer: build_balancer(&route.load_balancing.strategy),
                    outlier: route_outlier.clone(),
                })
                .collect();
            // One `CompiledCanaryPool` per `[[listeners.canary]]` pool, in
            // declaration order -- `handle`'s `resolve_default_or_canary_pool`
            // walks this `Vec` only for a request that matched no route.
            let compiled_canary: Vec<lb_proxy::CompiledCanaryPool> = canary_pools
                .iter()
                .map(
                    |(canary, _, canary_pool, canary_outlier)| lb_proxy::CompiledCanaryPool {
                        percent: canary.percent,
                        pool: Arc::clone(canary_pool),
                        balancer: build_balancer(&canary.load_balancing.strategy),
                        outlier: canary_outlier.clone(),
                    },
                )
                .collect();
            ListenerCoreKind::Http(Box::new(ProxyContext {
                rate_limiter,
                balancer: build_balancer(&lc.load_balancing.strategy),
                pool: Arc::clone(&pool),
                routes: compiled_routes,
                canary: compiled_canary,
                canary_cursor: std::sync::atomic::AtomicUsize::new(0),
                // Same fact `hsts_max_age_secs` below is gated on -- a
                // sticky cookie routes traffic, so it earns the same
                // `Secure` treatment as HSTS earns its own header.
                sticky: lc.sticky.as_ref().map(|s| StickyRuntime {
                    cookie_name: s.cookie_name.clone(),
                    max_age_secs: s.max_age_secs,
                    secure: lc.tls.is_some(),
                }),
                cache: lc.cache.as_ref().map(|c| {
                    Arc::new(ResponseCache::new(
                        c.max_entry_bytes,
                        c.max_total_bytes,
                        Duration::from_secs(c.default_ttl_secs),
                        SystemClock,
                    ))
                }),
                waf: lc.waf.as_ref().map(|w| w.mode),
                waf_inspect_headers: lc.waf.as_ref().is_some_and(|w| w.inspect_headers),
                circuit_breakers,
                outlier: outlier.clone(),
                acme_challenges: Some(Arc::clone(acme_challenges)),
                client,
                per_backend_client,
                backend_tls: backend_tls.is_some(),
                backend_tls_connector: backend_tls.clone(),
                rate_limit_key: lc.rate_limit.key.clone(),
                forward_timeout: lc.forward_timeout(),
                max_request_body_bytes: lc.max_request_body_bytes(),
                websocket_idle_timeout: lc.websocket_idle_timeout(),
                backend_tcp_keepalive: lc.backend_tcp_keepalive.clone(),
                cluster: cluster_coordinator,
                metrics: listener_metrics,
                backend_metrics,
                access_log: lb_proxy::AccessLog::new(logging.log_requests, logging.sample_rate),
                body_read_timeout: lc.body_read_timeout(),
                // Both gating conditions collapse into this one `Option`
                // here, at the one place that knows both facts: whether this
                // listener terminates TLS at all (`lc.tls`) and whether HSTS
                // was actually turned on (`hsts_max_age_secs() > 0`, since 0
                // is the default and must stay a no-op, not `max-age=0`).
                // `handle` downstream cannot see either fact for itself.
                hsts_max_age_secs: lc
                    .tls
                    .as_ref()
                    .map(|t| t.hsts_max_age_secs())
                    .filter(|&v| v > 0),
            }))
        }
        Protocol::Tcp => {
            // The one place the L4 data plane's re-encryption is chosen.
            // `lb-tcp` sees a trait object and never learns which TLS
            // implementation is behind it -- and, for the same reason as the
            // HTTP client above, the probe is handed this same `Arc` rather
            // than a second transport built from the same config.
            let outbound: Option<Arc<dyn lb_core::OutboundTransport>> = backend_tls.map(|c| {
                Arc::new(lb_tls::BackendTlsTransport::new(&c))
                    as Arc<dyn lb_core::OutboundTransport>
            });
            ListenerCoreKind::Tcp(Box::new(TcpContext {
                rate_limiter,
                balancer: build_balancer(&lc.load_balancing.strategy),
                pool: Arc::clone(&pool),
                circuit_breakers,
                outlier: outlier.clone(),
                connect_timeout: lc.connect_timeout(),
                idle_timeout: lc.idle_timeout(),
                backend_tls: outbound,
                backend_tcp_keepalive: lc.backend_tcp_keepalive.clone(),
                cluster: cluster_coordinator,
                metrics: listener_metrics,
                backend_metrics,
            }))
        }
    };

    let routes: Vec<RoutePool> = route_pools
        .into_iter()
        .map(|(route, backends, pool, outlier)| RoutePool {
            backends,
            pool,
            outlier,
            health_check: route.health_check.clone(),
        })
        .collect();
    let canary: Vec<CanaryPool> = canary_pools
        .into_iter()
        .map(|(canary, backends, pool, outlier)| CanaryPool {
            backends,
            pool,
            outlier,
            health_check: canary.health_check.clone(),
        })
        .collect();

    ListenerCore {
        backends,
        pool,
        outlier,
        kind,
        routes,
        canary,
    }
}

/// Spawns one listener's health checkers, DNS poller (if `dns_discovery` is
/// set), and rate-limit sweeper — everything a ctx rebuild makes stale,
/// since they check/resolve/sweep against the *old* pool and rate limiter.
/// Never the TLS cert-reload task; see `WiredApp::tls_reload_tasks`.
pub(crate) fn spawn_listener_tasks(
    lc: &ListenerConfig,
    core: &ListenerCore,
    metrics: &Arc<Metrics>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = Vec::new();

    match &core.kind {
        ListenerCoreKind::Http(ctx) => {
            tasks.push(spawn_sweeper(
                ctx.rate_limiter.clone(),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ));
            if let Some(cache) = &ctx.cache {
                tasks.push(spawn_cache_sweeper(
                    Arc::clone(cache),
                    Duration::from_secs(30),
                ));
            }
            let probe_client: Arc<dyn lb_core::ProbeClient> = match &ctx.per_backend_client {
                Some(per_backend) => Arc::clone(per_backend) as Arc<dyn lb_core::ProbeClient>,
                None => Arc::new(lb_proxy::ProbeCapableClient(ctx.client.clone())),
            };
            let transport = ProbeTransport::Http {
                client: probe_client,
                backend_tls: ctx.backend_tls,
            };
            if let Some(dns) = &lc.dns_discovery {
                tasks.push(crate::dns::spawn_dns_poller(
                    crate::dns::TokioResolver,
                    dns.clone(),
                    Arc::clone(&core.pool),
                    lc.name.clone(),
                    ctx.per_backend_client.clone(),
                    lc.health_check.clone(),
                    transport.clone(),
                    Arc::clone(metrics),
                ));
            }
            spawn_health_checkers(
                &lc.name,
                &lc.health_check,
                &core.backends,
                &core.pool,
                &mut tasks,
                metrics,
                &transport,
                core.outlier.as_ref(),
            );
            // Every `[[listeners.routes]]` rule gets the same probe
            // transport as the default backends above (same client, same
            // trust roots -- routes share the listener's TLS/client policy),
            // but its own `health_check` settings.
            for route in &core.routes {
                spawn_health_checkers(
                    &lc.name,
                    &route.health_check,
                    &route.backends,
                    &route.pool,
                    &mut tasks,
                    metrics,
                    &transport,
                    route.outlier.as_ref(),
                );
            }
            // Same reasoning as routes above, for `[[listeners.canary]]`.
            for canary in &core.canary {
                spawn_health_checkers(
                    &lc.name,
                    &canary.health_check,
                    &canary.backends,
                    &canary.pool,
                    &mut tasks,
                    metrics,
                    &transport,
                    canary.outlier.as_ref(),
                );
            }
        }
        ListenerCoreKind::Tcp(ctx) => {
            tasks.push(spawn_sweeper(
                ctx.rate_limiter.clone(),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ));
            let transport = ProbeTransport::Tcp(ctx.backend_tls.clone());
            if let Some(dns) = &lc.dns_discovery {
                tasks.push(crate::dns::spawn_dns_poller(
                    crate::dns::TokioResolver,
                    dns.clone(),
                    Arc::clone(&core.pool),
                    lc.name.clone(),
                    None,
                    lc.health_check.clone(),
                    transport.clone(),
                    Arc::clone(metrics),
                ));
            }
            spawn_health_checkers(
                &lc.name,
                &lc.health_check,
                &core.backends,
                &core.pool,
                &mut tasks,
                metrics,
                &transport,
                core.outlier.as_ref(),
            );
        }
    }

    tasks
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
    for cert in &tls_cfg.certificates {
        if cert.acme.is_some() {
            lb_tls::ensure_bootstrap_certificate(
                &cert.cert_file,
                &cert.key_file,
                &cert.hostnames[0],
            )
            .map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "listener '{}' could not write a bootstrap certificate for '{}': {err}",
                        lc.name, cert.name
                    ),
                )
            })?;
        }
    }
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
pub(crate) fn build_backend_connector(
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
#[derive(Clone)]
pub(crate) enum ProbeTransport {
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
#[allow(clippy::too_many_arguments)]
fn spawn_health_checkers(
    listener_name: &str,
    health_check: &HealthCheckConfig,
    backends: &[Backend],
    pool: &Arc<BackendPool>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    metrics: &Metrics,
    transport: &ProbeTransport,
    outlier: Option<&Arc<OutlierDetector>>,
) {
    let interval = Duration::from_millis(health_check.interval_ms);
    let timeout = Duration::from_millis(health_check.timeout_ms);

    // Same cadence as the per-backend probes above, not a new operator-
    // facing timer -- see `spawn_outlier_detector`'s own docs for why a
    // pool-wide computation cannot just reuse one backend's own tick.
    if let Some(detector) = outlier {
        tasks.push(spawn_outlier_detector(
            Arc::clone(pool),
            Arc::clone(detector),
            interval,
        ));
    }

    for b in backends {
        let config = ActiveCheckConfig {
            interval,
            healthy_gauge: Some(metrics.backend(listener_name, &b.id.0).healthy),
        };
        match transport {
            ProbeTransport::Http {
                client,
                backend_tls,
            } => {
                let path = health_check
                    .path
                    .clone()
                    .expect("config validation guarantees http listeners have a health_check.path");
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

    /// TLS-reload tasks plus every listener's health-checker/DNS-poller/
    /// sweeper tasks — the two buckets `background_tasks` used to be one
    /// flat `Vec` of, before per-listener reload needed to tell them apart.
    async fn total_task_count(app: &WiredApp) -> usize {
        app.tls_reload_tasks.len()
            + app
                .reload
                .tasks
                .lock()
                .await
                .values()
                .map(|tasks| tasks.len())
                .sum::<usize>()
    }

    async fn abort_all_tasks(app: WiredApp) {
        for task in app.tls_reload_tasks {
            task.abort();
        }
        for (_, tasks) in app.reload.tasks.lock().await.drain() {
            for task in tasks {
                task.abort();
            }
        }
    }

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
        assert_eq!(total_task_count(&app).await, 5);

        match &app.listeners[0] {
            ListenerRuntime::Http { ctx, .. } => {
                let ctx = ctx.load();
                assert_eq!(ctx.pool.all_backend_ids().len(), 2);
                assert!(ctx.pool.is_eligible(&BackendId::new("w1")));
            }
            _ => panic!("expected an http listener"),
        }

        abort_all_tasks(app).await;
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

        abort_all_tasks(app).await;
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
                assert!(ctx.load().per_backend_client.is_some());
            }
            _ => panic!("expected an http listener"),
        }

        abort_all_tasks(app).await;
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
                assert!(ctx.load().per_backend_client.is_none());
            }
            _ => panic!("expected an http listener"),
        }

        abort_all_tasks(app).await;
    }

    #[tokio::test]
    async fn applies_drain_timeout_default() {
        let config = Config::parse(CONFIG).unwrap();
        let app = build_app(&config, None).unwrap();
        assert_eq!(app.drain_timeout, Duration::from_millis(10_000));
        abort_all_tasks(app).await;
    }
}
