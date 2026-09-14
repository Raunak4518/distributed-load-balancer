use crate::error::ConfigError;
use crate::http2::Http2Config;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    pub listeners: Vec<ListenerConfig>,
    /// Absent means single-node: no peer listener, no coordination, and
    /// behaviour identical to Phases 1-2.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
    /// Absent disables metrics and health endpoints entirely.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Absent disables OpenTelemetry trace export entirely. Spans are still
    /// created (that cost is unconditional -- see `lb-tracing`) but nothing
    /// ever reads them without this section.
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AdminConfig {
    /// Bind privately. This surface exposes internal topology (backend names,
    /// health, traffic volumes) and must never face the public internet.
    pub listen: SocketAddr,
    /// Name of the environment variable holding the admin bearer token.
    /// Preferred: config files end up in version control, secrets shouldn't.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Literal token. Accepted for tests and constrained environments; the
    /// environment-variable form is preferred.
    #[serde(default)]
    pub token: Option<String>,
}

impl AdminConfig {
    /// Resolves the admin bearer token.
    ///
    /// Unlike `ClusterConfig::resolve_secret`, `Ok(None)` (neither field set)
    /// is a valid, common result -- it means the admin listener stays
    /// unauthenticated, exactly as it always was before this existed. Both
    /// fields set is rejected by `Config::validate()` before this is ever
    /// called; `token_env` naming an unset variable fails fast here, same as
    /// `resolve_secret`.
    ///
    /// Deliberately not done during `parse`, for the same reason
    /// `resolve_secret` isn't: reading the environment is a side effect, and
    /// config parsing should be pure. `lb-server` calls this at startup,
    /// before anything binds.
    pub fn resolve_token(&self) -> Result<Option<Vec<u8>>, ConfigError> {
        let token = match (&self.token_env, &self.token) {
            (None, None) => return Ok(None),
            (Some(var), None) => std::env::var(var).map_err(|_| {
                ConfigError::Invalid(format!(
                    "admin.token_env names '{var}', but that environment variable is not set"
                ))
            })?,
            (None, Some(literal)) => literal.clone(),
            (Some(_), Some(_)) => {
                return Err(ConfigError::Invalid(
                    "admin requires at most one of token_env or token".into(),
                ))
            }
        };
        if token.is_empty() {
            return Err(ConfigError::Invalid("admin token must not be empty".into()));
        }
        Ok(Some(token.into_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TracingConfig {
    /// Where spans are exported to, over OTLP/HTTP. A local collector
    /// (`http://localhost:4318`) is the common case; a plain `http://`
    /// endpoint is deliberately supported, not just `https://` -- see
    /// `lb-tracing`'s docs for why re-encrypting telemetry export isn't
    /// this project's problem to solve.
    pub otlp_endpoint: String,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
}

fn default_sample_ratio() -> f64 {
    1.0
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub format: LogFormat,
    /// Off by default: at 50k req/s, one line per request is ~50,000 lines a
    /// second. Turning this on is a capacity decision, not a preference.
    #[serde(default)]
    pub log_requests: bool,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            format: LogFormat::default(),
            log_requests: false,
            sample_rate: default_sample_rate(),
        }
    }
}

fn default_sample_rate() -> f64 {
    0.01
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Json,
    Pretty,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ClusterConfig {
    pub node_id: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub peers: Vec<SocketAddr>,
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Name of the environment variable holding the peer-sync secret.
    /// Preferred: config files end up in version control, secrets should not.
    #[serde(default)]
    pub shared_secret_env: Option<String>,
    /// Literal secret. Accepted for tests and constrained environments; the
    /// environment-variable form is preferred.
    #[serde(default)]
    pub shared_secret: Option<String>,
    /// Absent means the peer channel stays HMAC-authenticated but
    /// unencrypted, as it was before this existed -- every node id and
    /// rate-limit count is readable to anyone who can observe the link.
    #[serde(default)]
    pub tls: Option<PeerTlsConfig>,
}

/// Mutual TLS for the cluster peer channel. Every node presents the same
/// cert/key to every peer it talks to -- gossip is symmetric, one node has
/// one identity for it, unlike a listener's per-hostname certificates.
///
/// Peer identity is verified by the standard WebPKI machinery (chain to
/// `ca_file`, `ServerName`/client-cert checks), not a hand-rolled verifier:
/// each node's certificate must carry its own gossip bind IP as a Subject
/// Alternative Name, and every peer's `ca_file` must point at the same
/// signing CA.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PeerTlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_file: PathBuf,
    pub handshake_timeout_ms: Option<u64>,
}

impl PeerTlsConfig {
    /// Same default as `TlsConfig::handshake_timeout` -- nothing about the
    /// peer channel makes a slower client more tolerable than a listener's.
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms.unwrap_or(5_000))
    }
}

fn default_sync_interval_ms() -> u64 {
    200
}

fn default_window_secs() -> u64 {
    10
}

impl ClusterConfig {
    pub fn sync_interval(&self) -> Duration {
        Duration::from_millis(self.sync_interval_ms)
    }

    /// Resolves the peer-sync secret.
    ///
    /// Deliberately not done during `parse`: reading the environment is a
    /// side effect, and config parsing should be pure so tests can exercise
    /// it without touching global state. `lb-server` calls this at startup,
    /// before anything binds, so a missing secret fails fast.
    pub fn resolve_secret(&self) -> Result<Vec<u8>, ConfigError> {
        let secret = match (&self.shared_secret_env, &self.shared_secret) {
            (Some(var), None) => std::env::var(var).map_err(|_| {
                ConfigError::Invalid(format!(
                    "cluster.shared_secret_env names '{var}', but that environment variable is not set"
                ))
            })?,
            (None, Some(literal)) => literal.clone(),
            _ => {
                return Err(ConfigError::Invalid(
                    "cluster requires exactly one of shared_secret_env or shared_secret".into(),
                ))
            }
        };
        if secret.is_empty() {
            return Err(ConfigError::Invalid(
                "cluster peer secret must not be empty".into(),
            ));
        }
        Ok(secret.into_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            drain_timeout_ms: default_drain_timeout_ms(),
        }
    }
}

fn default_drain_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,

    // HTTP-only
    pub forward_timeout_ms: Option<u64>,
    pub max_request_body_bytes: Option<usize>,
    pub write_timeout_ms: Option<u64>,
    /// Caps how long a WebSocket (or other `Upgrade`) connection may sit
    /// idle after the backend accepts the handshake -- the request-shaped
    /// timeouts above (`forward_timeout_ms`, body read/write) stop applying
    /// the moment the upgrade completes, since the connection is no longer
    /// carrying HTTP request/response traffic. Defaults to 300s, matching
    /// `idle_timeout_ms`'s own default on a TCP listener -- the closest
    /// analog, since a post-upgrade connection is pumped exactly like one.
    pub websocket_idle_timeout_ms: Option<u64>,
    /// Compresses responses (gzip/brotli/deflate/zstd, negotiated against
    /// the client's `Accept-Encoding`) that aren't already encoded and pass
    /// `tower_http`'s default size/content-type heuristics -- a CPU/latency
    /// trade-off an operator should opt into, not one this project imposes.
    /// Off by default, same as nginx's own `gzip off`. TCP has no concept of
    /// a response to compress.
    #[serde(default)]
    pub compression: bool,

    // TCP-only
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,

    // Edge hardening — defaults applied by the accessors below.
    pub max_connections: Option<usize>,
    pub max_connections_per_ip: Option<usize>,
    pub header_read_timeout_ms: Option<u64>,
    pub body_read_timeout_ms: Option<u64>,

    /// Applies to both protocols: a listener behind a trusted front-end
    /// proxy/ELB reads the real client address from a PROXY protocol
    /// header (v1 or v2, auto-detected) instead of trusting the immediate
    /// TCP peer, which would just be that front-end's own address. A hard
    /// trust boundary, not a best-effort hint: a connection whose header is
    /// missing or malformed is dropped rather than falling back to the raw
    /// peer -- see `lb_server::proxy_protocol`'s module docs for why.
    #[serde(default)]
    pub proxy_protocol: bool,

    /// Applies to both protocols and both directions independently -- the
    /// socket this listener accepts from clients. `None` (the default)
    /// means exactly what it always meant: no keepalive tuning, OS
    /// defaults, `SO_KEEPALIVE` never explicitly touched.
    #[serde(default)]
    pub client_tcp_keepalive: Option<TcpKeepaliveConfig>,
    /// The socket this listener dials to a backend -- independent of
    /// `client_tcp_keepalive` above, since a client connection and its
    /// backend connection are different sockets with potentially different
    /// idle characteristics worth tuning separately (nginx's `so_keepalive`
    /// vs `proxy_socket_keepalive`, HAProxy's `clitcpka`/`srvtcpka`).
    #[serde(default)]
    pub backend_tcp_keepalive: Option<TcpKeepaliveConfig>,

    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub backend_tls: Option<BackendTlsConfig>,
    #[serde(default)]
    pub http2: Option<Http2Config>,
    #[serde(default)]
    pub dns_discovery: Option<crate::dns::DnsDiscoveryConfig>,

    #[serde(default)]
    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub rate_limit: RateLimitConfig,
    pub load_balancing: LoadBalancingConfig,

    /// HTTP-only. Routes a request to a *different* set of backends based
    /// on its path and/or `Host` header -- nginx's `location` blocks and
    /// HAProxy's ACL-based backend selection, both doing the same job.
    /// Evaluated in declaration order, first match wins; a request that
    /// matches no rule (or every rule, if this is empty) falls through to
    /// this listener's own `backends`/`health_check`/`load_balancing`
    /// above, which is what makes this fully backward compatible -- an
    /// existing config with no `[[listeners.routes]]` means exactly what it
    /// always meant.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// HTTP-only. Splits traffic that matched no `routes` rule across one or
    /// more independently health-checked, independently load-balanced pools
    /// by percentage -- a canary/blue-green rollout construct, distinct from
    /// `weight` on an individual backend (which biases selection *within*
    /// one pool). Each pool's `percent` is an absolute share of the
    /// listener's total request volume; the sum across every entry here must
    /// be at most 99, leaving the listener's own `backends` above at least
    /// 1% so it is never configured but silently unreachable. Evaluated
    /// after `routes`: a request that matches a route rule is unaffected by
    /// this section entirely. Empty (the default) costs nothing extra --
    /// every request falls straight through to `backends`/`load_balancing`
    /// above, exactly as it did before this section existed.
    #[serde(default)]
    pub canary: Vec<CanaryPoolConfig>,

    /// HTTP-only. Once a client's request lands on a backend, sets a cookie
    /// naming it and prefers that backend on the client's next request --
    /// nginx's commercial `sticky` module, HAProxy's `cookie` directive.
    /// Layered on top of whatever `load_balancing.strategy` is chosen
    /// rather than being a strategy itself: the whole point is "keep
    /// picking what worked last time, and fall back to the underlying
    /// algorithm when that's not possible," which every strategy already
    /// gives it for free. Listener-level, not per-route -- a request that
    /// resolves into a route's pool still uses this same cookie; a pin
    /// naming a backend from a different pool simply fails eligibility and
    /// falls through, exactly as an absent cookie would.
    #[serde(default)]
    pub sticky: Option<StickyConfig>,

    /// HTTP-only. Answers a repeated `GET` straight from memory instead of
    /// forwarding it to a backend at all -- nginx's `proxy_cache`, Varnish.
    /// Deliberately narrow for v1: only `GET` requests, only a `200`
    /// response, and only one that declares a `Content-Length` within
    /// `max_entry_bytes` are ever cached (chunked/unknown-length, non-GET,
    /// and non-200 traffic is simply proxied exactly as it is today,
    /// streamed, uncached) -- see `lb_proxy::cache`'s module docs for why
    /// that precondition is what keeps buffering a response safe. `Cache-
    /// Control: max-age=N` from the backend picks the TTL when present and
    /// nonzero; `no-store`/`private`/`no-cache`/`max-age=0` all mean "don't
    /// cache"; otherwise `default_ttl_secs` applies. Listener-level, not
    /// per-route: a route's `path_prefix`/`host` are already part of the
    /// cache key, so one cache per listener is already correctly
    /// partitioned between routes without a separate per-route toggle.
    #[serde(default)]
    pub cache: Option<CacheConfig>,

    /// HTTP-only. Blocks (or, in `log` mode, just records) a request whose
    /// path or query string contains an obviously malicious pattern --
    /// SQL-injection, XSS, or path-traversal tokens -- before it reaches a
    /// route, the cache, or a backend. Deliberately a small, fixed,
    /// built-in check for v1, not an operator-configurable rule engine: see
    /// `lb_proxy::waf`'s module docs for the exact scope and why.
    #[serde(default)]
    pub waf: Option<WafConfig>,
}

/// See `ListenerConfig::waf`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WafConfig {
    /// `block` refuses the request outright (`403`); `log` records the
    /// match (metric + a warning log line) and forwards it exactly as if
    /// this section weren't configured -- the naxsi-style "roll out in
    /// detection mode first" path, useful for an operator who wants to see
    /// what the built-in rules would have caught before enforcing them.
    #[serde(default)]
    pub mode: WafMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    #[default]
    Block,
    Log,
}

/// See `ListenerConfig::cache`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CacheConfig {
    /// A single response larger than this (by its `Content-Length`) is
    /// never cached -- the response is still served, just not stored.
    #[serde(default = "default_cache_max_entry_bytes")]
    pub max_entry_bytes: usize,
    /// Aggregate budget across every entry this listener's cache holds.
    /// Once full, new entries are simply not admitted until something
    /// already stored expires and is swept -- there is no eviction
    /// algorithm competing for space in v1.
    #[serde(default = "default_cache_max_total_bytes")]
    pub max_total_bytes: usize,
    /// Used only when the backend's response carries no `Cache-Control:
    /// max-age` of its own.
    #[serde(default = "default_cache_default_ttl_secs")]
    pub default_ttl_secs: u64,
}

fn default_cache_max_entry_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_cache_max_total_bytes() -> usize {
    64 * 1024 * 1024
}

fn default_cache_default_ttl_secs() -> u64 {
    60
}

/// See `ListenerConfig::client_tcp_keepalive`/`backend_tcp_keepalive`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TcpKeepaliveConfig {
    /// How long the connection may sit idle before the first probe
    /// (`TCP_KEEPIDLE`/`TCP_KEEPALIVE`).
    #[serde(default = "default_tcp_keepalive_time_secs")]
    pub time_secs: u64,
    /// How long between probes once they start (`TCP_KEEPINTVL`).
    #[serde(default = "default_tcp_keepalive_interval_secs")]
    pub interval_secs: u64,
    /// How many unanswered probes before the connection is considered dead
    /// (`TCP_KEEPCNT`).
    #[serde(default = "default_tcp_keepalive_retries")]
    pub retries: u32,
}

fn default_tcp_keepalive_time_secs() -> u64 {
    60
}

fn default_tcp_keepalive_interval_secs() -> u64 {
    10
}

fn default_tcp_keepalive_retries() -> u32 {
    6
}

/// See `ListenerConfig::sticky`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StickyConfig {
    /// The cookie's value is the raw backend id, unsigned: ids are
    /// operator-chosen, already exposed unauthenticated via the admin
    /// API's `GET /backends`, and not secret. A forged or stale cookie can
    /// at worst name a real-but-ineligible or nonexistent backend, both of
    /// which fall straight through to the underlying strategy -- never a
    /// crash, never a forced bad route.
    #[serde(default = "default_sticky_cookie_name")]
    pub cookie_name: String,
    /// `None` sends no `Max-Age`/`Expires` -- a session cookie, gone when
    /// the browser closes. `Some` is refreshed on every response that sets
    /// the cookie, so an active client's pin never expires mid-session.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
}

fn default_sticky_cookie_name() -> String {
    "lb_sticky".to_string()
}

/// One routing rule -- see `ListenerConfig::routes`. Deliberately does not
/// support its own `dns_discovery` or `backend_tls`: every route shares the
/// listener's single TLS/client policy and differs only in which static
/// backends and which load-balancing strategy/health-check apply. Widening
/// that is possible later; it is not what was found missing.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RouteConfig {
    /// Matched as a path *segment* prefix, not a bare `starts_with`:
    /// `"/api"` matches `/api` and `/api/anything`, but not `/apiary` --
    /// nginx's own `location /api` has exactly this gotcha, and this
    /// avoids it by construction. `None` matches every path.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Case-insensitive exact match against the request's `Host` header.
    /// `None` matches every host.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub load_balancing: LoadBalancingConfig,
}

/// One weighted traffic-split pool -- see `ListenerConfig::canary`. Same
/// shape as `RouteConfig` minus `path_prefix`/`host` (a canary pool is
/// selected by a percentage roll, not by matching anything about the
/// request) plus `percent`. Deliberately distinct from `BackendConfig`'s own
/// `weight`: that is a *relative* unit `weighted_round_robin` uses to bias
/// selection among backends inside one pool, while `percent` here is an
/// *absolute* share of the listener's total request volume, orthogonal to
/// whichever `load_balancing.strategy` a canary pool uses internally.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CanaryPoolConfig {
    pub percent: u8,
    #[serde(default)]
    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub load_balancing: LoadBalancingConfig,
}

impl ListenerConfig {
    pub fn forward_timeout(&self) -> Duration {
        Duration::from_millis(self.forward_timeout_ms.unwrap_or(5_000))
    }

    pub fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes.unwrap_or(1024 * 1024)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(2_000))
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms.unwrap_or(300_000))
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections.unwrap_or(10_000)
    }

    /// A global cap alone protects the process but not its users: one
    /// attacker could otherwise consume the whole budget.
    pub fn max_connections_per_ip(&self) -> usize {
        self.max_connections_per_ip.unwrap_or(100)
    }

    /// Caps how long a client may take to send the request head. Without
    /// this, dribbling headers holds a connection open indefinitely.
    pub fn header_read_timeout(&self) -> Duration {
        Duration::from_millis(self.header_read_timeout_ms.unwrap_or(5_000))
    }

    /// Caps how long a client may take to send the body. A size limit alone
    /// is not a bound: 1 MiB at one byte per second is eleven days.
    pub fn body_read_timeout(&self) -> Duration {
        Duration::from_millis(self.body_read_timeout_ms.unwrap_or(10_000))
    }

    /// Caps how long a client may take to *read* the response -- the write
    /// side of the same problem `header_read_timeout`/`body_read_timeout`
    /// solve for reads. Without this, a client that stops draining its
    /// socket holds the connection (and its connection-limit permit) open
    /// forever, since nothing else on this path watches the write side.
    /// 30s matches the same ballpark nginx's `send_timeout` and HAProxy's
    /// `timeout client` default to: generous for a genuinely slow client,
    /// still bounded.
    pub fn write_timeout(&self) -> Duration {
        Duration::from_millis(self.write_timeout_ms.unwrap_or(30_000))
    }

    /// See `websocket_idle_timeout_ms`.
    pub fn websocket_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.websocket_idle_timeout_ms.unwrap_or(300_000))
    }

    /// Whether this listener serves HTTP/2.
    ///
    /// The TLS requirement lives here, in one place, rather than being
    /// re-derived at each call site: HTTP/2 is negotiated over ALPN, ALPN
    /// only exists inside a TLS handshake, and this node is the edge — so a
    /// plaintext listener is HTTP/1.1 regardless of what the config says.
    pub fn http2_enabled(&self) -> bool {
        self.protocol == Protocol::Http
            && self.tls.is_some()
            && self.http2.as_ref().map(|h| h.enabled()).unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TlsConfig {
    pub certificates: Vec<CertificateConfig>,
    pub handshake_timeout_ms: Option<u64>,
    pub min_version: Option<TlsVersion>,
    pub reload_interval_secs: Option<u64>,
    pub hsts_max_age_secs: Option<u64>,
}

impl TlsConfig {
    /// Caps the TLS handshake. Nothing in Phase 5 covers this window: hyper
    /// never sees a connection whose handshake has not completed, so
    /// `header_read_timeout` cannot apply to it.
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms.unwrap_or(5_000))
    }

    pub fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.reload_interval_secs.unwrap_or(60))
    }

    pub fn min_version(&self) -> TlsVersion {
        self.min_version.unwrap_or(TlsVersion::Tls12)
    }

    /// 0 means off, which is the default: HSTS is cached by browsers for its
    /// full max-age, so enabling it must be a deliberate act.
    pub fn hsts_max_age_secs(&self) -> u64 {
        self.hsts_max_age_secs.unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CertificateConfig {
    /// Appears in metrics. Operator-chosen, never client-controlled.
    pub name: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    #[serde(default)]
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TryFrom<String> for TlsVersion {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "1.2" => Ok(TlsVersion::Tls12),
            "1.3" => Ok(TlsVersion::Tls13),
            other => Err(format!(
                "invalid tls.min_version '{other}': expected \"1.2\" or \"1.3\""
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BackendTlsConfig {
    /// Omit for the system trust store. Internal PKI is the common case on
    /// this path, which is why the file form exists at all.
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub danger_accept_invalid_certs: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub address: SocketAddr,
    /// Consulted only by `load_balancing.strategy = "weighted_round_robin"`
    /// or `"consistent_hash"` -- ignored by every other strategy, including
    /// the default `round_robin`.
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HealthCheckConfig {
    /// Required for HTTP listeners, forbidden for TCP listeners (there is
    /// nothing to GET on a Postgres port).
    pub path: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
    /// Consecutive successes required in `HalfOpen` before the circuit
    /// closes. Defaults to 1, exactly preserving pre-existing behavior.
    #[serde(default = "default_half_open_successes_required")]
    pub half_open_successes_required: u32,
    /// Each re-trip into `Open` since the backend last stayed `Closed` for
    /// `flap_streak_reset_ms` multiplies its cooldown by this factor, up to
    /// `max_flap_cooldown_ms`. Defaults to 1.0 (no growth), exactly
    /// preserving pre-existing behavior.
    #[serde(default = "default_flap_backoff_multiplier")]
    pub flap_backoff_multiplier: f64,
    /// Ceiling on the scaled cooldown from `flap_backoff_multiplier`.
    /// Defaults to effectively unbounded.
    #[serde(default = "default_max_flap_cooldown_ms")]
    pub max_flap_cooldown_ms: u64,
    /// How long a backend must stay `Closed` before its next trip is
    /// treated as an isolated event rather than a continuation of its
    /// flapping streak.
    #[serde(default = "default_flap_streak_reset_ms")]
    pub flap_streak_reset_ms: u64,
    /// If set, a request this backend answers in at least this long counts
    /// as a passive health-check failure against its circuit breaker, even
    /// though the response itself reached the client successfully. Distinct
    /// from active health checking (`HealthProbe`), which only ever sees
    /// status codes/timeouts, never real request latency.
    #[serde(default)]
    pub unhealthy_latency_ms: Option<u64>,
    /// If set, a backend with at least this many in-flight
    /// requests/connections (`BackendPool::active_count`) counts its next
    /// completed request as a passive health-check failure against its
    /// circuit breaker, independent of that request's own latency or status.
    #[serde(default)]
    pub unhealthy_request_count: Option<usize>,
}

fn default_half_open_successes_required() -> u32 {
    1
}

fn default_flap_backoff_multiplier() -> f64 {
    1.0
}

fn default_max_flap_cooldown_ms() -> u64 {
    u64::MAX
}

fn default_flap_streak_reset_ms() -> u64 {
    60_000
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RateLimitConfig {
    pub key: RateLimitKeySource,
    pub rate_per_sec: f64,
    pub burst: u32,
    /// Caps how many distinct keys are tracked. Beyond this, new keys share
    /// one overflow budget — see the Phase 5 design for why that beats
    /// rejecting newcomers or evicting established clients.
    #[serde(default = "default_max_tracked_keys")]
    pub max_tracked_keys: usize,
}

fn default_max_tracked_keys() -> usize {
    100_000
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum RateLimitKeySource {
    SourceIp,
    Header(String),
}

impl TryFrom<String> for RateLimitKeySource {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s == "source_ip" {
            Ok(RateLimitKeySource::SourceIp)
        } else if let Some(header) = s.strip_prefix("header:") {
            Ok(RateLimitKeySource::Header(header.to_string()))
        } else {
            Err(format!(
                "invalid rate_limit.key '{s}': expected 'source_ip' or 'header:<name>'"
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LoadBalancingConfig {
    pub strategy: LoadBalancingStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    RoundRobin,
    /// Fewest in-flight requests/connections wins. Needs no per-request
    /// identity, unlike `ConsistentHash`.
    LeastConnections,
    /// Round-robin, but each backend's `weight` (default 1) controls how
    /// often it's picked relative to the others.
    WeightedRoundRobin,
    /// Hashes this listener's rate-limit key (`source_ip`, or the header
    /// value) onto a ring of backends, so the same client keeps landing on
    /// the same backend as long as the backend set doesn't change. Backend
    /// `weight` still applies, via virtual nodes on the ring.
    ConsistentHash,
    /// Power-of-two-choices: samples two eligible backends at random and
    /// picks whichever has the lower `decaying_latency_estimate * (pending +
    /// 1)`. Adapts to real backend responsiveness and current load, unlike
    /// the other four strategies, none of which look at latency at all.
    PeakEwmaP2c,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one listener is required".into(),
            ));
        }

        let mut names = HashSet::new();
        let mut addresses = HashSet::new();

        for l in &self.listeners {
            if !names.insert(&l.name) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate listener name: {}",
                    l.name
                )));
            }
            if !addresses.insert(l.listen) {
                return Err(ConfigError::Invalid(format!(
                    "listener '{}' reuses listen address {} — two listeners cannot bind the same address",
                    l.name, l.listen
                )));
            }
            l.validate()?;
        }

        if let Some(cluster) = &self.cluster {
            if cluster.node_id.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "cluster.node_id must not be empty".into(),
                ));
            }
            if cluster.sync_interval_ms == 0 {
                return Err(ConfigError::Invalid(
                    "cluster.sync_interval_ms must be positive".into(),
                ));
            }
            if cluster.window_secs == 0 {
                return Err(ConfigError::Invalid(
                    "cluster.window_secs must be positive".into(),
                ));
            }
            if cluster.peers.contains(&cluster.listen) {
                return Err(ConfigError::Invalid(format!(
                    "cluster.peers contains this node's own listen address {} — peers must list only the other nodes",
                    cluster.listen
                )));
            }
            if let Some(clash) = self.listeners.iter().find(|l| l.listen == cluster.listen) {
                return Err(ConfigError::Invalid(format!(
                    "cluster.listen {} is already used by listener '{}'",
                    cluster.listen, clash.name
                )));
            }
            // Mandatory: an optional security control defaults to off and
            // stays off. Deliberate break with Phase 3 configs — the peer
            // port influences rate-limiting decisions, so unauthenticated
            // access to it is a denial-of-service vector.
            match (&cluster.shared_secret_env, &cluster.shared_secret) {
                (Some(_), None) | (None, Some(_)) => {}
                _ => {
                    return Err(ConfigError::Invalid(
                        "cluster requires exactly one of shared_secret_env or shared_secret".into(),
                    ))
                }
            }
        }

        if let Some(admin) = &self.admin {
            if let Some(clash) = self.listeners.iter().find(|l| l.listen == admin.listen) {
                return Err(ConfigError::Invalid(format!(
                    "admin.listen {} is already used by listener '{}'",
                    admin.listen, clash.name
                )));
            }
            if let Some(cluster) = &self.cluster {
                if cluster.listen == admin.listen {
                    return Err(ConfigError::Invalid(format!(
                        "admin.listen {} is already used by cluster.listen",
                        admin.listen
                    )));
                }
            }
            // Unlike cluster's shared_secret above, *neither* set is fine --
            // an admin token defaults to absent (today's behavior,
            // unauthenticated) rather than being mandatory, since making it
            // mandatory would break every existing [admin] config.
            if admin.token_env.is_some() && admin.token.is_some() {
                return Err(ConfigError::Invalid(
                    "admin requires at most one of token_env or token".into(),
                ));
            }
        }

        if !(0.0..=1.0).contains(&self.logging.sample_rate) {
            return Err(ConfigError::Invalid(
                "logging.sample_rate must be between 0.0 and 1.0".into(),
            ));
        }

        if let Some(t) = &self.tracing {
            if t.otlp_endpoint.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "tracing.otlp_endpoint must not be empty".into(),
                ));
            }
            if !(0.0..=1.0).contains(&t.sample_ratio) {
                return Err(ConfigError::Invalid(
                    "tracing.sample_ratio must be between 0.0 and 1.0".into(),
                ));
            }
        }
        Ok(())
    }
}

impl ListenerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid =
            |msg: String| ConfigError::Invalid(format!("listener '{}': {msg}", self.name));

        match (&self.dns_discovery, self.backends.is_empty()) {
            (Some(_), false) => {
                return Err(invalid(
                    "backends and dns_discovery are mutually exclusive — a listener's \
                     backend set comes from exactly one source"
                        .into(),
                ))
            }
            (None, true) => return Err(invalid("at least one backend is required".into())),
            _ => {}
        }
        if let Some(dns) = &self.dns_discovery {
            if dns.name.trim().is_empty() {
                return Err(invalid("dns_discovery.name must not be empty".into()));
            }
            if dns.port == 0 {
                return Err(invalid("dns_discovery.port must be positive".into()));
            }
        }
        // Unique across the default backends *and every route's* -- not
        // just within one list. `ProxyContext`'s circuit-breaker/metrics
        // maps are flat `HashMap<BackendId, _>` with no per-pool scoping,
        // so a collision between a route's backend and another route's (or
        // the default's) would silently overwrite one's state with the
        // other's.
        let mut ids = HashSet::new();
        for b in &self.backends {
            if !ids.insert(&b.id) {
                return Err(invalid(format!("duplicate backend id: {}", b.id)));
            }
        }
        for route in &self.routes {
            for b in &route.backends {
                if !ids.insert(&b.id) {
                    return Err(invalid(format!(
                        "duplicate backend id across routes: {}",
                        b.id
                    )));
                }
            }
        }
        for pool in &self.canary {
            for b in &pool.backends {
                if !ids.insert(&b.id) {
                    return Err(invalid(format!(
                        "duplicate backend id across canary pools: {}",
                        b.id
                    )));
                }
            }
        }

        if self.rate_limit.rate_per_sec <= 0.0 {
            return Err(invalid("rate_limit.rate_per_sec must be positive".into()));
        }
        if self.rate_limit.burst == 0 {
            return Err(invalid("rate_limit.burst must be positive".into()));
        }
        if self.rate_limit.max_tracked_keys == 0 {
            return Err(invalid(
                "rate_limit.max_tracked_keys must be positive".into(),
            ));
        }
        if self.health_check.flap_backoff_multiplier < 1.0 {
            return Err(invalid(
                "health_check.flap_backoff_multiplier must be >= 1.0".into(),
            ));
        }
        if self.health_check.unhealthy_latency_ms == Some(0) {
            return Err(invalid(
                "health_check.unhealthy_latency_ms must be positive if set".into(),
            ));
        }
        if self.health_check.unhealthy_request_count == Some(0) {
            return Err(invalid(
                "health_check.unhealthy_request_count must be positive if set".into(),
            ));
        }

        if self.max_connections() == 0 || self.max_connections_per_ip() == 0 {
            return Err(invalid(
                "max_connections and max_connections_per_ip must be positive".into(),
            ));
        }
        if self.max_connections_per_ip() > self.max_connections() {
            return Err(invalid(
                "max_connections_per_ip cannot exceed max_connections".into(),
            ));
        }
        if self.header_read_timeout().is_zero()
            || self.body_read_timeout().is_zero()
            || self.write_timeout().is_zero()
        {
            return Err(invalid(
                "header_read_timeout_ms, body_read_timeout_ms and write_timeout_ms must be positive"
                    .into(),
            ));
        }

        match self.protocol {
            Protocol::Http => {
                if self.health_check.path.is_none() {
                    return Err(invalid(
                        "health_check.path is required for http listeners".into(),
                    ));
                }
                if self.connect_timeout_ms.is_some() || self.idle_timeout_ms.is_some() {
                    return Err(invalid(
                        "connect_timeout_ms/idle_timeout_ms are tcp-only settings".into(),
                    ));
                }
                for route in &self.routes {
                    if route.backends.is_empty() {
                        return Err(invalid(
                            "each [[listeners.routes]] needs at least one backend".into(),
                        ));
                    }
                    if route.health_check.path.is_none() {
                        return Err(invalid(
                            "each [[listeners.routes]] needs health_check.path, same as the listener itself".into(),
                        ));
                    }
                    if route.health_check.flap_backoff_multiplier < 1.0 {
                        return Err(invalid(
                            "each [[listeners.routes]] health_check.flap_backoff_multiplier must be >= 1.0".into(),
                        ));
                    }
                    if route.health_check.unhealthy_latency_ms == Some(0)
                        || route.health_check.unhealthy_request_count == Some(0)
                    {
                        return Err(invalid(
                            "each [[listeners.routes]] health_check.unhealthy_latency_ms/unhealthy_request_count must be positive if set".into(),
                        ));
                    }
                }
                let mut canary_percent_total: u32 = 0;
                for pool in &self.canary {
                    if pool.backends.is_empty() {
                        return Err(invalid(
                            "each [[listeners.canary]] needs at least one backend".into(),
                        ));
                    }
                    if pool.health_check.path.is_none() {
                        return Err(invalid(
                            "each [[listeners.canary]] needs health_check.path, same as the listener itself".into(),
                        ));
                    }
                    if pool.health_check.flap_backoff_multiplier < 1.0 {
                        return Err(invalid(
                            "each [[listeners.canary]] health_check.flap_backoff_multiplier must be >= 1.0".into(),
                        ));
                    }
                    if pool.health_check.unhealthy_latency_ms == Some(0)
                        || pool.health_check.unhealthy_request_count == Some(0)
                    {
                        return Err(invalid(
                            "each [[listeners.canary]] health_check.unhealthy_latency_ms/unhealthy_request_count must be positive if set".into(),
                        ));
                    }
                    if pool.percent == 0 || pool.percent > 99 {
                        return Err(invalid(
                            "each [[listeners.canary]] percent must be between 1 and 99".into(),
                        ));
                    }
                    canary_percent_total += pool.percent as u32;
                }
                if canary_percent_total > 99 {
                    return Err(invalid(
                        "the sum of every [[listeners.canary]] percent must be at most 99, leaving the listener's own backends at least 1%".into(),
                    ));
                }
            }
            Protocol::Tcp => {
                if self.health_check.path.is_some() {
                    return Err(invalid(
                        "health_check.path is http-only — a tcp backend has no path to probe"
                            .into(),
                    ));
                }
                if self.forward_timeout_ms.is_some()
                    || self.max_request_body_bytes.is_some()
                    || self.write_timeout_ms.is_some()
                    || self.websocket_idle_timeout_ms.is_some()
                {
                    return Err(invalid(
                        "forward_timeout_ms/max_request_body_bytes/write_timeout_ms/websocket_idle_timeout_ms are http-only settings -- a tcp listener gets equivalent protection from idle_timeout_ms"
                            .into(),
                    ));
                }
                if self.compression {
                    return Err(invalid(
                        "compression is an http-only setting -- a tcp listener has no response to compress"
                            .into(),
                    ));
                }
                if !self.routes.is_empty() {
                    return Err(invalid(
                        "routes is an http-only setting -- a tcp listener has no path or Host to route on"
                            .into(),
                    ));
                }
                if !self.canary.is_empty() {
                    return Err(invalid(
                        "canary is an http-only setting -- a tcp listener has no request identity to split traffic by"
                            .into(),
                    ));
                }
                if self.sticky.is_some() {
                    return Err(invalid(
                        "sticky is an http-only setting -- a tcp listener has no cookie to set or read"
                            .into(),
                    ));
                }
                if self.cache.is_some() {
                    return Err(invalid(
                        "cache is an http-only setting -- a tcp listener has no response to cache"
                            .into(),
                    ));
                }
                if self.waf.is_some() {
                    return Err(invalid(
                        "waf is an http-only setting -- a tcp listener has no path or query to inspect"
                            .into(),
                    ));
                }
                if let RateLimitKeySource::Header(name) = &self.rate_limit.key {
                    return Err(invalid(format!(
                        "rate_limit.key 'header:{name}' is http-only — a tcp listener has no headers to read, use 'source_ip'"
                    )));
                }
            }
        }

        if self.backend_tls.is_some() {
            if let Some(dns) = &self.dns_discovery {
                let Some(name) = dns.server_name.as_deref() else {
                    return Err(invalid(
                        "dns_discovery.server_name is required when backend_tls is set".into(),
                    ));
                };
                if name.parse::<IpAddr>().is_ok() {
                    return Err(invalid(format!(
                        "dns_discovery.server_name = \"{name}\" is an IP address — it \
                         must be the hostname on the backends' certificate"
                    )));
                }
                let authority = format!("{name}:{}", dns.port);
                if http::uri::Authority::try_from(authority.as_str()).is_err() {
                    return Err(invalid(format!(
                        "dns_discovery.server_name = \"{name}\" cannot form a valid \
                         authority (check for stray spaces or punctuation)"
                    )));
                }
            }
            // server_name -> first backend id that used it. Duplicate
            // detection is scoped to HTTP below: at L7,
            // `lb_proxy::resolver::PinnedResolver` (the table that pins the
            // forwarding dial to `address`) is keyed by server_name, so two
            // backends sharing one name collapse onto whichever address is
            // registered last -- round-robin becomes a no-op, and outcomes
            // get recorded against the wrong backend's circuit breaker. At
            // L4 there is no such shared table: each connection dials its
            // own backend's own `address` directly, so several TCP replicas
            // presenting the same certificate name is an ordinary,
            // functioning topology, not a bug -- rejecting it there would
            // only be pointlessly restrictive.
            let mut first_use: HashMap<&str, &str> = HashMap::new();

            for backend in &self.backends {
                let Some(name) = backend.server_name.as_deref() else {
                    return Err(invalid(format!(
                        "backend '{}' needs a server_name when backend_tls is set — \
                         certificates are issued for hostnames, but the backend is \
                         addressed as {}. Add server_name = \"<the name on its certificate>\".",
                        backend.id, backend.address
                    )));
                };

                // server_name identifies the hostname on the backend's
                // certificate. Accepting an IP literal here would reopen the
                // exact bug this field exists to prevent: a stock
                // `hyper_util::HttpConnector` parses an IP-literal URI host
                // *before* ever consulting a resolver, so an IP-literal
                // server_name would dial that IP directly -- straight past
                // `PinnedResolver` and the pinned `address` it exists to
                // enforce. IP-SAN certificates are a real but separate
                // feature this project isn't building right now.
                if name.parse::<IpAddr>().is_ok() {
                    return Err(invalid(format!(
                        "backend '{}' has server_name = \"{name}\", which is an IP \
                         address — server_name must be the hostname on the backend's \
                         certificate, not an address (IP-SAN certificates are not \
                         supported)",
                        backend.id
                    )));
                }

                // The L7 forwarding path (`lb_proxy::service::build_outbound_request`)
                // builds its outbound request's URI authority as
                // `{server_name}:{port}` and hands it to `hyper::Uri::builder`,
                // which *panics* rather than erroring on a malformed
                // authority. Before this phase that authority was always a
                // `SocketAddr`'s `Display`, valid by construction;
                // server_name is free text from an operator's config now, so
                // it is checked here against the exact parser the request
                // path uses -- `http::uri::Authority`, the same type
                // `hyper::Uri` is built from -- so a typo fails startup
                // instead of panicking on every request to this listener.
                let authority = format!("{name}:{}", backend.address.port());
                if http::uri::Authority::try_from(authority.as_str()).is_err() {
                    return Err(invalid(format!(
                        "backend '{}' has server_name = \"{name}\", which cannot form a \
                         valid request authority (check for stray spaces or punctuation)",
                        backend.id
                    )));
                }

                if self.protocol == Protocol::Http {
                    if let Some(first_id) = first_use.insert(name, backend.id.as_str()) {
                        return Err(invalid(format!(
                            "backends '{first_id}' and '{}' both use server_name = \"{name}\" \
                             — at L7 each server_name resolves to exactly one address, so \
                             sharing one collapses both backends onto whichever address is \
                             registered last, silently defeating load balancing. Give each \
                             backend a distinct server_name.",
                            backend.id
                        )));
                    }
                }
            }
        }
        if let Some(tls) = &self.tls {
            if self.protocol == Protocol::Tcp && tls.hsts_max_age_secs() > 0 {
                return Err(invalid(
                    "hsts_max_age_secs is meaningless on a tcp listener — there are no \
                     responses to add a header to"
                        .into(),
                ));
            }
            if tls.certificates.is_empty() {
                return Err(invalid(
                    "[listeners.tls] needs at least one certificate".into(),
                ));
            }
        }
        if let Some(h2) = &self.http2 {
            if self.protocol == Protocol::Tcp {
                return Err(invalid(
                    "http2 settings are meaningless on a tcp listener — HTTP/2 is \
                     an application protocol and the L4 data plane does not parse one"
                        .to_string(),
                ));
            }
            if h2.max_concurrent_streams() == 0 {
                return Err(invalid(
                    "http2.max_concurrent_streams must be greater than 0 — zero \
                     advertises that no streams may be opened, which accepts \
                     connections and then serves nothing"
                        .to_string(),
                ));
            }
            if h2.backend_h2c() && self.backend_tls.is_some() {
                return Err(invalid(
                    "http2.backend_h2c cannot be combined with backend_tls — a TLS \
                     backend negotiates HTTP/2 over ALPN automatically, so \
                     backend_h2c is only for plaintext backends"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [[listeners]]
        name = "web"
        protocol = "http"
        listen = "0.0.0.0:8080"

          [[listeners.backends]]
          id = "web1"
          address = "127.0.0.1:9001"

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
        name = "postgres"
        protocol = "tcp"
        listen = "0.0.0.0:5432"

          [[listeners.backends]]
          id = "pg1"
          address = "10.0.0.5:5432"

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

    #[test]
    fn parses_mixed_protocol_config() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(cfg.listeners[0].protocol, Protocol::Http);
        assert_eq!(cfg.listeners[1].protocol, Protocol::Tcp);
        assert_eq!(cfg.server.drain_timeout_ms, 10_000); // default applied
        assert_eq!(cfg.listeners[0].max_request_body_bytes(), 1024 * 1024);
        assert_eq!(
            cfg.listeners[1].idle_timeout(),
            Duration::from_millis(300_000)
        );
    }

    #[test]
    fn rejects_empty_listeners() {
        let text = "listeners = []";
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_listener_names() {
        let text = VALID.replace(r#"name = "postgres""#, r#"name = "web""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_listen_addresses() {
        let text = VALID.replace(r#"listen = "0.0.0.0:5432""#, r#"listen = "0.0.0.0:8080""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_http_listener_without_health_path() {
        let text = VALID.replace("          path = \"/health\"\n", "");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_tcp_listener_with_health_path() {
        // Give the tcp listener a path by adding one to its health_check.
        let text = VALID.replace(
            "          [listeners.health_check]\n          interval_ms = 2000\n          timeout_ms = 500\n          failure_threshold = 3\n          cooldown_ms = 5000\n\n          [listeners.rate_limit]\n          key = \"source_ip\"\n          rate_per_sec = 10",
            "          [listeners.health_check]\n          path = \"/health\"\n          interval_ms = 2000\n          timeout_ms = 500\n          failure_threshold = 3\n          cooldown_ms = 5000\n\n          [listeners.rate_limit]\n          key = \"source_ip\"\n          rate_per_sec = 10",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_header_rate_limit_key_on_tcp_listener() {
        let text = VALID.replace(
            "          key = \"source_ip\"\n          rate_per_sec = 10",
            "          key = \"header:X-API-Key\"\n          rate_per_sec = 10",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("http-only"),
            "error should explain headers don't exist at L4, got: {err}"
        );
    }

    #[test]
    fn rejects_http_only_setting_on_tcp_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:5432\"",
            "        listen = \"0.0.0.0:5432\"\n        max_request_body_bytes = 1024",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_tcp_only_setting_on_http_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        idle_timeout_ms = 1000",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_write_timeout_ms_on_tcp_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:5432\"",
            "        listen = \"0.0.0.0:5432\"\n        write_timeout_ms = 1000",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("write_timeout_ms"),
            "error should name write_timeout_ms, got: {err}"
        );
    }

    #[test]
    fn compression_defaults_to_disabled() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(!cfg.listeners[0].compression);
    }

    #[test]
    fn parses_compression_enabled() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        compression = true",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        assert!(cfg.listeners[0].compression);
    }

    #[test]
    fn rejects_compression_on_tcp_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:5432\"",
            "        listen = \"0.0.0.0:5432\"\n        compression = true",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("compression"),
            "error should name compression, got: {err}"
        );
    }

    /// Inserts `route_toml` as a second listener entry's worth of extra
    /// TOML, right before the "postgres" (TCP) listener -- keeps every
    /// route test's fixture anchored to the same known-good `VALID` base
    /// rather than hand-building a whole config from scratch.
    fn with_route(route_toml: &str) -> String {
        VALID.replace(
            "\n        [[listeners]]\n        name = \"postgres\"",
            &format!("{route_toml}\n        [[listeners]]\n        name = \"postgres\""),
        )
    }

    const ROUTE: &str = r#"

          [[listeners.routes]]
          path_prefix = "/api"

            [[listeners.routes.backends]]
            id = "api1"
            address = "127.0.0.1:9101"

            [listeners.routes.health_check]
            path = "/health"
            interval_ms = 2000
            timeout_ms = 500
            failure_threshold = 3
            cooldown_ms = 5000

            [listeners.routes.load_balancing]
            strategy = "round_robin"
"#;

    #[test]
    fn routes_default_to_empty() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].routes.is_empty());
    }

    #[test]
    fn parses_a_route_with_path_prefix() {
        let cfg = Config::parse(&with_route(ROUTE)).expect("valid config should parse");
        let route = &cfg.listeners[0].routes[0];
        assert_eq!(route.path_prefix.as_deref(), Some("/api"));
        assert_eq!(route.host, None);
        assert_eq!(route.backends.len(), 1);
        assert_eq!(route.backends[0].id, "api1");
    }

    #[test]
    fn parses_a_route_with_host() {
        let text =
            with_route(ROUTE).replace("path_prefix = \"/api\"", "host = \"api.example.com\"");
        let cfg = Config::parse(&text).expect("valid config should parse");
        assert_eq!(
            cfg.listeners[0].routes[0].host.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(cfg.listeners[0].routes[0].path_prefix, None);
    }

    #[test]
    fn rejects_routes_on_tcp_listener() {
        // Both listeners' blocks end in the identical two lines, so a plain
        // `.replace()` would insert into both -- `rfind` targets only the
        // *last* occurrence, i.e. the TCP listener's.
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str(ROUTE);
        text.push_str(&VALID[insert_at..]);

        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("routes"),
            "error should name routes, got: {err}"
        );
    }

    #[test]
    fn rejects_a_route_with_no_backends() {
        let text = with_route(ROUTE).replace(
            "[[listeners.routes.backends]]\n            id = \"api1\"\n            address = \"127.0.0.1:9101\"\n\n",
            "",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("backend"));
    }

    #[test]
    fn rejects_a_route_with_no_health_check_path() {
        let text = with_route(ROUTE).replace("path = \"/health\"\n            ", "");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("health_check"));
    }

    #[test]
    fn rejects_duplicate_backend_id_between_default_and_a_route() {
        let text = with_route(ROUTE).replace("id = \"api1\"", "id = \"web1\"");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn rejects_duplicate_backend_id_across_two_routes() {
        // A second route, same backend id as the first, different path so
        // this isn't rejected for being a duplicate *rule* -- only the id
        // collision should trip validation.
        let second_route = ROUTE.replace("path_prefix = \"/api\"", "path_prefix = \"/other\"");
        let text = with_route(&format!("{ROUTE}{second_route}"));
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    const CANARY: &str = r#"

          [[listeners.canary]]
          percent = 5

            [[listeners.canary.backends]]
            id = "web-canary"
            address = "127.0.0.1:9201"

            [listeners.canary.health_check]
            path = "/health"
            interval_ms = 2000
            timeout_ms = 500
            failure_threshold = 3
            cooldown_ms = 5000

            [listeners.canary.load_balancing]
            strategy = "round_robin"
"#;

    #[test]
    fn canary_defaults_to_empty() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].canary.is_empty());
    }

    #[test]
    fn parses_a_configured_canary_pool() {
        let cfg = Config::parse(&with_route(CANARY)).expect("valid config should parse");
        let pool = &cfg.listeners[0].canary[0];
        assert_eq!(pool.percent, 5);
        assert_eq!(pool.backends.len(), 1);
        assert_eq!(pool.backends[0].id, "web-canary");
    }

    #[test]
    fn rejects_canary_on_tcp_listener() {
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str(CANARY);
        text.push_str(&VALID[insert_at..]);

        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("canary"),
            "error should name canary, got: {err}"
        );
    }

    #[test]
    fn rejects_a_canary_pool_with_no_backends() {
        let text = with_route(CANARY).replace(
            "[[listeners.canary.backends]]\n            id = \"web-canary\"\n            address = \"127.0.0.1:9201\"\n\n",
            "",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("backend"));
    }

    #[test]
    fn rejects_a_canary_pool_with_no_health_check_path() {
        let text = with_route(CANARY).replace("path = \"/health\"\n            ", "");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("health_check"));
    }

    #[test]
    fn rejects_a_canary_percent_of_zero() {
        let text = with_route(CANARY).replace("percent = 5", "percent = 0");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("percent"));
    }

    #[test]
    fn rejects_a_canary_percent_over_99() {
        let text = with_route(CANARY).replace("percent = 5", "percent = 100");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("percent"));
    }

    #[test]
    fn rejects_canary_percentages_summing_over_99() {
        let second_pool = CANARY
            .replace("percent = 5", "percent = 96")
            .replace("id = \"web-canary\"", "id = \"web-canary-2\"");
        let text = with_route(&format!(
            "{}{second_pool}",
            CANARY.replace("percent = 5", "percent = 4")
        ));
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("percent"));
    }

    #[test]
    fn rejects_duplicate_backend_id_between_default_and_a_canary_pool() {
        let text = with_route(CANARY).replace("id = \"web-canary\"", "id = \"web1\"");
        let err = Config::parse(&text).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn sticky_defaults_to_none() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].sticky.is_none());
    }

    #[test]
    fn parses_sticky_with_default_cookie_name() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.sticky]",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let sticky = cfg.listeners[0]
            .sticky
            .as_ref()
            .expect("sticky should parse");
        assert_eq!(sticky.cookie_name, "lb_sticky");
        assert_eq!(sticky.max_age_secs, None);
    }

    #[test]
    fn parses_a_configured_sticky_section() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.sticky]\n          cookie_name = \"my_cookie\"\n          max_age_secs = 3600",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let sticky = cfg.listeners[0]
            .sticky
            .as_ref()
            .expect("sticky should parse");
        assert_eq!(sticky.cookie_name, "my_cookie");
        assert_eq!(sticky.max_age_secs, Some(3600));
    }

    #[test]
    fn rejects_sticky_on_tcp_listener() {
        // Both listeners' blocks end in the identical two lines, so a plain
        // `.replace()` would insert into both -- `rfind` targets only the
        // *last* occurrence, i.e. the TCP listener's, same trick
        // `rejects_routes_on_tcp_listener` uses above.
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str("\n\n          [listeners.sticky]");
        text.push_str(&VALID[insert_at..]);

        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("sticky"),
            "error should name sticky, got: {err}"
        );
    }

    #[test]
    fn cache_defaults_to_none() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].cache.is_none());
    }

    #[test]
    fn parses_cache_with_defaults() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.cache]",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let cache = cfg.listeners[0].cache.as_ref().expect("cache should parse");
        assert_eq!(cache.max_entry_bytes, 2 * 1024 * 1024);
        assert_eq!(cache.max_total_bytes, 64 * 1024 * 1024);
        assert_eq!(cache.default_ttl_secs, 60);
    }

    #[test]
    fn parses_a_configured_cache_section() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.cache]\n          max_entry_bytes = 1024\n          max_total_bytes = 4096\n          default_ttl_secs = 30",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let cache = cfg.listeners[0].cache.as_ref().expect("cache should parse");
        assert_eq!(cache.max_entry_bytes, 1024);
        assert_eq!(cache.max_total_bytes, 4096);
        assert_eq!(cache.default_ttl_secs, 30);
    }

    #[test]
    fn rejects_cache_on_tcp_listener() {
        // Same `rfind`-the-last-occurrence trick as `rejects_sticky_on_tcp_listener`
        // above -- both listener blocks share identical trailing lines.
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str("\n\n          [listeners.cache]");
        text.push_str(&VALID[insert_at..]);

        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("cache"),
            "error should name cache, got: {err}"
        );
    }

    #[test]
    fn waf_defaults_to_none() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].waf.is_none());
    }

    #[test]
    fn parses_waf_with_default_mode() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.waf]",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let waf = cfg.listeners[0].waf.as_ref().expect("waf should parse");
        assert_eq!(waf.mode, WafMode::Block);
    }

    #[test]
    fn parses_waf_log_mode() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.waf]\n          mode = \"log\"",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let waf = cfg.listeners[0].waf.as_ref().expect("waf should parse");
        assert_eq!(waf.mode, WafMode::Log);
    }

    #[test]
    fn rejects_waf_on_tcp_listener() {
        // Same `rfind`-the-last-occurrence trick as `rejects_cache_on_tcp_listener`
        // above -- both listener blocks share identical trailing lines.
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str("\n\n          [listeners.waf]");
        text.push_str(&VALID[insert_at..]);

        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("waf"),
            "error should name waf, got: {err}"
        );
    }

    #[test]
    fn tcp_keepalive_defaults_to_none_on_both_directions() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(cfg.listeners[0].client_tcp_keepalive.is_none());
        assert!(cfg.listeners[0].backend_tcp_keepalive.is_none());
    }

    #[test]
    fn parses_client_tcp_keepalive_with_defaults() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.client_tcp_keepalive]",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let ka = cfg.listeners[0]
            .client_tcp_keepalive
            .as_ref()
            .expect("client_tcp_keepalive should parse");
        assert_eq!(ka.time_secs, 60);
        assert_eq!(ka.interval_secs, 10);
        assert_eq!(ka.retries, 6);
    }

    #[test]
    fn parses_a_configured_backend_tcp_keepalive() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n\n          [listeners.backend_tcp_keepalive]\n          time_secs = 30\n          interval_secs = 5\n          retries = 3",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        let ka = cfg.listeners[0]
            .backend_tcp_keepalive
            .as_ref()
            .expect("backend_tcp_keepalive should parse");
        assert_eq!(ka.time_secs, 30);
        assert_eq!(ka.interval_secs, 5);
        assert_eq!(ka.retries, 3);
    }

    #[test]
    fn tcp_keepalive_is_valid_on_a_tcp_listener() {
        // Unlike sticky/cache/waf/routes, keepalive applies to both
        // protocols -- both directions must parse on a TCP listener with no
        // rejection.
        let anchor = "          [listeners.load_balancing]\n          strategy = \"round_robin\"";
        let insert_at = VALID.rfind(anchor).unwrap() + anchor.len();
        let mut text = String::from(&VALID[..insert_at]);
        text.push_str("\n\n          [listeners.client_tcp_keepalive]\n\n          [listeners.backend_tcp_keepalive]");
        text.push_str(&VALID[insert_at..]);

        Config::parse(&text).expect("keepalive should be valid on a tcp listener");
    }

    #[test]
    fn proxy_protocol_defaults_to_disabled() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert!(!cfg.listeners[0].proxy_protocol);
        assert!(!cfg.listeners[1].proxy_protocol);
    }

    #[test]
    fn parses_proxy_protocol_on_either_protocol() {
        let text = VALID
            .replace(
                "        listen = \"0.0.0.0:8080\"",
                "        listen = \"0.0.0.0:8080\"\n        proxy_protocol = true",
            )
            .replace(
                "        listen = \"0.0.0.0:5432\"",
                "        listen = \"0.0.0.0:5432\"\n        proxy_protocol = true",
            );
        let cfg = Config::parse(&text).expect("valid config should parse");
        assert!(cfg.listeners[0].proxy_protocol);
        assert!(cfg.listeners[1].proxy_protocol);
    }

    #[test]
    fn write_timeout_defaults_to_30_seconds() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(
            cfg.listeners[0].write_timeout(),
            Duration::from_millis(30_000)
        );
    }

    #[test]
    fn parses_a_configured_write_timeout() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        write_timeout_ms = 45000",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        assert_eq!(
            cfg.listeners[0].write_timeout(),
            Duration::from_millis(45_000)
        );
    }

    #[test]
    fn websocket_idle_timeout_defaults_to_300_seconds() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(
            cfg.listeners[0].websocket_idle_timeout(),
            Duration::from_millis(300_000)
        );
    }

    #[test]
    fn parses_a_configured_websocket_idle_timeout() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        websocket_idle_timeout_ms = 60000",
        );
        let cfg = Config::parse(&text).expect("valid config should parse");
        assert_eq!(
            cfg.listeners[0].websocket_idle_timeout(),
            Duration::from_millis(60_000)
        );
    }

    #[test]
    fn rejects_websocket_idle_timeout_ms_on_tcp_listener() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:5432\"",
            "        listen = \"0.0.0.0:5432\"\n        websocket_idle_timeout_ms = 1000",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("websocket_idle_timeout_ms"),
            "error should name websocket_idle_timeout_ms, got: {err}"
        );
    }

    #[test]
    fn rejects_zero_write_timeout() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"\n        write_timeout_ms = 0",
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("write_timeout_ms"),
            "error should name write_timeout_ms, got: {err}"
        );
    }

    #[test]
    fn rejects_non_positive_rate() {
        let text = VALID.replace("rate_per_sec = 50", "rate_per_sec = 0");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    /// Phase 3 shape: valid then, rejected now because it has no secret.
    const CLUSTER_NO_SECRET: &str = r#"
        [cluster]
        node_id = "lb-1"
        listen = "127.0.0.1:7946"
        peers = ["127.0.0.1:7947"]
    "#;

    const CLUSTER: &str = r#"
        [cluster]
        node_id = "lb-1"
        listen = "127.0.0.1:7946"
        peers = ["127.0.0.1:7947"]
        shared_secret = "test-secret"
    "#;

    #[test]
    fn parses_cluster_section_with_defaults() {
        let text = format!("{CLUSTER}{VALID}");
        let cfg = Config::parse(&text).unwrap();
        let cluster = cfg.cluster.expect("cluster section should parse");
        assert_eq!(cluster.node_id, "lb-1");
        assert_eq!(cluster.sync_interval_ms, 200);
        assert_eq!(cluster.window_secs, 10);
    }

    #[test]
    fn cluster_is_optional() {
        assert!(Config::parse(VALID).unwrap().cluster.is_none());
    }

    #[test]
    fn cluster_tls_is_optional_and_defaults_to_none() {
        let text = format!("{CLUSTER}{VALID}");
        let cfg = Config::parse(&text).unwrap();
        assert!(cfg.cluster.unwrap().tls.is_none());
    }

    #[test]
    fn parses_a_configured_cluster_tls_section() {
        let text = format!(
            "{CLUSTER}\n  [cluster.tls]\n  cert_file = \"node.crt\"\n  key_file = \"node.key\"\n  ca_file = \"ca.crt\"\n  handshake_timeout_ms = 2000\n{VALID}"
        );
        let cfg = Config::parse(&text).unwrap();
        let tls = cfg.cluster.unwrap().tls.expect("cluster.tls should parse");
        assert_eq!(tls.cert_file, std::path::PathBuf::from("node.crt"));
        assert_eq!(tls.key_file, std::path::PathBuf::from("node.key"));
        assert_eq!(tls.ca_file, std::path::PathBuf::from("ca.crt"));
        assert_eq!(tls.handshake_timeout(), Duration::from_millis(2000));
    }

    #[test]
    fn cluster_tls_handshake_timeout_defaults_to_5_seconds() {
        let text = format!(
            "{CLUSTER}\n  [cluster.tls]\n  cert_file = \"node.crt\"\n  key_file = \"node.key\"\n  ca_file = \"ca.crt\"\n{VALID}"
        );
        let cfg = Config::parse(&text).unwrap();
        let tls = cfg.cluster.unwrap().tls.unwrap();
        assert_eq!(tls.handshake_timeout(), Duration::from_millis(5_000));
    }

    #[test]
    fn rejects_peers_containing_our_own_listen_address() {
        let text = format!("{}{VALID}", CLUSTER.replace("7947", "7946"));
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_cluster_listen_clashing_with_a_traffic_listener() {
        let text = format!(
            "{}{VALID}",
            CLUSTER.replace("127.0.0.1:7946", "0.0.0.0:8080")
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_node_id() {
        let text = format!("{}{VALID}", CLUSTER.replace(r#""lb-1""#, r#""""#));
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn admin_and_logging_are_optional_with_defaults() {
        let cfg = Config::parse(VALID).unwrap();
        assert!(cfg.admin.is_none());
        assert!(!cfg.logging.log_requests);
        assert_eq!(cfg.logging.format, LogFormat::Json);
    }

    #[test]
    fn parses_admin_and_logging_sections() {
        let text = format!(
            "[admin]\nlisten = \"127.0.0.1:9090\"\n\n[logging]\nformat = \"pretty\"\nlog_requests = true\nsample_rate = 0.5\n\n{VALID}"
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.admin.unwrap().listen.port(), 9090);
        assert_eq!(cfg.logging.format, LogFormat::Pretty);
        assert!(cfg.logging.log_requests);
        assert_eq!(cfg.logging.sample_rate, 0.5);
    }

    #[test]
    fn rejects_admin_listen_clashing_with_a_traffic_listener() {
        let text = format!("[admin]\nlisten = \"0.0.0.0:8080\"\n\n{VALID}");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn admin_token_defaults_to_none() {
        let text = format!("[admin]\nlisten = \"127.0.0.1:9090\"\n\n{VALID}");
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.admin.unwrap().resolve_token().unwrap(), None);
    }

    #[test]
    fn resolves_a_literal_admin_token() {
        let text = format!("[admin]\nlisten = \"127.0.0.1:9090\"\ntoken = \"s3cret\"\n\n{VALID}");
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.admin.unwrap().resolve_token().unwrap(),
            Some(b"s3cret".to_vec())
        );
    }

    #[test]
    fn resolves_an_admin_token_from_the_environment() {
        let text = format!(
            "[admin]\nlisten = \"127.0.0.1:9090\"\ntoken_env = \"LB_TEST_ADMIN_TOKEN\"\n\n{VALID}"
        );
        let cfg = Config::parse(&text).unwrap();
        std::env::set_var("LB_TEST_ADMIN_TOKEN", "from-env");
        assert_eq!(
            cfg.admin.unwrap().resolve_token().unwrap(),
            Some(b"from-env".to_vec())
        );
        std::env::remove_var("LB_TEST_ADMIN_TOKEN");
    }

    #[test]
    fn reports_a_missing_admin_token_environment_variable() {
        let text = format!(
            "[admin]\nlisten = \"127.0.0.1:9090\"\ntoken_env = \"LB_DEFINITELY_UNSET_ADMIN_TOKEN_XYZ\"\n\n{VALID}"
        );
        let cfg = Config::parse(&text).unwrap();
        assert!(cfg.admin.unwrap().resolve_token().is_err());
    }

    #[test]
    fn rejects_an_empty_admin_token() {
        let text = format!("[admin]\nlisten = \"127.0.0.1:9090\"\ntoken = \"\"\n\n{VALID}");
        let cfg = Config::parse(&text).unwrap();
        assert!(cfg.admin.unwrap().resolve_token().is_err());
    }

    #[test]
    fn rejects_admin_with_both_token_sources() {
        let text = format!(
            "[admin]\nlisten = \"127.0.0.1:9090\"\ntoken = \"a\"\ntoken_env = \"SOME_VAR\"\n\n{VALID}"
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_out_of_range_sample_rate() {
        let text = format!("[logging]\nsample_rate = 1.5\n\n{VALID}");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn tracing_is_optional_and_disabled_by_default() {
        let cfg = Config::parse(VALID).unwrap();
        assert!(cfg.tracing.is_none());
    }

    #[test]
    fn parses_tracing_section_with_defaults() {
        let text = format!("[tracing]\notlp_endpoint = \"http://localhost:4318\"\n\n{VALID}");
        let cfg = Config::parse(&text).unwrap();
        let t = cfg.tracing.unwrap();
        assert_eq!(t.otlp_endpoint, "http://localhost:4318");
        assert_eq!(t.service_name, None);
        assert_eq!(t.sample_ratio, 1.0);
    }

    #[test]
    fn rejects_an_empty_otlp_endpoint() {
        let text = format!("[tracing]\notlp_endpoint = \"\"\n\n{VALID}");
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(
            err.contains("tracing.otlp_endpoint"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn rejects_out_of_range_tracing_sample_ratio() {
        let text = format!(
            "[tracing]\notlp_endpoint = \"http://localhost:4318\"\nsample_ratio = 1.5\n\n{VALID}"
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(
            err.contains("tracing.sample_ratio"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn listener_limits_have_defaults() {
        let cfg = Config::parse(VALID).unwrap();
        let l = &cfg.listeners[0];
        assert_eq!(l.max_connections(), 10_000);
        assert_eq!(l.max_connections_per_ip(), 100);
        assert_eq!(l.header_read_timeout(), Duration::from_millis(5_000));
        assert_eq!(l.body_read_timeout(), Duration::from_millis(10_000));
        assert_eq!(l.rate_limit.max_tracked_keys, 100_000);
        assert_eq!(l.health_check.half_open_successes_required, 1);
        assert_eq!(l.health_check.flap_backoff_multiplier, 1.0);
        assert_eq!(l.health_check.max_flap_cooldown_ms, u64::MAX);
        assert_eq!(l.health_check.flap_streak_reset_ms, 60_000);
        assert_eq!(l.health_check.unhealthy_latency_ms, None);
        assert_eq!(l.health_check.unhealthy_request_count, None);
    }

    #[test]
    fn parses_an_explicit_half_open_successes_required() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          half_open_successes_required = 3",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.listeners[0].health_check.half_open_successes_required,
            3
        );
    }

    #[test]
    fn parses_explicit_flap_backoff_settings() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          flap_backoff_multiplier = 2.0\n          max_flap_cooldown_ms = 60000\n          flap_streak_reset_ms = 120000",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        let hc = &cfg.listeners[0].health_check;
        assert_eq!(hc.flap_backoff_multiplier, 2.0);
        assert_eq!(hc.max_flap_cooldown_ms, 60_000);
        assert_eq!(hc.flap_streak_reset_ms, 120_000);
    }

    #[test]
    fn parses_explicit_passive_health_thresholds() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          unhealthy_latency_ms = 250\n          unhealthy_request_count = 20",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        let hc = &cfg.listeners[0].health_check;
        assert_eq!(hc.unhealthy_latency_ms, Some(250));
        assert_eq!(hc.unhealthy_request_count, Some(20));
    }

    #[test]
    fn rejects_a_zero_unhealthy_latency_ms() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          unhealthy_latency_ms = 0",
            1,
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(
            err.contains("unhealthy_latency_ms"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn rejects_a_zero_unhealthy_request_count() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          unhealthy_request_count = 0",
            1,
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(
            err.contains("unhealthy_request_count"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn rejects_a_flap_backoff_multiplier_below_one() {
        let text = VALID.replacen(
            "cooldown_ms = 5000",
            "cooldown_ms = 5000\n          flap_backoff_multiplier = 0.5",
            1,
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(
            err.contains("flap_backoff_multiplier"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn rejects_per_ip_cap_above_global_cap() {
        let text = VALID.replace(
            "        listen = \"0.0.0.0:8080\"",
            "        listen = \"0.0.0.0:8080\"
        max_connections = 10
        max_connections_per_ip = 100",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn cluster_without_a_secret_is_rejected() {
        let text = format!("{CLUSTER_NO_SECRET}{VALID}");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn cluster_with_both_secret_sources_is_rejected() {
        let text = format!(
            "{}{VALID}",
            CLUSTER.replace(
                "shared_secret = \"test-secret\"",
                "shared_secret = \"a\"
        shared_secret_env = \"SOME_VAR\""
            )
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn resolves_a_literal_secret() {
        let cfg = Config::parse(&format!("{CLUSTER}{VALID}")).unwrap();
        assert_eq!(
            cfg.cluster.unwrap().resolve_secret().unwrap(),
            b"test-secret".to_vec()
        );
    }

    #[test]
    fn rejects_an_empty_secret() {
        let text = format!("{}{VALID}", CLUSTER.replace("test-secret", ""));
        let cfg = Config::parse(&text).unwrap();
        assert!(cfg.cluster.unwrap().resolve_secret().is_err());
    }

    #[test]
    fn reports_a_missing_environment_variable() {
        let text = format!(
            "{}{VALID}",
            CLUSTER.replace(
                "shared_secret = \"test-secret\"",
                "shared_secret_env = \"LB_DEFINITELY_UNSET_VARIABLE_XYZ\""
            )
        );
        let cfg = Config::parse(&text).unwrap();
        let err = cfg.cluster.unwrap().resolve_secret().unwrap_err();
        assert!(format!("{err}").contains("not set"));
    }

    #[test]
    fn rejects_duplicate_backend_ids_within_a_listener() {
        let text = VALID.replace(
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"",
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9002\"",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    /// Full valid config for a listener whose `backend_tls` is set. `danger`
    /// controls `danger_accept_invalid_certs`; `server_name`, when present,
    /// is written onto the backend.
    fn tls_backend_toml(server_name: Option<&str>, danger: bool) -> String {
        let server_name_line = match server_name {
            Some(name) => format!("  server_name = \"{name}\"\n"),
            None => String::new(),
        };
        format!(
            r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.backend_tls]
  danger_accept_invalid_certs = {danger}

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"
{server_name_line}
  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        )
    }

    /// Full valid config for a listener with neither `tls` nor `backend_tls`
    /// set, and no `server_name` on its backend.
    fn plain_backend_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    fn dns_discovery_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.dns_discovery]
  name = "backend.svc.cluster.local"
  port = 9001

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    fn dns_discovery_with_static_backends_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.dns_discovery]
  name = "backend.svc.cluster.local"
  port = 9001

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    fn dns_discovery_with_empty_name_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.dns_discovery]
  name = ""
  port = 9001

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    fn dns_discovery_with_backend_tls_toml(protocol: &str, server_name: Option<&str>) -> String {
        let server_name_line = match server_name {
            Some(name) => format!("  server_name = \"{name}\"\n"),
            None => String::new(),
        };
        let health_check = if protocol == "http" {
            "  path = \"/health\"\n  interval_ms = 1000\n  timeout_ms = 200\n  failure_threshold = 2\n  cooldown_ms = 500\n"
        } else {
            "  interval_ms = 1000\n  timeout_ms = 200\n  failure_threshold = 2\n  cooldown_ms = 500\n"
        };
        format!(
            r#"
[[listeners]]
name = "web"
protocol = "{protocol}"
listen = "0.0.0.0:443"

  [listeners.dns_discovery]
  name = "backend.svc.cluster.local"
  port = 9001
{server_name_line}
  [listeners.backend_tls]
  danger_accept_invalid_certs = false

  [listeners.health_check]
{health_check}
  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        )
    }

    #[test]
    fn dns_discovery_with_backend_tls_requires_a_server_name_for_tcp_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("tcp", None);
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(
            err.contains("dns_discovery.server_name"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn dns_discovery_with_backend_tls_requires_a_server_name_for_http_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("http", None);
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(
            err.contains("dns_discovery.server_name"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn dns_discovery_backend_tls_server_name_must_not_be_an_ip_for_tcp_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("tcp", Some("203.0.113.7"));
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("IP address"), "unhelpful error: {err}");
    }

    #[test]
    fn dns_discovery_backend_tls_server_name_must_not_be_an_ip_for_http_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("http", Some("203.0.113.7"));
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("IP address"), "unhelpful error: {err}");
    }

    #[test]
    fn dns_discovery_with_backend_tls_and_a_server_name_is_accepted_for_tcp_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("tcp", Some("backend.internal"));
        let config = Config::parse(&toml).unwrap();
        assert_eq!(
            config.listeners[0]
                .dns_discovery
                .as_ref()
                .unwrap()
                .server_name
                .as_deref(),
            Some("backend.internal")
        );
    }

    #[test]
    fn dns_discovery_with_backend_tls_and_a_server_name_is_accepted_for_http_listeners() {
        let toml = dns_discovery_with_backend_tls_toml("http", Some("backend.internal"));
        let config = Config::parse(&toml).unwrap();
        assert_eq!(
            config.listeners[0]
                .dns_discovery
                .as_ref()
                .unwrap()
                .server_name
                .as_deref(),
            Some("backend.internal")
        );
    }

    #[test]
    fn dns_discovery_alone_is_a_valid_backend_source() {
        let config = Config::parse(&dns_discovery_toml()).unwrap();
        let dns = config.listeners[0].dns_discovery.as_ref().unwrap();
        assert_eq!(dns.name, "backend.svc.cluster.local");
        assert_eq!(dns.port, 9001);
        assert_eq!(dns.poll_interval(), Duration::from_secs(10));
        assert!(config.listeners[0].backends.is_empty());
    }

    #[test]
    fn dns_discovery_and_static_backends_are_mutually_exclusive() {
        let err = Config::parse(&dns_discovery_with_static_backends_toml())
            .unwrap_err()
            .to_string();
        assert!(err.contains("mutually exclusive"), "unhelpful error: {err}");
    }

    #[test]
    fn a_listener_with_neither_backends_nor_dns_discovery_is_rejected() {
        let err = Config::parse(&plain_backend_toml().replace(
            "  [[listeners.backends]]\n  id = \"b1\"\n  address = \"127.0.0.1:9001\"\n",
            "",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("at least one backend"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn dns_discovery_with_an_empty_name_is_rejected() {
        let err = Config::parse(&dns_discovery_with_empty_name_toml())
            .unwrap_err()
            .to_string();
        assert!(err.contains("dns_discovery.name"), "unhelpful error: {err}");
    }

    /// Full valid config for a *tcp* listener whose `tls` section turns HSTS
    /// on — a combination that must be rejected, since a tcp listener never
    /// produces an HTTP response to carry the header.
    fn tcp_listener_with_hsts_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "tcp"
listen = "0.0.0.0:443"

  [listeners.tls]
  hsts_max_age_secs = 3600

    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "/etc/lb/a.crt"
    key_file = "/etc/lb/a.key"
    hostnames = ["example.com"]

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    #[test]
    fn parses_a_tls_listener_with_defaults() {
        let toml = r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.tls]
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "/etc/lb/a.crt"
    key_file = "/etc/lb/a.key"
    hostnames = ["example.com"]

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#;
        let config = Config::parse(toml).unwrap();
        let tls = config.listeners[0].tls.as_ref().unwrap();
        assert_eq!(tls.certificates.len(), 1);
        assert_eq!(tls.certificates[0].name, "primary");
        assert_eq!(tls.handshake_timeout(), Duration::from_millis(5_000));
        assert_eq!(tls.reload_interval(), Duration::from_secs(60));
        assert_eq!(tls.min_version(), TlsVersion::Tls12);
        // HSTS is off unless someone deliberately turns it on: browsers cache
        // the policy for its full max-age, so it is close to irreversible.
        assert_eq!(tls.hsts_max_age_secs(), 0);
    }

    #[test]
    fn a_backend_without_server_name_is_rejected_when_backend_tls_is_set() {
        let toml = tls_backend_toml(/* server_name = */ None, /* danger = */ false);
        let err = Config::parse(&toml).unwrap_err().to_string();
        // Fails at startup rather than at the first request, following the
        // cluster-secret precedent.
        assert!(err.contains("server_name"), "unhelpful error: {err}");
        assert!(err.contains("b1"), "error must name the backend: {err}");
    }

    #[test]
    fn server_name_is_not_required_without_backend_tls() {
        let toml = plain_backend_toml();
        assert!(Config::parse(&toml).is_ok());
    }

    /// Before this check, a stray space in `server_name` (a plausible typo)
    /// would parse as config fine, start the listener fine, and then panic
    /// on every single request -- `hyper::Uri::builder` panics rather than
    /// erroring on a malformed authority, and before this phase the
    /// authority was always a `SocketAddr`'s `Display`, valid by
    /// construction. This is the regression test for that: it must fail at
    /// `Config::parse`, not at request time.
    #[test]
    fn a_server_name_that_cannot_form_a_valid_request_authority_is_rejected() {
        let toml = tls_backend_toml(Some("web1 internal"), false);
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("b1"), "error must name the backend: {err}");
        assert!(
            err.contains("web1 internal"),
            "error must show the offending value: {err}"
        );
    }

    /// `server_name` identifies the hostname on the backend's certificate.
    /// Accepting an IP literal here would reopen the exact bug the
    /// DNS-pinning fix closed: a stock `HttpConnector` parses an IP-literal
    /// URI host *before* ever consulting a resolver, so an IP-literal
    /// `server_name` would dial straight past the pinned table and the
    /// `address` it exists to enforce.
    #[test]
    fn an_ip_literal_server_name_is_rejected() {
        let toml = tls_backend_toml(Some("10.0.0.5"), false);
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("b1"), "error must name the backend: {err}");
        assert!(
            err.contains("10.0.0.5"),
            "error must show the offending value: {err}"
        );
    }

    /// Two backends of one listener, both given `server_name`. `protocol`
    /// selects which of the duplicate-`server_name` tests below this
    /// supports: rejected on an HTTP listener (the resolver table that pins
    /// the L7 dial is keyed by `server_name`, so a duplicate silently
    /// collapses two backends onto one address), accepted on a TCP listener
    /// (no such shared table exists there -- several replicas presenting one
    /// certificate name is an ordinary topology).
    fn duplicate_server_name_toml(protocol: &str) -> String {
        let tcp_only_listener_settings = if protocol == "tcp" {
            "connect_timeout_ms = 2000\nidle_timeout_ms = 5000\n"
        } else {
            ""
        };
        let health_check = if protocol == "tcp" {
            "  [listeners.health_check]\n  interval_ms = 1000\n  timeout_ms = 200\n  failure_threshold = 2\n  cooldown_ms = 500\n"
        } else {
            "  [listeners.health_check]\n  path = \"/health\"\n  interval_ms = 1000\n  timeout_ms = 200\n  failure_threshold = 2\n  cooldown_ms = 500\n"
        };
        format!(
            r#"
[[listeners]]
name = "web"
protocol = "{protocol}"
listen = "0.0.0.0:443"
{tcp_only_listener_settings}
  [listeners.backend_tls]
  danger_accept_invalid_certs = false

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"
  server_name = "api.internal"

  [[listeners.backends]]
  id = "b2"
  address = "127.0.0.1:9002"
  server_name = "api.internal"

{health_check}
  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        )
    }

    /// The regression test for fix #2: without duplicate detection, `b1` and
    /// `b2` above would both parse fine, and `lb_proxy::resolver::PinnedResolver`'s
    /// `server_name -> address` table would silently collapse them onto
    /// whichever address is registered last -- load balancing becomes a
    /// no-op, and outcomes get attributed to the wrong backend's circuit
    /// breaker.
    #[test]
    fn duplicate_server_names_on_an_http_listener_are_rejected() {
        let toml = duplicate_server_name_toml("http");
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("b1"), "error must name one backend: {err}");
        assert!(
            err.contains("b2"),
            "error must name the other backend: {err}"
        );
        assert!(
            err.contains("api.internal"),
            "error must show the shared server_name: {err}"
        );
    }

    /// The mirror image, proving the HTTP-only scoping above is a deliberate
    /// choice and not an oversight: L4 has no shared resolver table (each
    /// connection dials its own backend's own `address`), so several TCP
    /// backends sharing one certificate name is an ordinary, working
    /// topology and must not be rejected.
    #[test]
    fn duplicate_server_names_on_a_tcp_listener_are_allowed() {
        let toml = duplicate_server_name_toml("tcp");
        assert!(Config::parse(&toml).is_ok());
    }

    #[test]
    fn hsts_is_rejected_on_a_tcp_listener() {
        let toml = tcp_listener_with_hsts_toml();
        let err = Config::parse(&toml).unwrap_err().to_string();
        // A TCP listener has no responses to put a header on.
        assert!(err.contains("hsts"), "unhelpful error: {err}");
    }

    #[test]
    fn tls_version_strings_use_dotted_form() {
        assert_eq!(
            TlsVersion::try_from("1.3".to_string()).unwrap(),
            TlsVersion::Tls13
        );
        assert!(TlsVersion::try_from("1.1".to_string()).is_err());
    }

    /// Full valid config for a TLS-terminating HTTP listener with no
    /// `[listeners.http2]` section at all.
    fn tls_listener_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.tls]
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "/etc/lb/a.crt"
    key_file = "/etc/lb/a.key"
    hostnames = ["example.com"]

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    /// Same TLS listener as `tls_listener_toml`, but with HTTP/2 explicitly
    /// switched off.
    fn tls_listener_with_http2_disabled_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.tls]
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "/etc/lb/a.crt"
    key_file = "/etc/lb/a.key"
    hostnames = ["example.com"]

  [listeners.http2]
  enabled = false

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    /// Full valid config for a plaintext (no `tls` section) HTTP listener.
    fn plaintext_listener_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:8080"

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    /// Full valid config for a TCP listener that also carries an
    /// `[listeners.http2]` section -- a combination that must be rejected,
    /// since the L4 data plane has no application protocol to speak HTTP/2
    /// over.
    fn tcp_listener_with_http2_toml() -> String {
        r#"
[[listeners]]
name = "postgres"
protocol = "tcp"
listen = "0.0.0.0:5432"

  [listeners.http2]
  max_concurrent_streams = 64

  [[listeners.backends]]
  id = "pg1"
  address = "10.0.0.5:5432"

  [listeners.health_check]
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    /// Full valid config for a TLS listener whose `[listeners.http2]`
    /// section sets `max_concurrent_streams = 0`.
    fn tls_listener_with_zero_streams_toml() -> String {
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:443"

  [listeners.tls]
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "/etc/lb/a.crt"
    key_file = "/etc/lb/a.key"
    hostnames = ["example.com"]

  [listeners.http2]
  max_concurrent_streams = 0

  [[listeners.backends]]
  id = "b1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
  interval_ms = 1000
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 500

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10
  burst = 10

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        .to_string()
    }

    #[test]
    fn http2_defaults_are_safe_without_configuration() {
        let config = Config::parse(&tls_listener_toml()).unwrap();
        let listener = &config.listeners[0];
        // A TLS listener gets HTTP/2 and every protection without the operator
        // writing an [listeners.http2] section at all.
        assert!(listener.http2_enabled());

        let h2 = listener.http2.clone().unwrap_or_default();
        assert_eq!(h2.max_concurrent_streams(), 128);
        // Matches h2's own built-in bound rather than sitting above it. A
        // default looser than the library's buys nothing: the library would
        // clamp first, and "safe unconfigured" would be the library's claim
        // rather than ours.
        assert_eq!(h2.max_pending_accept_reset_streams(), 20);
        assert_eq!(h2.max_local_error_reset_streams(), 128);
        assert_eq!(h2.max_header_list_size(), 16384);
        assert_eq!(h2.max_frame_size(), 16384);
        assert_eq!(h2.keep_alive_interval(), Duration::from_secs(20));
        assert_eq!(h2.keep_alive_timeout(), Duration::from_secs(10));
        assert!(!h2.backend_h2c());
    }

    #[test]
    fn http2_can_be_disabled_on_a_tls_listener() {
        let config = Config::parse(&tls_listener_with_http2_disabled_toml()).unwrap();
        assert!(!config.listeners[0].http2_enabled());
    }

    #[test]
    fn a_plaintext_listener_never_enables_http2() {
        // No ALPN without TLS, and this node is the edge -- h2c on an
        // unencrypted public port is attack surface nobody asked for.
        let config = Config::parse(&plaintext_listener_toml()).unwrap();
        assert!(!config.listeners[0].http2_enabled());
    }

    #[test]
    fn http2_is_rejected_on_a_tcp_listener() {
        let err = Config::parse(&tcp_listener_with_http2_toml())
            .unwrap_err()
            .to_string();
        // HTTP/2 is an application protocol; the L4 data plane does not parse one.
        assert!(err.contains("http2"), "unhelpful error: {err}");
    }

    #[test]
    fn a_zero_max_concurrent_streams_is_rejected() {
        // Zero would advertise "you may open no streams", which is a listener
        // that accepts connections and then serves nothing -- worse than being
        // switched off, because it looks healthy.
        let err = Config::parse(&tls_listener_with_zero_streams_toml())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("max_concurrent_streams"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn backend_h2c_with_backend_tls_is_rejected() {
        let mut toml = tls_backend_toml(Some("web1.internal"), false);
        toml.push_str("\n  [listeners.http2]\n  backend_h2c = true\n");
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("backend_h2c"), "unhelpful error: {err}");
        assert!(err.contains("backend_tls"), "unhelpful error: {err}");
    }

    #[test]
    fn parses_least_connections_strategy() {
        let text = VALID.replacen(
            "strategy = \"round_robin\"",
            "strategy = \"least_connections\"",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.listeners[0].load_balancing.strategy,
            LoadBalancingStrategy::LeastConnections
        );
    }

    #[test]
    fn parses_weighted_round_robin_strategy() {
        let text = VALID.replacen(
            "strategy = \"round_robin\"",
            "strategy = \"weighted_round_robin\"",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.listeners[0].load_balancing.strategy,
            LoadBalancingStrategy::WeightedRoundRobin
        );
    }

    #[test]
    fn parses_consistent_hash_strategy() {
        let text = VALID.replacen(
            "strategy = \"round_robin\"",
            "strategy = \"consistent_hash\"",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.listeners[0].load_balancing.strategy,
            LoadBalancingStrategy::ConsistentHash
        );
    }

    #[test]
    fn backend_weight_defaults_to_one() {
        let cfg = Config::parse(VALID).unwrap();
        assert_eq!(cfg.listeners[0].backends[0].weight, 1);
    }

    #[test]
    fn parses_peak_ewma_p2c_strategy() {
        let text = VALID.replacen(
            "strategy = \"round_robin\"",
            "strategy = \"peak_ewma_p2c\"",
            1,
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(
            cfg.listeners[0].load_balancing.strategy,
            LoadBalancingStrategy::PeakEwmaP2c
        );
    }
}
