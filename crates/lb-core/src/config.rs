use crate::error::ConfigError;
use crate::http2::Http2Config;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    /// Bind privately. This surface exposes internal topology (backend names,
    /// health, traffic volumes) and must never face the public internet.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub protocol: Protocol,
    pub listen: SocketAddr,

    // HTTP-only
    pub forward_timeout_ms: Option<u64>,
    pub max_request_body_bytes: Option<usize>,

    // TCP-only
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,

    // Edge hardening — defaults applied by the accessors below.
    pub max_connections: Option<usize>,
    pub max_connections_per_ip: Option<usize>,
    pub header_read_timeout_ms: Option<u64>,
    pub body_read_timeout_ms: Option<u64>,

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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct BackendTlsConfig {
    /// Omit for the system trust store. Internal PKI is the common case on
    /// this path, which is why the file form exists at all.
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub danger_accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub address: SocketAddr,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Required for HTTP listeners, forbidden for TCP listeners (there is
    /// nothing to GET on a Postgres port).
    pub path: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancingConfig {
    pub strategy: LoadBalancingStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    RoundRobin,
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
        let mut ids = HashSet::new();
        for b in &self.backends {
            if !ids.insert(&b.id) {
                return Err(invalid(format!("duplicate backend id: {}", b.id)));
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
        if self.header_read_timeout().is_zero() || self.body_read_timeout().is_zero() {
            return Err(invalid(
                "header_read_timeout_ms and body_read_timeout_ms must be positive".into(),
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
            }
            Protocol::Tcp => {
                if self.health_check.path.is_some() {
                    return Err(invalid(
                        "health_check.path is http-only — a tcp backend has no path to probe"
                            .into(),
                    ));
                }
                if self.forward_timeout_ms.is_some() || self.max_request_body_bytes.is_some() {
                    return Err(invalid(
                        "forward_timeout_ms/max_request_body_bytes are http-only settings".into(),
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
        let text = format!(
            "[tracing]\notlp_endpoint = \"http://localhost:4318\"\n\n{VALID}"
        );
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
        assert!(err.contains("tracing.otlp_endpoint"), "unhelpful error: {err}");
    }

    #[test]
    fn rejects_out_of_range_tracing_sample_ratio() {
        let text = format!(
            "[tracing]\notlp_endpoint = \"http://localhost:4318\"\nsample_ratio = 1.5\n\n{VALID}"
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("tracing.sample_ratio"), "unhelpful error: {err}");
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
}
