use crate::error::ConfigError;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub address: SocketAddr,
    #[serde(default = "default_weight")]
    pub weight: u32,
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
        }
        Ok(())
    }
}

impl ListenerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid =
            |msg: String| ConfigError::Invalid(format!("listener '{}': {msg}", self.name));

        if self.backends.is_empty() {
            return Err(invalid("at least one backend is required".into()));
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

    const CLUSTER: &str = r#"
        [cluster]
        node_id = "lb-1"
        listen = "127.0.0.1:7946"
        peers = ["127.0.0.1:7947"]
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
    fn rejects_duplicate_backend_ids_within_a_listener() {
        let text = VALID.replace(
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"",
            "          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9001\"\n\n          [[listeners.backends]]\n          id = \"web1\"\n          address = \"127.0.0.1:9002\"",
        );
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }
}
