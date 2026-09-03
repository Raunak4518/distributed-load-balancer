use crate::error::ConfigError;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub backends: Vec<BackendConfig>,
    pub health_check: HealthCheckConfig,
    pub rate_limit: RateLimitConfig,
    pub load_balancing: LoadBalancingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_forward_timeout_ms")]
    pub forward_timeout_ms: u64,
}

fn default_max_request_body_bytes() -> usize {
    1024 * 1024
}

fn default_forward_timeout_ms() -> u64 {
    5000
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
    pub path: String,
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
            Err(format!("invalid rate_limit.key '{s}': expected 'source_ip' or 'header:<name>'"))
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
        let text = std::fs::read_to_string(path_ref)
            .map_err(|source| ConfigError::Io { path: path_ref.display().to_string(), source })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.backends.is_empty() {
            return Err(ConfigError::Invalid("at least one backend is required".into()));
        }
        if self.rate_limit.rate_per_sec <= 0.0 {
            return Err(ConfigError::Invalid("rate_limit.rate_per_sec must be positive".into()));
        }
        if self.rate_limit.burst == 0 {
            return Err(ConfigError::Invalid("rate_limit.burst must be positive".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for b in &self.backends {
            if !seen.insert(&b.id) {
                return Err(ConfigError::Invalid(format!("duplicate backend id: {}", b.id)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [server]
        listen = "0.0.0.0:8080"

        [[backends]]
        id = "b1"
        address = "127.0.0.1:9001"

        [[backends]]
        id = "b2"
        address = "127.0.0.1:9002"
        weight = 2

        [health_check]
        path = "/health"
        interval_ms = 2000
        timeout_ms = 500
        failure_threshold = 3
        cooldown_ms = 5000

        [rate_limit]
        key = "source_ip"
        rate_per_sec = 50
        burst = 100

        [load_balancing]
        strategy = "round_robin"
    "#;

    #[test]
    fn parses_valid_config() {
        let cfg = Config::parse(VALID).expect("valid config should parse");
        assert_eq!(cfg.backends.len(), 2);
        assert_eq!(cfg.backends[0].weight, 1); // default applied
        assert_eq!(cfg.backends[1].weight, 2);
        assert_eq!(cfg.rate_limit.key, RateLimitKeySource::SourceIp);
        assert_eq!(cfg.load_balancing.strategy, LoadBalancingStrategy::RoundRobin);
        assert_eq!(cfg.server.max_request_body_bytes, 1024 * 1024); // default applied
    }

    #[test]
    fn parses_header_based_rate_limit_key() {
        let text = VALID.replace(r#"key = "source_ip""#, r#"key = "header:X-API-Key""#);
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.rate_limit.key, RateLimitKeySource::Header("X-API-Key".into()));
    }

    #[test]
    fn rejects_empty_backends() {
        const NO_BACKENDS: &str = r#"
            backends = []

            [server]
            listen = "0.0.0.0:8080"

            [health_check]
            path = "/health"
            interval_ms = 2000
            timeout_ms = 500
            failure_threshold = 3
            cooldown_ms = 5000

            [rate_limit]
            key = "source_ip"
            rate_per_sec = 50
            burst = 100

            [load_balancing]
            strategy = "round_robin"
        "#;
        assert!(matches!(Config::parse(NO_BACKENDS), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_non_positive_rate() {
        let text = VALID.replace("rate_per_sec = 50", "rate_per_sec = 0");
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_duplicate_backend_ids() {
        let text = VALID.replace(r#"id = "b2""#, r#"id = "b1""#);
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_unknown_rate_limit_key_format() {
        let text = VALID.replace(r#"key = "source_ip""#, r#"key = "nonsense""#);
        assert!(Config::parse(&text).is_err());
    }
}
