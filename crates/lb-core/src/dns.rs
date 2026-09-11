use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct DnsDiscoveryConfig {
    pub name: String,
    pub port: u16,
    pub poll_interval_secs: Option<u64>,
    pub server_name: Option<String>,
}

impl DnsDiscoveryConfig {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs.unwrap_or(10))
    }
}
