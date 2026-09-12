use crate::backend::BackendId;
use crate::pool::BackendPool;

pub trait LoadBalancer: Send + Sync {
    /// `key` is whatever the caller already uses to key rate limiting
    /// (`source_ip`, or a header value) -- passed through rather than
    /// separately configured, so a listener's existing identity choice is
    /// also its sticky-routing identity. Strategies that don't need one
    /// (`RoundRobin`, `LeastConnections`, `WeightedRoundRobin`) ignore it.
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId>;
}
