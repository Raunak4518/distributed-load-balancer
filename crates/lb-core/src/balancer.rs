use crate::backend::BackendId;
use crate::pool::BackendPool;
use std::time::Duration;

pub trait LoadBalancer: Send + Sync {
    /// `key` is whatever the caller already uses to key rate limiting
    /// (`source_ip`, or a header value) -- passed through rather than
    /// separately configured, so a listener's existing identity choice is
    /// also its sticky-routing identity. Strategies that don't need one
    /// (`RoundRobin`, `LeastConnections`, `WeightedRoundRobin`) ignore it.
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId>;

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        match self.pick(pool, key) {
            Some(id) if !excluded.contains(&id) => Some(id),
            _ => pool
                .eligible_backends()
                .into_iter()
                .find(|id| !excluded.contains(id)),
        }
    }

    /// Feedback from one completed attempt against `id` -- called
    /// unconditionally by both the HTTP and TCP data planes after every
    /// attempt, success or failure alike, so a strategy that wants it never
    /// has to be specially wired in. Default no-op: `RoundRobin`,
    /// `LeastConnections`, `WeightedRoundRobin`, and `ConsistentHash` have no
    /// use for it and need no change. `PeakEwmaP2c` is the one strategy that
    /// overrides this.
    fn record_latency(&self, _id: &BackendId, _latency: Duration) {}
}
