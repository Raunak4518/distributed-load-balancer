use lb_core::{BackendId, BackendPool, LoadBalancer};

/// Picks the eligible backend with the fewest in-flight requests/
/// connections, per `BackendPool::active_count` — which only means anything
/// because the caller wraps every attempt in `BackendPool::track_active`.
/// Ties go to whichever comes first in `eligible_backends()`'s order,
/// deliberately not randomized: a stable tie-break makes this
/// reproducible in tests, and an even split at zero load doesn't need
/// randomness to look even.
#[derive(Default)]
pub struct LeastConnections;

impl LeastConnections {
    pub fn new() -> Self {
        LeastConnections
    }
}

impl LoadBalancer for LeastConnections {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        _key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        pool.eligible_backends()
            .into_iter()
            .filter(|id| !excluded.contains(id))
            .min_by_key(|id| pool.active_count(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;
    use std::sync::Arc;

    fn pool_of(ids: &[&str]) -> Arc<BackendPool> {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        Arc::new(BackendPool::new(backends))
    }

    #[test]
    fn picks_the_backend_with_fewer_active_connections() {
        let pool = pool_of(&["b1", "b2"]);
        let _busy = pool.track_active(&BackendId::new("b1"));
        let lc = LeastConnections::new();
        assert_eq!(lc.pick(&pool, ""), Some(BackendId::new("b2")));
    }

    #[test]
    fn an_even_load_picks_the_first_eligible_backend() {
        let pool = pool_of(&["b1", "b2"]);
        let lc = LeastConnections::new();
        assert_eq!(lc.pick(&pool, ""), Some(BackendId::new("b1")));
    }

    #[test]
    fn skips_ineligible_backends_even_if_they_have_no_load() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let _busy = pool.track_active(&BackendId::new("b2"));
        let lc = LeastConnections::new();
        assert_eq!(lc.pick(&pool, ""), Some(BackendId::new("b2")));
    }

    #[test]
    fn returns_none_when_no_backends_eligible() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let lc = LeastConnections::new();
        assert_eq!(lc.pick(&pool, ""), None);
    }

    #[test]
    fn rebalances_as_connections_finish() {
        let pool = pool_of(&["b1", "b2"]);
        let lc = LeastConnections::new();

        let first = lc.pick(&pool, "").unwrap();
        let guard = pool.track_active(&first);
        // With one backend now busy, the other must win next.
        let second = lc.pick(&pool, "").unwrap();
        assert_ne!(first, second);

        drop(guard);
        // Even again -- back to the stable first-eligible tie-break.
        assert_eq!(lc.pick(&pool, ""), Some(BackendId::new("b1")));
    }
}
