use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Round-robin over a sequence where each eligible backend appears
/// `weight` times (default 1, so an all-default-weight config behaves
/// exactly like plain `RoundRobin`). Rebuilt from `eligible_backends()` on
/// every `pick()` rather than cached: backend counts and weights here are
/// small enough (operator-configured, not request-scale) that flattening
/// them each call is negligible next to the network I/O a proxied request
/// actually does, and it means a health/circuit change is reflected
/// immediately with no invalidation to get wrong.
///
/// A weight of `0` deliberately excludes a backend from this rotation
/// entirely -- a "drain without deleting the entry" escape hatch -- rather
/// than being clamped up to 1. Any weight above `MAX_WEIGHT` is clamped
/// down to it, so a config typo (or a very large `weight`) can't make one
/// `pick()` call flatten into a multi-million-entry allocation.
const MAX_WEIGHT: u32 = 1000;

#[derive(Default)]
pub struct WeightedRoundRobin {
    cursor: AtomicUsize,
}

impl WeightedRoundRobin {
    pub fn new() -> Self {
        WeightedRoundRobin {
            cursor: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancer for WeightedRoundRobin {
    fn pick(&self, pool: &BackendPool, _key: &str) -> Option<BackendId> {
        let mut expanded = Vec::new();
        for id in pool.eligible_backends() {
            let weight = pool.backend(&id).map(|b| b.weight).unwrap_or(1);
            let weight = weight.min(MAX_WEIGHT);
            for _ in 0..weight {
                expanded.push(id.clone());
            }
        }
        if expanded.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % expanded.len();
        Some(expanded[idx].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;

    fn pool_with_weights(entries: &[(&str, u32)]) -> BackendPool {
        let backends = entries
            .iter()
            .map(|(id, weight)| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), *weight, None))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn default_weights_behave_like_plain_round_robin() {
        let pool = pool_with_weights(&[("b1", 1), ("b2", 1), ("b3", 1)]);
        let wrr = WeightedRoundRobin::new();
        let picks: Vec<_> = (0..6).map(|_| wrr.pick(&pool, "").unwrap()).collect();
        assert_eq!(
            picks,
            vec![
                BackendId::new("b1"),
                BackendId::new("b2"),
                BackendId::new("b3"),
                BackendId::new("b1"),
                BackendId::new("b2"),
                BackendId::new("b3"),
            ]
        );
    }

    /// The point of the whole strategy, and incidentally the first test in
    /// this codebase that proves `Backend.weight` does anything at all.
    #[test]
    fn a_heavier_backend_is_picked_proportionally_more_often() {
        let pool = pool_with_weights(&[("light", 1), ("heavy", 3)]);
        let wrr = WeightedRoundRobin::new();
        let picks: Vec<_> = (0..8).map(|_| wrr.pick(&pool, "").unwrap()).collect();
        let heavy_count = picks
            .iter()
            .filter(|id| **id == BackendId::new("heavy"))
            .count();
        let light_count = picks
            .iter()
            .filter(|id| **id == BackendId::new("light"))
            .count();
        assert_eq!(heavy_count, 6);
        assert_eq!(light_count, 2);
    }

    #[test]
    fn zero_weight_excludes_a_backend_without_removing_it() {
        let pool = pool_with_weights(&[("drained", 0), ("active", 1)]);
        let wrr = WeightedRoundRobin::new();
        let picks: Vec<_> = (0..4).map(|_| wrr.pick(&pool, "").unwrap()).collect();
        assert!(picks.iter().all(|id| *id == BackendId::new("active")));
    }

    #[test]
    fn skips_ineligible_backends() {
        let pool = pool_with_weights(&[("b1", 1), ("b2", 5)]);
        pool.set_active_healthy(&BackendId::new("b2"), false);
        let wrr = WeightedRoundRobin::new();
        for _ in 0..4 {
            assert_eq!(wrr.pick(&pool, ""), Some(BackendId::new("b1")));
        }
    }

    #[test]
    fn returns_none_when_no_backends_eligible() {
        let pool = pool_with_weights(&[("b1", 1)]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let wrr = WeightedRoundRobin::new();
        assert_eq!(wrr.pick(&pool, ""), None);
    }

    #[test]
    fn an_enormous_weight_is_clamped_rather_than_allocating_unbounded() {
        let pool = pool_with_weights(&[("b1", u32::MAX)]);
        let wrr = WeightedRoundRobin::new();
        // Would hang/OOM building a `u32::MAX`-entry Vec if unclamped; this
        // completing at all is the assertion.
        assert_eq!(wrr.pick(&pool, ""), Some(BackendId::new("b1")));
    }
}
