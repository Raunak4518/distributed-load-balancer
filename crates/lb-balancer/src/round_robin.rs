use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub struct RoundRobin {
    cursor: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        RoundRobin {
            cursor: AtomicUsize::new(0),
        }
    }
}

impl LoadBalancer for RoundRobin {
    fn pick(&self, pool: &BackendPool, _key: &str) -> Option<BackendId> {
        let eligible = pool.eligible_backends();
        if eligible.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % eligible.len();
        Some(eligible[idx].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;

    fn pool_of(ids: &[&str]) -> BackendPool {
        let backends = ids
            .iter()
            .map(|id| Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), 1, None))
            .collect();
        BackendPool::new(backends)
    }

    #[test]
    fn cycles_through_all_eligible_backends() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        let rr = RoundRobin::new();
        let picks: Vec<_> = (0..6).map(|_| rr.pick(&pool, "").unwrap()).collect();
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

    #[test]
    fn skips_ineligible_backends() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        pool.set_active_healthy(&BackendId::new("b2"), false);
        let rr = RoundRobin::new();
        let picks: Vec<_> = (0..4).map(|_| rr.pick(&pool, "").unwrap()).collect();
        assert!(!picks.contains(&BackendId::new("b2")));
    }

    #[test]
    fn returns_none_when_no_backends_eligible() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let rr = RoundRobin::new();
        assert_eq!(rr.pick(&pool, ""), None);
    }
}
