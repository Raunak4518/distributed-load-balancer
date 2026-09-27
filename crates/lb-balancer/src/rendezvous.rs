use crate::hash::hash_parts;
use lb_core::{BackendId, BackendPool, LoadBalancer};

#[derive(Default)]
pub struct RendezvousHash;

impl RendezvousHash {
    pub fn new() -> Self {
        RendezvousHash
    }
}

fn score(key: &str, id: &BackendId, weight: u32) -> f64 {
    let h = hash_parts(&[key.as_bytes(), id.0.as_bytes()]);
    let unit = ((h >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    f64::from(weight) / -unit.ln()
}

impl LoadBalancer for RendezvousHash {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        pool.eligible_with_weights()
            .into_iter()
            .filter(|(id, weight)| *weight > 0 && !excluded.contains(id))
            .map(|(id, weight)| (score(key, &id, weight), id))
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, id)| id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;

    fn pool_of(backends: &[(&str, u32)]) -> BackendPool {
        BackendPool::new(
            backends
                .iter()
                .map(|(id, weight)| {
                    Backend::new(*id, "127.0.0.1:9000".parse().unwrap(), *weight, None)
                })
                .collect(),
        )
    }

    #[test]
    fn the_same_key_always_lands_on_the_same_backend() {
        let pool = pool_of(&[("a", 1), ("b", 1), ("c", 1)]);
        let hrw = RendezvousHash::new();
        let first = hrw.pick(&pool, "client-9").unwrap();
        for _ in 0..10 {
            assert_eq!(hrw.pick(&pool, "client-9"), Some(first.clone()));
        }
    }

    #[test]
    fn a_heavier_backend_owns_a_proportionally_larger_share() {
        let pool = pool_of(&[("light", 1), ("heavy", 3)]);
        let hrw = RendezvousHash::new();
        let heavy = (0..8_000)
            .filter(|i| hrw.pick(&pool, &format!("k{i}")) == Some(BackendId::new("heavy")))
            .count();
        assert!(
            (5_600..=6_400).contains(&heavy),
            "heavy got {heavy} of 8000"
        );
    }

    #[test]
    fn zero_weight_and_ineligible_backends_are_never_picked() {
        let pool = pool_of(&[("zero", 0), ("down", 1), ("up", 1)]);
        pool.set_active_healthy(&BackendId::new("down"), false);
        let hrw = RendezvousHash::new();
        for i in 0..100 {
            assert_eq!(
                hrw.pick(&pool, &format!("k{i}")),
                Some(BackendId::new("up"))
            );
        }
    }
}
