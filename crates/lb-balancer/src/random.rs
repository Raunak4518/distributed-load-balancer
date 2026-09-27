use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::sync::atomic::{AtomicU64, Ordering};

struct Rng(AtomicU64);

impl Rng {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Rng(AtomicU64::new(seed | 1))
    }

    fn next(&self) -> u64 {
        let mut x = self.0.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0.store(x, Ordering::Relaxed);
        x
    }

    fn below(&self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

pub struct Random {
    rng: Rng,
}

impl Default for Random {
    fn default() -> Self {
        Random { rng: Rng::seeded() }
    }
}

impl Random {
    pub fn new() -> Self {
        Random::default()
    }
}

impl LoadBalancer for Random {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        _key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        let mut eligible = pool.eligible_backends();
        eligible.retain(|id| !excluded.contains(id));
        if eligible.is_empty() {
            return None;
        }
        Some(eligible.swap_remove(self.rng.below(eligible.len())))
    }
}

pub struct WeightedRandom {
    rng: Rng,
}

impl Default for WeightedRandom {
    fn default() -> Self {
        WeightedRandom { rng: Rng::seeded() }
    }
}

impl WeightedRandom {
    pub fn new() -> Self {
        WeightedRandom::default()
    }
}

impl LoadBalancer for WeightedRandom {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        _key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        let candidates: Vec<(BackendId, u64)> = pool
            .eligible_with_weights()
            .into_iter()
            .filter(|(id, weight)| *weight > 0 && !excluded.contains(id))
            .map(|(id, weight)| (id, u64::from(weight)))
            .collect();
        let total: u64 = candidates.iter().map(|(_, w)| w).sum();
        if total == 0 {
            return None;
        }
        let mut target = self.rng.next() % total;
        for (id, weight) in candidates {
            if target < weight {
                return Some(id);
            }
            target -= weight;
        }
        None
    }
}

pub struct LeastRequest {
    rng: Rng,
}

impl Default for LeastRequest {
    fn default() -> Self {
        LeastRequest { rng: Rng::seeded() }
    }
}

impl LeastRequest {
    pub fn new() -> Self {
        LeastRequest::default()
    }
}

impl LoadBalancer for LeastRequest {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        _key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        let mut eligible = pool.eligible_backends();
        eligible.retain(|id| !excluded.contains(id));
        match eligible.len() {
            0 => None,
            1 => eligible.pop(),
            n => {
                let first = self.rng.below(n);
                let mut second = self.rng.below(n - 1);
                if second >= first {
                    second += 1;
                }
                let (a, b) = (&eligible[first], &eligible[second]);
                let winner = if pool.active_count(b) < pool.active_count(a) {
                    b
                } else {
                    a
                };
                Some(winner.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::Backend;
    use std::collections::HashMap;

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

    fn counts(lb: &dyn LoadBalancer, pool: &BackendPool, picks: usize) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for _ in 0..picks {
            *counts
                .entry(lb.pick(pool, "k").unwrap().0.to_string())
                .or_insert(0) += 1;
        }
        counts
    }

    #[test]
    fn random_spreads_evenly_and_skips_ineligible_backends() {
        let pool = pool_of(&[("a", 1), ("b", 1), ("c", 1), ("down", 1)]);
        pool.set_active_healthy(&BackendId::new("down"), false);
        let counts = counts(&Random::new(), &pool, 9_000);
        assert!(!counts.contains_key("down"));
        for id in ["a", "b", "c"] {
            assert!(
                (2_700..=3_300).contains(&counts[id]),
                "{id}: {}",
                counts[id]
            );
        }
    }

    #[test]
    fn weighted_random_follows_the_weights() {
        let pool = pool_of(&[("light", 1), ("heavy", 3), ("zero", 0)]);
        let counts = counts(&WeightedRandom::new(), &pool, 8_000);
        assert!(!counts.contains_key("zero"));
        assert!(
            (5_600..=6_400).contains(&counts["heavy"]),
            "heavy: {}",
            counts["heavy"]
        );
    }

    #[test]
    fn least_request_prefers_the_less_loaded_of_its_two_samples() {
        let pool = std::sync::Arc::new(pool_of(&[("busy", 1), ("idle", 1)]));
        let _load: Vec<_> = (0..5)
            .map(|_| pool.track_active(&BackendId::new("busy")))
            .collect();
        let counts = counts(&LeastRequest::new(), &pool, 500);
        assert_eq!(counts.get("busy"), None);
        assert_eq!(counts["idle"], 500);
    }

    #[test]
    fn least_request_still_spreads_load_among_equally_idle_backends() {
        let pool = pool_of(&[("a", 1), ("b", 1), ("c", 1), ("d", 1)]);
        let counts = counts(&LeastRequest::new(), &pool, 8_000);
        for id in ["a", "b", "c", "d"] {
            assert!(
                (1_500..=2_500).contains(&counts[id]),
                "{id}: {}",
                counts[id]
            );
        }
    }
}
