use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Virtual nodes per unit of `weight` (so a weight-3 backend claims 3x the
/// ring real estate of a weight-1 one, same idea `WeightedRoundRobin` uses).
const VIRTUAL_NODES_PER_WEIGHT_UNIT: u32 = 10;
/// Weight is capped before scaling, same reasoning as
/// `weighted_round_robin::MAX_WEIGHT`: bounds how large one `pick()` call's
/// ring-building work can get regardless of a config typo.
const MAX_WEIGHT: u32 = 100;

/// Hashes the caller's key onto a ring built fresh from the *currently
/// eligible* backends on every `pick()` call — not cached. Two things make
/// that the right trade-off here, not a shortcut:
///
/// - A backend's virtual-node hash points depend only on its own id, never
///   on which other backends are present. So building the ring from
///   `eligible_backends()` directly (excluding a down backend's points
///   entirely) produces *exactly* the same routing decision as building
///   from every backend and skipping down ones during lookup would — the
///   keys that would have landed on the down backend's points simply fall
///   through to whichever backend's point is hash-adjacent, which is the
///   textbook "minimal remapping" property consistent hashing exists for.
///   Building from `eligible_backends()` gets that for free, with a plain
///   binary search instead of a skip-forward loop.
/// - Rebuilding avoids a whole class of cache-invalidation bugs a
///   persistent ring would need to get right (exactly when to rebuild on a
///   health flap vs. a real membership change). At the backend counts this
///   project targets, sorting a few hundred `u64`s per request is
///   negligible next to the network I/O the request itself does — a
///   deliberate trade-off, not an oversight.
#[derive(Default)]
pub struct ConsistentHash;

impl ConsistentHash {
    pub fn new() -> Self {
        ConsistentHash
    }
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

impl LoadBalancer for ConsistentHash {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        let mut ring: Vec<(u64, BackendId)> = Vec::new();
        for id in pool.eligible_backends() {
            let weight = pool
                .backend(&id)
                .map(|b| b.weight)
                .unwrap_or(1)
                .min(MAX_WEIGHT);
            for v in 0..(weight * VIRTUAL_NODES_PER_WEIGHT_UNIT) {
                let point = hash_str(&format!("{}\0{v}", id.0));
                ring.push((point, id.clone()));
            }
        }
        if ring.is_empty() {
            return None;
        }
        ring.sort_by_key(|(h, _)| *h);

        let target = hash_str(key);
        let idx = ring.partition_point(|(h, _)| *h < target) % ring.len();
        Some(ring[idx].1.clone())
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
    fn the_same_key_always_picks_the_same_backend() {
        let pool = pool_of(&["b1", "b2", "b3", "b4"]);
        let ch = ConsistentHash::new();
        let first = ch.pick(&pool, "client-42").unwrap();
        for _ in 0..20 {
            assert_eq!(ch.pick(&pool, "client-42"), Some(first.clone()));
        }
    }

    #[test]
    fn different_keys_spread_across_backends() {
        let pool = pool_of(&["b1", "b2", "b3", "b4"]);
        let ch = ConsistentHash::new();
        let picks: std::collections::HashSet<_> = (0..200)
            .map(|i| ch.pick(&pool, &format!("client-{i}")).unwrap())
            .collect();
        assert!(
            picks.len() > 1,
            "200 distinct keys all landed on the same backend"
        );
    }

    /// The actual point of consistent hashing over `key.hash() % len()`:
    /// removing one backend must not remap every key, only the ones that
    /// were closest to the removed backend's ring points.
    #[test]
    fn removing_a_backend_remaps_only_a_minority_of_keys() {
        let before = pool_of(&["b1", "b2", "b3", "b4"]);
        let after = pool_of(&["b1", "b2", "b3"]); // "b4" gone
        let ch = ConsistentHash::new();

        let keys: Vec<String> = (0..500).map(|i| format!("client-{i}")).collect();
        let remapped = keys
            .iter()
            .filter(|k| ch.pick(&before, k) != ch.pick(&after, k))
            .count();

        // A plain `hash(key) % len()` scheme remaps nearly everything when
        // the backend count changes; a real ring should remap roughly
        // 1/N of keys (here, ~25%). Generous bound to avoid a flaky test
        // while still failing hard against a naive modulo implementation.
        assert!(
            remapped < keys.len() / 2,
            "removing one of four backends remapped {remapped}/{} keys -- too close to a full remap",
            keys.len()
        );
    }

    #[test]
    fn skips_ineligible_backends() {
        let pool = pool_of(&["b1", "b2"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let ch = ConsistentHash::new();
        for i in 0..20 {
            assert_eq!(
                ch.pick(&pool, &format!("client-{i}")),
                Some(BackendId::new("b2"))
            );
        }
    }

    #[test]
    fn returns_none_when_no_backends_eligible() {
        let pool = pool_of(&["b1"]);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let ch = ConsistentHash::new();
        assert_eq!(ch.pick(&pool, "any-key"), None);
    }

    #[test]
    fn zero_weight_excludes_a_backend_from_the_ring() {
        let backends = vec![
            Backend::new("drained", "127.0.0.1:9000".parse().unwrap(), 0, None),
            Backend::new("active", "127.0.0.1:9001".parse().unwrap(), 1, None),
        ];
        let pool = BackendPool::new(backends);
        let ch = ConsistentHash::new();
        for i in 0..20 {
            assert_eq!(
                ch.pick(&pool, &format!("client-{i}")),
                Some(BackendId::new("active"))
            );
        }
    }
}
