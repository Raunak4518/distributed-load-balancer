use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

/// Virtual nodes per unit of `weight` (so a weight-3 backend claims 3x the
/// ring real estate of a weight-1 one, same idea `WeightedRoundRobin` uses).
const VIRTUAL_NODES_PER_WEIGHT_UNIT: u32 = 10;
/// Weight is capped before scaling, same reasoning as
/// `weighted_round_robin::MAX_WEIGHT`: bounds how large one `pick()` call's
/// ring-building work can get regardless of a config typo.
const MAX_WEIGHT: u32 = 100;

/// Caches the ring built from *every* backend (not just eligible ones) and
/// rebuilds it only when `BackendPool::version()` changes -- i.e. on real
/// membership/weight changes (`apply_resolved`), never on a health/circuit/
/// drain/outlier flip. Those flip far more often than membership changes and
/// must stay cheap, so `pick()` never hashes or sorts on the request path
/// once the ring is warm: it just clones the cached `Arc<Ring>` (a refcount
/// bump) and binary-searches it.
///
/// Because the ring is built from every backend, a currently-ineligible
/// backend still owns its points. `pick()` walks forward from the binary
/// search's landing point (wrapping, bounded by the ring's length so it
/// always terminates) and skips any point whose backend
/// `pool.is_eligible()` reports down -- reproducing the same "minimal
/// remapping" property the old rebuild-from-eligible-only design got from
/// simply omitting a down backend's points: a key that would have landed on
/// a down backend's point falls through to the next hash-adjacent one.
///
/// Published through `RwLock<Arc<Ring>>` rather than a plain `Mutex`: reads
/// (the overwhelmingly common case, since membership rarely changes) only
/// clone an `Arc` under a read lock, so concurrent `pick()` calls never
/// block each other. A rebuild swaps the `Arc` under a brief write lock and
/// never mutates the old `Ring` in place, so a reader either sees the ring
/// from before the swap or the one from after -- never a partially built one.
#[derive(Default)]
pub struct ConsistentHash {
    cached: RwLock<Arc<Ring>>,
}

#[derive(Default)]
struct Ring {
    pool_ptr: usize,
    version: u64,
    points: Vec<(u64, BackendId)>,
}

impl ConsistentHash {
    pub fn new() -> Self {
        ConsistentHash::default()
    }

    fn ring_for(&self, pool: &BackendPool) -> Arc<Ring> {
        let pool_ptr = pool as *const BackendPool as usize;
        let version = pool.version();

        let cached = Arc::clone(&self.cached.read().unwrap_or_else(|e| e.into_inner()));
        if cached.pool_ptr == pool_ptr && cached.version == version {
            return cached;
        }

        let mut points: Vec<(u64, BackendId)> = Vec::new();
        for id in pool.all_backend_ids() {
            let weight = pool
                .backend(&id)
                .map(|b| b.weight)
                .unwrap_or(1)
                .min(MAX_WEIGHT);
            for v in 0..(weight * VIRTUAL_NODES_PER_WEIGHT_UNIT) {
                let point = hash_str(&format!("{}\0{v}", id.0));
                points.push((point, id.clone()));
            }
        }
        points.sort_by_key(|(h, _)| *h);

        let fresh = Arc::new(Ring {
            pool_ptr,
            version,
            points,
        });
        *self.cached.write().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&fresh);
        fresh
    }
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

impl LoadBalancer for ConsistentHash {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        let ring = self.ring_for(pool);
        let len = ring.points.len();
        if len == 0 {
            return None;
        }

        let target = hash_str(key);
        let start = ring.points.partition_point(|(h, _)| *h < target) % len;
        for offset in 0..len {
            let idx = (start + offset) % len;
            let (_, id) = &ring.points[idx];
            if pool.is_eligible(id) {
                return Some(id.clone());
            }
        }
        None
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

    #[test]
    fn the_ring_is_reused_across_picks_when_the_pool_is_unchanged() {
        let pool = pool_of(&["b1", "b2", "b3"]);
        let ch = ConsistentHash::new();
        let first = ch.ring_for(&pool);
        let second = ch.ring_for(&pool);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn the_ring_does_not_rebuild_on_an_eligibility_flip() {
        let pool = pool_of(&["b1", "b2"]);
        let ch = ConsistentHash::new();
        let first = ch.ring_for(&pool);
        pool.set_active_healthy(&BackendId::new("b1"), false);
        let second = ch.ring_for(&pool);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn the_ring_rebuilds_after_a_membership_change() {
        let pool = pool_of(&["b1", "b2"]);
        let ch = ConsistentHash::new();
        let first = ch.ring_for(&pool);
        pool.apply_resolved(vec![
            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("b3", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);
        let second = ch.ring_for(&pool);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.points.len(), first.points.len() + 10);
    }

    #[test]
    fn concurrent_picks_survive_concurrent_membership_changes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pool = Arc::new(pool_of(&["b1", "b2", "b3"]));
        let ch = Arc::new(ConsistentHash::new());
        let stop = Arc::new(AtomicBool::new(false));

        let updater = {
            let pool = Arc::clone(&pool);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut toggle = false;
                while !stop.load(Ordering::Relaxed) {
                    toggle = !toggle;
                    let backends = if toggle {
                        vec![
                            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
                            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 3, None),
                        ]
                    } else {
                        vec![
                            Backend::new("b1", "127.0.0.1:9000".parse().unwrap(), 1, None),
                            Backend::new("b2", "127.0.0.1:9000".parse().unwrap(), 1, None),
                            Backend::new("b3", "127.0.0.1:9000".parse().unwrap(), 1, None),
                        ]
                    };
                    pool.apply_resolved(backends);
                }
            })
        };

        let pickers: Vec<_> = (0..4)
            .map(|t| {
                let pool = Arc::clone(&pool);
                let ch = Arc::clone(&ch);
                std::thread::spawn(move || {
                    for i in 0..5000 {
                        let key = format!("client-{t}-{i}");
                        let _ = ch.pick(&pool, &key);
                    }
                })
            })
            .collect();

        for p in pickers {
            p.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        updater.join().unwrap();

        pool.apply_resolved(vec![Backend::new(
            "only",
            "127.0.0.1:9000".parse().unwrap(),
            1,
            None,
        )]);
        for i in 0..20 {
            assert_eq!(
                ch.pick(&pool, &format!("final-{i}")),
                Some(BackendId::new("only"))
            );
        }
    }
}
