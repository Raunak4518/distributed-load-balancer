use crate::hash::hash_parts;
use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::sync::{Arc, RwLock};

const TABLE_SIZE: usize = 65_537;
const MAX_WEIGHT: u32 = 100;

#[derive(Default)]
pub struct Maglev {
    cached: RwLock<Arc<Table>>,
}

#[derive(Default)]
struct Table {
    pool_ptr: usize,
    version: u64,
    backends: Vec<BackendId>,
    entries: Vec<u32>,
}

impl Maglev {
    pub fn new() -> Self {
        Maglev::default()
    }

    fn table_for(&self, pool: &BackendPool) -> Arc<Table> {
        let pool_ptr = pool as *const BackendPool as usize;
        let version = pool.version();
        let cached = Arc::clone(&self.cached.read().unwrap_or_else(|e| e.into_inner()));
        if cached.pool_ptr == pool_ptr && cached.version == version && !cached.backends.is_empty() {
            return cached;
        }
        let fresh = Arc::new(build(pool, pool_ptr, version));
        *self.cached.write().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&fresh);
        fresh
    }
}

fn build(pool: &BackendPool, pool_ptr: usize, version: u64) -> Table {
    let mut backends = Vec::new();
    let mut weights = Vec::new();
    for id in pool.all_backend_ids() {
        let weight = pool
            .backend(&id)
            .map(|b| b.weight)
            .unwrap_or(1)
            .min(MAX_WEIGHT);
        if weight > 0 {
            backends.push(id);
            weights.push(weight);
        }
    }
    if backends.is_empty() {
        return Table {
            pool_ptr,
            version,
            ..Table::default()
        };
    }
    let size = TABLE_SIZE as u64;
    let permutations: Vec<(u64, u64)> = backends
        .iter()
        .map(|id| {
            let offset = hash_parts(&[id.0.as_bytes(), b"offset"]) % size;
            let skip = hash_parts(&[id.0.as_bytes(), b"skip"]) % (size - 1) + 1;
            (offset, skip)
        })
        .collect();
    let mut next = vec![0u64; backends.len()];
    let mut entries = vec![u32::MAX; TABLE_SIZE];
    let mut filled = 0;
    'fill: loop {
        for (i, &(offset, skip)) in permutations.iter().enumerate() {
            for _ in 0..weights[i] {
                let mut slot = ((offset + next[i] * skip) % size) as usize;
                while entries[slot] != u32::MAX {
                    next[i] += 1;
                    slot = ((offset + next[i] * skip) % size) as usize;
                }
                entries[slot] = i as u32;
                next[i] += 1;
                filled += 1;
                if filled == TABLE_SIZE {
                    break 'fill;
                }
            }
        }
    }
    Table {
        pool_ptr,
        version,
        backends,
        entries,
    }
}

impl LoadBalancer for Maglev {
    fn pick(&self, pool: &BackendPool, key: &str) -> Option<BackendId> {
        self.pick_excluding(pool, key, &[])
    }

    fn pick_excluding(
        &self,
        pool: &BackendPool,
        key: &str,
        excluded: &[BackendId],
    ) -> Option<BackendId> {
        let table = self.table_for(pool);
        if table.backends.is_empty() {
            return None;
        }
        let start = (hash_parts(&[key.as_bytes()]) % TABLE_SIZE as u64) as usize;
        let first = &table.backends[table.entries[start] as usize];
        if !excluded.contains(first) && pool.is_eligible(first) {
            return Some(first.clone());
        }
        let mut seen = vec![false; table.backends.len()];
        let mut seen_count = 0;
        for offset in 0..TABLE_SIZE {
            let index = table.entries[(start + offset) % TABLE_SIZE] as usize;
            if seen[index] {
                continue;
            }
            let id = &table.backends[index];
            if !excluded.contains(id) && pool.is_eligible(id) {
                return Some(id.clone());
            }
            seen[index] = true;
            seen_count += 1;
            if seen_count == table.backends.len() {
                break;
            }
        }
        None
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
    fn every_slot_is_filled_and_equal_weights_get_near_equal_shares() {
        let pool = pool_of(&[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 1)]);
        let maglev = Maglev::new();
        let table = maglev.table_for(&pool);
        assert!(table.entries.iter().all(|&e| e != u32::MAX));
        for backend in 0..5u32 {
            let share = table.entries.iter().filter(|&&e| e == backend).count();
            assert!(
                (TABLE_SIZE / 5 - 50..=TABLE_SIZE / 5 + 50).contains(&share),
                "backend {backend} owns {share} slots"
            );
        }
    }

    #[test]
    fn weights_scale_table_share() {
        let pool = pool_of(&[("light", 1), ("heavy", 3)]);
        let table = Maglev::new().table_for(&pool);
        let heavy = table.entries.iter().filter(|&&e| e == 1).count();
        let expected = TABLE_SIZE * 3 / 4;
        assert!(
            heavy.abs_diff(expected) < TABLE_SIZE / 50,
            "heavy owns {heavy}, expected about {expected}"
        );
    }

    #[test]
    fn only_keys_of_an_ineligible_backend_move() {
        let pool = pool_of(&[("a", 1), ("b", 1), ("c", 1), ("d", 1)]);
        let maglev = Maglev::new();
        let keys: Vec<String> = (0..4_000).map(|i| format!("k{i}")).collect();
        let before: Vec<BackendId> = keys
            .iter()
            .map(|k| maglev.pick(&pool, k).unwrap())
            .collect();
        let down = BackendId::new("b");
        pool.set_active_healthy(&down, false);
        for (key, was) in keys.iter().zip(&before) {
            let now = maglev.pick(&pool, key).unwrap();
            assert_ne!(now, down);
            if *was != down {
                assert_eq!(&now, was, "{key} moved although its backend stayed up");
            }
        }
    }

    #[test]
    fn the_table_is_rebuilt_only_on_membership_change() {
        let pool = pool_of(&[("a", 1), ("b", 1)]);
        let maglev = Maglev::new();
        let first = maglev.table_for(&pool);
        pool.set_active_healthy(&BackendId::new("a"), false);
        assert!(Arc::ptr_eq(&first, &maglev.table_for(&pool)));
        pool.apply_resolved(vec![
            Backend::new("a", "127.0.0.1:9000".parse().unwrap(), 1, None),
            Backend::new("c", "127.0.0.1:9000".parse().unwrap(), 1, None),
        ]);
        assert!(!Arc::ptr_eq(&first, &maglev.table_for(&pool)));
    }
}
