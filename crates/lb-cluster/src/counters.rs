use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Per-key request counts, partitioned by the node that admitted them and
/// bucketed by Unix epoch second.
///
/// This is a G-Counter CRDT. Each cell `(key, node_id, epoch_second)` has
/// exactly one writer — the node named by `node_id` — and only ever grows.
/// That is what makes the merge a per-cell `max`: once a second has elapsed
/// the cell is frozen at its true value, so `max` converges to it regardless
/// of message ordering, duplication, or delay.
///
/// Note the two directions carefully, because getting them the wrong way
/// round silently breaks the limiter: counts are **summed across nodes**
/// (consumption is additive) and **maxed within a single node's cell**
/// (that cell has one writer).
pub struct CounterStore {
    window_secs: u64,
    keys: DashMap<String, KeyCounts>,
    snapshot_cursor: AtomicUsize,
}

const MAX_TRACKED_KEYS: usize = 100_000;

const MAX_SNAPSHOT_BUCKET_ENTRIES: usize = 5_000;

const FUTURE_SKEW_TOLERANCE_SECS: u64 = 5;

#[derive(Default)]
struct KeyCounts {
    /// node_id -> (epoch_second -> count)
    per_node: HashMap<String, HashMap<u64, u64>>,
}

impl KeyCounts {
    fn total_in_window(&self, now_secs: u64, window_secs: u64) -> u64 {
        let cutoff = now_secs.saturating_sub(window_secs.saturating_sub(1));
        self.per_node
            .values()
            .flat_map(|buckets| buckets.iter())
            .filter(|(epoch, _)| **epoch >= cutoff && **epoch <= now_secs)
            .map(|(_, count)| *count)
            .sum()
    }

    fn prune(&mut self, now_secs: u64, window_secs: u64) {
        let cutoff = now_secs.saturating_sub(window_secs.saturating_sub(1));
        for buckets in self.per_node.values_mut() {
            buckets.retain(|epoch, _| *epoch >= cutoff);
        }
        self.per_node.retain(|_, buckets| !buckets.is_empty());
    }
}

impl CounterStore {
    pub fn new(window_secs: u64) -> Self {
        CounterStore {
            window_secs: window_secs.max(1),
            keys: DashMap::new(),
            snapshot_cursor: AtomicUsize::new(0),
        }
    }

    /// Atomically decides whether this request fits the cluster budget and,
    /// if so, records it against `node_id`'s current bucket.
    ///
    /// The sum and the increment happen under one entry lock, so a single
    /// node never over-admits against its own view. The only slack in the
    /// system is cross-node propagation delay.
    pub fn try_admit(&self, key: &str, node_id: &str, now_secs: u64, limit: u64) -> bool {
        // Borrowed lookup first: every key past its first request in this
        // window takes this path and allocates nothing. `key.to_string()`
        // below is only worth paying the first time a key is seen.
        if let Some(mut counts) = self.keys.get_mut(key) {
            return Self::try_record(&mut counts, node_id, now_secs, self.window_secs, limit);
        }
        let mut counts = self.keys.entry(key.to_string()).or_default();
        Self::try_record(&mut counts, node_id, now_secs, self.window_secs, limit)
    }

    fn try_record(
        counts: &mut KeyCounts,
        node_id: &str,
        now_secs: u64,
        window_secs: u64,
        limit: u64,
    ) -> bool {
        if counts.total_in_window(now_secs, window_secs) >= limit {
            return false;
        }
        Self::record(counts, node_id, now_secs);
        true
    }

    /// Same borrowed-lookup-first shape as `try_admit` above, one level
    /// down: `node_id` is almost always this same node's own fixed id, so
    /// the allocating path is only ever taken once per node per key.
    fn record(counts: &mut KeyCounts, node_id: &str, now_secs: u64) {
        if let Some(buckets) = counts.per_node.get_mut(node_id) {
            *buckets.entry(now_secs).or_insert(0) += 1;
            return;
        }
        let buckets = counts.per_node.entry(node_id.to_string()).or_default();
        *buckets.entry(now_secs).or_insert(0) += 1;
    }

    pub fn total_in_window(&self, key: &str, now_secs: u64) -> u64 {
        self.keys
            .get(key)
            .map(|k| k.total_in_window(now_secs, self.window_secs))
            .unwrap_or(0)
    }

    /// Merges a peer's view of its own cells. Per-cell `max`, never sum:
    /// re-receiving the same update must not inflate the count.
    ///
    /// `now_secs` bounds two things a peer's message cannot be trusted to
    /// bound itself: an `epoch` more than `FUTURE_SKEW_TOLERANCE_SECS` ahead
    /// of `now_secs` is dropped (a node can only ever report a count for a
    /// second at or near the present, and an unbounded future-dated cell
    /// would otherwise never be reclaimed by `prune`, since its cutoff
    /// comparison is relative to whatever `now_secs` is at prune time --
    /// the tolerance absorbs ordinary clock skew between real nodes, which
    /// `snapshot_message`'s own `now` and this node's `now_secs` at merge
    /// time are never perfectly identical), and a brand-new `key` is
    /// dropped once this store already tracks `MAX_TRACKED_KEYS`, mirroring
    /// `lb_ratelimit::Gcra`'s own key cap for the same reason: an
    /// attacker's key set must not be free to grow this node's memory
    /// without bound.
    pub fn merge(&self, key: &str, node_id: &str, buckets: &[(u64, u64)], now_secs: u64) {
        let max_epoch = now_secs + FUTURE_SKEW_TOLERANCE_SECS;
        if !buckets.iter().any(|(epoch, _)| *epoch <= max_epoch) {
            return;
        }
        if let Some(mut counts) = self.keys.get_mut(key) {
            Self::merge_into(&mut counts, node_id, buckets, max_epoch);
            return;
        }
        if self.keys.len() >= MAX_TRACKED_KEYS {
            return;
        }
        let mut counts = self.keys.entry(key.to_string()).or_default();
        Self::merge_into(&mut counts, node_id, buckets, max_epoch);
    }

    fn merge_into(counts: &mut KeyCounts, node_id: &str, buckets: &[(u64, u64)], max_epoch: u64) {
        if let Some(node_buckets) = counts.per_node.get_mut(node_id) {
            for (epoch, count) in buckets {
                if *epoch > max_epoch {
                    continue;
                }
                let slot = node_buckets.entry(*epoch).or_insert(0);
                *slot = (*slot).max(*count);
            }
            return;
        }
        if !buckets.iter().any(|(epoch, _)| *epoch <= max_epoch) {
            return;
        }
        let node_buckets = counts.per_node.entry(node_id.to_string()).or_default();
        for (epoch, count) in buckets {
            if *epoch > max_epoch {
                continue;
            }
            let slot = node_buckets.entry(*epoch).or_insert(0);
            *slot = (*slot).max(*count);
        }
    }

    /// Our own in-window cells, for pushing to peers. A node is only
    /// authoritative for its own counts and never relays anyone else's.
    pub fn snapshot_own(&self, node_id: &str, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        self.snapshot_own_capped(node_id, now_secs, MAX_SNAPSHOT_BUCKET_ENTRIES)
    }

    fn snapshot_own_capped(
        &self,
        node_id: &str,
        now_secs: u64,
        max_entries: usize,
    ) -> Vec<(String, Vec<(u64, u64)>)> {
        let cutoff = now_secs.saturating_sub(self.window_secs.saturating_sub(1));
        let mut keys: Vec<String> = self.keys.iter().map(|item| item.key().clone()).collect();
        keys.sort_unstable();
        if keys.is_empty() {
            return Vec::new();
        }
        let len = keys.len();
        let mut idx = self.snapshot_cursor.load(Ordering::Relaxed) % len;
        let mut out = Vec::new();
        let mut total_entries = 0usize;
        for _ in 0..len {
            if let Some(item) = self.keys.get(&keys[idx]) {
                if let Some(buckets) = item.per_node.get(node_id) {
                    let in_window: Vec<(u64, u64)> = buckets
                        .iter()
                        .filter(|(epoch, _)| **epoch >= cutoff)
                        .map(|(epoch, count)| (*epoch, *count))
                        .collect();
                    if !in_window.is_empty() {
                        if total_entries > 0 && total_entries + in_window.len() > max_entries {
                            break;
                        }
                        total_entries += in_window.len();
                        out.push((keys[idx].clone(), in_window));
                    }
                }
            }
            idx = (idx + 1) % len;
        }
        self.snapshot_cursor.store(idx, Ordering::Relaxed);
        out
    }

    pub fn prune(&self, now_secs: u64) {
        let window = self.window_secs;
        self.keys.retain(|_, counts| {
            counts.prune(now_secs, window);
            !counts.per_node.is_empty()
        });
    }

    #[cfg(test)]
    fn key_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn admits_until_the_limit_then_refuses() {
        let store = CounterStore::new(10);
        for _ in 0..3 {
            assert!(store.try_admit("k", "n1", NOW, 3));
        }
        assert!(!store.try_admit("k", "n1", NOW, 3));
        assert_eq!(store.total_in_window("k", NOW), 3);
    }

    #[test]
    fn a_refused_request_is_not_counted() {
        let store = CounterStore::new(10);
        assert!(store.try_admit("k", "n1", NOW, 1));
        assert!(!store.try_admit("k", "n1", NOW, 1));
        assert!(!store.try_admit("k", "n1", NOW, 1));
        // Still 1: refusals must not inflate the count, or a blocked client
        // would push its own window out forever.
        assert_eq!(store.total_in_window("k", NOW), 1);
    }

    #[test]
    fn counts_from_different_nodes_are_summed() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW, 4)], NOW);
        store.merge("k", "n2", &[(NOW, 6)], NOW);
        // Additive across nodes — this is the property Trap 1 in the spec
        // gets wrong by using max.
        assert_eq!(store.total_in_window("k", NOW), 10);
    }

    #[test]
    fn one_nodes_counts_reduce_anothers_budget() {
        let store = CounterStore::new(10);
        store.merge("k", "peer", &[(NOW, 9)], NOW);
        assert!(store.try_admit("k", "me", NOW, 10)); // 10th request
        assert!(!store.try_admit("k", "me", NOW, 10)); // budget exhausted by peer
    }

    #[test]
    fn keys_are_independent() {
        let store = CounterStore::new(10);
        assert!(store.try_admit("a", "n1", NOW, 1));
        assert!(store.try_admit("b", "n1", NOW, 1));
        assert!(!store.try_admit("a", "n1", NOW, 1));
    }

    #[test]
    fn counts_outside_the_window_are_excluded() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW - 20, 100)], NOW); // long past
        store.merge("k", "n1", &[(NOW, 2)], NOW);
        assert_eq!(store.total_in_window("k", NOW), 2);
    }

    #[test]
    fn window_edge_is_inclusive_at_both_ends() {
        let store = CounterStore::new(10);
        // A 10s window covers [NOW-9, NOW].
        store.merge("k", "n1", &[(NOW - 9, 1), (NOW - 10, 1), (NOW, 1)], NOW);
        assert_eq!(store.total_in_window("k", NOW), 2);
    }

    #[test]
    fn merge_is_idempotent() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW, 5)], NOW);
        store.merge("k", "n1", &[(NOW, 5)], NOW);
        store.merge("k", "n1", &[(NOW, 5)], NOW);
        // A duplicated message must not inflate anything — this is why the
        // merge is max and not +=.
        assert_eq!(store.total_in_window("k", NOW), 5);
    }

    #[test]
    fn merge_is_commutative() {
        let a = CounterStore::new(10);
        a.merge("k", "n1", &[(NOW, 3)], NOW);
        a.merge("k", "n2", &[(NOW, 7)], NOW);

        let b = CounterStore::new(10);
        b.merge("k", "n2", &[(NOW, 7)], NOW);
        b.merge("k", "n1", &[(NOW, 3)], NOW);

        assert_eq!(a.total_in_window("k", NOW), b.total_in_window("k", NOW));
    }

    #[test]
    fn merge_is_associative_and_order_independent_for_one_node() {
        // Out-of-order delivery of the same node's successive counts must
        // converge to the highest, not the last-received.
        let a = CounterStore::new(10);
        a.merge("k", "n1", &[(NOW, 2)], NOW);
        a.merge("k", "n1", &[(NOW, 9)], NOW);
        a.merge("k", "n1", &[(NOW, 5)], NOW); // stale message arriving late

        assert_eq!(a.total_in_window("k", NOW), 9);
    }

    #[test]
    fn snapshot_returns_only_our_own_in_window_cells() {
        let store = CounterStore::new(10);
        store.merge("k", "me", &[(NOW, 2), (NOW - 50, 99)], NOW);
        store.merge("k", "other", &[(NOW, 7)], NOW);

        let snap = store.snapshot_own("me", NOW);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "k");
        assert_eq!(snap[0].1, vec![(NOW, 2)]);
    }

    #[test]
    fn a_capped_snapshot_stops_at_the_entry_limit() {
        let store = CounterStore::new(10);
        for i in 0..10 {
            store.merge(&format!("k{i}"), "me", &[(NOW, 1)], NOW);
        }
        let snap = store.snapshot_own_capped("me", NOW, 4);
        assert_eq!(snap.len(), 4);
    }

    #[test]
    fn a_capped_snapshot_always_includes_at_least_one_key() {
        let store = CounterStore::new(10);
        store.merge("big", "me", &[(NOW, 1), (NOW - 1, 1), (NOW - 2, 1)], NOW);
        let snap = store.snapshot_own_capped("me", NOW, 1);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "big");
    }

    #[test]
    fn successive_capped_snapshots_round_robin_across_all_keys() {
        let store = CounterStore::new(10);
        for i in 0..6 {
            store.merge(&format!("k{i}"), "me", &[(NOW, 1)], NOW);
        }
        let first = store.snapshot_own_capped("me", NOW, 3);
        let second = store.snapshot_own_capped("me", NOW, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        let mut seen: Vec<String> = first.into_iter().chain(second).map(|(k, _)| k).collect();
        seen.sort();
        assert_eq!(seen, vec!["k0", "k1", "k2", "k3", "k4", "k5"]);
    }

    #[test]
    fn prune_drops_out_of_window_cells_and_empty_keys() {
        let store = CounterStore::new(10);
        store.merge("stale", "n1", &[(NOW - 100, 5)], NOW);
        store.merge("fresh", "n1", &[(NOW, 5)], NOW);
        assert_eq!(store.key_count(), 2);

        store.prune(NOW);

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.total_in_window("fresh", NOW), 5);
        assert_eq!(store.total_in_window("stale", NOW), 0);
    }

    /// A peer's clock running a couple of seconds ahead of ours (ordinary,
    /// unsynchronized real-world skew -- not an attack) must not have its
    /// admitted counts silently dropped at merge time, or the cluster budget
    /// under-counts a perfectly legitimate peer.
    #[test]
    fn a_cell_within_ordinary_clock_skew_is_still_merged() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW + 2, 5)], NOW);
        assert_eq!(store.total_in_window("k", NOW + 2), 5);
    }

    #[test]
    fn a_future_dated_cell_is_dropped_not_merged() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW + 1_000_000, 5)], NOW);
        assert_eq!(store.key_count(), 0);
        assert_eq!(store.total_in_window("k", NOW + 1_000_000), 0);
    }

    #[test]
    fn a_future_dated_cell_on_an_already_tracked_key_is_still_dropped() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW, 3)], NOW);
        store.merge("k", "n1", &[(NOW + 1_000_000, 5)], NOW);
        store.prune(NOW + 1_000_000);
        assert_eq!(store.key_count(), 0);
    }

    #[test]
    fn merge_stops_tracking_new_keys_past_the_cap() {
        let store = CounterStore::new(10);
        for i in 0..(MAX_TRACKED_KEYS + 10) {
            store.merge(&format!("k{i}"), "n1", &[(NOW, 1)], NOW);
        }
        assert_eq!(store.key_count(), MAX_TRACKED_KEYS);
    }

    #[test]
    fn counts_age_out_as_time_advances() {
        let store = CounterStore::new(10);
        assert!(store.try_admit("k", "n1", NOW, 1));
        assert!(!store.try_admit("k", "n1", NOW, 1));
        // Ten seconds later the old bucket has left the window, so the
        // budget is available again. This is also why a dead peer needs no
        // explicit expiry: its counts simply age out.
        assert!(store.try_admit("k", "n1", NOW + 10, 1));
    }
}
