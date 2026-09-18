use crate::counters::CounterStore;
use crate::protocol::{KeyEntry, SyncMessage};
use lb_core::{Clock, ClusterCoordinator};
use std::sync::Arc;

/// What happened when merging a peer message.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    Merged,
    /// The message claimed *our* node_id. Two nodes sharing an id collide in
    /// the CRDT and silently under-count, so this is surfaced loudly rather
    /// than merged.
    OwnNodeIdEcho,
}

/// Process-wide cluster state: one counter store and one identity, shared by
/// every listener in this process.
pub struct ClusterNode<C: Clock> {
    node_id: String,
    store: CounterStore,
    clock: C,
    /// Pre-shared key authenticating every peer message. Mandatory: the peer
    /// port influences rate-limiting decisions, so unauthenticated access to
    /// it is a denial-of-service vector.
    secret: Vec<u8>,
}

impl<C: Clock> ClusterNode<C> {
    pub fn new(node_id: impl Into<String>, window_secs: u64, clock: C, secret: Vec<u8>) -> Self {
        ClusterNode {
            node_id: node_id.into(),
            store: CounterStore::new(window_secs),
            clock,
            secret,
        }
    }

    pub fn with_skew_rejection_counter(mut self, counter: lb_metrics::IntCounter) -> Self {
        self.store = self.store.with_skew_rejection_counter(counter);
        self
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn store(&self) -> &CounterStore {
        &self.store
    }

    /// Merges a peer's counters. Rejects a message bearing our own id: that
    /// can only mean duplicate `node_id` configuration, and merging it would
    /// corrupt our own cells.
    pub fn merge_message(&self, msg: &SyncMessage) -> MergeOutcome {
        if msg.node_id == self.node_id {
            return MergeOutcome::OwnNodeIdEcho;
        }
        let now = self.clock.unix_secs();
        for entry in &msg.entries {
            self.store
                .merge(&entry.key, &msg.node_id, &entry.buckets, now);
        }
        MergeOutcome::Merged
    }

    /// Our own in-window counters, ready to push to peers.
    pub fn snapshot_message(&self) -> SyncMessage {
        let now = self.clock.unix_secs();
        SyncMessage {
            node_id: self.node_id.clone(),
            entries: self
                .store
                .snapshot_own(&self.node_id, now)
                .into_iter()
                .map(|(key, buckets)| KeyEntry { key, buckets })
                .collect(),
        }
    }

    pub fn prune(&self) {
        self.store.prune(self.clock.unix_secs());
    }
}

/// One listener's view of the cluster budget.
///
/// Keys are namespaced by listener name: two listeners may both rate-limit
/// "10.0.0.7" and those are unrelated budgets.
pub struct ListenerCoordinator<C: Clock> {
    node: Arc<ClusterNode<C>>,
    namespace: String,
    limit: u64,
}

impl<C: Clock> ListenerCoordinator<C> {
    pub fn new(node: Arc<ClusterNode<C>>, namespace: impl Into<String>, limit: u64) -> Self {
        ListenerCoordinator {
            node,
            namespace: namespace.into(),
            limit,
        }
    }

    fn namespaced(&self, key: &str) -> String {
        // \u{1} cannot appear in a header value or an IP string, so it cannot
        // be used to forge a collision between listeners.
        format!("{}\u{1}{}", self.namespace, key)
    }
}

impl<C: Clock> ClusterCoordinator for ListenerCoordinator<C> {
    fn try_admit(&self, key: &str) -> bool {
        self.node.store.try_admit(
            &self.namespaced(key),
            &self.node.node_id,
            self.node.clock.unix_secs(),
            self.limit,
        )
    }
}

/// Worst-case count by which the cluster-wide budget for one key can be
/// transiently over-admitted before gossip convergence catches up: each of
/// the other `peer_count` nodes can independently admit up to
/// `rate_per_sec` requests per second of `sync_interval` against a shared
/// key before this node's next gossip round would see them.
pub fn convergence_over_admission_bound(
    rate_per_sec: f64,
    sync_interval_ms: u64,
    peer_count: usize,
) -> u64 {
    let per_node_burst = rate_per_sec * (sync_interval_ms as f64 / 1000.0);
    (per_node_burst * peer_count as f64).ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use lb_core::test_util::FakeClock;
    use std::time::Duration;

    fn node(id: &str, clock: FakeClock) -> Arc<ClusterNode<FakeClock>> {
        Arc::new(ClusterNode::new(id, 10, clock, b"test-secret".to_vec()))
    }

    #[test]
    fn admits_up_to_the_limit_then_refuses() {
        let coord = ListenerCoordinator::new(node("n1", FakeClock::new()), "web", 3);
        assert!(coord.try_admit("1.2.3.4"));
        assert!(coord.try_admit("1.2.3.4"));
        assert!(coord.try_admit("1.2.3.4"));
        assert!(!coord.try_admit("1.2.3.4"));
    }

    #[test]
    fn listeners_have_independent_budgets_for_the_same_key() {
        let shared = node("n1", FakeClock::new());
        let web = ListenerCoordinator::new(shared.clone(), "web", 1);
        let db = ListenerCoordinator::new(shared, "db", 1);

        assert!(web.try_admit("1.2.3.4"));
        assert!(!web.try_admit("1.2.3.4"));
        // Same client IP, different listener, separate budget.
        assert!(db.try_admit("1.2.3.4"));
    }

    #[test]
    fn a_peers_counts_consume_our_budget() {
        let clock = FakeClock::new();
        let a = node("a", clock.clone());
        let b = node("b", clock.clone());

        let coord_a = ListenerCoordinator::new(a.clone(), "web", 4);
        let coord_b = ListenerCoordinator::new(b.clone(), "web", 4);

        // Node A uses the whole budget.
        for _ in 0..4 {
            assert!(coord_a.try_admit("1.2.3.4"));
        }
        // Before sync, B is unaware and would admit — this is the
        // over-admission window the spec documents.
        assert!(coord_b.try_admit("1.2.3.4"));

        // After sync, a fresh node sees A's counts and refuses.
        let b2 = node("b2", clock.clone());
        let coord_b2 = ListenerCoordinator::new(b2.clone(), "web", 4);
        assert_eq!(
            b2.merge_message(&a.snapshot_message()),
            MergeOutcome::Merged
        );
        assert!(!coord_b2.try_admit("1.2.3.4"));
    }

    #[test]
    fn merging_a_message_with_our_own_id_is_rejected() {
        let a = node("same-id", FakeClock::new());
        let impostor = node("same-id", FakeClock::new());
        let coord = ListenerCoordinator::new(impostor.clone(), "web", 5);
        coord.try_admit("1.2.3.4");

        assert_eq!(
            a.merge_message(&impostor.snapshot_message()),
            MergeOutcome::OwnNodeIdEcho
        );
    }

    #[test]
    fn merge_of_the_same_message_twice_does_not_double_count() {
        let clock = FakeClock::new();
        let a = node("a", clock.clone());
        let b = node("b", clock.clone());
        let coord_a = ListenerCoordinator::new(a.clone(), "web", 10);
        for _ in 0..5 {
            coord_a.try_admit("k");
        }

        let msg = a.snapshot_message();
        b.merge_message(&msg);
        b.merge_message(&msg);

        let coord_b = ListenerCoordinator::new(b.clone(), "web", 6);
        // 5 from A + this one = 6, so exactly one more fits. If the duplicate
        // merge had double-counted, this would be refused.
        assert!(coord_b.try_admit("k"));
        assert!(!coord_b.try_admit("k"));
    }

    #[test]
    fn budget_recovers_once_counts_age_out_of_the_window() {
        let clock = FakeClock::new();
        let coord = ListenerCoordinator::new(node("n1", clock.clone()), "web", 1);
        assert!(coord.try_admit("k"));
        assert!(!coord.try_admit("k"));

        clock.advance(Duration::from_secs(10));
        assert!(coord.try_admit("k"));
    }

    #[test]
    fn convergence_bound_scales_with_rate_interval_and_peer_count() {
        // 100 req/s, 200ms gossip round -> 20 requests one node can admit
        // before a peer's next sync round would see them; three peers could
        // each independently do this at once.
        assert_eq!(convergence_over_admission_bound(100.0, 200, 3), 60);
    }

    #[test]
    fn convergence_bound_is_zero_with_no_peers() {
        assert_eq!(convergence_over_admission_bound(100.0, 200, 0), 0);
    }

    #[test]
    fn convergence_bound_rounds_up_a_fractional_burst() {
        // 1 req/s, 1500ms round -> 1.5 requests/node, rounded up to 2, times
        // one peer.
        assert_eq!(convergence_over_admission_bound(1.0, 1_500, 1), 2);
    }

    #[test]
    fn delayed_delivery_of_successive_snapshots_converges_to_in_order_result() {
        let sender_clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new(
            "sender",
            10,
            sender_clock,
            b"secret".to_vec(),
        ));
        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 100);

        assert!(coord.try_admit("k"));
        let snap1 = sender.snapshot_message();

        assert!(coord.try_admit("k"));
        assert!(coord.try_admit("k"));
        let snap2 = sender.snapshot_message();

        assert!(coord.try_admit("k"));
        let snap3 = sender.snapshot_message();

        let in_order = ClusterNode::new("receiver", 10, FakeClock::new(), b"secret".to_vec());
        in_order.merge_message(&snap1);
        in_order.merge_message(&snap2);
        in_order.merge_message(&snap3);

        let delayed = ClusterNode::new("receiver", 10, FakeClock::new(), b"secret".to_vec());
        delayed.merge_message(&snap3);
        delayed.merge_message(&snap1);
        delayed.merge_message(&snap2);

        assert_eq!(in_order.store().raw_state(), delayed.store().raw_state());
    }

    #[test]
    fn partial_delivery_from_some_peers_reflects_only_those_peers() {
        let clock = FakeClock::new();
        let peer_a = Arc::new(ClusterNode::new("a", 10, clock.clone(), b"secret".to_vec()));
        let peer_b = Arc::new(ClusterNode::new("b", 10, clock.clone(), b"secret".to_vec()));
        let peer_c = Arc::new(ClusterNode::new("c", 10, clock.clone(), b"secret".to_vec()));

        for peer in [&peer_a, &peer_b, &peer_c] {
            let coord = ListenerCoordinator::new(Arc::clone(peer), "web", 10);
            assert!(coord.try_admit("k"));
        }

        let receiver = ClusterNode::new("receiver", 10, clock.clone(), b"secret".to_vec());
        receiver.merge_message(&peer_a.snapshot_message());
        receiver.merge_message(&peer_c.snapshot_message());

        let state = receiver.store().raw_state();
        let nodes = state.get("web\u{1}k").expect("key present after merge");
        assert!(nodes.contains_key("a"));
        assert!(nodes.contains_key("c"));
        assert!(!nodes.contains_key("b"));
        assert_eq!(
            receiver
                .store()
                .total_in_window("web\u{1}k", clock.unix_secs()),
            2
        );
    }

    use proptest::prelude::*;

    fn key_entry_strategy(now: u64) -> impl Strategy<Value = KeyEntry> {
        (0u8..3, prop::collection::vec((0u8..11, 0u64..50), 1..4)).prop_map(move |(k, buckets)| {
            KeyEntry {
                key: format!("k{k}"),
                buckets: buckets
                    .into_iter()
                    .map(|(e, c)| (now - 3 + e as u64, c))
                    .collect(),
            }
        })
    }

    fn sync_message_strategy(now: u64) -> impl Strategy<Value = SyncMessage> {
        prop::collection::vec(key_entry_strategy(now), 0..5).prop_map(|entries| SyncMessage {
            node_id: "peer".to_string(),
            entries,
        })
    }

    fn xorshift_shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
        let mut out = items.to_vec();
        let mut state = seed | 1;
        for i in (1..out.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = (state as usize) % (i + 1);
            out.swap(i, j);
        }
        out
    }

    fn tagged_message_strategy(now: u64) -> impl Strategy<Value = (u8, SyncMessage)> {
        (0u8..4, key_entry_strategy(now)).prop_map(|(sender, entry)| {
            (
                sender,
                SyncMessage {
                    node_id: format!("peer{sender}"),
                    entries: vec![entry],
                },
            )
        })
    }

    fn multi_sender_message_stream(now: u64) -> impl Strategy<Value = Vec<(u8, SyncMessage)>> {
        prop::collection::vec(tagged_message_strategy(now), 1..10)
    }

    proptest! {
        #[test]
        fn prop_duplicate_gossip_message_delivery_is_idempotent(msg in sync_message_strategy(1_700_000_000)) {
            let receiver = ClusterNode::new("receiver", 1_000_000, FakeClock::new(), b"secret".to_vec());
            receiver.merge_message(&msg);
            let once = receiver.store().raw_state();
            receiver.merge_message(&msg);
            let twice = receiver.store().raw_state();
            prop_assert_eq!(once, twice);
        }

        #[test]
        fn prop_delayed_gossip_delivery_converges_like_in_order_delivery(
            msgs in prop::collection::vec(sync_message_strategy(1_700_000_000), 1..5),
            seed in any::<u64>(),
        ) {
            let receiver_in_order = ClusterNode::new("receiver", 1_000_000, FakeClock::new(), b"secret".to_vec());
            for msg in &msgs {
                receiver_in_order.merge_message(msg);
            }

            let receiver_delayed = ClusterNode::new("receiver", 1_000_000, FakeClock::new(), b"secret".to_vec());
            for msg in xorshift_shuffled(&msgs, seed) {
                receiver_delayed.merge_message(&msg);
            }

            prop_assert_eq!(
                receiver_in_order.store().raw_state(),
                receiver_delayed.store().raw_state()
            );
        }

        #[test]
        fn prop_partial_delivery_reflects_exactly_the_delivered_senders(
            msgs in multi_sender_message_stream(1_700_000_000),
            delivered_mask in 0u8..16,
        ) {
            let is_delivered = |sender: u8| (delivered_mask >> sender) & 1 == 1;

            let receiver = ClusterNode::new("receiver", 1_000_000, FakeClock::new(), b"secret".to_vec());
            let mut expected_msgs = Vec::new();
            for (sender, msg) in &msgs {
                if is_delivered(*sender) {
                    receiver.merge_message(msg);
                    expected_msgs.push(msg.clone());
                }
            }

            let state = receiver.store().raw_state();
            let delivered_ids: std::collections::HashSet<String> = (0u8..4)
                .filter(|sender| is_delivered(*sender))
                .map(|sender| format!("peer{sender}"))
                .collect();
            for nodes in state.values() {
                for sender_id in nodes.keys() {
                    prop_assert!(delivered_ids.contains(sender_id));
                }
            }

            let expected = ClusterNode::new("receiver", 1_000_000, FakeClock::new(), b"secret".to_vec());
            for msg in &expected_msgs {
                expected.merge_message(msg);
            }
            prop_assert_eq!(state, expected.store().raw_state());
        }
    }
}
