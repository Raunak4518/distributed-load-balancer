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
}
