# Distributed Load Balancer — Phase 3 (Multi-Node Coordination) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the rate limiter enforce a *global* limit across several load-balancer nodes, so that running N nodes no longer multiplies the configured limit by N.

**Architecture:** A new `lb-cluster` crate holds a G-Counter CRDT of per-key request counts, bucketed by Unix epoch second and summed over a sliding window. Nodes push their own counters to a static list of peers over length-prefixed TCP; merging is per-cell `max`, which is convergent under reordering, duplication and delay. A `ClusterCoordinator` trait in `lb-core` lets `lb-proxy` and `lb-tcp` consult the cluster budget after their local GCRA check, and disappears entirely (`Option::None`) when no `[cluster]` section is configured.

**Tech Stack:** Rust 2021, `tokio` (net/io/time/sync), `dashmap`, `serde` + `serde_json`, existing workspace crates.

**Spec:** [`docs/superpowers/specs/2026-09-04-lb-phase3-design.md`](../specs/2026-09-04-lb-phase3-design.md)

## Global Constraints

- No `unwrap`/`expect` reachable from network input — the peer listener parses data from other machines.
- Every decode path is bounded: max message size enforced **before** allocating.
- Cluster coordination is strictly off the request path for I/O: `try_admit` touches only in-memory state, never the network.
- A peer being unreachable is normal, never fatal, and never blocks a client request.
- `Clock::now()` (monotonic) for elapsed time; `Clock::unix_secs()` (wall) for bucket alignment. Never substitute one for the other.
- Omitting `[cluster]` must leave Phase 1/2 behaviour bit-for-bit unchanged.
- `cargo fmt` and `cargo clippy --workspace --all-targets -- -D warnings` clean at the end.
- Commit messages carry **no** `Co-Authored-By` trailer.

---

## Task 1: `Clock::unix_secs` + `lb-cluster` crate with the G-Counter store

**Files:**
- Modify: `crates/lb-core/src/clock.rs`
- Create: `crates/lb-cluster/Cargo.toml`, `crates/lb-cluster/src/lib.rs`, `crates/lb-cluster/src/counters.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Changes: `lb_core::Clock` gains `fn unix_secs(&self) -> u64`. `SystemClock` implements it from `SystemTime`; `FakeClock` advances it alongside its instant.
- Produces: `lb_cluster::CounterStore` — `new(window_secs: u64)`, `try_admit(&self, key: &str, node_id: &str, now_secs: u64, limit: u64) -> bool`, `total_in_window(&self, key: &str, now_secs: u64) -> u64`, `merge(&self, key: &str, node_id: &str, buckets: &[(u64, u64)])`, `snapshot_own(&self, node_id: &str, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)>`, `prune(&self, now_secs: u64)`.

- [ ] **Step 1: Extend the `Clock` trait**

Replace `crates/lb-core/src/clock.rs`:
```rust
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Monotonic time, for measuring *elapsed* intervals (GCRA, circuit
    /// breaker cooldowns). Immune to wall-clock jumps; meaningless across
    /// processes.
    fn now(&self) -> Instant;

    /// Wall-clock seconds since the Unix epoch, for time boundaries that must
    /// be *shared between machines* (cluster bucket alignment). Never use
    /// this to measure elapsed time — it can jump.
    fn unix_secs(&self) -> u64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock set before 1970 is pathological; treat it as the epoch
            // rather than panicking on a request path.
            .unwrap_or(0)
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::Clock;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct FakeState {
        instant: Instant,
        unix_millis: u64,
    }

    #[derive(Clone)]
    pub struct FakeClock {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeClock {
        pub fn new() -> Self {
            // An arbitrary but realistic epoch base, so bucket numbers in
            // tests look like real timestamps rather than 0, 1, 2.
            Self::with_unix_secs(1_700_000_000)
        }

        pub fn with_unix_secs(unix_secs: u64) -> Self {
            FakeClock {
                state: Arc::new(Mutex::new(FakeState {
                    instant: Instant::now(),
                    unix_millis: unix_secs * 1000,
                })),
            }
        }

        /// Advances monotonic and wall clocks together.
        pub fn advance(&self, d: Duration) {
            let mut guard = self.state.lock().expect("fake clock mutex poisoned");
            guard.instant += d;
            guard.unix_millis += d.as_millis() as u64;
        }
    }

    impl Default for FakeClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.state.lock().expect("fake clock mutex poisoned").instant
        }

        fn unix_secs(&self) -> u64 {
            self.state.lock().expect("fake clock mutex poisoned").unix_millis / 1000
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn advances_by_exact_duration() {
            let clock = FakeClock::new();
            let start = clock.now();
            clock.advance(Duration::from_secs(5));
            assert_eq!(clock.now().duration_since(start), Duration::from_secs(5));
        }

        #[test]
        fn does_not_advance_on_its_own() {
            let clock = FakeClock::new();
            assert_eq!(clock.now(), clock.now());
            assert_eq!(clock.unix_secs(), clock.unix_secs());
        }

        #[test]
        fn wall_clock_advances_with_monotonic_clock() {
            let clock = FakeClock::with_unix_secs(1_000);
            assert_eq!(clock.unix_secs(), 1_000);
            clock.advance(Duration::from_secs(3));
            assert_eq!(clock.unix_secs(), 1_003);
        }

        #[test]
        fn sub_second_advances_accumulate_into_whole_seconds() {
            let clock = FakeClock::with_unix_secs(1_000);
            clock.advance(Duration::from_millis(600));
            assert_eq!(clock.unix_secs(), 1_000);
            clock.advance(Duration::from_millis(600));
            assert_eq!(clock.unix_secs(), 1_001);
        }
    }
}
```

- [ ] **Step 2: Run the clock tests**

Run: `cargo test -p lb-core --features test-util`
Expected: PASS, including the two new wall-clock tests. Other crates will not compile yet if they implement `Clock` — none do besides these two, so the workspace should still build.

Run: `cargo build --workspace`
Expected: succeeds.

- [ ] **Step 3: Scaffold `lb-cluster`**

Add `"crates/lb-cluster"` to `members` in the root `Cargo.toml` (before `"crates/lb-server"`).

`crates/lb-cluster/Cargo.toml`:
```toml
[package]
name = "lb-cluster"
version = "0.1.0"
edition.workspace = true

[dependencies]
lb-core = { path = "../lb-core" }
dashmap = "6"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["rt", "net", "io-util", "time", "macros"] }

[dev-dependencies]
lb-core = { path = "../lb-core", features = ["test-util"] }
tokio = { version = "1", features = [
    "rt-multi-thread",
    "macros",
    "net",
    "io-util",
    "time",
] }
```

`crates/lb-cluster/src/lib.rs`:
```rust
mod counters;

pub use counters::CounterStore;
```

- [ ] **Step 4: Write the counter store**

`crates/lb-cluster/src/counters.rs`:
```rust
use dashmap::DashMap;
use std::collections::HashMap;

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
}

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
        }
    }

    /// Atomically decides whether this request fits the cluster budget and,
    /// if so, records it against `node_id`'s current bucket.
    ///
    /// The sum and the increment happen under one entry lock, so a single
    /// node never over-admits against its own view. The only slack in the
    /// system is cross-node propagation delay.
    pub fn try_admit(&self, key: &str, node_id: &str, now_secs: u64, limit: u64) -> bool {
        let mut entry = self.keys.entry(key.to_string()).or_default();
        if entry.total_in_window(now_secs, self.window_secs) >= limit {
            return false;
        }
        *entry
            .per_node
            .entry(node_id.to_string())
            .or_default()
            .entry(now_secs)
            .or_insert(0) += 1;
        true
    }

    pub fn total_in_window(&self, key: &str, now_secs: u64) -> u64 {
        self.keys
            .get(key)
            .map(|k| k.total_in_window(now_secs, self.window_secs))
            .unwrap_or(0)
    }

    /// Merges a peer's view of its own cells. Per-cell `max`, never sum:
    /// re-receiving the same update must not inflate the count.
    pub fn merge(&self, key: &str, node_id: &str, buckets: &[(u64, u64)]) {
        let mut entry = self.keys.entry(key.to_string()).or_default();
        let node_buckets = entry.per_node.entry(node_id.to_string()).or_default();
        for (epoch, count) in buckets {
            let slot = node_buckets.entry(*epoch).or_insert(0);
            *slot = (*slot).max(*count);
        }
    }

    /// Our own in-window cells, for pushing to peers. A node is only
    /// authoritative for its own counts and never relays anyone else's.
    pub fn snapshot_own(&self, node_id: &str, now_secs: u64) -> Vec<(String, Vec<(u64, u64)>)> {
        let cutoff = now_secs.saturating_sub(self.window_secs.saturating_sub(1));
        let mut out = Vec::new();
        for item in self.keys.iter() {
            let Some(buckets) = item.value().per_node.get(node_id) else {
                continue;
            };
            let in_window: Vec<(u64, u64)> = buckets
                .iter()
                .filter(|(epoch, _)| **epoch >= cutoff)
                .map(|(epoch, count)| (*epoch, *count))
                .collect();
            if !in_window.is_empty() {
                out.push((item.key().clone(), in_window));
            }
        }
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
        store.merge("k", "n1", &[(NOW, 4)]);
        store.merge("k", "n2", &[(NOW, 6)]);
        // Additive across nodes — this is the property Trap 1 in the spec
        // gets wrong by using max.
        assert_eq!(store.total_in_window("k", NOW), 10);
    }

    #[test]
    fn one_nodes_counts_reduce_anothers_budget() {
        let store = CounterStore::new(10);
        store.merge("k", "peer", &[(NOW, 9)]);
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
        store.merge("k", "n1", &[(NOW - 20, 100)]); // long past
        store.merge("k", "n1", &[(NOW, 2)]);
        assert_eq!(store.total_in_window("k", NOW), 2);
    }

    #[test]
    fn window_edge_is_inclusive_at_both_ends() {
        let store = CounterStore::new(10);
        // A 10s window covers [NOW-9, NOW].
        store.merge("k", "n1", &[(NOW - 9, 1), (NOW - 10, 1), (NOW, 1)]);
        assert_eq!(store.total_in_window("k", NOW), 2);
    }

    #[test]
    fn merge_is_idempotent() {
        let store = CounterStore::new(10);
        store.merge("k", "n1", &[(NOW, 5)]);
        store.merge("k", "n1", &[(NOW, 5)]);
        store.merge("k", "n1", &[(NOW, 5)]);
        // A duplicated message must not inflate anything — this is why the
        // merge is max and not +=.
        assert_eq!(store.total_in_window("k", NOW), 5);
    }

    #[test]
    fn merge_is_commutative() {
        let a = CounterStore::new(10);
        a.merge("k", "n1", &[(NOW, 3)]);
        a.merge("k", "n2", &[(NOW, 7)]);

        let b = CounterStore::new(10);
        b.merge("k", "n2", &[(NOW, 7)]);
        b.merge("k", "n1", &[(NOW, 3)]);

        assert_eq!(a.total_in_window("k", NOW), b.total_in_window("k", NOW));
    }

    #[test]
    fn merge_is_associative_and_order_independent_for_one_node() {
        // Out-of-order delivery of the same node's successive counts must
        // converge to the highest, not the last-received.
        let a = CounterStore::new(10);
        a.merge("k", "n1", &[(NOW, 2)]);
        a.merge("k", "n1", &[(NOW, 9)]);
        a.merge("k", "n1", &[(NOW, 5)]); // stale message arriving late

        assert_eq!(a.total_in_window("k", NOW), 9);
    }

    #[test]
    fn snapshot_returns_only_our_own_in_window_cells() {
        let store = CounterStore::new(10);
        store.merge("k", "me", &[(NOW, 2), (NOW - 50, 99)]);
        store.merge("k", "other", &[(NOW, 7)]);

        let snap = store.snapshot_own("me", NOW);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "k");
        assert_eq!(snap[0].1, vec![(NOW, 2)]);
    }

    #[test]
    fn prune_drops_out_of_window_cells_and_empty_keys() {
        let store = CounterStore::new(10);
        store.merge("stale", "n1", &[(NOW - 100, 5)]);
        store.merge("fresh", "n1", &[(NOW, 5)]);
        assert_eq!(store.key_count(), 2);

        store.prune(NOW);

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.total_in_window("fresh", NOW), 5);
        assert_eq!(store.total_in_window("stale", NOW), 0);
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
```

- [ ] **Step 5: Run the counter tests**

Run: `cargo test -p lb-cluster`
Expected: PASS — all 13 tests, including the three CRDT-law tests.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/lb-core crates/lb-cluster
git commit -m "feat(lb-cluster): add G-Counter CRDT store for cluster-wide request counts"
```

---

## Task 2: Wire protocol

**Files:**
- Create: `crates/lb-cluster/src/protocol.rs`
- Modify: `crates/lb-cluster/src/lib.rs`

**Interfaces:**
- Produces: `lb_cluster::protocol::{SyncMessage, KeyEntry, MAX_MESSAGE_BYTES, encode, read_message}`.
  - `SyncMessage { node_id: String, entries: Vec<KeyEntry> }`, `KeyEntry { key: String, buckets: Vec<(u64, u64)> }`.
  - `encode(&SyncMessage) -> serde_json::Result<Vec<u8>>` — 4-byte big-endian length prefix + JSON.
  - `read_message<R: AsyncRead + Unpin>(&mut R) -> io::Result<SyncMessage>`.

- [ ] **Step 1: Write the protocol module**

`crates/lb-cluster/src/protocol.rs`:
```rust
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Hard ceiling on one message. Checked *before* allocating: a length prefix
/// read from a socket is attacker-controlled, and trusting it is a textbook
/// memory-exhaustion bug.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncMessage {
    pub node_id: String,
    pub entries: Vec<KeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub key: String,
    pub buckets: Vec<(u64, u64)>,
}

pub fn encode(msg: &SyncMessage) -> serde_json::Result<Vec<u8>> {
    let payload = serde_json::to_vec(msg)?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub async fn read_message<R>(reader: &mut R) -> io::Result<SyncMessage>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer announced {len} byte message, over the {MAX_MESSAGE_BYTES} limit"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("malformed sync message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SyncMessage {
        SyncMessage {
            node_id: "lb-1".into(),
            entries: vec![KeyEntry {
                key: "127.0.0.1".into(),
                buckets: vec![(1_700_000_000, 5), (1_700_000_001, 2)],
            }],
        }
    }

    #[tokio::test]
    async fn round_trips() {
        let encoded = encode(&sample()).unwrap();
        let mut cursor = std::io::Cursor::new(encoded);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert_eq!(decoded, sample());
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        // Claim 4 GiB, send nothing. Must fail on the length check rather
        // than trying to allocate the buffer.
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{err}").contains("over the"));
    }

    #[tokio::test]
    async fn rejects_truncated_payload() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&100u32.to_be_bytes());
        framed.extend_from_slice(b"only a few bytes");
        let mut cursor = std::io::Cursor::new(framed);

        assert!(read_message(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let payload = b"{not json";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        let mut cursor = std::io::Cursor::new(framed);

        let err = read_message(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_two_messages_from_one_stream() {
        // Framing must allow several messages back to back on one connection.
        let mut framed = encode(&sample()).unwrap();
        framed.extend_from_slice(&encode(&sample()).unwrap());
        let mut cursor = std::io::Cursor::new(framed);

        assert_eq!(read_message(&mut cursor).await.unwrap(), sample());
        assert_eq!(read_message(&mut cursor).await.unwrap(), sample());
    }
}
```

`crates/lb-cluster/src/lib.rs`:
```rust
mod counters;
pub mod protocol;

pub use counters::CounterStore;
```

- [ ] **Step 2: Run the protocol tests**

Run: `cargo test -p lb-cluster`
Expected: PASS — the counter tests plus five protocol tests.

- [ ] **Step 3: Commit**

```bash
git add crates/lb-cluster
git commit -m "feat(lb-cluster): add length-prefixed peer sync protocol with bounded decoding"
```

---

## Task 3: `ClusterCoordinator` trait, `ClusterNode`, and per-listener coordinators

**Files:**
- Create: `crates/lb-core/src/cluster.rs`
- Modify: `crates/lb-core/src/lib.rs`
- Create: `crates/lb-cluster/src/coordinator.rs`
- Modify: `crates/lb-cluster/src/lib.rs`

**Interfaces:**
- Produces: `lb_core::ClusterCoordinator` — `fn try_admit(&self, key: &str) -> bool`.
- Produces: `lb_cluster::{ClusterNode, ListenerCoordinator}`:
  - `ClusterNode::new(node_id: impl Into<String>, window_secs: u64, clock: C) -> Self` (generic over `C: Clock`), plus `store()`, `node_id()`, `merge_message(&self, msg: &SyncMessage) -> MergeOutcome`, `snapshot_message(&self) -> SyncMessage`, `prune(&self)`.
  - `MergeOutcome::{Merged, OwnNodeIdEcho}` — the second flags the duplicate-`node_id` misconfiguration.
  - `ListenerCoordinator::new(node: Arc<ClusterNode<C>>, namespace: impl Into<String>, limit: u64)`, implementing `ClusterCoordinator`.

- [ ] **Step 1: Add the trait to `lb-core`**

`crates/lb-core/src/cluster.rs`:
```rust
/// Cluster-wide admission control, consulted *after* the node-local rate
/// limiter has already allowed a request.
///
/// Implementations must not perform I/O: this sits on the request path, and
/// coordination happens out of band.
pub trait ClusterCoordinator: Send + Sync {
    /// Returns true if this request fits within the cluster-wide budget for
    /// `key`, recording it if so.
    fn try_admit(&self, key: &str) -> bool;
}
```

`crates/lb-core/src/lib.rs` — add `pub mod cluster;` and `pub use cluster::ClusterCoordinator;`.

- [ ] **Step 2: Write the coordinator**

`crates/lb-cluster/src/coordinator.rs`:
```rust
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
}

impl<C: Clock> ClusterNode<C> {
    pub fn new(node_id: impl Into<String>, window_secs: u64, clock: C) -> Self {
        ClusterNode {
            node_id: node_id.into(),
            store: CounterStore::new(window_secs),
            clock,
        }
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
        for entry in &msg.entries {
            self.store.merge(&entry.key, &msg.node_id, &entry.buckets);
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
        Arc::new(ClusterNode::new(id, 10, clock))
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

        // After sync, B sees A's counts and refuses.
        let b2 = node("b2", clock.clone());
        let coord_b2 = ListenerCoordinator::new(b2.clone(), "web", 4);
        assert_eq!(b2.merge_message(&a.snapshot_message()), MergeOutcome::Merged);
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
```

`crates/lb-cluster/src/lib.rs`:
```rust
mod coordinator;
mod counters;
pub mod protocol;

pub use coordinator::{ClusterNode, ListenerCoordinator, MergeOutcome};
pub use counters::CounterStore;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p lb-core -p lb-cluster --features lb-core/test-util`
Expected: PASS — including the six coordinator tests.

- [ ] **Step 4: Commit**

```bash
git add crates/lb-core crates/lb-cluster
git commit -m "feat(lb-cluster): add ClusterCoordinator trait and per-listener cluster budgets"
```

---

## Task 4: Peer networking (listener + periodic push)

**Files:**
- Create: `crates/lb-cluster/src/gossip.rs`
- Modify: `crates/lb-cluster/src/lib.rs`

**Interfaces:**
- Produces: `lb_cluster::{spawn_peer_listener, spawn_sync_loop}`:
  - `spawn_peer_listener<C: Clock + 'static>(node: Arc<ClusterNode<C>>, listener: TcpListener) -> JoinHandle<()>`
  - `spawn_sync_loop<C: Clock + 'static>(node: Arc<ClusterNode<C>>, peers: Vec<SocketAddr>, interval: Duration, connect_timeout: Duration) -> JoinHandle<()>`

Note the listener takes an already-bound `TcpListener` rather than a `SocketAddr`, so `lb-server` can bind every port up front and fail fast — and so tests can bind port 0 and learn the real address.

- [ ] **Step 1: Write the gossip module**

`crates/lb-cluster/src/gossip.rs`:
```rust
use crate::coordinator::{ClusterNode, MergeOutcome};
use crate::protocol::{encode, read_message};
use lb_core::Clock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Accepts peer connections and merges the counters they push.
pub fn spawn_peer_listener<C>(node: Arc<ClusterNode<C>>, listener: TcpListener) -> tokio::task::JoinHandle<()>
where
    C: Clock + 'static,
{
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // A transient accept failure must not kill coordination for
                // the life of the process.
                continue;
            };
            let node = Arc::clone(&node);
            tokio::spawn(async move {
                handle_peer_connection(node, stream, peer).await;
            });
        }
    })
}

async fn handle_peer_connection<C>(node: Arc<ClusterNode<C>>, mut stream: TcpStream, peer: SocketAddr)
where
    C: Clock,
{
    loop {
        match read_message(&mut stream).await {
            Ok(msg) => {
                if node.merge_message(&msg) == MergeOutcome::OwnNodeIdEcho {
                    eprintln!(
                        "cluster: peer {peer} announced node_id '{}', which is ours — \
                         two nodes share a node_id, and their counts will collide",
                        msg.node_id
                    );
                }
            }
            // Includes clean EOF when the peer closes after pushing. A bad
            // frame closes only this connection, never the listener.
            Err(_) => return,
        }
    }
}

/// Periodically pushes our own counters to every peer, then prunes.
///
/// Each round opens a fresh connection per peer. That costs a handshake but
/// removes all reconnect/backoff state, and at a handful of peers and a
/// sub-second interval the cost is irrelevant next to the traffic being
/// balanced.
pub fn spawn_sync_loop<C>(
    node: Arc<ClusterNode<C>>,
    peers: Vec<SocketAddr>,
    interval: Duration,
    connect_timeout: Duration,
) -> tokio::task::JoinHandle<()>
where
    C: Clock + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            let message = node.snapshot_message();
            if !message.entries.is_empty() {
                let Ok(framed) = encode(&message) else {
                    continue;
                };
                for peer in &peers {
                    // A peer being down is normal, not an error: its counts
                    // age out of the window on their own.
                    let _ = push_to_peer(*peer, &framed, connect_timeout).await;
                }
            }

            node.prune();
        }
    })
}

async fn push_to_peer(peer: SocketAddr, framed: &[u8], connect_timeout: Duration) -> std::io::Result<()> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(peer))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    stream.write_all(framed).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ListenerCoordinator;
    use lb_core::test_util::FakeClock;
    use lb_core::ClusterCoordinator;

    async fn bound_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn counters_propagate_from_one_node_to_another() {
        let clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new("sender", 10, clock.clone()));
        let receiver = Arc::new(ClusterNode::new("receiver", 10, clock.clone()));

        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

        // Sender consumes 4 of a budget of 5.
        let sender_coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 5);
        for _ in 0..4 {
            assert!(sender_coord.try_admit("1.2.3.4"));
        }

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![addr],
            Duration::from_millis(20),
            Duration::from_millis(500),
        );

        // Wait for the receiver to see the sender's counts.
        let receiver_coord = ListenerCoordinator::new(Arc::clone(&receiver), "web", 5);
        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver.store().total_in_window("web\u{1}1.2.3.4", clock.unix_secs()) == 4 {
                converged = true;
                break;
            }
        }
        assert!(converged, "receiver never saw the sender's counters");

        // The receiver now has only one slot left out of the shared budget.
        assert!(receiver_coord.try_admit("1.2.3.4"));
        assert!(!receiver_coord.try_admit("1.2.3.4"));
    }

    #[tokio::test]
    async fn an_unreachable_peer_does_not_break_the_sync_loop() {
        let clock = FakeClock::new();
        let sender = Arc::new(ClusterNode::new("sender", 10, clock.clone()));

        // One dead address, one live receiver.
        let dead = {
            let (l, a) = bound_listener().await;
            drop(l);
            a
        };
        let receiver = Arc::new(ClusterNode::new("receiver", 10, clock.clone()));
        let (listener, live) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));

        let _sync = spawn_sync_loop(
            Arc::clone(&sender),
            vec![dead, live],
            Duration::from_millis(20),
            Duration::from_millis(200),
        );

        // The live peer still receives, despite the dead one in the list.
        let mut converged = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver.store().total_in_window("web\u{1}k", clock.unix_secs()) == 1 {
                converged = true;
                break;
            }
        }
        assert!(converged, "a dead peer blocked delivery to a live one");
    }

    #[tokio::test]
    async fn garbage_from_a_peer_does_not_kill_the_listener() {
        let clock = FakeClock::new();
        let receiver = Arc::new(ClusterNode::new("receiver", 10, clock.clone()));
        let (listener, addr) = bound_listener().await;
        let _srv = spawn_peer_listener(Arc::clone(&receiver), listener);

        // Send junk that is not a valid frame.
        {
            let mut junk = TcpStream::connect(addr).await.unwrap();
            junk.write_all(b"absolutely not a valid frame").await.unwrap();
            junk.shutdown().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The listener still serves a well-formed peer afterwards.
        let sender = Arc::new(ClusterNode::new("sender", 10, clock.clone()));
        let coord = ListenerCoordinator::new(Arc::clone(&sender), "web", 10);
        assert!(coord.try_admit("k"));
        let framed = encode(&sender.snapshot_message()).unwrap();
        {
            let mut good = TcpStream::connect(addr).await.unwrap();
            good.write_all(&framed).await.unwrap();
            good.shutdown().await.unwrap();
        }

        let mut converged = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if receiver.store().total_in_window("web\u{1}k", clock.unix_secs()) == 1 {
                converged = true;
                break;
            }
        }
        assert!(converged, "listener stopped working after a malformed frame");
    }
}
```

`crates/lb-cluster/src/lib.rs`:
```rust
mod coordinator;
mod counters;
mod gossip;
pub mod protocol;

pub use coordinator::{ClusterNode, ListenerCoordinator, MergeOutcome};
pub use counters::CounterStore;
pub use gossip::{spawn_peer_listener, spawn_sync_loop};
```

- [ ] **Step 2: Run the gossip tests**

Run: `cargo test -p lb-cluster --features lb-core/test-util`
Expected: PASS — all counter, protocol, coordinator, and the three gossip tests.

- [ ] **Step 3: Commit**

```bash
git add crates/lb-cluster
git commit -m "feat(lb-cluster): add peer sync listener and periodic push loop"
```

---

## Task 5: Config and wiring

**Files:**
- Modify: `crates/lb-core/src/config.rs`
- Modify: `crates/lb-proxy/src/service.rs`
- Modify: `crates/lb-tcp/src/session.rs`
- Modify: `crates/lb-server/src/wiring.rs`, `crates/lb-server/src/lib.rs`, `crates/lb-server/Cargo.toml`

**Interfaces:**
- Produces: `lb_core::ClusterConfig { node_id, listen, peers, sync_interval_ms, window_secs }`; `Config::cluster: Option<ClusterConfig>`.
- Changes: `ProxyContext` and `TcpContext` each gain `pub cluster: Option<Arc<dyn ClusterCoordinator>>`.
- Changes: `build_app` returns `WiredApp` with an added `cluster_listener: Option<(TcpListener-to-be, SocketAddr)>`; see Step 4 for the exact shape.

- [ ] **Step 1: Add `ClusterConfig`**

In `crates/lb-core/src/config.rs`, add to the `Config` struct:
```rust
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
```

And the type plus defaults:
```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    pub node_id: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub peers: Vec<SocketAddr>,
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_sync_interval_ms() -> u64 {
    200
}

fn default_window_secs() -> u64 {
    10
}

impl ClusterConfig {
    pub fn sync_interval(&self) -> Duration {
        Duration::from_millis(self.sync_interval_ms)
    }
}
```

In `Config::validate`, after the listener loop, add cluster validation:
```rust
        if let Some(cluster) = &self.cluster {
            if cluster.node_id.trim().is_empty() {
                return Err(ConfigError::Invalid("cluster.node_id must not be empty".into()));
            }
            if cluster.sync_interval_ms == 0 {
                return Err(ConfigError::Invalid(
                    "cluster.sync_interval_ms must be positive".into(),
                ));
            }
            if cluster.window_secs == 0 {
                return Err(ConfigError::Invalid("cluster.window_secs must be positive".into()));
            }
            if cluster.peers.contains(&cluster.listen) {
                return Err(ConfigError::Invalid(format!(
                    "cluster.peers contains this node's own listen address {} — peers must list only the other nodes",
                    cluster.listen
                )));
            }
            if let Some(clash) = self.listeners.iter().find(|l| l.listen == cluster.listen) {
                return Err(ConfigError::Invalid(format!(
                    "cluster.listen {} is already used by listener '{}'",
                    cluster.listen, clash.name
                )));
            }
        }
```

Add to `lb-core/src/lib.rs`'s config re-export list: `ClusterConfig`.

Add these tests to `config.rs`'s test module:
```rust
    const CLUSTER: &str = r#"
        [cluster]
        node_id = "lb-1"
        listen = "127.0.0.1:7946"
        peers = ["127.0.0.1:7947"]
    "#;

    #[test]
    fn parses_cluster_section_with_defaults() {
        let text = format!("{CLUSTER}{VALID}");
        let cfg = Config::parse(&text).unwrap();
        let cluster = cfg.cluster.expect("cluster section should parse");
        assert_eq!(cluster.node_id, "lb-1");
        assert_eq!(cluster.sync_interval_ms, 200);
        assert_eq!(cluster.window_secs, 10);
    }

    #[test]
    fn cluster_is_optional() {
        assert!(Config::parse(VALID).unwrap().cluster.is_none());
    }

    #[test]
    fn rejects_peers_containing_our_own_listen_address() {
        let text = format!("{}{VALID}", CLUSTER.replace("7947", "7946"));
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_cluster_listen_clashing_with_a_traffic_listener() {
        let text = format!("{}{VALID}", CLUSTER.replace("127.0.0.1:7946", "0.0.0.0:8080"));
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_node_id() {
        let text = format!("{}{VALID}", CLUSTER.replace(r#""lb-1""#, r#""""#));
        assert!(matches!(Config::parse(&text), Err(ConfigError::Invalid(_))));
    }
```

Note: `[cluster]` must come *before* the `[[listeners]]` array in the TOML, hence `format!("{CLUSTER}{VALID}")` — a table defined after an array-of-tables would be parsed into the last table of that array.

- [ ] **Step 2: Consult the coordinator in `lb-proxy`**

In `crates/lb-proxy/src/service.rs`, add `cluster` to the context:
```rust
    pub cluster: Option<Arc<dyn lb_core::ClusterCoordinator>>,
```

And in `handle`, immediately after the local GCRA check passes (before the circuit-breaker refresh):
```rust
    // Cluster budget is consulted only after the local limiter allowed the
    // request: local is free, this is shared state.
    if let Some(cluster) = &ctx.cluster {
        if !cluster.try_admit(&key) {
            return Ok(simple_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            ));
        }
    }
```

Every `ProxyContext { .. }` literal in `service.rs`'s tests needs `cluster: None` added.

- [ ] **Step 3: Consult the coordinator in `lb-tcp`**

In `crates/lb-tcp/src/session.rs`, add to `TcpContext`:
```rust
    pub cluster: Option<Arc<dyn lb_core::ClusterCoordinator>>,
```

And in `handle_connection`, immediately after the local rate-limit check:
```rust
    if let Some(cluster) = &ctx.cluster {
        if !cluster.try_admit(&key) {
            return ConnectionOutcome::RateLimited;
        }
    }
```

The test helper `context(..)` in that file needs `cluster: None`.

- [ ] **Step 4: Wire it in `lb-server`**

`crates/lb-server/Cargo.toml` — add:
```toml
lb-cluster = { path = "../lb-cluster" }
```

In `crates/lb-server/src/wiring.rs`:
```rust
use lb_cluster::{ClusterNode, ListenerCoordinator};
use lb_core::ClusterCoordinator;

pub type AppClusterNode = ClusterNode<SystemClock>;
```

Add to `WiredApp`:
```rust
pub struct WiredApp {
    pub listeners: Vec<ListenerRuntime>,
    pub background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub drain_timeout: Duration,
    /// Present only when `[cluster]` is configured.
    pub cluster: Option<ClusterSetup>,
}

pub struct ClusterSetup {
    pub node: Arc<AppClusterNode>,
    pub listen: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub sync_interval: Duration,
}
```

In `build_app`, before the per-listener loop:
```rust
    let cluster_node = config.cluster.as_ref().map(|c| {
        Arc::new(ClusterNode::new(
            c.node_id.clone(),
            c.window_secs,
            SystemClock,
        ))
    });
```

Inside the per-listener loop, after `rate_limiter` is built, derive this listener's coordinator:
```rust
        // The global cap is the sustained rate over the whole window; the
        // local GCRA continues to shape bursts inside it.
        let cluster_coordinator: Option<Arc<dyn ClusterCoordinator>> =
            match (&cluster_node, &config.cluster) {
                (Some(node), Some(cc)) => {
                    let limit = (lc.rate_limit.rate_per_sec * cc.window_secs as f64).ceil() as u64;
                    Some(Arc::new(ListenerCoordinator::new(
                        Arc::clone(node),
                        lc.name.clone(),
                        limit.max(1),
                    )))
                }
                _ => None,
            };
```

Pass `cluster: cluster_coordinator` into both the `ProxyContext` and `TcpContext` literals.

And build the returned `WiredApp`:
```rust
    let cluster = match (cluster_node, config.cluster.as_ref()) {
        (Some(node), Some(cc)) => Some(ClusterSetup {
            node,
            listen: cc.listen,
            peers: cc.peers.clone(),
            sync_interval: cc.sync_interval(),
        }),
        _ => None,
    };

    WiredApp {
        listeners,
        background_tasks,
        drain_timeout: Duration::from_millis(config.server.drain_timeout_ms),
        cluster,
    }
```

In `crates/lb-server/src/lib.rs`'s `run`, after binding traffic listeners and before spawning them, bind and start the cluster:
```rust
    // Bound here with the traffic listeners so a port clash fails startup,
    // rather than after we are already serving.
    let mut cluster_tasks = Vec::new();
    if let Some(setup) = cluster {
        let peer_listener = TcpListener::bind(setup.listen).await.map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("cluster peer listener could not bind {}: {err}", setup.listen),
            )
        })?;
        eprintln!(
            "cluster node '{}' peer listener on {} ({} peer(s))",
            setup.node.node_id(),
            peer_listener.local_addr()?,
            setup.peers.len()
        );
        cluster_tasks.push(lb_cluster::spawn_peer_listener(
            Arc::clone(&setup.node),
            peer_listener,
        ));
        cluster_tasks.push(lb_cluster::spawn_sync_loop(
            Arc::clone(&setup.node),
            setup.peers.clone(),
            setup.sync_interval,
            Duration::from_secs(2),
        ));
    }
```
Destructure `cluster` out of `WiredApp` alongside the other fields, and at shutdown abort `cluster_tasks` in the same loop that aborts `background_tasks`.

- [ ] **Step 5: Run the full suite**

Run: `cargo test --workspace --features lb-core/test-util`
Expected: PASS everywhere. Phases 1 and 2 tests are unaffected because they configure no `[cluster]` section and therefore get `cluster: None`.

- [ ] **Step 6: Commit**

```bash
git add crates Cargo.lock
git commit -m "feat(lb-server): wire cluster coordination into listeners and the request path"
```

---

## Task 6: End-to-end multi-node test and docs

**Files:**
- Create: `crates/lb-server/tests/cluster_integration.rs`
- Modify: `crates/lb-server/tests/support.rs`
- Modify: `config.example.toml`, `README.md`

- [ ] **Step 1: Add a clustered-config helper**

Append to `crates/lb-server/tests/support.rs`:
```rust
/// One HTTP listener plus a `[cluster]` section, for multi-node tests.
#[allow(clippy::too_many_arguments)]
pub fn cluster_config_toml(
    node_id: &str,
    cluster_listen: SocketAddr,
    peers: &[SocketAddr],
    traffic_listen: SocketAddr,
    backend: SocketAddr,
    rate_per_sec: f64,
    burst: u32,
    window_secs: u64,
) -> String {
    let peer_list: Vec<String> = peers.iter().map(|p| format!("\"{p}\"")).collect();
    format!(
        r#"
[cluster]
node_id = "{node_id}"
listen = "{cluster_listen}"
peers = [{peers}]
sync_interval_ms = 50
window_secs = {window_secs}

[[listeners]]
name = "web"
protocol = "http"
listen = "{traffic_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#,
        peers = peer_list.join(", ")
    )
}
```

- [ ] **Step 2: Write the end-to-end cluster tests**

`crates/lb-server/tests/cluster_integration.rs`:
```rust
mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::Duration;
use support::{cluster_config_toml, spawn_counting_backend};
use tokio::net::TcpListener;

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn get(listen: SocketAddr) -> StatusCode {
    reqwest::Client::new()
        .get(format!("http://{listen}/"))
        .send()
        .await
        .unwrap()
        .status()
}

/// The headline test: node B must refuse traffic because node A already
/// spent the shared budget. If coordination were broken, B would happily
/// serve — which is exactly the bug Phase 3 exists to fix.
#[tokio::test]
async fn one_nodes_traffic_exhausts_the_budget_for_another() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;

    let cluster_a = free_addr().await;
    let cluster_b = free_addr().await;
    let traffic_a = free_addr().await;
    let traffic_b = free_addr().await;

    // rate 2/s over a 10s window => a global budget of 20.
    // burst 100 keeps the *local* GCRA out of the way, so this test is
    // measuring the cluster layer and not Phase 1's limiter.
    let config_a = Config::parse(&cluster_config_toml(
        "lb-a", cluster_a, &[cluster_b], traffic_a, backend, 2.0, 100, 10,
    ))
    .unwrap();
    let config_b = Config::parse(&cluster_config_toml(
        "lb-b", cluster_b, &[cluster_a], traffic_b, backend, 2.0, 100, 10,
    ))
    .unwrap();

    tokio::spawn(lb_server::run(config_a));
    tokio::spawn(lb_server::run(config_b));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Node A spends the entire global budget of 20.
    let mut admitted_a = 0;
    for _ in 0..20 {
        if get(traffic_a).await == StatusCode::OK {
            admitted_a += 1;
        }
    }
    assert_eq!(admitted_a, 20, "node A should have had the full budget");

    // Let the counters propagate (sync_interval is 50ms).
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Node B now sees A's counts and must refuse.
    for _ in 0..5 {
        assert_eq!(
            get(traffic_b).await,
            StatusCode::TOO_MANY_REQUESTS,
            "node B admitted traffic despite the cluster budget being spent"
        );
    }
}

/// Control for the test above: without `[cluster]`, node B has no idea what
/// node A did and serves happily. This is the pre-Phase-3 behaviour, and its
/// presence proves the test above is actually detecting coordination.
#[tokio::test]
async fn without_clustering_each_node_enforces_its_own_budget() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let traffic_a = free_addr().await;
    let traffic_b = free_addr().await;

    let solo = |listen: SocketAddr| {
        format!(
            r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 1000
  burst = 1000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
        )
    };

    tokio::spawn(lb_server::run(Config::parse(&solo(traffic_a)).unwrap()));
    tokio::spawn(lb_server::run(Config::parse(&solo(traffic_b)).unwrap()));
    tokio::time::sleep(Duration::from_millis(200)).await;

    for _ in 0..5 {
        assert_eq!(get(traffic_a).await, StatusCode::OK);
    }
    for _ in 0..5 {
        assert_eq!(get(traffic_b).await, StatusCode::OK);
    }
}

/// Three nodes sharing one budget: total admissions must respect the global
/// limit plus the propagation slack the spec documents, and must be far below
/// the un-coordinated `3 × limit`.
#[tokio::test]
async fn three_nodes_hold_the_global_limit_within_the_documented_bound() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;

    let cluster: Vec<SocketAddr> = vec![free_addr().await, free_addr().await, free_addr().await];
    let traffic: Vec<SocketAddr> = vec![free_addr().await, free_addr().await, free_addr().await];

    for i in 0..3 {
        let peers: Vec<SocketAddr> = cluster
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, a)| *a)
            .collect();
        let config = Config::parse(&cluster_config_toml(
            &format!("lb-{i}"),
            cluster[i],
            &peers,
            traffic[i],
            backend,
            2.0,
            100,
            10,
        ))
        .unwrap();
        tokio::spawn(lb_server::run(config));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let global_limit = 20; // rate 2/s * 10s window

    // Round-robin across the three nodes, pausing to let counts propagate so
    // this measures steady-state enforcement rather than the cold-start race.
    let mut admitted = 0;
    for round in 0..12 {
        for node in &traffic {
            if get(*node).await == StatusCode::OK {
                admitted += 1;
            }
        }
        if round % 2 == 1 {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    assert!(
        admitted >= global_limit,
        "the cluster should admit at least its budget, admitted {admitted}"
    );
    // The upper bound MUST sit below what an uncoordinated cluster would
    // admit, or the test proves nothing. Local burst is 100 per node, so
    // without coordination all 36 requests would sail through; a bound of
    // 40 would therefore pass on a completely broken cluster. 30 leaves
    // room for the propagation slack the spec documents while still failing
    // loudly if coordination stops working.
    assert!(
        admitted <= global_limit + 10,
        "cluster over-admitted: {admitted} against a global limit of {global_limit} \
         (36 would mean no coordination at all)"
    );
}
```

- [ ] **Step 3: Run the cluster integration tests**

Run: `cargo test -p lb-server --test cluster_integration`
Expected: PASS — all three.

If `three_nodes_hold_the_global_limit_within_the_documented_bound` is flaky, do **not** widen the bound to make it pass. Investigate first: print `admitted`, and confirm whether the excess matches the propagation window (requests issued faster than `sync_interval_ms` can converge). Widening a bound to hide a real over-admission would defeat the purpose of the test.

- [ ] **Step 4: Update docs**

Append a cluster section to `config.example.toml` (at the very top, before `[server]`, since a TOML table after an array-of-tables would be captured by it):
```toml
# ── Cluster coordination (optional) ───────────────────────────────────
# Omit this whole section to run as a single node.
# Enforces the rate limit ACROSS nodes: without it, N nodes each admit
# `rate_per_sec`, so the effective global limit is N x what you configured.
# [cluster]
# node_id          = "lb-1"                  # must be unique per node
# listen           = "127.0.0.1:7946"        # peer sync port — bind privately
# peers            = ["127.0.0.1:7947"]      # the OTHER nodes
# sync_interval_ms = 200
# window_secs      = 10
```

In `README.md`, retitle to "Phases 1–3", add `lb-cluster` to the workspace layout, and add:
```markdown
## Running more than one node

A single node enforces `rate_per_sec` correctly. Three nodes, each enforcing
it locally, let a client through at `3 × rate_per_sec` — the limit is silently
multiplied by the node count. Adding a `[cluster]` section makes the limit
global.

Each node counts the requests it admits into one-second buckets and pushes
those counts to its peers. The counters are a **G-Counter CRDT**: counts are
summed *across* nodes (consumption is additive) and merged with `max` *within*
a node's own cell (which only ever grows). That merge is commutative,
associative and idempotent, so it survives reordered, duplicated and delayed
messages — which is what a network does to you.

**The guarantee is approximate and bounded**, deliberately. Between sync
rounds the cluster may over-admit by up to
`peers × requests-per-peer-per-sync-interval`. An exact limit needs a round
trip to shared state on every request; this design keeps coordination off the
request path entirely. Under a network partition it favours availability:
both halves keep serving and the global limit is temporarily exceeded.

The peer port accepts **unauthenticated** input that influences rate-limiting
decisions. Bind it to a private interface. Authentication for the peer channel
is not implemented.
```

- [ ] **Step 5: Verify the example config still starts**

Run: `cargo run -p lb-server -- config.example.toml`
Expected: starts and prints its listeners (the `[cluster]` block is commented out, so no peer listener). Ctrl+C to stop.

- [ ] **Step 6: Commit**

```bash
git add crates/lb-server config.example.toml README.md
git commit -m "test(lb-server): add multi-node cluster integration tests; document clustering"
```

---

## Post-Plan Verification

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings
cargo test --workspace --features lb-core/test-util
```

All three must be clean. Commit any formatting changes separately.
