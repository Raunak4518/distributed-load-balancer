# Distributed Load Balancer — Phase 3 Design (Multi-Node Coordination)

**Date:** 2026-09-04
**Status:** Approved for implementation planning
**Builds on:** [Phase 1 — L7 HTTP](2026-09-03-lb-phase1-design.md) and [Phase 2 — L4 TCP](2026-09-04-lb-phase2-design.md), both shipped.
**Scope:** Making the rate limiter enforce a *global* limit across several load-balancer nodes.

## 1. The Problem

Run three LB nodes, each configured `rate_per_sec = 50`, and a client that reaches all three gets up to 150 req/s. The configured limit is silently multiplied by the node count. Every other part of the system already works per-node correctly — backend selection, health checking, circuit breaking are all legitimately node-local — but a rate limit is inherently a statement about *aggregate* traffic, so it is the one thing that breaks when you scale out.

Phase 3 fixes exactly that, and nothing else.

## 2. Two Traps Worth Recording

Both were found while designing this, and both would have produced a limiter that looks correct and is not.

**Trap 1 — "gossip the TAT and take the max" is wrong.** GCRA state is one timestamp (the theoretical arrival time). The obvious distributed version shares it and merges with `max`. But if node A and node B have each admitted 5 requests, both hold `TAT = now + 5·period`, and `max` yields `now + 5·period` — when 10 requests were actually consumed. **Consumption is additive, not max-able.** Merging with `max` systematically under-counts and therefore over-admits.

**Trap 2 — GCRA's idle-forgiveness cannot be expressed as a grow-only counter.** The natural fix for Trap 1 is to make the TAT a sum of per-node grow-only counters (a G-Counter, which merges safely). But GCRA drains via `tat = max(stored_tat, now)`: after an idle period the timestamp *resets forward*. A reset is not monotonic, so it is not expressible as an increment. Worse, two nodes observing a drained bucket concurrently would both jump their counters, double-counting.

The conclusion is that exact distributed GCRA is not a small change, and forcing it would trade a correct local limiter for a subtly broken distributed one. So Phase 3 does not distribute GCRA. It layers a mechanism that *is* naturally distributable underneath it.

## 3. Design

### 3.1 Two layers

| Layer | Scope | Job |
|---|---|---|
| **Local GCRA** (unchanged from Phase 1) | per node | Burst shaping on the fast path, zero coordination |
| **Global sliding-window counter** (new) | cluster-wide | Enforce the aggregate sustained rate |

A request must pass **both**. The local GCRA runs first because it is free; the global check only runs for requests the local layer already accepted.

### 3.2 The counter is a G-Counter CRDT

Each node counts the requests **it** admitted, per key, into fixed one-second buckets:

```
counts[key][node_id][epoch_second] = u64
```

- A node only ever writes its **own** `node_id` entry, and only ever increments it.
- The global count for a key is the **sum** over all nodes and all buckets inside the window.
- Merging two views takes the **max** per `(key, node_id, epoch_second)` cell.

`max`-per-cell is the correct merge here precisely because each cell is grow-only and owned by exactly one writer: once that second has passed the cell is frozen at its true final value, and `max` converges to it. This makes the merge **commutative, associative, and idempotent** — so it is safe under message reordering, duplication, and arbitrary delay, which is what a network will do to you. Those three properties are asserted directly by tests (§7), because they are the reason the design is correct.

Note the contrast with Trap 1: we sum *across* nodes (consumption is additive) and take max *within* a single node's cell (that cell has one writer). Getting those two operations the right way round is the whole design.

### 3.2.1 This requires wall-clock time, and that is an assumption

Buckets are keyed by **Unix epoch second**, not by a monotonic instant. That is forced: bucket boundaries have to line up *across machines*, and a monotonic clock's origin is per-process, so it cannot express a shared boundary.

The assumption this creates: nodes need roughly-agreeing wall clocks (i.e. NTP, which any serious deployment already runs). The failure mode is graceful rather than sharp — skew of a second or two simply lands a node's contributions in neighbouring buckets, and since the window sums ten of them, the total barely moves. Large skew degrades accuracy but never breaks convergence or safety, because the merge is still a per-cell `max` over cells that only ever grow.

Concretely this means `lb-core`'s `Clock` trait gains a `unix_secs()` method alongside `now()`. The distinction is deliberate and worth keeping straight: `now()` (monotonic) is what GCRA and the circuit breaker need, because they measure *elapsed* time and must be immune to clock jumps; `unix_secs()` is what bucket alignment needs, because it must be *shared*. Using either one for the other's job would be a bug.

### 3.3 Why staleness handles itself

A dead or partitioned peer stops sending updates. Its buckets then age out of the sliding window within `window_secs`, after which they contribute zero — which is correct, because a node that is down is not admitting traffic either. No explicit peer-expiry policy, no tombstones, no failure detector needed for correctness. `last_seen` is tracked only for operator visibility.

### 3.4 The guarantee, stated honestly

This is an **approximate** limiter, and the approximation is bounded:

> Between synchronisation rounds, the cluster may over-admit by at most `(number_of_peers × requests_admitted_per_peer_per_sync_interval)` before the counts converge.

Shrinking `sync_interval_ms` tightens the bound at the cost of more network chatter. An *exact* limiter requires a round trip to a shared authority on every single request (the Redis/`redis-cell` model), which buys exactness at the price of per-request latency and a hard dependency that must itself be made highly available. Phase 3 takes the other trade deliberately. §7 includes a test that asserts the stated bound actually holds.

**Under network partition this design favours availability over correctness (AP, not CP):** two partitioned halves each stop seeing the other's counts and each admit up to the full limit. Traffic keeps flowing; the global limit is temporarily exceeded. That is the intended behaviour for a load balancer, where refusing all traffic because peers are unreachable would be a worse failure than briefly over-admitting.

### 3.5 Topology and transport

- **Static full mesh.** Peers are listed in config. Every node pushes its own counters directly to every peer each `sync_interval_ms`; nodes never relay other nodes' data. That is `O(N²)` messages, which is fine for the handful of nodes a load balancer tier actually runs, and it removes an entire class of epidemic-propagation bugs. Dynamic membership (SWIM and friends) is explicitly out of scope.
- **Framing:** a 4-byte big-endian length prefix followed by a JSON payload, over TCP. **The length prefix is validated against a hard maximum before any allocation** — an unvalidated length from a socket is a textbook memory-exhaustion vector.
- **Only recently-active keys are sent**, bounding message size.

### 3.6 Self-detectable misconfiguration

If two nodes share a `node_id`, their cells collide and the cluster under-counts. That is an operator error, but a partly detectable one: **if a node receives a sync message carrying its own `node_id`, it logs a loud error**, because that can only mean a duplicate id.

### 3.7 Configuration

```toml
[cluster]
node_id          = "lb-1"                          # must be unique per node
listen           = "127.0.0.1:7946"                # peer sync listener
peers            = ["127.0.0.1:7947", "127.0.0.1:7948"]   # other nodes, excluding self
sync_interval_ms = 200
window_secs      = 10
```

Omitting `[cluster]` entirely leaves Phases 1–2 behaviour exactly unchanged — single-node, no coordination, no peer listener. This keeps the common case simple and gives the tests a clean "clustered vs not" comparison.

The global cap is derived from the existing per-listener `rate_limit.rate_per_sec`:

```
global_limit = rate_per_sec × window_secs
```

A ten-second default window is deliberate: it absorbs legitimate bursts (which the local GCRA is already shaping) while still holding the *sustained* rate to `rate_per_sec` globally. A one-second window would reject bursts the operator explicitly allowed via `burst`.

**A sliding window's cold-start behaviour, stated plainly:** the semantic is "no more than `global_limit` in any window of length `window_secs`", so an empty window permits a full `global_limit` before it engages. From cold, the cluster's short-term rate is bounded not by the global layer but by the *local* GCRAs — up to `nodes × burst` immediately, then `nodes × rate_per_sec` — until the window fills, after which sustained throughput settles at `rate_per_sec` globally. This is inherent to sliding windows rather than a defect, but it means the global layer governs *sustained* rate and the local layer governs *instantaneous* rate. Operators sizing a cluster should know which layer is binding at which timescale. A shorter window tightens the sustained bound sooner at the cost of rejecting permitted bursts.

Validation, fail-fast at startup as always: `node_id` non-empty, `listen` not also used by a traffic listener, `peers` must not contain our own `listen` address, `sync_interval_ms > 0`, `window_secs > 0`.

### 3.8 Architecture

New crate **`lb-cluster`**:
- `counters.rs` — the G-Counter store: per-key/per-node/per-bucket counts, merge, windowed sum, pruning.
- `protocol.rs` — message types, length-prefixed framing, encode/decode, max-size enforcement.
- `gossip.rs` — the peer listener (accept, decode, merge) and the periodic push loop.
- `coordinator.rs` — `GossipCoordinator`, implementing the `ClusterCoordinator` trait.

New trait in **`lb-core`**:

```rust
pub trait ClusterCoordinator: Send + Sync {
    /// Returns true if this request fits within the cluster-wide budget,
    /// recording it if so.
    fn try_admit(&self, key: &str) -> bool;
}
```

`lb-proxy` and `lb-tcp` gain an `Option<Arc<dyn ClusterCoordinator>>` and consult it only when present.

**On `dyn` here rather than a generic parameter:** `ProxyContext` and `TcpContext` already carry three type parameters. A fourth would propagate through every signature that touches them, to save one virtual call per request — a call that sits next to actual network I/O and is therefore free in relative terms. `HealthProbe` went the other way (generic, no `dyn`) because there it cost nothing. Same principle, opposite conclusion, for a reason worth writing down.

### 3.9 Request flow with clustering enabled

1. Local GCRA check. Deny → `429` (HTTP) or close (TCP), exactly as before.
2. `ClusterCoordinator::try_admit(key)`:
   - sum this key's counts across all nodes within the window,
   - if `sum >= global_limit` → deny, and **do not** increment,
   - otherwise increment our own current-second bucket and admit.
   This check-then-increment is atomic *within* a node, so a single node never over-admits against its own view; the approximation is purely the cross-node propagation delay.
3. Proceed with backend selection and forwarding, unchanged.

Every `sync_interval_ms`, the node pushes its own recently-active counters to each peer and prunes buckets that have fallen outside the window.

## 4. What Phase 3 Deliberately Does Not Share

**Health state stays node-local.** If node A cannot reach backend X but node B can, that is genuine per-node reachability information — a real network path that exists from one place and not another. Sharing it would make B avoid a backend it can serve perfectly well. Each node continues to health-check and circuit-break independently, which is both less code and more correct.

Also out of scope: dynamic membership/discovery, authentication or encryption on the peer channel, shared circuit-breaker state, and distributed backend selection.

## 5. Error Handling

- Phase 1/2 rules carry over: nothing reachable from network input may panic.
- A peer being unreachable is **normal**, not an error condition: a failed push is logged at most once per peer per backoff period and retried on the next tick. It never blocks or fails a client request.
- The peer sync path is entirely off the request path. If coordination is completely broken, each node degrades to local-only limiting (over-admitting by up to the node count) and keeps serving traffic.
- Malformed peer messages are dropped and the connection closed; one bad peer cannot take down the listener.
- All decode paths are bounded: max message size, max keys per message.

## 6. Security Note (a real limitation, not a footnote)

The peer sync port accepts unauthenticated input that directly influences rate-limiting decisions. Anyone who can reach it can inflate counters and cause legitimate traffic to be rejected — a denial-of-service vector. **The peer listener must be bound to a private interface or protected by network policy.** Authentication and transport encryption for the peer channel are deferred, and this is documented in the README rather than left implicit.

## 7. Testing Strategy

The correctness of this phase rests on CRDT properties and on a stated error bound, so both are tested directly rather than assumed.

- **CRDT laws** (the heart of it): merge is *commutative* (merging A then B equals B then A), *idempotent* (merging the same update twice changes nothing), and *associative*. Property-style tests over several update orderings.
- **Window arithmetic**: buckets outside the window are excluded; rollover across a second boundary behaves; pruning removes only out-of-window data.
- **Protocol**: encode/decode round trip; a length prefix above the maximum is rejected without allocating; truncated and malformed frames are rejected cleanly.
- **Multi-node convergence** (headline): three coordinators wired to each other in-process, driven with traffic, then asserted to converge on the same global count once sync settles.
- **Global limit enforcement**: with three coordinators sharing a limit, total admissions must not exceed `global_limit` plus the documented bound — the test encodes the §3.4 guarantee.
- **Duplicate `node_id` detection**: a message bearing our own id is detected.
- **End-to-end**: three complete `lb-server` instances in one test process, fronting the same backend, hammered concurrently; total admitted traffic respects the global limit within the bound. This is the actual proof that the phase works.
- **Cluster disabled**: with no `[cluster]` section, behaviour is byte-for-byte Phase 2 — all existing tests must continue to pass untouched.

## 8. Decisions Log

- **Peer-to-peer over Redis**: Redis (the `redis-cell` model) is the industry-standard exact answer, but there is no Redis available in this environment and Docker's daemon is not running — the code could not have been executed even once. Unverifiable distributed-systems code is precisely the kind most likely to be subtly wrong. Peer coordination needs no external service and is fully testable in-process.
- **Sliding-window counters over distributed GCRA**: see §2. Exact distributed GCRA founders on idle-forgiveness not being monotonic; the windowed counter is a natural CRDT and its weaker guarantee can be stated and tested precisely.
- **G-Counter (sum across nodes, max within a cell)**: the only merge that is correct for additive consumption with single-writer cells, and it is convergent under the reordering and duplication a real network produces.
- **Static full mesh over epidemic gossip**: `O(N²)` is irrelevant at load-balancer tier sizes, and it eliminates relay/propagation bugs entirely.
- **Ten-second default window**: enforces sustained rate globally without rejecting the bursts `burst` explicitly permits.
- **AP under partition**: for a load balancer, continuing to serve while briefly over-admitting beats refusing traffic because a peer is unreachable.
- **Health state stays local**: per-node reachability is real information, not noise to be averaged away.
- **`dyn` for the coordinator, generics for the probe**: see §3.8 — the cost/benefit genuinely differs between the two.
