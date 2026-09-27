# Cluster Coordinator

The load balancer supports distributed rate limiting across multiple instances without relying on Redis or Memcached. This is achieved via a peer-to-peer CRDT (Conflict-free Replicated Data Type) and an authenticated gossip protocol.

## The Problem with Distributed Sums

If Node A and Node B both track requests for the key `admin-api`, they need to share their totals. If Node A tells Node B "I have 5 requests," and later tells Node B "I have 8 requests," Node B cannot simply sum those numbers, or it will count the first 5 requests twice.

## The G-Counter CRDT

The cluster solves this using a Grow-Only Counter (G-Counter) over a sliding time window.

State is partitioned into cells keyed by three values: `(Key, NodeID, TimeBucket)`.
A TimeBucket represents a discrete second in time.

**The Golden Rule of G-Counters:** Node A is the *only* writer to cells where `NodeID == Node A`. 

When Node A gossips its state to Node B, Node B receives the cell `("admin-api", "Node A", T=10, Count=8)`. Node B performs a `max` merge into its own local store:

```rust
let current = local_store.get(cell_key);
let new_count = std::cmp::max(current, gossiped_count);
local_store.insert(cell_key, new_count);
```

If Node B had previously seen a count of 5, it updates to 8. Because operations are associative, commutative, and idempotent, packets can arrive out of order, be duplicated, or be delayed without corrupting the final count.

To find the global rate limit for `admin-api`, a node simply queries its local store, summing the most recent cells for that key across all known `NodeIDs` within the sliding time window.

## Network Partitions and Node Failure

The CRDT requires no consensus, no Raft, and no leader election.

- **Network Partition:** If Node A and Node B cannot communicate, they continue admitting requests based on their local state. Once the partition heals, they exchange their cells and the `max` merge instantly converges their state.
- **Node Failure:** Because state is time-windowed (e.g., the last 60 seconds), a dead node requires no failure detection logic. Its historical cells simply age out of the time window and are evicted by the background GC loop. If the node restarts, it begins writing to a new cell starting from 0.

## The Gossip Protocol

The cluster communicates over a dedicated TCP port. 
Every 500ms, each node selects random peers and pushes its recently updated cells.

Because this port is often exposed across data centers, all gossip packets are authenticated using HMAC-SHA256 with a shared secret defined in the configuration. 

```rust
// Only packets with a valid HMAC signature are processed
if !hmac::verify(secret, &packet.payload, &packet.signature) {
    warn!("Discarding invalid gossip packet from peer");
    return;
}
```

## Trade-offs

This design trades perfect consistency for extreme availability and low latency. 
The request path never blocks waiting for the network; it only reads the local, eventually-consistent `DashMap`. The cost is a brief window of over-admission (bounded by the 500ms gossip interval) if multiple nodes receive concurrent bursts.
