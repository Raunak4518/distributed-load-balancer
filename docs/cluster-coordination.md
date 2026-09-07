# Cluster Coordination

Multiple load balancer nodes share rate-limit state using a G-Counter CRDT synchronized via gossip.

## Counter Store

The `CounterStore` implements a Grow-Only Counter (G-Counter) over a sliding time window. 

State is partitioned by `(key, node_id, epoch_second)`. Each cell has exactly one writer—the node matching `node_id`—and its value only ever increments.

### Merge Semantics

When merging state from peers, the store applies a `max` operation to each cell. 

This is the only correct way to merge the cells. If the store summed values across the same cell, a duplicated message would inflate the count. 

To determine total consumption, the store sums the cells across all nodes within the time window. If the store maxed values across different nodes, N nodes could each admit the full rate limit, multiplying the allowed budget by N.

The per-cell `max` ensures merges are idempotent, commutative, and associative. Out-of-order delivery converges to the correct state.

### Admission

The `ListenerCoordinator` namespaces rate-limit keys by listener name using the `\u{1}` character to prevent collisions.

When a request arrives, `try_admit` evaluates the total consumed tokens against the limit. The limit is the configured `rate_per_sec` multiplied by the `window_secs`.

If the total is below the limit, the store increments this node's cell for the current second. The evaluation and increment execute under the same lock, ensuring a node never over-admits against its own local view.

## Gossip Protocol

Nodes push their local counters to peers every `sync_interval_ms` (default 500ms).

### Wire Format

Messages are framed over TCP:
`[4-byte BE length][32-byte HMAC-SHA256 tag][JSON SyncMessage]`

A node only transmits cells it owns. It does not relay cells received from other nodes.

### Security

A pre-shared key is required to join the cluster. Without authentication, the peer port would be an open Denial of Service vector.

The HMAC tag covers the JSON payload and is verified in constant time before the payload is deserialized. A 4 MiB hard limit is checked before memory is allocated.

Messages that claim to originate from the receiving node's ID are rejected.

Errors close the individual peer connection. They do not crash the peer listener.

### Sync Loop

The sync loop snapshots the node's in-window cells. For each peer, it opens a fresh TCP connection, writes the framed message, and closes the connection. 

This trades the cost of a TCP handshake for the simplicity of stateless pushing. It avoids managing connection pools, reconnect loops, or backoff timers.

After pushing, the node prunes cells that fall outside the sliding window.

## Dead Peers

The system has no explicit peer health tracking. If a peer dies, its historical counts age out of the sliding window naturally. If it restarts, it begins counting from zero in the current second.
