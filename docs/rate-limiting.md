# Rate Limiting

The load balancer uses a two-tier rate limiting system: a local GCRA shapes bursts, and an optional cluster-wide G-Counter CRDT enforces a global budget. The cluster check runs only after the local check allows the request.

## Local GCRA

The Generic Cell Rate Algorithm (GCRA) tracks a theoretical arrival time (TAT) per key. Each request advances the TAT by the interval between permitted requests (`1 / rate_per_sec`). A request is allowed if the new TAT does not exceed the current time by more than the maximum burst (`burst_limit × interval`). 

If a request is denied, the TAT remains unchanged, and a `Retry-After` duration is calculated.

### Bounded State

The GCRA stores state per key. To prevent an attacker from exhausting memory by requesting unique keys, the number of tracked keys is capped by `max_tracked_keys`. 

When the map reaches capacity, new keys share a single overflow budget keyed by `\u{0}overflow`. This sentinel value cannot collide with a valid IP or HTTP header.

This ensures established clients keep their own limits, while a spray attack collectively gets the throughput of a single client. It avoids evicting legitimate clients (LRU) or blocking all new traffic (strict deny).

### Sweeper

A tokio task runs every 30 seconds to clean up stale state. Keys whose TAT is more than 60 seconds behind the current time are evicted. 

The total key count is tracked via an `AtomicUsize` for fast capacity checks. The sweeper resyncs this atomic from the actual map length to fix any drift.

### Key Extraction

For HTTP listeners, the key is either the connection's true peer IP or a configured header. Trusting `X-Forwarded-For` by default would allow clients to bypass limits by spoofing the header. For TCP listeners, only the peer IP is available.

## Cluster CRDT

When `[cluster]` is configured, multiple nodes share rate-limit counters.

### Data Model

Each cell in the `CounterStore` is partitioned by `(key, node_id, epoch_second)`. A cell has exactly one writer (the node identified by `node_id`) and only increments.

### Merge Semantics

Counts are summed across nodes and maxed within a single node's cell.

If the merge summed within a node's cell, a duplicated message would inflate the count. If the merge maxed across nodes, N nodes could each admit the full budget, multiplying the limit by N.

The per-cell `max` makes the merge idempotent, commutative, and associative. Out-of-order delivery converges to the correct state.

### Admission

`ListenerCoordinator` namespaces keys by listener name using `\u{1}` as a separator. 

To evaluate a request, the coordinator sums the counts across all nodes for the last `window_secs` seconds. If the sum is below the limit, the coordinator increments this node's cell for the current second.

The sum and increment happen under the same entry lock. A node never over-admits against its own view. The only slack in the system is the propagation delay between nodes.

### Gossip Protocol

Nodes push their local counters to peers every `sync_interval_ms` (default 500ms).

The wire format is:
`[4-byte BE length][32-byte HMAC-SHA256 tag][JSON SyncMessage]`

The HMAC tag covers the JSON payload. It is verified in constant time (`hmac::verify_slice`) before deserialization. Messages shorter than 32 bytes or exceeding the 4 MiB limit are rejected before allocation.

Each sync round opens a new TCP connection per peer. This spends a handshake but avoids managing reconnect and backoff state.

### Security

A pre-shared key is mandatory. An attacker who reaches the peer port without the secret cannot bypass the HMAC verification. 

Because cells only grow and the merge is a `max` operation, an attacker cannot deflate counters. Errors close the individual connection, not the listener.

### Dead Peer Handling

A dead peer requires no explicit expiry logic. Its historical counts simply age out of the sliding window. A restarted peer begins counting from zero in the current second.
