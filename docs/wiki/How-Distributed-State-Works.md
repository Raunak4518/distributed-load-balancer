# How Distributed State Works

The load balancer instances share rate-limit counters. They do not use a centralized datastore like Redis. Instead, they replicate state using a CRDT (Conflict-free Replicated Data Type) over an authenticated gossip protocol.

## The Problem with Sums

If Node A and Node B both track requests for `192.168.1.1`, they need to know each other's totals. If Node A tells Node B "I have 5 requests," and later tells Node B "I have 8 requests," Node B cannot simply add those numbers, or it will count the first 5 twice.

## The CRDT Solution

The system uses a Grow-Only Counter (G-Counter). State is partitioned by `(key, node_id, second)`. 

Node A is the *only* writer to its own cells. When Node A sends its state to Node B, Node B merges the state using a `max` function. If Node B receives the count `5` and then `8` for Node A's cell, `max(5, 8) = 8`.

To find the total cluster-wide consumption, a node simply sums the most recent cells across all nodes within the configured sliding time window. 

## Node Failure

Because the state is time-windowed (e.g., the last 60 seconds), a dead node requires no special handling. Its old cells simply slide out of the time window and are discarded. If the node restarts, it begins writing to a new cell for the current second, starting from zero.
