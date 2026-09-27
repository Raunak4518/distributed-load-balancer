# Load Balancer

The router is responsible for selecting a backend from the pool of available targets. It sits between the rate limiter and the connection forwarding logic.

## Motivation
A static configuration file might list 10 backends. However, at runtime, some backends may be down, some may be overloaded, and some may have just been added to the configuration. The router must dynamically select a target from the *currently eligible* subset, applying a chosen distribution strategy (e.g., Round Robin).

## Backend Eligibility

The router does not perform health checks or track connection failures itself. It relies entirely on the `BackendPool` for state.

When `picker.pick(pool)` is called, the router evaluates the pool. A backend is eligible if and only if:
1. `backend.active_healthy.load() == true`
2. `backend.circuit_open.load() == false`

If all backends are ineligible, the router returns `None`, and the proxy immediately returns a `503 Service Unavailable` (or drops the TCP connection).

## Round Robin Algorithm

The currently implemented strategy is Round Robin. It attempts to distribute requests evenly across all eligible backends.

### Implementation
The algorithm uses an `AtomicUsize` counter to track the next index.

```rust
let current_idx = self.counter.fetch_add(1, Ordering::Relaxed);
```

Because backends can be dynamically marked unhealthy, the set of eligible backends changes. The algorithm handles this by taking the counter modulo the total number of backends, and then scanning forward from that index until it finds an eligible backend.

If it scans the entire pool and finds nothing, it aborts.

### Complexity
- **Time:** O(N) where N is the total number of backends, because it may have to scan the entire pool to find a healthy target. In the happy path (all backends healthy), it is O(1).
- **Space:** O(1). The routing state is just a single atomic integer.
- **Synchronization:** The `fetch_add` operation is wait-free. Concurrent requests can safely pick backends without blocking each other.

## Interactions

- **Caller:** The data plane (`ProxyContext` or `TcpContext`) calls the router after passing the rate limit.
- **Reads:** The router reads the `active_healthy` and `circuit_open` atomics from the `BackendPool`.
- **Failure Behavior:** If the chosen backend fails to connect, the data plane trips the circuit breaker and asks the router for a second choice. The router will inherently skip the failing backend on the retry because its `circuit_open` flag is now true.
