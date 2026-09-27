# Health Checker

The load balancer implements both active background health checks and request-path circuit breaking. These two mechanisms work together to ensure that traffic is not routed to dead backends.

## 1. Active Probes

The `lb-healthcheck` crate spawns a background Tokio task for every configured backend. This task wakes up periodically (e.g., every 10 seconds), probes the backend, and updates the `active_healthy` flag in the `BackendPool`.

### The Shared Transport Invariant

A critical design choice is that the health checker does not use a separate network stack. It uses the exact same `OutboundTransport` trait object as the data plane.

If the proxy is configured to use `backend_tls` with specific custom root certificates, the health check uses that same TLS configuration. 

**Why this matters:**
If a backend's certificate expires, the TLS handshake will fail. Because the health check uses the real TLS transport, the health check fails, and the backend is correctly marked unhealthy. If the health check used a generic TCP ping, it would incorrectly report the backend as healthy, leading to a "green dashboard" while all real request traffic fails with TLS validation errors.

## 2. Circuit Breaker

Active probes are slow. If a backend crashes 1 second after a health check succeeds, the proxy would continue sending traffic into a black hole for 9 seconds.

To solve this, the proxy implements a **3-State Circuit Breaker** on the request path.

When the proxy attempts to forward a request and the connection fails (e.g., `ECONNREFUSED`), the proxy calls `circuit_breaker.record_failure()`.

If the failure count crosses the configured threshold, the circuit trips to the **Open** state. The backend is immediately excluded from routing decisions.

### Recovery (Half-Open State)

The circuit breaker cannot stay Open forever, but we also do not want to flood a recovering backend with traffic.

After a timeout, the circuit transitions to **Half-Open**. In this state, the router allows exactly *one* request to flow to the backend as a probe.
- If that request succeeds, the circuit closes (resetting failures to 0) and normal traffic resumes.
- If that request fails, the circuit trips back to Open immediately, waiting for another timeout.

## State Ownership and Concurrency

The health checks and circuit breaker state live on the `Backend` struct inside the `BackendPool`.

```rust
pub struct Backend {
    pub id: BackendId,
    pub address: SocketAddr,
    pub active_healthy: AtomicBool,
    pub circuit_open: AtomicBool,
}
```

The router evaluates these atomics on every request. Because they are `AtomicBool`, the router does not need to acquire a lock to check backend health. Background tasks can mutate them without stalling the request pipeline.
