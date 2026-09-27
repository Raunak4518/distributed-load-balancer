# Extending the System

This guide explains how to add new algorithms or components to the load balancer. Because the system heavily relies on trait objects (`Arc<dyn Trait>`), extending it usually does not require touching the complex async data plane (`lb-proxy` or `lb-tcp`).

## Adding a New Load Balancing Strategy

If you want to implement "Least Connections" routing, follow these steps:

### 1. Implement the Trait
Create a new struct in `lb-balancer/src/least_conn.rs`.

```rust
use lb_core::{BackendId, BackendPool, LoadBalancer};
use std::sync::atomic::Ordering;

pub struct LeastConnections;

impl LoadBalancer for LeastConnections {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId> {
        let mut best_id = None;
        let mut min_conns = usize::MAX;

        // Iterate over all backends in the pool
        for backend in pool.all_backends() {
            // Check eligibility
            if !backend.active_healthy.load(Ordering::Relaxed) || 
                backend.circuit_open.load(Ordering::Relaxed) {
                continue;
            }

            // Assume Backend struct was updated to track active_connections
            let conns = backend.active_connections.load(Ordering::Relaxed);
            if conns < min_conns {
                min_conns = conns;
                best_id = Some(backend.id);
            }
        }
        
        best_id
    }
}
```

### 2. Update Configuration Parsing
In `lb-core/src/config.rs`, update the `Strategy` enum to include your new strategy so it can be parsed from `config.toml`.

```rust
#[derive(Deserialize)]
pub enum Strategy {
    RoundRobin,
    LeastConnections, // <-- New
}
```

### 3. Wire It Up
In `lb-server/src/wiring.rs`, the proxy builds the `Arc<dyn LoadBalancer>`. Update the match statement:

```rust
let balancer: Arc<dyn LoadBalancer> = match config.strategy {
    Strategy::RoundRobin => Arc::new(RoundRobin::new(pool.clone())),
    Strategy::LeastConnections => Arc::new(LeastConnections::new()),
};
```

That's it. The `ProxyContext` will automatically start calling your `.pick()` method on every request.

## Adding a New Rate Limiting Algorithm

Similarly, if you want to implement a Sliding Window instead of GCRA, you would implement the `lb_core::RateLimiter` trait:

```rust
pub trait RateLimiter: Send + Sync {
    /// Returns true if the request is allowed.
    fn check(&self, key: &str, limit: RateLimit) -> bool;
}
```

Implement it in `lb-ratelimit/src/sliding_window.rs`, expose it in the config, and wire it in `lb-server`.

## Debugging

When extending the system, use `tracing`.

```rust
use tracing::{debug, info, warn, error};

debug!("Evaluated backend {} with {} connections", backend.id, conns);
```
Run the binary with `RUST_LOG=debug cargo run` to see your logs. Because the data plane is highly concurrent, logs are usually the easiest way to debug routing logic without stepping through Tokio tasks in a debugger.
