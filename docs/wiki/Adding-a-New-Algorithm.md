# Adding a New Load Balancing Algorithm

Load balancing algorithms live in the `lb-balancer` crate. To add a new one (e.g., Least Connections):

## 1. Implement the Trait
Create a struct and implement `lb_core::LoadBalancer`:

```rust
use lb_core::{BackendId, BackendPool, LoadBalancer};

pub struct LeastConnections;

impl LoadBalancer for LeastConnections {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId> {
        // Iterate over pool.all_backend_ids()
        // Check pool.is_eligible(id)
        // Return the best fit
    }
}
```

## 2. Expose the Config
Update the `LoadBalancingConfig` in `lb_core::config` to parse your new strategy. 

## 3. Wire It Up
In `lb_server::wiring::build_app`, match on the parsed config and box your implementation:

```rust
let balancer: Arc<dyn LoadBalancer> = match config.strategy {
    Strategy::RoundRobin => Arc::new(RoundRobin::new(pool.clone())),
    Strategy::LeastConnections => Arc::new(LeastConnections::new()),
};
```

Because the data plane relies solely on the `LoadBalancer` trait, no changes are required in `lb-proxy` or `lb-tcp`.
