# Architecture Trade-offs

## 1. Traits over Concrete Types
The data plane (`lb-proxy` and `lb-tcp`) communicates with rate limiters, load balancers, and TLS transports purely through `Arc<dyn Trait>` objects. 
- **Gained:** The TCP proxy doesn't need to link to `rustls`. Fast compile times, decoupled testing.
- **Sacrificed:** Dynamic dispatch overhead. However, this cost is paid once per connection (or once per request), which is negligible compared to network I/O.

## 2. Shared Transports for Probes
The active health checker uses the exact same `hyper_util::Client` and TLS connection pool as the data plane.
- **Gained:** Perfect probe fidelity. If a backend has an expired certificate, the health probe fails exactly like real traffic would.
- **Sacrificed:** Health checks cannot easily run on isolated network paths.

## 3. Decentralized Rate Limiting
Rate limiting uses a peer-to-peer CRDT instead of a central Redis instance.
- **Gained:** No external dependencies. Survives network partitions. Zero network latency on the critical path (admission decisions are local).
- **Sacrificed:** Perfect enforcement. Between gossip intervals, nodes make decisions on slightly stale data, allowing a brief window of over-admission.
