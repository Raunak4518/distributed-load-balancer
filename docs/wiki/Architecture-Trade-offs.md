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

## 4. Narrow, Opt-In Caching Rather Than a General Response Cache
By default the load balancer still never buffers or caches an HTTP response — every response is streamed exactly as it always was, and TCP sessions still `try_join!` bytes with no buffering at all. `[listeners.cache]` is the one opt-in exception, and it is scoped narrowly on purpose: only a `GET` request, a `200` response, and one that declares a `Content-Length` within a configured cap are ever buffered and stored, in memory, per listener, with a plain TTL (`Cache-Control: max-age` or a configured default) and no eviction algorithm beyond "stop admitting new entries once the budget is full." A config hot-reload wipes it.

- **Alternatives Considered:** A full Varnish-style cache with `Vary`/`ETag`/conditional-request support and an explicit purge API; staying with the original streaming-only design indefinitely.
- **Chosen Approach:** Buffer only the narrow, safe-by-construction subset of responses described above; leave everything else — the general case, and all of TCP — streamed and uncached, unchanged from before this existed.
- **Trade-offs:**
  - *Gained:* A real answer for the read-heavy, mostly-static case (repeated identical `GET`s) nginx's `proxy_cache`/Varnish already cover, without the complexity a general cache would need: no invalidation-by-pattern, no distributed cache coherency across nodes, no risk of ever buffering a body whose size wasn't already known to be small.
  - *Sacrificed:* No conditional requests, no per-route cache policy, no cross-node shared cache, and a cache that never grows past its configured budget rather than one that evicts intelligently under pressure. Still not what this project reaches for to absorb genuinely large or highly dynamic read traffic — that remains a job for a CDN or the backends themselves.
