# Roadmap

Work is done top to bottom. A phase starts only when the one before it is done,
because every later phase builds on the guarantees of the earlier ones.
`[x]` means shipped on `main`, with a test that fails without the change.

## Phase 0 — Make the existing system trustworthy

### Data plane
- [x] Request-body limit is a real memory bound (bounded read, early `Content-Length` refusal)
- [x] Upstream response-body idle timeout
- [x] HTTP/2 preface/SETTINGS deadline (not disarmed by one byte)
- [x] Finished connection tasks reaped continuously
- [x] Stable per-backend runtime state across pool refreshes
- [x] WebSocket/Upgrade connections counted as in-flight load
- [x] Retries exclude a backend that already failed this request
- [x] WebSocket upgrades honor the sticky pin and retry connect failures
- [x] Total request deadline (`request_timeout_ms`), separate from the per-attempt timeouts
- [x] Retry policy classifies failures (connect error, timeout, reset, 5xx) and respects method idempotency
- [x] Retry budget per route/pool, not only per listener
- [x] Stream request bodies to the backend when no retry or cache needs them buffered
- [x] Audit: every `spawn()` has an owner and a shutdown path
- [x] Audit: every map keyed by client input has a cardinality bound
- [x] Audit: cancellation (client disconnect) propagates to the upstream request

### Cluster
- [x] Changed keys gossiped first; documented convergence bound
- [x] Gossip `node_id` bound to the peer certificate under `[cluster.tls]`
- [x] Push to peers concurrently with a bounded fan-out
- [x] Convergence metrics (last successful sync per peer, snapshot size/pages)
- [x] Node incarnation (boot generation) so a restarted node's counts add to its previous boot's, not max with them
- [x] Documented semantics for replay, duplicates, clock skew/rollback, partition and rejoin (with tests)

### Security
- [x] rustls updated for RUSTSEC-2026-0285; daily `cargo audit`
- [x] Admin auth required off loopback; probes open
- [x] PROXY protocol restricted to trusted CIDRs
- [x] ACME keys written atomically, `0600`, fsynced
- [x] Unknown config fields rejected (`deny_unknown_fields`)
- [x] Release checksums and verified installs
- [x] Audit log of admin write operations (drain/undrain)
- [x] Separate read-only and read-write admin tokens (authorization, not just authentication)
- [x] Optional mTLS for the admin listener
- [ ] `cargo deny` (licenses, sources, duplicate versions) in CI

## Phase 1 — An elite proxy
- [ ] Upstream connection pools: per-backend max connections / pending / active, max requests and lifetime per connection, queue-time metric
- [ ] HTTP/2 upstream GOAWAY handling and connection draining
- [ ] Overload manager: memory/FD/connection pressure → staged shedding levels
- [ ] Adaptive concurrency limit per backend (gradient-based)
- [ ] Slow start / warm-up for recovered and newly added backends
- [ ] Priority failover and backup pools; locality/zone-aware selection
- [ ] Maglev and rendezvous (HRW) hashing; hash-movement measurement
- [ ] Random, P2C least-request, weighted random strategies
- [ ] Peak-EWMA score extended with error rate, tail latency and queue delay, with hysteresis
- [ ] `Forwarded` / `X-Forwarded-*` with trusted-proxy semantics
- [ ] Request smuggling defenses audit (TE/CL, duplicate headers, authority/Host validation)
- [ ] Header rewrite, redirects, fixed/maintenance responses
- [ ] Request mirroring / shadow traffic
- [ ] Cache: `ETag`/`Last-Modified` revalidation, `stale-while-revalidate`, `stale-if-error`, request coalescing, purge API, LRU/TinyLFU eviction
- [ ] Health checks: gRPC, body/header matching, jitter, adaptive intervals
- [ ] Multi-worker accept with `SO_REUSEPORT`, per-worker counters
- [ ] Socket tuning: backlog, `SO_RCVBUF`/`SO_SNDBUF`, `TCP_DEFER_ACCEPT`, `TCP_FASTOPEN`
- [ ] Zero-copy L4 forwarding (`splice`) on Linux, benchmarked against the copy loop

## Phase 2 — Modern protocols
- [ ] gRPC: status-aware retries, deadlines, gRPC health checks, gRPC-Web
- [ ] UDP load balancing with flow tracking and expiry
- [ ] TLS passthrough (SNI routing without termination)
- [ ] QUIC listener and HTTP/3 downstream (quinn/h3): limits, amplification protection, retry tokens, 0-RTT off by default, Alt-Svc
- [ ] HTTP/3 upstream; QUIC metrics and qlog

## Phase 3 — Distributed architecture
- [ ] Immutable `ConfigSnapshot` with generation numbers; atomic publish to workers
- [ ] Management API: validate, diff, apply, rollback, history
- [ ] Dynamic backends via API without reload
- [ ] Service discovery: DNS SRV, Kubernetes EndpointSlices, Consul
- [ ] Raft-backed control state (config, membership) separate from gossiped telemetry
- [ ] Locality-weighted, multi-zone and multi-region routing with failover

## Phase 4 — Programmability
- [ ] Routing policy expressions (host, path, header, cookie, method, source IP, JWT claim)
- [ ] JWT/JWKS validation, API keys, claims-based routing
- [ ] WASM filter chain for request/response headers and bodies
- [ ] Progressive delivery: automatic canary promotion/rollback from error and latency signals

## Phase 5 — Security platform
- [ ] WAF: canonicalization, rule IDs, anomaly scoring, dry-run mode, body inspection
- [ ] DoS layer: handshake admission, HTTP/2 rapid-reset/stream-exhaustion limits, per-client budgets
- [ ] Rate limiting: sliding window, concurrency and bandwidth limits, hierarchical quotas
- [ ] OCSP stapling, ECDSA/RSA per-SNI selection, per-route client-cert policies
- [ ] Signed releases, SBOM, provenance attestations

## Phase 6 — Performance
- [ ] CPU pinning and NUMA-aware workers
- [ ] Buffer pools; allocation profiling per request
- [ ] `io_uring` experiment, benchmarked
- [ ] eBPF/XDP experiments, benchmarked

## Phase 7 — Proof
- [ ] Reproducible comparison benchmarks against HAProxy, Envoy, NGINX on identical setups
- [ ] Fuzzing: HTTP/1 parser path, PROXY protocol, gossip frames, config
- [ ] `loom` models for the lock-free pool and counter code
- [ ] Multi-host cluster tests with partitions, loss and clock skew
- [ ] 24–72 hour soak tests
- [ ] TLA+ models: config publication atomicity, quota error bound, drain eventually reaches zero
- [ ] Published SLOs, tested continuously

## Tooling and ecosystem
- [ ] `lbctl` CLI: status, config validate/diff/apply/rollback, backend drain, `route explain`
- [ ] Per-request decision trace (why this backend, why this retry)
- [ ] Helm chart, Kubernetes Gateway API controller
- [ ] Grafana dashboards
