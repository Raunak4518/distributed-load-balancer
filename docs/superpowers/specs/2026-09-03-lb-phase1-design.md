# Distributed Load Balancer — Phase 1 Design

**Date:** 2026-09-03
**Status:** Approved for implementation planning
**Scope of this document:** Phase 1 only (single-node, L7 HTTP). Phase 2 (L4/TCP) and Phase 3 (multi-node distributed coordination) are named here for context but specified separately once Phase 1 ships.

## 1. Purpose & Context

A load balancer + rate limiter, built from scratch in Rust, intended both as a portfolio-quality demonstration of systems/distributed-systems understanding and as a standalone project held to an enterprise-grade quality bar (correctness, bounded resource usage, graceful degradation, clear documentation of design decisions) — without a specific external system to integrate with yet.

### Phased scope

| Phase | Scope |
|---|---|
| **Phase 1** (this doc) | Single load-balancer process, L7 HTTP, distributing across a fleet of backend servers. Round-robin selection, GCRA rate limiting, active + passive health checking, static TOML config. |
| Phase 2 (future) | L4/TCP proxying alongside L7. |
| Phase 3 (future) | Multiple load-balancer nodes coordinating shared state (rate-limit counters, health status) — the "distributed load balancer" in the fuller sense. |

Phase 1 must be a complete, correct, independently useful load balancer on its own — not a scaffold that only makes sense once later phases exist.

### Explicitly out of scope for Phase 1
- TLS termination
- Config hot-reload (restart-to-reconfigure is the Phase 1 contract)
- Metrics endpoint (Prometheus), structured logging, admin/control API — deferred to a later phase (confirmed explicitly; not an oversight)
- Multi-node coordination (Phase 3)
- L4/TCP proxying (Phase 2)

## 2. Design Principles

These apply across every crate and were confirmed explicitly as a hard requirement, not just a preference:

- **Depend on traits, not concretions.** Every pluggable concern (backend selection, rate limiting, health signal) is a trait in `lb-core`. Concrete implementations live in their own crates and are swappable without touching call sites.
- **Single responsibility per module.** Pool ownership, selection policy, health signal production, and health signal consumption are four separate concerns even though they cooperate on one decision (is this backend eligible?).
- **No god objects.** `lb-proxy` orchestrates a request by calling into other crates' trait objects; it does not itself implement rate-limit math, selection logic, or health polling.
- **Dependency injection at the seams that need testability.** Most notably, time — GCRA correctness depends on precise timing, so `Clock` is injected rather than called globally.
- **Bounded resources everywhere.** No unbounded maps (stale rate-limit keys are swept), no unbounded retries (bounded to one), timeouts on every I/O boundary.

## 3. Architecture

### 3.1 Workspace layout

```
distributed-load-balancer/
├── Cargo.toml                # workspace root
├── crates/
│   ├── lb-core/               # shared types + traits, no I/O
│   ├── lb-ratelimit/          # GCRA rate limiter
│   ├── lb-balancer/           # LoadBalancer trait + RoundRobin
│   ├── lb-healthcheck/        # active poller + passive circuit breaker
│   ├── lb-proxy/              # hyper Service: orchestrates one request
│   └── lb-server/             # binary: config loading + wiring + main()
└── tests/                     # workspace-level integration tests
```

**`lb-core`** — `Backend`, `BackendId`, `BackendPool`, config structs, and the core traits:
```rust
pub trait RateLimiter: Send + Sync {
    fn check(&self, key: &str) -> Decision; // Allow | Deny { retry_after }
}

pub trait LoadBalancer: Send + Sync {
    fn pick(&self, pool: &BackendPool) -> Option<BackendId>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
```
`BackendPool` owns backend state (address, weight, health flags) behind a shared, concurrency-safe handle; both `lb-balancer` and `lb-healthcheck` operate on it, but neither owns it. `lb-proxy` reads it through `pool.is_eligible(id)`, a single fused view of active-check status AND circuit-breaker state — the proxy layer never needs to know two separate mechanisms produced that answer.

**`lb-ratelimit`** — GCRA implementation.
- Per-key state: a single TAT (theoretical arrival time) timestamp — this is GCRA's core memory advantage over sliding-window logs (O(1) per key, not O(requests) per key).
- Store: `DashMap<String, AtomicI64>` (or sharded `Mutex<HashMap>`) so unrelated clients don't contend on one lock.
- Config per rule: `rate` (req/sec) + `burst` (bucket capacity), which derive GCRA's emission interval and delay-variation tolerance.
- A background sweeper task evicts keys whose TAT has aged out, keeping the map bounded under churn (many distinct clients over time, not just a fixed set).
- Takes a `Clock` for testability — burst/refill boundary behavior is tested via a `FakeClock`, not real `sleep()`.

**`lb-balancer`** — `RoundRobin` is a thin, stateless-per-call implementation: an atomic cursor over `pool.eligible_backends()`. Adding least-connections or weighted round robin later is a new struct implementing `LoadBalancer`, not a rewrite of this one.

**`lb-healthcheck`** — two independent signals feeding one gate:
- *Active checker*: one background tokio task per backend, on a configurable interval, `GET <health_path>` with a timeout, expects 2xx. Updates an `AtomicBool` "administratively healthy" flag per backend.
- *Passive circuit breaker*: fed by real request outcomes reported from `lb-proxy` after each forwarded request (success / failure / timeout). Tracks a rolling failure-rate window per backend. States: `Closed → Open` (trips at a configured failure threshold, backend excluded from selection for a cooldown) `→ HalfOpen` (after cooldown, allows a trickle of probe requests) `→ Closed` (on success) or back to `Open` (on failure).
- A backend is eligible only if the active flag is healthy **and** the circuit is not `Open`.

**`lb-proxy`** — the hyper `Service` implementing the per-request flow in §3.2. Depends on `lb-core` traits only — it is wired to concrete `lb-ratelimit`/`lb-balancer`/`lb-healthcheck` implementations by `lb-server` at startup, not by direct dependency.

**`lb-server`** — binary crate. Parses TOML config into `lb-core` structs (fail-fast on invalid config, before binding anything), constructs concrete implementations, wires them behind `lb-core` trait objects, starts the hyper listener and background health-check tasks, and owns the graceful-shutdown sequence.

### 3.2 Request data flow

1. Connection arrives on the configured listen address; hyper hands the request to `lb-proxy`'s `Service::call`.
2. Extract client identity per config (source IP, or a named header) → `RateLimiter::check(key)`. Over limit → immediate `429` with `Retry-After`, no backend touched.
3. `LoadBalancer::pick(&pool)` returns the next eligible backend. `None` (no eligible backends) → immediate `503`.
4. Forward the request via a connection-pooled hyper client, **streaming** the request/response bodies through rather than buffering them fully, so per-request memory stays bounded regardless of body size.
5. On completion, report outcome (success / failure / timeout, with latency) to the circuit breaker for that backend.
6. On a forwarding failure (connect error, timeout), retry once against a different eligible backend (bounded — never retry storms); if that also fails, `502`/`504`.

### 3.3 Configuration

TOML, parsed once at startup:

```toml
[server]
listen = "0.0.0.0:8080"

[[backends]]
id = "b1"
address = "127.0.0.1:9001"
weight = 1

[health_check]
path = "/health"
interval_ms = 2000
timeout_ms = 500
failure_threshold = 3
cooldown_ms = 5000

[rate_limit]
key = "source_ip"          # or "header:X-API-Key"
rate_per_sec = 50
burst = 100

[load_balancing]
strategy = "round_robin"
```

Invalid config (bad address, zero/negative rate, unknown strategy name) fails fast at startup with a clear error, before the listener binds. Hot-reload is not supported in Phase 1.

## 4. Error Handling

- Each crate defines its own error enum (`thiserror`). No `unwrap`/`expect` reachable from request-handling code — untrusted input must never be able to panic the service.
- Clients see only `429` (rate limited), `502`/`504` (upstream failure/timeout), or `503` (no eligible backend / draining). No backend addresses, internal errors, or stack traces are ever exposed in a response.
- Every I/O boundary has a timeout: connect, request, idle. No unbounded waits that could exhaust the connection pool.
- Graceful shutdown on `SIGINT`/`SIGTERM`: stop accepting new connections, drain in-flight requests within a deadline, then exit.

## 5. Testing Strategy

- **`Clock` abstraction**: `SystemClock` in production, `FakeClock` in tests — GCRA burst/refill boundaries are tested against simulated time, not real `sleep()`, so tests are both precise and fast.
- **Unit tests per crate**:
  - `lb-ratelimit`: GCRA boundary math — burst allowed then throttled, refill over simulated time, per-key isolation.
  - `lb-balancer`: round-robin cycling, correct skip of ineligible backends, behavior with zero eligible backends.
  - `lb-healthcheck`: circuit breaker state transitions, table-driven (closed→open→half-open→closed/open).
- **Integration tests** (workspace-level `tests/`): real fake-backend HTTP servers + the real proxy over real sockets — end-to-end routing, rate-limiting, and failover-on-backend-death.
- **Soak test** (stretch goal, not a Phase 1 requirement): concurrent load to confirm no panics/deadlocks and that GCRA holds within tolerance under real contention.

## 6. Decisions Log (why, not just what)

- **hyper directly, not axum/pingora**: the goal is to own the proxy engine (streaming, connection pooling, backpressure) rather than have a framework hide it — axum is built for servers that respond, not proxies that forward dynamically; pingora would skip the "from scratch" learning/portfolio value entirely.
- **GCRA over token bucket / sliding window counter**: single-timestamp-per-key is the most memory-efficient production-grade option (same family as Cloudflare/Redis's `redis-cell`) and a stronger differentiator than the more commonly-implemented token bucket.
- **Workspace of crates over one crate with modules**: Phase 2 (L4) and Phase 3 (distributed coordination) are known to be coming; crate boundaries drawn now are seams that later phases can plug into, rather than a single crate that needs surgery later.
- **Active + passive health checking over active-only**: passive circuit breaking reacts to real failures immediately rather than waiting up to one polling interval, which is closer to how production LBs (Envoy, HAProxy) behave and materially reduces error exposure during a backend's failure window.
- **Metrics/logging/admin API deferred, not omitted by oversight**: explicitly confirmed out of scope for Phase 1 to keep it focused; Phase 1's trait boundaries (e.g. reporting outcomes to the circuit breaker) are exactly where a metrics hook would attach later, so deferring doesn't create rework.
