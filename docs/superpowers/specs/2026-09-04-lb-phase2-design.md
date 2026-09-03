# Distributed Load Balancer — Phase 2 Design (L4/TCP)

**Date:** 2026-09-04
**Status:** Approved for implementation planning
**Builds on:** [Phase 1 design](2026-09-03-lb-phase1-design.md) (single-node L7 HTTP LB — shipped)
**Scope of this document:** Phase 2 only. Phase 3 (multi-node distributed coordination) is specified separately.

## 1. Purpose

Add L4 (raw TCP) proxying alongside the existing L7 (HTTP) proxying, so one process can front both HTTP services and non-HTTP TCP services (Postgres, Redis, SMTP, anything) at the same time.

### The governing insight

At L4 you are moving **bytes**, not **requests**. There is no path, no headers, no status codes, and no way to tell a client "you have been rate limited" — the only vocabulary available is *accept the connection* or *close it*. Nearly every difference between Phase 1 and Phase 2 falls out of that single fact:

| Concern | L7 (Phase 1) | L4 (Phase 2) |
|---|---|---|
| Unit of work | one HTTP request | one TCP connection |
| Rate-limit key | source IP **or** a header | source IP only (no headers exist) |
| Rate-limit denial | `429` + `Retry-After` | close the connection, silently |
| Rate-limit unit | requests/sec | connections/sec |
| Health probe | `GET /health`, 2xx = healthy | TCP connect succeeds = healthy |
| Retry after failure | needs request-body buffering | free — no client bytes have moved yet |
| Backend failure surfaced as | `502`/`503`/`504` | connection closed |

## 2. Design Principles

Unchanged from Phase 1 §2 (trait boundaries over concretions, single responsibility per module, no god objects, dependency injection at testability seams, bounded resources everywhere). Phase 2 is largely a *test* of those principles: if Phase 1's boundaries were drawn correctly, most of it should be reusable for a completely different protocol without modification. §6 records how that turned out.

## 3. Configuration — restructured around listeners

This is a **breaking change** to the Phase 1 config format, taken deliberately. Phase 1 assumed exactly one listener, so its settings (`listen`, `backends`, `rate_limit`, …) lived at the top level. Supporting N listeners of differing protocols means those settings become per-listener. Bolting a parallel `[[tcp_listeners]]` section alongside the old shape was rejected: it would leave two config dialects to keep in sync forever. Nothing is deployed yet, so the cost of breaking the format now is a one-line change to the example config.

```toml
[server]
drain_timeout_ms = 10000        # was a hardcoded constant in Phase 1

[[listeners]]
name     = "web"
protocol = "http"
listen   = "0.0.0.0:8080"
forward_timeout_ms     = 5000
max_request_body_bytes = 1048576         # HTTP-only

  [[listeners.backends]]
  id = "web1"
  address = "127.0.0.1:9001"
  weight  = 1

  [listeners.health_check]
  path = "/health"                       # HTTP-only
  interval_ms = 2000
  timeout_ms = 500
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 50
  burst = 100

  [listeners.load_balancing]
  strategy = "round_robin"

[[listeners]]
name     = "postgres"
protocol = "tcp"
listen   = "0.0.0.0:5432"
connect_timeout_ms = 2000
idle_timeout_ms    = 300000              # TCP-only

  [[listeners.backends]]
  id = "pg1"
  address = "10.0.0.5:5432"

  [listeners.health_check]
  interval_ms = 2000                     # no `path` — nothing to GET
  timeout_ms = 500
  failure_threshold = 3
  cooldown_ms = 5000

  [listeners.rate_limit]
  key = "source_ip"                      # the only legal value for tcp
  rate_per_sec = 10
  burst = 20

  [listeners.load_balancing]
  strategy = "round_robin"
```

### Validation rules (all fail fast at startup, before any socket is bound)

- At least one listener must be defined; each listener needs at least one backend.
- Listener `name`s must be unique (they identify listeners in errors and logs).
- Listener `listen` addresses must be unique — two listeners cannot bind the same address.
- `protocol = "http"` requires `health_check.path`; `protocol = "tcp"` must **not** set it.
- `protocol = "tcp"` rejects `rate_limit.key = "header:<name>"` with an explanatory error — there are no headers at L4. This is the single most valuable validation in Phase 2: it turns a conceptual impossibility into a startup error instead of silent nonsense.
- `max_request_body_bytes` / `forward_timeout_ms` are HTTP-only; `connect_timeout_ms` / `idle_timeout_ms` are TCP-only. Setting one on the wrong protocol is an error, not a silent no-op.
- Existing Phase 1 rules carry over per listener: positive `rate_per_sec`, non-zero `burst`, unique backend ids within a listener.

## 4. Architecture

### 4.1 New: `HealthProbe` trait in `lb-core`

```rust
pub trait HealthProbe: Send + Sync {
    fn probe(&self, backend: &Backend) -> impl std::future::Future<Output = bool> + Send;
}
```

Two implementations in `lb-healthcheck`:
- `HttpProbe { path: String }` — the existing behavior: `GET http://<addr><path>`, 2xx means healthy.
- `TcpConnectProbe` — open a TCP connection to the backend; if it establishes, the backend is alive; close it immediately.

The listener's protocol selects the probe at wiring time; there is no config knob for it, so there is nothing to misconfigure. A trait (rather than an enum) keeps this consistent with `RateLimiter`/`LoadBalancer`/`Clock` and lets richer probes (send-expect payloads, TLS handshake, gRPC health protocol) be added later without touching the checker. Generics rather than `dyn` keep it zero-cost; the explicit `+ Send` on the returned future is required for the probe to be usable inside `tokio::spawn`.

`spawn_active_checker` becomes generic over `P: HealthProbe` and loses its `reqwest::Client` parameter (the client now lives inside `HttpProbe`), which also removes `lb-healthcheck`'s hard dependency on HTTP for TCP-only deployments.

### 4.2 New crate: `lb-tcp`

The complete L4 data plane, deliberately small:

1. Accept a connection; take the peer's IP as the rate-limit key.
2. `RateLimiter::check(peer_ip)` → on `Deny`, **drop the connection immediately** and return. There is no protocol in which to explain the rejection; closing is the only signal available.
3. Refresh circuit-breaker state into `BackendPool` (same pattern as `lb-proxy`), then `LoadBalancer::pick(&pool)`. No eligible backend → close.
4. `TcpStream::connect(backend.address)` under `connect_timeout`.
5. On connect failure: report to that backend's circuit breaker and **retry once against another backend**. This is safe precisely because no client bytes have been read yet.
6. On connect success: report success, then pump bytes in both directions until either side finishes (§4.3).

### 4.3 Bidirectional copy with idle timeout and correct half-close

`tokio::io::copy_bidirectional` handles half-close correctly but offers no idle timeout; a plain `tokio::time::timeout` around the whole copy would impose a maximum *lifetime*, which is wrong — a healthy nine-hour Postgres session is not a fault. So `lb-tcp` implements its own pump:

```rust
async fn pump<R, W>(reader: R, writer: W, idle: Duration) -> io::Result<u64>
```

Each pump loops on `tokio::time::timeout(idle, reader.read(&mut buf))`:
- read returns `n > 0` → write it, add to the total, and the next iteration's timer starts fresh (this is what makes it a true *idle* timeout rather than a lifetime cap),
- read returns `0` (EOF) → call `writer.shutdown()` to propagate the half-close, then return,
- the timeout elapses → return an idle-timeout error, tearing the connection down.

Both directions run under `tokio::try_join!`, not `tokio::select!`. That distinction matters: `select!` would tear down the whole connection the moment *either* direction saw EOF, breaking every protocol that half-closes one direction and keeps reading the other. `try_join!` lets each direction end independently and only finishes when both are done — which is what a correct TCP proxy does.

### 4.4 `lb-server`: from one listener to N

- `build_context` becomes per-listener, producing a `ListenerRuntime` enum with `Http(Arc<HttpContext>)` and `Tcp(Arc<TcpContext>)` variants. The enum is appropriate here (unlike for probes) because this is a genuinely closed set that `run` must exhaustively match on to know which accept loop to drive.
- `run` binds every listener up front — so a port conflict or permission error fails startup rather than half-starting — then drives one accept loop per listener.
- All accepted connections, HTTP and TCP alike, go into a single `JoinSet` so the existing drain-with-deadline shutdown covers both. `drain_timeout_ms` becomes configurable because the right value differs sharply by workload: HTTP requests finish in milliseconds, while a long-lived TCP session will simply be cut off at the deadline. That truncation is correct and intended; it is documented rather than worked around.

## 5. Error Handling

Phase 1's rules carry over, with L4-specific additions:

- No `unwrap`/`expect` reachable from connection handling; untrusted input must never panic the process.
- Every L4 I/O boundary is bounded: `connect_timeout` on dialing a backend, `idle_timeout` on each read, and the drain deadline on shutdown.
- A client is never told *why* its connection closed — rate limited, no healthy backend, and idle timeout are indistinguishable from the client's side. That is inherent to L4, not an oversight; operators diagnose it from logs (Phase 3) rather than the wire.
- One failing connection must never take down its listener's accept loop: per-connection errors are contained to that connection's task.
- Accept-loop errors are logged and the loop continues; a transient `accept()` failure (e.g. per-process fd exhaustion) must not kill a listener permanently.

## 6. Reuse: what Phase 1's trait boundaries bought

Reused for TCP with **no modification**: `lb-balancer` (round robin), `lb-ratelimit` (GCRA), `lb-healthcheck`'s `CircuitBreaker`, and `lb-core`'s `Backend`/`BackendId`/`BackendPool`/`Clock`. All were written against protocol-neutral types, never against HTTP.

Changed: `lb-core::config` (restructured for listeners), `lb-healthcheck::spawn_active_checker` (generic over `HealthProbe` instead of hardcoding an HTTP GET), and `lb-server` (N listeners instead of one).

Untouched: `lb-proxy` — the entire L7 data plane needs no changes to coexist with L4.

## 7. Testing Strategy

- **`pump` unit tests** (the riskiest new logic, tested in isolation): bytes flow through; EOF propagates as a write shutdown; an idle connection times out; the timer resets on activity rather than capping total lifetime.
- **`TcpConnectProbe` unit tests**: a listening socket probes healthy; a closed port probes unhealthy.
- **Config validation tests**: every rule in §3 has a test, especially the `header:` key rejected on a TCP listener and `path` required on an HTTP listener.
- **`lb-tcp` integration tests** against a real TCP echo server: bytes round-trip end to end; a connection over the rate limit is closed without reaching any backend; a dead backend fails over to a healthy one on the connect-failure retry.
- **The headline Phase 2 test**: one `lb-server` process running an HTTP listener and a TCP listener simultaneously, serving both correctly — this is the capability Phase 2 exists to add, so it gets an explicit end-to-end test.
- Phase 1's existing tests must keep passing (updated only for the new config shape), proving L7 was not regressed.

## 8. Out of Scope for Phase 2

Unchanged from Phase 1's deferrals: TLS termination, config hot-reload, Prometheus metrics, structured logging, admin/control API, and multi-node coordination (Phase 3).

Newly named and deferred: UDP proxying, PROXY-protocol headers (for preserving the true client IP to backends), per-listener maximum concurrent connections, and protocol sniffing (auto-detecting HTTP vs raw TCP on one port).

## 9. Decisions Log

- **Restructured config instead of an additive TCP section**: two parallel dialects would drift; nothing is deployed, so breaking the format is cheap now and expensive later.
- **`HealthProbe` as a trait, not an enum**: consistent with the codebase's existing extension points, and probe types are a genuinely open set (send-expect, TLS, gRPC health all plausible). Generic, not `dyn`, so it stays zero-cost.
- **Protocol picks the probe, no config knob**: an HTTP listener always wants an HTTP probe. Making it configurable would add a way to get it wrong for a case nobody has asked for.
- **`try_join!` over `select!` for the byte pump**: `select!` is shorter but silently breaks half-close, which is a correctness bug in a general-purpose TCP proxy.
- **Per-read idle timeout instead of a whole-connection timeout**: a long-lived connection is normal at L4; only a *stalled* one is a fault.
- **Retry once on connect failure only**: at L4 a failed connect means zero client bytes have moved, so retry is trivially safe — no buffering, no size cap, and no equivalent of Phase 1's request-body compromise. Once bytes flow, retry is impossible and is not attempted.
- **Rate-limit denial closes the connection silently**: there is no L4 mechanism to say why, and inventing one (e.g. writing a message before closing) would corrupt whatever protocol the client actually speaks.
