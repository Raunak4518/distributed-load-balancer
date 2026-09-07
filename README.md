# Distributed Load Balancer

A multi-protocol load balancer in Rust. Terminates TLS, rate-limits by IP or header, health-checks backends, and forwards traffic over HTTP or raw TCP. Multiple instances share rate-limit counters through a gossip-based CRDT protocol — no central data store required.

```
Client → TLS termination → Rate limiter → Backend selection → Forward
                              │                                  │
                         (local GCRA +                    (retry once on
                          cluster CRDT)                    failure)
```

## What It Does

- **HTTP/1.1 and HTTP/2** (ALPN-negotiated over TLS), plus raw **TCP** proxying.
- **TLS termination** at the edge via rustls. Optional **backend re-encryption** with certificate verification.
- **GCRA rate limiting** per key, with bounded state. An overflow bucket prevents memory exhaustion under address-spray attacks.
- **Cluster-wide rate limiting** via a G-Counter CRDT, synchronized over HMAC-authenticated gossip.
- **Active health checking**: HTTP probes (GET, 2xx = healthy) or TCP connect probes, using the *same* transport as real traffic.
- **Circuit breaking** per backend: Closed → Open → HalfOpen, with configurable threshold and cooldown.
- **Prometheus metrics** on a private admin port. Separate `/healthz` (liveness, always 200) and `/ready` (readiness, 503 when no backend is eligible).
- **Connection hardening**: global + per-IP caps, slowloris timeout, HTTP/2 Rapid Reset mitigation, body size and read-time limits.
- **Graceful shutdown**: SIGTERM/SIGINT drains in-flight connections within a configurable timeout.

## Architecture

Eleven crates. `lb-server` is the binary; the rest are libraries with narrow responsibilities:

```
lb-server          Binary. Config, binding, wiring, shutdown.
├── lb-core        Traits (LoadBalancer, RateLimiter, HealthProbe, Clock, etc.),
│                  types (Backend, BackendPool), config parsing and validation.
├── lb-proxy       L7 forwarding, body limits, hop-by-hop stripping, DNS-pinned resolver.
├── lb-tcp         L4 proxying: bidirectional pump with idle timeout.
├── lb-balancer    Round-robin (weighted, skips ineligible backends).
├── lb-ratelimit   GCRA with bounded key tracking and periodic sweep.
├── lb-healthcheck Active health checks, HTTP/TCP probes, circuit breaker.
├── lb-cluster     G-Counter CRDT, HMAC-authenticated gossip, peer sync.
├── lb-tls         TLS termination (rustls), backend connector, cert reloading.
├── lb-metrics     Prometheus registry, admin HTTP server (/metrics, /healthz, /ready).
└── lb-bench       Micro-benchmarks for pool selection, GCRA, cluster admit, circuit refresh.
```

Dependencies flow strictly downward. `lb-core` depends on nothing inside the workspace. The data-plane crates (`lb-proxy`, `lb-tcp`) never import each other and never import `lb-tls`. `lb-tcp` has no `rustls` in its dependency tree — it asks an `OutboundTransport` trait object to wrap its stream and pumps whatever comes back.

`lb-server` is the only crate that knows the concrete types. It wires `Gcra<SystemClock>`, `RoundRobin`, `ClusterNode<SystemClock>`, and `BackendTlsTransport` into a `ProxyContext` or `TcpContext` and hands them to the data plane as trait objects.

## Quick Start

**Build:**
```bash
cargo build --release
```

**Run:**
```bash
# Uses ./config.toml by default
./target/release/lb-server

# Or specify a path
./target/release/lb-server /etc/lb/config.toml
```

**Test:**
```bash
cargo test --workspace --features lb-core/test-util
```

**Benchmark:**
```bash
cargo run --release -p lb-bench
```

## Configuration

All configuration lives in a single TOML file. A bad config fails the process at startup — no partial or default-assumed settings are served.

See [`config.example.toml`](config.example.toml) for the authoritative reference with inline commentary. The major sections:

- **`[[listeners]]`** — one per entry point: protocol (`http`/`tcp`), bind address, backends, rate limits, health checks, optional TLS.
- **`[listeners.tls]`** — edge TLS termination. ALPN, handshake timeout, HSTS, cert reload interval.
- **`[listeners.backend_tls]`** — re-encryption to backends. Custom CA or system roots. `danger_accept_invalid_certs` is logged as a warning and exported as a metric.
- **`[listeners.http2]`** — per-listener HTTP/2 settings. Every field has a safe default; omitting the section still gets full protection.
- **`[cluster]`** — distributed rate limiting. Node ID, peer addresses, sliding window, pre-shared key (mandatory).
- **`[admin]`** — private admin listener for metrics and health endpoints.

Full field-by-field reference: [docs/configuration-reference.md](docs/configuration-reference.md)

## How Requests Move

### HTTP

1. Accept loop acquires a global semaphore *before* `accept()`. At capacity, the kernel refuses for us.
2. Per-IP slot checked after accept. Rejection drops the socket.
3. TLS handshake runs in the spawned task, not the accept loop. Both limit guards held across it.
4. ALPN result dispatches to HTTP/1.1 (`header_read_timeout`) or HTTP/2 (stream limits, PING keep-alive, `FirstByteDeadline`).
5. Local GCRA check — free, in-process. Then cluster budget if configured.
6. Circuit-breaker states refreshed from the breakers to the pool.
7. Body read with size cap and timeout.
8. Round-robin picks an eligible backend. Request forwarded through a `hyper_util::Client` with connection pooling.
9. On backend failure, one retry to a different backend. On success, hop-by-hop headers stripped, `X-Request-Id` added, HSTS injected if configured.

### TCP

Same accept/TLS flow. Source-IP rate limit only (no headers at L4). Backend connection established, then bidirectional pump with `tokio::try_join!` (not `select!` — half-close is preserved). One retry on connect failure.

## Observability

The admin port (`/metrics`) exposes Prometheus counters and histograms: requests by status class, latency, active connections, rate-limit rejections (local vs. cluster), backend health, circuit state, TLS handshake outcomes, and certificate expiry.

`/healthz` is always 200 — liveness must not follow backend health, or a backend outage restarts the load balancer in a loop. `/ready` returns 503 when no backend in any pool is eligible.

## Documentation

- [Architecture](docs/architecture.md) — crate graph, trait boundaries, wiring
- [Request Lifecycle](docs/request-lifecycle.md) — step-by-step HTTP and TCP traces
- [Rate Limiting](docs/rate-limiting.md) — GCRA, bounded state, cluster CRDT
- [TLS](docs/tls.md) — termination, re-encryption, cert reloading, ALPN, HSTS
- [Health Checking](docs/health-checking.md) — probes, circuit breaker, shared-transport invariant
- [Cluster Coordination](docs/cluster-coordination.md) — G-Counter, gossip protocol, security
- [Configuration Reference](docs/configuration-reference.md) — every field, its default, its validation
- [Metrics Reference](docs/metrics-reference.md) — every metric, its labels, what to alert on
- [Edge Hardening](docs/edge-hardening.md) — connection limits, slowloris, HTTP/2, body caps

## CI

GitHub Actions runs `cargo fmt`, `cargo clippy`, and `cargo test` on every push to `main` and every pull request.

## License

See the repository for license terms.
