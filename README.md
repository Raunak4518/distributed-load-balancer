# Distributed Load Balancer — Phases 1–8

A multi-protocol load balancer in Rust. Terminates TLS, speaks HTTP/1.1 and HTTP/2, rate-limits by IP or header, health-checks backends, and forwards traffic over HTTP or raw TCP. Multiple instances share rate-limit counters through a gossip-based CRDT protocol — no central data store required.

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

**CLI flags:**
```bash
lb-server --check-config /etc/lb-server/config.toml   # validate and exit
lb-server --version
lb-server --help
```

### Running it

Three ways to run `lb-server`, none tied to a particular platform:

**Docker** (published for `linux/amd64` and `linux/arm64`):
```bash
docker run -v $(pwd)/config.toml:/etc/lb-server/config.toml:ro -p 8080:8080 \
  ghcr.io/raunak4518/distributed-load-balancer:latest
```
Or build locally: `docker build -t lb-server .`

**systemd** (any Linux distro, from a prebuilt binary or `cargo build --release`):
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lb-server
sudo install -m755 target/release/lb-server /usr/local/bin/lb-server
sudo mkdir -p /etc/lb-server && sudo cp config.toml /etc/lb-server/config.toml
sudo cp packaging/systemd/lb-server.service /etc/systemd/system/
sudo systemctl enable --now lb-server
```

**From source**, on anything `rustc`/Tokio supports: `cargo build --release -p lb-server`.

**Install script** (Linux or macOS, `x86_64` or `arm64` — picks the right release asset automatically):
```bash
curl -fsSL https://raw.githubusercontent.com/Raunak4518/distributed-load-balancer/main/scripts/install.sh | sh
```

Prebuilt binaries are published on each [GitHub Release](https://github.com/Raunak4518/distributed-load-balancer/releases) by [`.github/workflows/release.yml`](.github/workflows/release.yml): static, dependency-free `musl` builds for `x86_64`/`aarch64` Linux (run on any distro, any glibc version, containers included), and native builds for `x86_64`/`aarch64` (Apple Silicon) macOS.

## Configuration

All configuration lives in a single TOML file. A bad config fails the process at startup — no partial or default-assumed settings are served.

**Pick your setup**: [`examples/`](examples/) has one minimal, runnable config per common deployment shape — plain HTTP reverse proxy, TCP passthrough, TLS termination with backend re-encryption, DNS-discovered backends, and a two-node cluster. Copy the one closest to your use case and adjust the addresses.

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

## HTTP/2

HTTP/2 is negotiated over ALPN during the TLS handshake and is **on by default for every TLS listener** — an operator who writes no `[listeners.http2]` section still gets it, fully protected by the defaults below. Set `[listeners.http2] enabled = false` to keep a TLS listener on HTTP/1.1 only.

A **plaintext listener always stays HTTP/1.1**, deliberately: ALPN only exists inside a TLS handshake, so there is nothing to negotiate over on an unencrypted port. This node is also the edge, so prior-knowledge h2c on a plaintext listener — starting the HTTP/2 preface with no negotiation at all — is surface nobody asked for and isn't offered; `[listeners.http2]` is rejected outright on a `tcp` listener and has no effect on the client-facing side if written under a `protocol = "http"` listener with no `[listeners.tls]`. `backend_h2c` is the one exception: see Backends below.

Which protocol a connection got is decided once, right after the TLS handshake, by reading the negotiated ALPN protocol off the still-concrete `TlsStream` — there is no preface-sniffing. That result feeds two independent things: the `hyper` server builder used to drive the connection (HTTP/1.1's `header_read_timeout`, or HTTP/2's stream limits and PING keep-alive), and the `protocol` label (`http1`/`http2`) recorded on `lb_requests_total` — the same counter every request already incremented, not a new metric.

### Limits

Every field is optional; the values below are the defaults an unconfigured `[listeners.http2]` section gets.

| Setting | Default | Bounds |
|---|---:|---|
| `max_concurrent_streams` | 128 | Concurrent requests per connection. Under HTTP/2, one connection carries many concurrent requests, so a per-IP *connection* cap alone no longer bounds per-IP *work*: at the defaults here, `max_connections_per_ip` (100) times `max_concurrent_streams` (128) puts the per-IP concurrency ceiling at 12,800 requests, and since each in-flight request buffers its body up to `max_request_body_bytes` (1 MiB by default), that is a per-IP memory ceiling of roughly 12.8 GiB, not the ~100 MiB HTTP/1.1 implied. `max_concurrent_streams` does not restore Phase 5's per-IP bound on its own. The mandatory `[listeners.rate_limit]` is what actually keeps admitted concurrency down: it runs before the body is read, and with `key = "source_ip"` its `burst` setting is the real per-IP concurrency bound under HTTP/2. |
| `max_pending_accept_reset_streams` | 20 | Rapid Reset (CVE-2023-44487): a client opens streams and cancels them immediately, which evades `max_concurrent_streams` precisely by never being concurrent. 20 is deliberately h2's own built-in default (`DEFAULT_REMOTE_RESET_STREAM_MAX`) — looser is inert, since h2 enforces its own bound underneath regardless, and tighter starts cutting off ordinary client-initiated cancellations. |
| `max_local_error_reset_streams` | 128 | Bounds resets this side is forced to send back to a client whose frames keep failing protocol validation — h2's own default here is 1024; 128 is deliberately tighter. |
| `max_header_list_size` | 16384 | Bounds HPACK/`CONTINUATION` expansion, where a few frames can inflate into a lot of server-side header state. |
| `max_frame_size` | 16384 | Per-frame size ceiling. |
| `keep_alive_interval_secs` / `keep_alive_timeout_secs` | 20 / 10 | HTTP/2's liveness check, sent as PING frames on an established connection. There is deliberately no `header_read_timeout` equivalent here: an idle HTTP/2 connection is normal where an idle HTTP/1.1 one is not, and PING is what tells the two apart. |

hyper's PING keep-alive only arms once the client's h2 preface has actually arrived, which leaves the window between "TLS handshake done" and "preface received" uncovered — a client that negotiates `h2` and then goes silent would otherwise hold its connection and per-IP slot forever. A `FirstByteDeadline` stream adapter (`crates/lb-server/src/first_byte.rs`) closes that gap on the HTTP/2 branch by arming a deadline at connection start and disarming it on the first byte read.

The disarm condition is "a byte arrived," not "the preface completed," so a client that sends one byte and then stalls mid-preface still disarms the deadline; from there it is bounded only by the per-IP connection cap from Phase 5, not by anything h2-specific. This residual is left alone deliberately: raising the disarm threshold to the full 24-byte h2 preface would only move the attacker's cost from one byte to 24 and close nothing structurally, and a true deadline on handshake *completion* isn't something hyper exposes.

### Backends

Backend HTTP/2 needs no configuration when the backend is reached over `[listeners.backend_tls]`: ALPN negotiates `h2` vs. `http/1.1` per connection during the backend handshake, so a mixed fleet — some backends on HTTP/2, some not — works automatically. `[listeners.http2] backend_h2c = true` is for plaintext backends only, which have no ALPN and so no other way to advertise `h2`; it makes every backend connection prior-knowledge HTTP/2 (`http2_only(true)` on the client builder), which is only sound when the backend is known out of band to actually speak it. `backend_h2c` together with `backend_tls` is rejected at config-parse time, since a TLS backend already negotiates HTTP/2 on its own.

Unlike the rest of `[listeners.http2]`, `backend_h2c` works independently of `[listeners.tls]` and of this listener's own `http2.enabled`: it is read straight off the config and applied to the outbound backend client regardless of what the frontend negotiates. Only the client-facing side needs TLS, because that side's ALPN negotiation is what TLS provides — the backend leg has no ALPN either way. A plaintext-front, plaintext-h2c-backend listener genuinely gets prior-knowledge h2c to its backends.

Because an HTTP/1.1 backend's response can now land on an HTTP/2 client stream (and vice versa), hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, plus anything named inside `Connection`) are stripped in both directions regardless of which protocol either side used.

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
