<div align="center">

# Distributed Load Balancer

**A multi-protocol L4/L7 load balancer written in Rust, with cluster-wide rate limiting coordinated over gossip — no central data store required.**

[![CI](https://github.com/Raunak4518/distributed-load-balancer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Raunak4518/distributed-load-balancer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Raunak4518/distributed-load-balancer?sort=semver)](https://github.com/Raunak4518/distributed-load-balancer/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg?logo=rust)](https://www.rust-lang.org)
[![Container](https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://github.com/Raunak4518/distributed-load-balancer/pkgs/container/distributed-load-balancer)

[Getting started](docs/getting-started.md) ·
[Documentation](docs/README.md) ·
[Configuration](docs/configuration-reference.md) ·
[Benchmarks](docs/benchmarks.md) ·
[Contributing](CONTRIBUTING.md)

</div>

---

`lb-server` terminates TLS, serves HTTP/1.1 and HTTP/2, proxies raw TCP, and spreads traffic across backends using one of five selection strategies — including a latency-aware Peak-EWMA power-of-two-choices balancer. It health-checks backends actively and passively, ejects failing ones through a circuit breaker and statistical outlier detection, and rate-limits clients with GCRA. When several instances run side by side, they share rate-limit state through an HMAC-authenticated G-Counter CRDT, so a client's budget holds across the whole fleet.

It is built to be operated: memory that clients can influence is bounded (the response cache's byte budget is a hard limit; rate-limit keys are fixed-size, and their count caps can be exceeded only by requests racing each other, by one small entry each), rejections and backend failures are exported as Prometheus metrics, configuration reloads on `SIGHUP` without dropping connections, and shutdown drains in-flight requests.

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Installation](#installation)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Observability](#observability)
- [Performance](#performance)
- [Documentation](#documentation)
- [Project status](#project-status)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Features

**Traffic management**
- HTTP/1.1 and HTTP/2 (negotiated with ALPN), raw TCP passthrough, and WebSocket / `Upgrade` proxying.
- Five selection strategies: round robin, least connections, weighted round robin, consistent hashing, and Peak-EWMA with power-of-two choices.
- Path-prefix and `Host` routing to independent backend pools; percentage-based canary splits; cookie-based sticky sessions.
- DNS-based backend discovery with state preserved across re-resolution.
- Retries to a freshly picked backend, restricted to idempotent methods and bounded by a retry budget.
- In-memory response caching and gzip / brotli / deflate / zstd response compression.

**Resilience**
- Active HTTP and TCP health checks that use the same transport as real traffic.
- Passive health signals (latency and concurrency thresholds) feeding a lock-free circuit breaker with flap backoff.
- Statistical outlier detection, with a pool-wide ejection ceiling so a correlated failure cannot eject every backend.
- Manual drain and undrain through the admin API.
- Live configuration reload on `SIGHUP`, validated all-or-nothing; graceful shutdown with a drain deadline.

**Security at the edge**
- TLS termination on rustls (`ring`), SNI with multiple certificates, automatic certificates via ACME (HTTP-01), and certificate hot reload.
- Backend re-encryption with certificate verification and DNS-pinned dialing.
- Global and per-IP connection caps, read- and write-side slowloris timeouts, body size limits, and HTTP/2 limits including the Rapid Reset (CVE-2023-44487) mitigation.
- PROXY protocol v1 and v2, a built-in WAF (block or log mode), and bearer-token authentication on the admin API with constant-time comparison.

**Distributed rate limiting**
- Per-key GCRA with bounded memory: new keys beyond the cap share an overflow bucket instead of evicting established clients.
- Cluster-wide budgets via a G-Counter CRDT gossiped between nodes, authenticated with HMAC-SHA256, optionally over mutual TLS, with clock-skew and memory bounds.

**Observability**
- Prometheus metrics, liveness (`/healthz`) and readiness (`/ready`) endpoints, and a JSON backend inspection API.
- Structured JSON logging with sampled access logs, and OpenTelemetry trace export over OTLP/HTTP.

## Quick start

Build the binary (or [install a release](#installation)):

```bash
cargo build --release -p lb-server
```

Save this as `lb.toml` — it balances two backends on ports 9001 and 9002 and exposes the admin API on 9090:

```toml
[[listeners]]
name     = "web"
protocol = "http"
listen   = "127.0.0.1:8080"

[[listeners.backends]]
id      = "web1"
address = "127.0.0.1:9001"

[[listeners.backends]]
id      = "web2"
address = "127.0.0.1:9002"

[listeners.health_check]
path              = "/health"
interval_ms       = 2000
timeout_ms        = 500
failure_threshold = 3
cooldown_ms       = 5000

[listeners.rate_limit]
key          = "source_ip"
rate_per_sec = 50
burst        = 100

[listeners.load_balancing]
strategy = "round_robin"

[admin]
listen = "127.0.0.1:9090"
```

Validate it, run it, and send traffic:

```bash
./target/release/lb-server --check-config lb.toml
./target/release/lb-server lb.toml

curl http://127.0.0.1:8080/            # alternates between web1 and web2
curl http://127.0.0.1:9090/backends    # live backend state as JSON
curl http://127.0.0.1:9090/metrics     # Prometheus metrics
```

The [getting-started guide](docs/getting-started.md) walks through this end to end, including starting throwaway backends, watching a backend fail and recover, and reloading the configuration.

## Installation

Every tagged release publishes the following through [`.github/workflows/release.yml`](.github/workflows/release.yml):

| Artifact | Platforms |
|---|---|
| Static binaries (`musl`) | Linux `x86_64`, `aarch64` |
| Native binaries | macOS `x86_64`, `aarch64` (Apple Silicon) |
| `.deb` / `.rpm` packages | Linux `x86_64` (binary, systemd unit, default config) |
| Container image | `ghcr.io/raunak4518/distributed-load-balancer`, `linux/amd64` and `linux/arm64` |

**Install script** (Linux or macOS; selects the right release asset):

```bash
curl -fsSL https://raw.githubusercontent.com/Raunak4518/distributed-load-balancer/main/scripts/install.sh | sh
```

**Container** (mount your config over the default; listeners must bind `0.0.0.0` inside the container):

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/lb.toml:/etc/lb-server/config.toml:ro" \
  ghcr.io/raunak4518/distributed-load-balancer:latest
```

**Debian / Ubuntu or Fedora / RHEL:**

```bash
sudo dpkg -i lb-server_*.deb        # or: sudo rpm -i lb-server-*.rpm
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lb-server
sudo $EDITOR /etc/lb-server/config.toml
sudo systemctl enable --now lb-server
```

**From source**, on any platform supported by Rust and Tokio:

```bash
cargo install --git https://github.com/Raunak4518/distributed-load-balancer lb-server
```

Deployment details — the hardened systemd unit, reload and shutdown semantics, and the admin API — are in [docs/operations.md](docs/operations.md).

## How it works

Every HTTP request passes through a fixed, ordered pipeline, and each stage can end the request early:

```mermaid
flowchart LR
    A[Accept<br/>connection caps] --> B[PROXY protocol<br/>TLS + ALPN]
    B --> C[Rate limit<br/>local GCRA]
    C --> D[WAF]
    D --> E[Cluster<br/>budget]
    E --> F[Cache<br/>lookup]
    F --> G[Route / canary<br/>pool selection]
    G --> H[Pick backend<br/>strategy + sticky]
    H --> I[Forward<br/>retry once]
    I --> J[Response<br/>headers, cache, compression]
```

The workspace is split into twelve crates with one-directional dependencies. `lb-core` defines the traits every component is built against — `LoadBalancer`, `RateLimiter`, `HealthProbe`, `Clock`, `OutboundTransport` — and `lb-server` is the only crate that knows the concrete types:

| Crate | Responsibility |
|---|---|
| `lb-server` | The binary: configuration, listener binding, wiring, reload and shutdown. |
| `lb-core` | Traits, the backend pool, and configuration parsing and validation. |
| `lb-proxy` / `lb-tcp` | The L7 and L4 data planes. |
| `lb-balancer` | Selection strategies. |
| `lb-healthcheck` | Health probes, circuit breaker, outlier detection. |
| `lb-ratelimit` / `lb-cluster` | Local GCRA and gossip-based cluster coordination. |
| `lb-tls` | Termination, re-encryption, ACME, certificate reload, peer mTLS. |
| `lb-metrics` / `lb-tracing` | Metrics and admin server; logging and trace export. |
| `lb-bench` | Micro-benchmarks and real-traffic evaluation harnesses. |

See [docs/architecture.md](docs/architecture.md) for the dependency rules and concurrency model, and [docs/request-lifecycle.md](docs/request-lifecycle.md) for the full step-by-step trace.

## Configuration

Configuration is a single TOML file, validated in full at startup: an invalid file stops the process before it binds a socket, and `lb-server --check-config <path>` runs the same validation without starting. The main sections are:

| Section | Purpose |
|---|---|
| `[[listeners]]` | An entry point: protocol, bind address, backends, and per-listener limits and timeouts. |
| `[listeners.health_check]`, `[listeners.rate_limit]`, `[listeners.load_balancing]` | Required on every listener. |
| `[[listeners.routes]]`, `[[listeners.canary]]`, `[listeners.sticky]` | Routing, traffic splitting and session affinity (HTTP). |
| `[listeners.tls]`, `[listeners.backend_tls]`, `[listeners.http2]` | Edge TLS, backend re-encryption and HTTP/2 limits. |
| `[listeners.cache]`, `[listeners.waf]`, `[listeners.retry_budget]` | Optional HTTP features. |
| `[cluster]`, `[admin]`, `[logging]`, `[tracing]` | Process-wide settings. |

- [docs/configuration-reference.md](docs/configuration-reference.md) documents every field, default and validation rule, and which fields reload live on `SIGHUP`.
- [`config.example.toml`](config.example.toml) is an annotated configuration covering every section.
- [`examples/`](examples/) has minimal configurations for an HTTP reverse proxy, TCP passthrough, TLS with backend re-encryption, DNS discovery, and a two-node cluster.

## Observability

The optional admin listener serves:

| Endpoint | Purpose |
|---|---|
| `GET /metrics` | Prometheus metrics: requests, latency, connections, backend health and circuit state, rate-limit rejections, retries, TLS and certificate expiry, cache, WAF. |
| `GET /healthz` | Liveness. Always `200` — deliberately independent of backend health, so a backend outage cannot restart the load balancer in a loop. |
| `GET /ready` | Readiness. `503` when no backend is eligible. |
| `GET /backends` | Every backend's health, circuit, drain and in-flight state as JSON. |
| `POST /backends/{listener}/{id}/drain` · `/undrain` | Take a backend out of rotation without a config change. |

Set `[admin] token_env` to require a bearer token on every admin request. The [metrics reference](docs/metrics-reference.md) lists every metric with suggested Prometheus alert rules.

## Performance

Measured with the in-repository harness against a real `lb-server` process on loopback — one Windows machine, 16 logical cores, release build, four backends. These are single-machine figures, not capacity guarantees; methodology, caveats and reproduction commands are in [docs/benchmarks.md](docs/benchmarks.md).

| Scenario | Result |
|---|---|
| Round robin, 128 concurrent connections | 6,189 req/s; p50 20.2 ms, p99 33.9 ms; 0 errors |
| Backend killed mid-run (64 connections, 16 s) | 90,823 requests, 0 client-visible errors |
| Per-request bookkeeping (pick, circuit refresh, GCRA, cluster admit), 5 backends | ≈ 2 µs |
| Full TLS 1.3 handshake, ECDSA P-256 (client + server CPU) | ≈ 1 ms |

Under load-dependent backend latency, the adaptive strategies shift traffic toward the backend with capacity while round robin cannot:

| Strategy | Share to fastest backend | Throughput | p50 latency |
|---|---:|---:|---:|
| `round_robin` | 25.0% | 523 req/s | 152.5 ms |
| `least_connections` | 69.9% | 1,427 req/s | 16.5 ms |
| `peak_ewma_p2c` | 49.2% | 880 req/s | 62.7 ms |

## Documentation

| Topic | |
|---|---|
| Getting started | [docs/getting-started.md](docs/getting-started.md) |
| Operations and deployment | [docs/operations.md](docs/operations.md) |
| Load balancing, routing, canary, sticky sessions | [docs/load-balancing.md](docs/load-balancing.md) |
| Health checking, circuit breaking, outlier detection | [docs/health-checking.md](docs/health-checking.md) |
| Rate limiting | [docs/rate-limiting.md](docs/rate-limiting.md) |
| Cluster coordination | [docs/cluster-coordination.md](docs/cluster-coordination.md) |
| TLS and ACME | [docs/tls.md](docs/tls.md) |
| HTTP features: HTTP/2, caching, compression, WebSocket | [docs/http-features.md](docs/http-features.md) |
| Edge hardening | [docs/edge-hardening.md](docs/edge-hardening.md) |
| Configuration reference | [docs/configuration-reference.md](docs/configuration-reference.md) |
| Metrics reference | [docs/metrics-reference.md](docs/metrics-reference.md) |
| Request lifecycle | [docs/request-lifecycle.md](docs/request-lifecycle.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Benchmarks | [docs/benchmarks.md](docs/benchmarks.md) |

## Project status

The current release is **0.3**. The project follows [Semantic Versioning](https://semver.org/); before 1.0, configuration keys and metric names may change between minor versions, and every such change is recorded in the [changelog](CHANGELOG.md).

Known limitations, each documented on the linked page:

- The proxy does not add `X-Forwarded-For` / `Forwarded` headers; backends see the load balancer's address ([HTTP features](docs/http-features.md#x-forwarded-for--forwarded)).
- The response cache does not revalidate (`ETag`, conditional requests) and relies on the backend's `Cache-Control`/`Vary` to mark cookie-personalized responses ([HTTP features](docs/http-features.md#personalized-content-and-limitations)).
- Unknown configuration keys are ignored rather than rejected ([configuration reference](docs/configuration-reference.md#top-level-structure)).
- `SIGHUP` reload is Unix-only, and the admin listener has no TLS of its own ([operations](docs/operations.md)).
- ACME issues single-domain certificates over HTTP-01 only ([TLS](docs/tls.md#acme-automatic-certificates)).

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the checks CI runs, and the testing standards reviewers apply. Everyone participating is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for security problems.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
