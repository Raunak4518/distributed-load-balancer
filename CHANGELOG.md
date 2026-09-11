# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **DNS-based service discovery**: a background poller (`lb-server`'s
  `TokioResolver`, real `tokio::net::lookup_host` I/O behind the `Resolve`
  trait) now resolves a `dns_discovery` listener's name on an interval and
  feeds the results into `BackendPool::apply_resolved`, so a listener's
  backend set can grow, shrink, or move without a restart.
  - Safe for TCP listeners and for HTTP listeners without `backend_tls`
    (both dial straight to the resolved address).
  - Rejected at config validation for HTTP listeners *with* `backend_tls`:
    the L7 dial-pinning table (`PinnedResolver`) is keyed by `server_name`,
    and DNS naturally returns several addresses under one name, which would
    collapse them onto a single pinned address and silently defeat load
    balancing. TCP's backend TLS has no such table — each connection dials
    and verifies independently — so it only requires a new
    `dns_discovery.server_name` config field.
- **Broader platform support**: multi-arch Docker images (`linux/amd64`,
  `linux/arm64`), a `.github/workflows/release.yml` that also publishes
  static, dependency-free `musl` binaries for `x86_64` and `aarch64` Linux
  on each version tag, and a `packaging/systemd/lb-server.service` unit for
  running from a plain binary on any Linux distribution.

## [0.1.0] - 2026-09-11

Initial release. An 11-crate Rust workspace implementing an L4/L7 load
balancer with distributed rate limiting, TLS termination, and HTTP/2 support.

### Added

- **Core proxying (L7 HTTP)**: config-driven backend pools, round-robin load
  balancing, a GCRA rate limiter, a circuit breaker per backend, active health
  checks, and request forwarding with retry on a failed backend.
- **Core proxying (L4 TCP)**: raw TCP session handling with the same rate
  limiting, failover, and circuit-breaking behavior as the HTTP path, servable
  alongside HTTP listeners in the same process.
- **Distributed rate limiting**: a G-Counter CRDT store shared across nodes
  over a length-prefixed, HMAC-SHA256-authenticated peer sync protocol, with
  per-listener cluster-wide budgets.
- **Observability**: a Prometheus metrics registry with pre-resolved handles,
  a private admin listener serving `/metrics`, `/healthz`, and `/ready`,
  structured tracing with per-request IDs, and a micro-benchmark harness for
  the hot path.
- **Edge hardening**: connection limits, header/body read timeouts, and a
  bounded, shared overflow bucket for rate-limit key tracking to cap memory
  under a key-exhaustion attack.
- **TLS**: certificate loading and validation with expiry checks, SNI-based
  certificate resolution, zero-downtime certificate reload, a handshake
  timeout, and backend re-encryption via a dedicated `BackendConnector`
  (dial pinned to the resolved address, not the `server_name`'s live DNS).
- **HTTP/2**: ALPN-negotiated HTTP/2 to clients and to backends, with a
  bounded first byte on new h2 connections and a Rapid Reset mitigation
  verified under simulated sabotage.
- **Dynamic backend pool membership**: `BackendPool` now holds its state in
  an `ArcSwap` snapshot, preserving per-backend health/circuit state across
  a membership change, so a backend set can be refreshed without a restart
  or per-request locking.
- **DNS-based service discovery (config only)**: a `dns_discovery` listener
  config section and a `Resolve` trait boundary, mutually exclusive with a
  static `backends` list at validation time. The resolver implementation and
  polling loop are not yet wired in — a static `backends` list remains the
  only way to serve traffic today.
- **CLI**: `lb-server` now accepts `--version`/`-V`, `--help`/`-h`, and
  `--check-config <PATH>` (parse and validate a config file without starting
  the process), in addition to the existing `lb-server [CONFIG_PATH]` and
  no-argument (`config.toml`) forms.
- Workspace-wide semantic versioning: every crate now shares one version via
  `version.workspace = true`.

### Fixed

- A backend removed from the pool between being picked and dialed no longer
  panics the request handler (L7 and L4); the request now falls through to
  the existing unavailable/failed-connect path instead.
- Looking up a circuit breaker for a backend with no pre-built entry no
  longer panics; the request now proceeds without circuit-breaker
  bookkeeping for that backend instead of crashing the connection.
