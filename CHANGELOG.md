# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`write_timeout_ms` (HTTP listeners)**: caps how long a client may take to
  *read* the response, mirroring `header_read_timeout_ms`/`body_read_timeout_ms`
  on the send side. Without it, a client that stops draining its socket
  (a full TCP receive window, or a client that has simply gone away) could
  hold a connection, its connection-limit permit, and its per-IP slot open
  forever — resource-bounded but not time-bounded. Defaults to 30s. TCP
  listeners get the same protection for free: `idle_timeout_ms` now applies
  to both directions of the byte pump, not just reads.
- **Three new `load_balancing.strategy` options**: `least_connections` (picks
  the eligible backend with the fewest in-flight requests/connections),
  `weighted_round_robin` (round-robin, but each backend's `weight` now
  actually does something — previously parsed and stored, never read), and
  `consistent_hash` (hashes this listener's rate-limit key onto a ring of
  backends, so the same client keeps landing on the same backend as long as
  the backend set doesn't change; removing a backend remaps only a minority
  of keys, not all of them). `round_robin` remains the default.
- **`examples/`**: one minimal, runnable config per deployment shape (plain
  HTTP reverse proxy, TCP passthrough, TLS termination with backend
  re-encryption, DNS-discovered backends, a two-node cluster), each validated
  against a real running instance rather than written speculatively.
- Active health checks now log a transition (`recovered` / `removed from
  rotation`) instead of failing silently — a backend going down or coming
  back up previously left no trace in the logs.
- **`dns_discovery` is now allowed together with `[listeners.backend_tls]`
  on HTTP listeners** (previously rejected at config validation — see the
  `[0.2.0]` notes below for why). Each backend resolved under the shared
  `server_name` now gets its own connection pool (`lb_proxy::per_backend`),
  built lazily per backend id, so several DNS-resolved addresses sharing one
  certificate name no longer collapse onto a single pooled connection —
  round-robin, per-backend circuit-breaking, and health-check attribution
  are all real again. TCP listeners were never affected.
- **`.deb`/`.rpm` packages** for `x86_64` Linux, published on each release
  alongside the existing binaries and Docker image, installing the binary,
  the systemd unit, and a default config in one step. The project is now
  dual-licensed under MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`),
  required for both package formats and previously undeclared anywhere in
  the repository.
- **OpenTelemetry trace export** (`lb-tracing`, new crate): one span per
  HTTP request and per TCP session, exported over OTLP/HTTP when a new
  `[tracing]` config section is present (absent means disabled — spans are
  still created either way, at the negligible cost `tracing` is designed
  for). The exporter uses a small custom blocking HTTP client rather than
  `reqwest`: the batch span processor drives its exporter from its own OS
  thread, not a Tokio task, so an async client has no reactor to run on
  there, and `reqwest` pulls in `native-tls`/`openssl-sys` regardless of
  requested features, which this project's musl static release binaries
  have no reason to inherit for a telemetry side channel.
- **Config hot-reload via `SIGHUP`** (`systemctl reload lb-server`, or
  `kill -HUP <pid>`): a listener's `backends`, `dns_discovery`, `health_check`,
  and `rate_limit` apply live, with no dropped connections — each newly
  accepted connection reads whatever config is current, while one already in
  flight keeps whichever snapshot it loaded (`ArcSwap`, the same pattern the
  TLS cert reloader already used for its own seam). Adding, removing, or
  re-addressing a listener; its `tls`/`backend_tls`/`http2`/connection-limit
  settings; and anything under `[server]`/`[admin]`/`[cluster]`/`[logging]`/
  `[tracing]` still require a restart — a reload that would need one is
  refused outright, logged with the reason, and changes nothing.

## [0.2.0] - 2026-09-12

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
  `linux/arm64`); a `.github/workflows/release.yml` that publishes static,
  dependency-free `musl` binaries for `x86_64`/`aarch64` Linux and native
  binaries for `x86_64`/`aarch64` (Apple Silicon) macOS on each version tag;
  a `packaging/systemd/lb-server.service` unit for running from a plain
  binary on any Linux distribution; and `scripts/install.sh`, which detects
  the host OS/arch and installs the matching release binary in one command.

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
