# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **WebSocket/`Upgrade` proxying.** Previously, `strip_hop_by_hop` removed
  the `Connection` and `Upgrade` headers on every request and response
  unconditionally, so a WebSocket handshake was silently mangled and any
  client routed through this load balancer for WebSocket traffic simply
  broke. A request carrying `Connection: Upgrade` + `Upgrade: websocket` is
  now detected before that stripping happens, dialed to the backend over
  its own dedicated, non-pooled HTTP/1.1 connection (never the shared
  pooled client -- reusing a pooled connection that's mid-WebSocket-stream
  for an unrelated request would be a cross-talk bug), and on a `101`, both
  legs are handed off (`hyper::upgrade`) to a background byte-pump reusing
  `lb_tcp::pump` verbatim. HTTP/1.1 only on both legs for v1 -- h2's own
  upgrade mechanism (RFC 8441 extended CONNECT) is a different bootstrapping
  protocol and out of scope; an h2 client connection has no `Upgrade` header
  semantics anyway. New `websocket_idle_timeout_ms` (HTTP listeners,
  default 300s) governs the post-upgrade connection once the request-shaped
  timeouts stop applying. New `lb_websocket_upgrades_total{listener,result}`
  metric.

### Added

- **`[listeners.waf]` (HTTP listeners)**: a WAF first slice -- blocks (or,
  in `mode = "log"`, just records) a request whose path or query string
  contains an obviously malicious pattern, checked before the request
  reaches a route, the response cache, or a backend. A small, fixed,
  built-in set of SQL-injection/XSS/path-traversal substring checks, not a
  rule engine: no percent-decoding/canonicalization, no header inspection,
  and no operator-supplied patterns (a regex dependency and the ReDoS
  question it raises for operator-authored patterns are a deliberately
  separate decision, not smuggled into this slice). `mode = "log"` records
  the match and still forwards the request, for rolling the rule set out in
  detection mode before enforcing it. New
  `lb_waf_blocked_total{listener,rule}` metric.
- **`[listeners.cache]` (HTTP listeners)**: answers a repeated `GET`
  straight from memory instead of forwarding it to a backend at all --
  nginx's `proxy_cache`, Varnish. Deliberately narrow for v1: only a `GET`
  request, only a `200` response, and only one that declares a
  `Content-Length` within `max_entry_bytes` is ever cached -- that
  precondition is what makes buffering a response safe to do at all, since
  it means a body is never fully collected unless it's already known to fit
  in the cap. `Cache-Control: max-age=N` from the backend picks the TTL when
  present and nonzero; `no-store`/`private`/`no-cache`/`max-age=0` all mean
  "don't cache"; otherwise `default_ttl_secs` applies. Everything else
  (chunked/unknown-length bodies, non-GET, non-200, `Vary`/`ETag`/
  conditional requests) is simply proxied exactly as it is with no
  `[listeners.cache]` section, streamed, uncached. Listener-level, not
  per-route: a route's `path_prefix`/`host` are already part of the cache
  key. Wiped on every config hot-reload -- the deliberately simplest
  invalidation story, with no purge-by-pattern API. New
  `lb_cache_result_total{listener,result}` metric.
- **`[listeners.sticky]` (HTTP listeners)**: sticky-cookie session
  affinity -- nginx's commercial `sticky` module, HAProxy's `cookie`
  directive. Once a client's request lands on a backend, sets a cookie
  naming it and prefers that backend on the client's next request, layered
  on top of whatever `load_balancing.strategy` is chosen rather than being
  a strategy itself: a request with no cookie, an unparseable one, or one
  naming a backend that's no longer eligible falls straight through to the
  underlying strategy, exactly as if sticky weren't configured. The
  cookie's value is the backend's own id, unsigned -- ids are already
  exposed via the admin API's `GET /backends` and aren't secret, and a
  forged or stale value can at worst fall through to the strategy, never
  force a bad route. Applies uniformly to a listener's default backends and
  every `[[listeners.routes]]` pool -- there is no separate per-route toggle.
- **`[[listeners.routes]]` (HTTP listeners)**: path-prefix and/or Host-header
  based backend selection within one listener -- nginx's `location` blocks
  and HAProxy's ACL-based backend selection, both doing the same job. Rules
  are evaluated in declaration order, first match wins; a request matching
  no rule (or every listener without a `[[listeners.routes]]` section at
  all) falls through to the listener's own top-level `backends`/
  `health_check`/`load_balancing`, which is what makes this fully backward
  compatible -- an existing config means exactly what it always meant.
  `path_prefix` matches on a path *segment* boundary (`/api` matches `/api`
  and `/api/anything`, not `/apiary`), avoiding nginx's own well-known
  `location /api` gotcha. Each route gets its own backends, health checks,
  and load-balancing strategy, but shares the listener's single TLS/client
  policy -- per-route `dns_discovery`/`backend_tls` is out of scope for now.
  `GET /backends` on the admin API now labels each backend with which
  route it belongs to (or `default`), and `drain`/`undrain` search across
  every route's backends the same way they already did for the default set.
- **`compression` (HTTP listeners)**: gzip/brotli/deflate/zstd response
  compression, negotiated against the client's `Accept-Encoding` via
  `tower-http`'s `CompressionLayer`. Off by default, matching nginx's own
  `gzip off` — a CPU/latency trade-off an operator should opt into. The
  per-listener toggle is threaded through as a predicate rather than a
  runtime choice between two tower stacks, so there is exactly one stack
  shape regardless of the config value.
- **Admin backend-management API**: `GET /backends` (every listener's
  backends, with health/circuit/drain state and in-flight connection
  counts, as JSON) and `POST /backends/{listener}/{id}/drain` /
  `.../undrain` on the existing private admin port — runtime inspection
  and draining with no config edit or reload, the two primitives nginx
  paywalls into nginx Plus's dynamic reconfiguration API. Deliberately
  narrower than adding/removing backends live (config + `SIGHUP` still
  owns that) — this is inspection and draining only. A drain is tracked
  as its own flag, independent of the active health checker's own
  healthy/unhealthy verdict, so a passing probe can't silently undo an
  operator's drain request.
- **`proxy_protocol` (either listener type)**: reads the real client address
  from a PROXY protocol header (v1 text, v2 binary, auto-detected) sent by a
  trusted front-end proxy/ELB/CDN ahead of everything else on the
  connection, instead of trusting the immediate TCP peer — which, behind
  another proxy, is just that proxy's own address. A hard trust boundary: a
  connection whose header is missing or malformed is dropped, not served
  under the raw peer address. Feeds directly into per-client rate limiting,
  access logs, and tracing, with no changes needed in either data plane —
  both already keyed on the connection's peer address.
- **`[cluster.tls]`: optional mutual TLS on the cluster peer channel.**
  Previously the peer channel was HMAC-SHA256 *authenticated* but never
  *encrypted* — the HMAC stopped a peer from forging counts, but anyone who
  could observe the link read every node id and rate-limit count in the
  clear. Every node presents the same cert/key to every peer (gossip is
  symmetric — one node, one identity) and verifies peers by IP SAN against
  a shared CA (`ca_file`), reusing rustls' own WebPKI verifiers rather than
  a hand-rolled one. Omitting the section keeps today's HMAC-only behavior
  unchanged — existing configs are unaffected.
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
