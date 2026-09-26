# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Updated rustls to 0.23.45** for RUSTSEC-2026-0285, in which TLS 1.3
  handshake messages were accepted across encryption-level boundaries. The
  edge TLS termination path was affected.
- **`max_request_body_bytes` did not bound memory.** The whole request body
  was buffered before its size was checked, so a client could make the proxy
  allocate far more than the limit. A declared `Content-Length` over the
  limit is now refused before reading, and other bodies are read through a
  counting limiter that stops as soon as the limit is passed.
- **The response cache could share private responses.** `Cache-Control`
  directives were read left to right and the first `max-age` ended the scan,
  so `max-age=600, private` or `max-age=600, no-store` was cached and served
  to every client. `no-store`, `private` and `no-cache` now forbid caching
  wherever they appear, across every `Cache-Control` line.
- Requests carrying `Authorization` now bypass the cache entirely, and
  responses carrying `Set-Cookie` are never stored.
- **Header-based rate-limit keys are now stored as a fixed-size hash.** The
  raw header value was stored and gossiped, so a client could grow memory
  with long values (up to ~400 KB each over HTTP/1.1) and API keys used as
  rate-limit keys crossed the cluster channel in plaintext. Keys are now
  `h:` plus 128 bits of SHA-256. On the first deploy, `consistent_hash`
  listeners keyed by a header remap each client once.
- **A node's gossip could be rejected wholesale.** A snapshot was capped at
  5,000 entries but not in bytes, so long keys could push every message
  past the 4 MiB receive limit, silently removing that node from cluster
  rate limiting. Snapshots now also stop at about 1 MiB.

### Added

- **Awaiting-first-probe state for new backends.** A backend that joins a
  pool while the process is serving (a later DNS poll or a config reload)
  receives no traffic until its first health probe succeeds, as long as
  another confirmed backend in the pool is eligible. When none is, awaiting
  backends are used rather than returning `503`, so cold starts and complete
  DNS replacements keep serving.
- `GET /backends` now reports `outlier_ejected` and `awaiting_first_probe`
  for every backend.

### Fixed

- **Finished connection tasks were kept until shutdown.** Each listener's
  connection set was only drained at shutdown, so its bookkeeping grew with
  every connection ever accepted. Finished tasks are now released as new
  connections arrive.
- **A backend could stall a response body indefinitely.**
  `forward_timeout_ms` only covered the wait for response headers. The new
  `response_body_idle_timeout_ms` (default 60s) bounds every gap in a
  streamed response body; a stalled response is aborted rather than
  presented as complete, and counted under
  `lb_request_timeouts_total{phase="upstream_body"}`.
- **Five metrics were registered but never updated**, and two more stayed
  flat for HTTP listeners. `lb_cluster_auth_failures_total`,
  `lb_cluster_peer_sync_total`, `lb_cluster_tracked_keys`,
  `lb_ratelimit_tracked_keys` and `lb_request_timeouts_total{phase="header"}`
  are now recorded, and `lb_connections_total`/`lb_active_connections` now
  count HTTP connections as well as TCP ones. The cluster metrics' `peer`
  label is limited to configured peers plus `unknown`.
- **A retry could go back to the backend that just failed.** The retry loop
  re-ran the strategy with no exclusion, so under `consistent_hash` (and
  often `least_connections`) it retried the same failing backend. Retries now
  exclude it; each strategy picks among the remaining backends with its own
  logic. A single-backend pool still retries.
- **One failed health probe removed a backend.** Active checks now use
  `health_check.unhealthy_threshold` (default 3) and `healthy_threshold`
  (default 2), so one slow or dropped probe no longer flaps a backend. A
  backend awaiting its first probe is still decided by that probe alone.
- **Behind a PROXY-protocol front end, `max_connections_per_ip` capped the
  front end rather than each client.** The per-IP slot was taken before the
  PROXY header was read; it is now taken after, keyed on the announced
  client address.
- **Unknown configuration keys are now rejected.** A misspelled key such as
  `max_conections` was silently ignored and its default applied; it is now a
  startup error naming the key.
- `health_check.max_ejected_fraction` could be exceeded under concurrency.
  Each ejection counted, decided and stored separately, so circuit trips on
  several request threads at once (the typical shape of a correlated
  failure) could all pass the check; 4 of 8 backends were observed ejected
  under a ceiling allowing 2. New ejections now run under a per-pool lock.
- The response cache honors `s-maxage` (it takes precedence over `max-age`)
  and `Vary`: the key now includes the normalized `Accept-Encoding`, so
  `Vary: Accept-Encoding` responses are cached per encoding, and any other
  `Vary` prevents caching. Previously a gzip body could be served to a
  client that had not asked for it.
- A WebSocket handshake could be answered from the cache when a plain `GET`
  for the same URL was stored, so the upgrade never happened. Upgrade
  handshakes now bypass the cache.
- `[listeners.cache] max_total_bytes` is now a hard limit. Concurrent inserts
  could previously overshoot it by up to one entry each.
- **DNS-discovered backends had no circuit breaker, passive health checks,
  outlier detection or per-backend metrics.** These were built once from the
  static backend list, which is empty on a `dns_discovery` listener, so a
  DNS backend that timed out or returned errors was never ejected. They are
  now created for each backend as DNS resolves it, before it can be
  selected, kept for as long as it stays resolved, and removed (including
  its metric series) when it leaves DNS.
- **A config reload returned failing backends to rotation.** Reload rebuilt
  each changed listener's pool with every backend marked healthy. Each
  backend's last health-check verdict is now carried over, a `dns_discovery`
  listener with unchanged discovery settings keeps its resolved backends,
  and a backend newly added by the reload waits for its first probe.

## [0.3.0] - 2026-09-26

### Added

- **ACME automatic certificates** (`[listeners.tls.certificates.acme]`):
  per-certificate issuance and renewal over HTTP-01, with a self-signed
  bootstrap certificate so the listener can serve before the first order
  completes, a retry ladder across an optional fallback and staging
  directory with exponential backoff, and hand-off to the existing
  certificate hot-reloader.
- **`peak_ewma_p2c` load-balancing strategy**: power-of-two-choices over a
  decaying per-backend latency estimate multiplied by in-flight requests,
  so traffic shifts away from slow or overloaded backends without any
  configured weights.
- **Passive health signals** (`health_check.unhealthy_latency_ms`,
  `health_check.unhealthy_request_count`): a slow or over-loaded backend
  trips its circuit breaker even when every response succeeds.
- **Circuit-breaker recovery controls**: `half_open_successes_required`
  (N consecutive successes to close) and flap backoff
  (`flap_backoff_multiplier`, `max_flap_cooldown_ms`,
  `flap_streak_reset_ms`) that lengthens the cooldown for a backend that
  keeps re-tripping.
- **Outlier detection** (`[listeners.health_check.outlier_detection]`):
  ejects a backend whose success rate falls a configurable number of
  standard deviations below its peers'. `health_check.max_ejected_fraction`
  caps how much of a pool circuit trips and outlier ejections may remove at
  once, so a correlated failure cannot empty the pool.
- **Retry budget** (`[listeners.retry_budget]`): a listener-wide GCRA
  bucket that caps retries, preventing retry-driven load amplification
  during a backend outage. New `lb_retry_*` counters record attempts,
  outcomes, budget admits/denials, and skipped non-idempotent retries.
- **`waf.inspect_headers`**: optionally applies the WAF rules to the
  `User-Agent`, `Referer` and `Cookie` headers as well as the path and
  query.
- **`proxy_protocol_timeout_ms`** (default 1000): bounds how long a
  listener waits for a PROXY protocol header.
- **Cluster metrics**: `lb_ratelimit_cluster_convergence_bound` exposes the
  theoretical gossip over-admission bound per listener, and
  `lb_cluster_future_skew_rejections_total{peer}` counts peer counter cells
  dropped for being too far in the future (label bounded to 64 peers plus
  `other`).
- **Evaluation harnesses**: `lb-bench-e2e` (strategy comparison,
  heterogeneous backends, retry amplification, reliability, convergence,
  failure patterns, concurrency signal), `lb-bench-cluster` (gossip
  convergence bound and partition recovery) and `lb-bench-h2-stress`
  (HTTP/2 Rapid Reset). Runs are persisted to
  `results/<timestamp>/{metadata.json,results.csv}`.
- **Windows**: `Ctrl+Break` now triggers graceful shutdown alongside
  `Ctrl+C`.
- **Documentation and project files**: every page under `docs/` rewritten
  against the code, new getting-started, operations, load-balancing and
  HTTP-features guides, a documentation index, `CONTRIBUTING.md`,
  `SECURITY.md`, `CODE_OF_CONDUCT.md`, GitHub issue and pull-request
  templates, Dependabot, and a pinned `stable` toolchain.
- **`[admin] token` / `token_env`**: optional bearer-token access control
  for the entire admin surface -- `/metrics`, `/healthz`, `/ready`, and
  `GET`/`POST /backends`. Checked once, centrally, in
  `lb_metrics::admin::route` (every route passes through it, including the
  `/backends` extension), so no handler needed its own auth logic. Token
  comparison is constant-time (`subtle::ConstantTimeEq`), the same concern
  `lb-cluster`'s gossip HMAC check already guards against. Absent (the
  default): the admin listener stays exactly as unauthenticated as it
  always was, but not silently -- a startup warning is logged and the new
  `lb_admin_auth_disabled` gauge reads `1`, mirroring
  `backend_tls_verification_disabled`'s "logged as a warning and exported
  as a metric" pattern. A rejected request increments the new
  `lb_admin_auth_failures_total` counter. This listener has no TLS of its
  own, so the token is defense in addition to binding privately, not a
  replacement for it -- documented explicitly rather than glossed over.
- **`[[listeners.canary]]` (HTTP listeners)**: weighted traffic-split /
  canary pools -- holds back a percentage of the request volume that
  matched no `[[listeners.routes]]` rule for one or more independently
  health-checked, independently load-balanced pools, each with its own
  `percent` (summing to at most 99, leaving the listener's own backends at
  least 1%). Distinct from a backend's own `weight`, which only biases
  selection *within* one pool. Selection is a deterministic `AtomicUsize`
  cursor mod 100 (no `rand` dependency), not random, for exact convergence
  to the configured split. When `[listeners.sticky]` is also configured, a
  returning client's pinned backend id is checked for pool membership
  *before* rolling the split -- a client whose session already landed in
  the canary pool stays there for the rest of its session instead of
  re-rolling on every request, which is the concrete thing nginx/HAProxy/
  Envoy don't give you for free. New `GET /backends` entries labeled
  `canary:{n} ({percent}%)`.
- **`[listeners.client_tcp_keepalive]` / `[listeners.backend_tcp_keepalive]`**
  (either listener type): `SO_KEEPALIVE`/`TCP_KEEPIDLE`/`TCP_KEEPINTVL`/
  `TCP_KEEPCNT` tuning -- nginx's `so_keepalive`/`proxy_socket_keepalive`,
  HAProxy's `clitcpka`/`srvtcpka`. The client-facing and backend-facing
  socket are tuned independently and both are optional; omitting a section
  leaves that socket at OS defaults, exactly as before this existed.
  Applied to the client socket right at accept time (before PROXY protocol
  or TLS touch it) and to every backend-dial path: the pooled HTTP client
  (via `HttpConnector`'s own native setters), the per-route/per-backend
  client pool, the raw TCP proxy's backend connection, and the WebSocket
  upgrade path's dedicated connection. `time_secs`/`interval_secs`/`retries`
  default to 60/10/6.
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

### Changed

- **Non-idempotent requests are no longer retried.** A failed `POST`,
  `PATCH` or other non-idempotent request now returns the error instead of
  being resent to another backend, so a request is never applied twice.
- **Response cache accounting** now counts the key, every header and a fixed
  per-entry overhead toward `max_total_bytes`, measured against real
  allocations. The same budget therefore holds fewer small entries than
  before, but it now bounds actual memory.
- **`SIGHUP` reload** now refuses changes to `compression`,
  `proxy_protocol`, `write_timeout_ms` and `client_tcp_keepalive`, which it
  previously accepted and silently ignored.
- **Resource bounds**: the backend client keeps at most 32 idle connections
  per host; the gossip peer listener accepts at most 4 concurrent
  connections per peer with a 30s read timeout; a gossip message carries at
  most 5,000 counter entries, rotating through the rest on later rounds; the
  cluster counter store tracks at most 100,000 keys.
- **Performance**: the circuit breaker is lock-free, backend ids are
  interned, per-call allocations were removed from the rate limiter and
  cluster store, the consistent-hash ring is cached between membership
  changes, and backend selection no longer hashes every backend on each
  pick (3-5x faster `pick()` on large pools).

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
- A `SIGHUP` reload now preserves manually drained backends and in-progress
  circuit-breaker state instead of returning every backend to rotation.
- DNS-discovered backends now get real active health checks, and per-backend
  clients for addresses DNS stopped returning are released.
- A stale success no longer cancels an open circuit breaker's cooldown.
- The TCP proxy's idle timeout is now shared across both directions rather
  than tracked per direction.
- Cluster counter merge now tolerates ordinary clock skew between nodes (up
  to 5s) while rejecting further-future cells that could never be pruned.
- Response cache: fixed races that could evict a freshly stored entry or
  corrupt the byte counter under concurrent writes, and HTTP/2 requests are
  now keyed by `:authority`, so two hosts can no longer share an entry.
- A connection guard outliving a backend's removal and re-addition could
  corrupt the new backend's in-flight count; re-resolving an unchanged DNS
  answer no longer invalidates cached balancer state.
- `peak_ewma_p2c` could lose latency updates under concurrent requests, and
  its decay math is hardened against overflow and NaN.
- A client that opened a connection to a `proxy_protocol` listener and sent
  nothing could hold the connection open indefinitely.

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

[Unreleased]: https://github.com/Raunak4518/distributed-load-balancer/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Raunak4518/distributed-load-balancer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Raunak4518/distributed-load-balancer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Raunak4518/distributed-load-balancer/releases/tag/v0.1.0
