# Configuration Reference

The load balancer reads a single TOML file, given as the first CLI argument, and validates it completely at startup: any violated constraint aborts the process before it binds a socket, rather than failing later at request time. This page documents every field the binary's config parser (`Config`, in [`config.rs`](../crates/lb-core/src/config.rs)) accepts, the validation rules `Config::validate()`/`ListenerConfig::validate()` enforce, and which fields apply on a SIGHUP reload versus which require a restart. For what each field actually *does* at runtime, see the linked sibling pages; this page only covers name, type, default, and validation.

Field names below are exact TOML keys, in the order their struct declares them. "Default" is the value used when the key is omitted; "required" means parsing fails (missing-field error) if the key is absent and no default exists.

## Top-level structure

```
[server]
[[listeners]]
  [listeners.tls]
    [[listeners.tls.certificates]]
      [listeners.tls.certificates.acme]
  [listeners.backend_tls]
  [listeners.http2]
  [listeners.dns_discovery]
  [[listeners.backends]]
  [listeners.health_check]
    [listeners.health_check.outlier_detection]
  [listeners.rate_limit]
  [listeners.load_balancing]
  [[listeners.routes]]
  [[listeners.canary]]
  [listeners.sticky]
  [listeners.cache]
  [listeners.waf]
  [listeners.retry_budget]
  [listeners.client_tcp_keepalive]
  [listeners.backend_tcp_keepalive]
[cluster]
  [cluster.tls]
[admin]
[logging]
[tracing]
```

`listeners` is the only field with no default at the top level — at least one entry is required. `cluster`, `admin`, and `tracing` are entirely absent by default: no cluster coordination, no admin/metrics listener, no trace export. An unknown key anywhere in the file is a startup error that names the key, so a typo such as `max_conections` is caught by `lb-server --check-config` rather than silently falling back to the default.

## `[server]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `drain_timeout_ms` | integer | `10000` | none | Maximum time to wait for in-flight requests to finish during graceful shutdown before connections are forcefully aborted. |

## `[[listeners]]`

One entry per entry point; repeat the table for multiple listeners.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `name` | string | required | must be unique across all listeners | Identifier used in metrics labels and logs. |
| `protocol` | string | required | `"http"` or `"tcp"` | Selects the L7 (HTTP) or L4 (TCP) data plane for this listener. |
| `listen` | socket address | required | must be unique across all listeners; must not collide with `cluster.listen` or `admin.listen` | Bind address, e.g. `"0.0.0.0:8080"`. |
| `forward_timeout_ms` | integer | `5000` | HTTP-only (must be unset on TCP) | Max time to wait for a backend response. |
| `max_request_body_bytes` | integer | `1048576` (1 MiB) | HTTP-only | Request body size cap. |
| `write_timeout_ms` | integer | `30000` | must be > 0; HTTP-only (must be unset on TCP) | Max time a client may take to read the response before the connection is dropped. |
| `websocket_idle_timeout_ms` | integer | `300000` (300s) | HTTP-only | Idle timeout applied to a connection after it upgrades (e.g. WebSocket); request-shaped timeouts stop applying once the upgrade completes. |
| `compression` | boolean | `false` | HTTP-only (must be `false`/unset on TCP) | Enables negotiated gzip/brotli/deflate/zstd response compression. |
| `connect_timeout_ms` | integer | `2000` | TCP-only (must be unset on HTTP) | Max time to establish the backend TCP connection. |
| `idle_timeout_ms` | integer | `300000` (300s) | TCP-only (must be unset on HTTP) | Max time a TCP session may sit idle before being closed. |
| `max_connections` | integer | `10000` | must be > 0; must be ≥ `max_connections_per_ip` | Global concurrent connection cap for this listener. |
| `max_connections_per_ip` | integer | `100` | must be > 0; must be ≤ `max_connections` | Concurrent connection cap per source IP. |
| `header_read_timeout_ms` | integer | `5000` | must be > 0 | Max time to read the request head (HTTP/1.1 slowloris defense); on HTTP/2 the same value also bounds time-to-first-byte before the `h2` preface arrives. Restart-only. |
| `body_read_timeout_ms` | integer | `10000` | must be > 0 | Max time a client may take to send the request body. |
| `proxy_protocol` | boolean | `false` | applies to both protocols | Reads the real client address from a PROXY protocol v1/v2 header instead of the raw TCP peer; a connection with a missing/malformed header is dropped. Restart-only. |
| `proxy_protocol_timeout_ms` | integer | `1000` | must be > 0 | Max time to wait for the PROXY protocol header. Restart-only. |
| `client_tcp_keepalive` | table | none | see [`TcpKeepaliveConfig`](#listenersclient_tcp_keepalive--listenersbackend_tcp_keepalive) | TCP keepalive tuning for the client-facing socket. Restart-only. |
| `backend_tcp_keepalive` | table | none | see below | TCP keepalive tuning for the socket dialed to a backend. |
| `tls` | table | none | see [`[listeners.tls]`](#listenerstls) | Enables edge TLS termination. Restart-only. |
| `backend_tls` | table | none | see [`[listeners.backend_tls]`](#listenersbackend_tls) | Enables re-encryption to backends. Restart-only. |
| `http2` | table | none | HTTP-only | HTTP/2 connection settings. Restart-only. |
| `dns_discovery` | table | none | mutually exclusive with `backends` | Resolves the backend set from a DNS name instead of a static list. |
| `backends` | array of tables | `[]` | exactly one of `backends`/`dns_discovery` must be set; ids unique across this listener's `backends` + every `routes[].backends` + every `canary[].backends` | Static backend list. |
| `health_check` | table | required | see [`[listeners.health_check]`](#listenershealth_check) | Active/passive health-check and circuit-breaker configuration. |
| `rate_limit` | table | required | see [`[listeners.rate_limit]`](#listenersrate_limit) | Per-listener rate limiting. |
| `load_balancing` | table | required | see [`[listeners.load_balancing]`](#listenersload_balancing) | Backend-selection strategy. |
| `routes` | array of tables | `[]` | HTTP-only (must be empty on TCP) | Path-/`Host`-based routing to alternate backend pools. Evaluated in declaration order, first match wins. |
| `canary` | array of tables | `[]` | HTTP-only (must be empty on TCP); sum of `percent` ≤ 99 | Percentage-based traffic splitting to alternate pools, evaluated for requests that matched no route. |
| `sticky` | table | none | HTTP-only | Cookie-based session affinity layered on top of `load_balancing.strategy`. |
| `cache` | table | none | HTTP-only | In-memory response cache for `GET` `200` responses. |
| `waf` | table | none | HTTP-only | Built-in request-pattern blocking/logging. |
| `retry_budget` | table | none | HTTP-only | Token-bucket cap on retried requests. |

`http2_enabled()` — whether HTTP/2 is actually served — is `protocol == "http" && tls is set && (http2.enabled != false)`; a plaintext listener never serves HTTP/2 regardless of `http2.enabled`, because ALPN only exists inside a TLS handshake ([`config.rs`](../crates/lb-core/src/config.rs)). See [load-balancing.md](load-balancing.md) for routes/canary/sticky behavior, [http-features.md](http-features.md) for cache/compression/WebSocket behavior, [edge-hardening.md](edge-hardening.md) for connection limits, PROXY protocol and the WAF, and [request-lifecycle.md](request-lifecycle.md) for how the timeouts above compose.

## `[listeners.tls]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `certificates` | array of tables | required | non-empty | Certificates this listener presents; see below. |
| `handshake_timeout_ms` | integer | `5000` | none | Max time to complete the TLS handshake. |
| `min_version` | string | `"1.2"` | `"1.2"` or `"1.3"` | Minimum negotiated TLS version. |
| `reload_interval_secs` | integer | `60` | none | Interval at which certificate files are checked for changes and reloaded. |
| `hsts_max_age_secs` | integer | `0` | must be `0` on a TCP listener | Adds `Strict-Transport-Security: max-age=<seconds>`; `0` (the default) omits the header. |

### `[[listeners.tls.certificates]]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `name` | string | required | none | Identifier used in metrics. |
| `cert_file` | path | required | none | Certificate chain file. |
| `key_file` | path | required | none | Private key file. |
| `hostnames` | array of strings | `[]` | if `acme` is set, exactly one hostname | SNI hostnames this certificate serves. |
| `acme` | table | none | see below | Automated certificate issuance/renewal for this certificate. |

### `[listeners.tls.certificates.acme]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `directory_url` | string | required | must not be empty | ACME directory endpoint. |
| `contact_email` | string | required | must not be empty | Contact email registered with the ACME account. |
| `account_key_file` | path | required | none | ACME account private key. |
| `renew_before_days` | integer | `30` | none | Renew when fewer than this many days remain before expiry. |
| `check_interval_secs` | integer | `43200` (12h) | none | Interval between renewal checks. |
| `ca_bundle_file` | path | none | none | Custom CA bundle for validating the ACME server's own certificate. |
| `fallback_directory_url` | string | none | must not be empty if set | Secondary ACME directory tried if the primary fails. |
| `staging_directory_url` | string | none | must not be empty if set | Staging directory, typically used for testing issuance without production rate limits. |

See [tls.md](tls.md) for certificate selection (SNI matching against `hostnames`), reload behavior, and the ACME issuance flow.

## `[listeners.backend_tls]`

Enables re-encryption to backends. Every backend the listener dials must then set `server_name`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `ca_file` | path | none (system trust store) | none | Custom CA bundle for verifying backend certificates. |
| `danger_accept_invalid_certs` | boolean | `false` | none | Disables backend certificate verification entirely. |

Validation tied to `backend_tls` (enforced regardless of which of `dns_discovery`/`backends` supplies the backend set):
- If `dns_discovery` is set, `dns_discovery.server_name` is required, must not be an IP literal, and must form a valid authority with `dns_discovery.port`.
- Every static backend needs `server_name` set; it must not be an IP literal, and `server_name:address.port()` must form a valid authority.
- On an HTTP listener only, two backends in the listener's own `backends` list must not share the same `server_name` (it collapses both onto one dial target and silently defeats load balancing); this uniqueness check does not extend to `routes[].backends` or `canary[].backends`. A TCP listener has no such restriction, since each TCP connection dials its backend's `address` directly with no shared name→address table.

See [tls.md](tls.md) for why `server_name` — not the certificate's `address` — is checked, and for `PinnedResolver`'s role.

## `[listeners.http2]`

HTTP-only; rejected if present on a TCP listener. Every field is optional; see [`http2.rs`](../crates/lb-core/src/http2.rs) for the security rationale behind each default.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `enabled` | boolean | `true` | none | Whether this listener advertises `h2` over ALPN (still requires `tls` to be set at all). |
| `max_concurrent_streams` | integer | `128` | must be > 0 | Concurrent streams allowed per connection. |
| `max_pending_accept_reset_streams` | integer | `20` | none | Rapid Reset (CVE-2023-44487) mitigation — matches `h2`'s own built-in bound. |
| `max_local_error_reset_streams` | integer | `128` | none | Limits server-initiated stream resets. |
| `max_header_list_size` | integer | `16384` | none | Bounds HPACK/`CONTINUATION` expansion. |
| `max_frame_size` | integer | `16384` | none | Max HTTP/2 frame payload size. |
| `keep_alive_interval_secs` | integer | `20` | none | Interval between HTTP/2 PING liveness frames. |
| `keep_alive_timeout_secs` | integer | `10` | none | Time to wait for a PING response before the connection is considered dead. |
| `backend_h2c` | boolean | `false` | cannot be combined with `backend_tls` (TLS backends negotiate `h2` over ALPN automatically) | Prior-knowledge HTTP/2 to plaintext backends. |

## `[listeners.dns_discovery]`

Mutually exclusive with `backends` — a listener's backend set comes from exactly one source. See [`dns.rs`](../crates/lb-core/src/dns.rs).

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `name` | string | required | must not be empty | DNS name to resolve for the backend set. |
| `port` | integer | required | must be > 0 | Port applied to every resolved address. |
| `poll_interval_secs` | integer | `10` | none | Interval between re-resolutions. |
| `server_name` | string | none | required (and validated, see above) if `backend_tls` is set | Hostname expected on the resolved backends' certificates. |

## `[[listeners.backends]]`

Also applies, with the identical shape, to `[[listeners.routes.backends]]` and `[[listeners.canary.backends]]`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `id` | string | required | unique per listener (across default/route/canary backends) | Backend identifier used in metrics and circuit-breaker/pool state. |
| `address` | socket address | required | none | Backend's IP and port. |
| `weight` | integer | `1` | none | Relative weight; consulted only by `weighted_round_robin` and `consistent_hash` (as virtual-node count). |
| `server_name` | string | none | required if `backend_tls` is set; see validation above | Hostname on the backend's certificate. |

## `[listeners.health_check]`

Also applies, with the identical shape, to `[listeners.routes.health_check]` and `[listeners.canary.health_check]`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `path` | string | none | required on HTTP listeners; must be unset on TCP listeners | GET path for active HTTP probes. |
| `interval_ms` | integer | required | none | Time between health probes. |
| `timeout_ms` | integer | required | none | Per-probe timeout. |
| `failure_threshold` | integer | required | none | Consecutive failures before the circuit breaker opens. |
| `cooldown_ms` | integer | required | none | Time the circuit stays open before a half-open probe is allowed. |
| `half_open_successes_required` | integer | `1` | none | Consecutive successes required in half-open state before the circuit closes. |
| `flap_backoff_multiplier` | float | `1.0` | must be ≥ 1.0 | Multiplies cooldown on each re-trip within `flap_streak_reset_ms`, up to `max_flap_cooldown_ms`. `1.0` disables growth. |
| `max_flap_cooldown_ms` | integer | `u64::MAX` (unbounded) | none | Ceiling on the flap-scaled cooldown. |
| `flap_streak_reset_ms` | integer | `60000` | none | How long a backend must stay closed before its next trip starts a new flap streak. |
| `unhealthy_latency_ms` | integer | none | must be > 0 if set | Response time above which a successful request still counts as a passive circuit-breaker failure. |
| `unhealthy_request_count` | integer | none | must be > 0 if set | In-flight request count above which the next completed request counts as a passive failure, regardless of its own latency/status. |
| `outlier_detection` | table | none | see below | Enables rolling statistical comparison of backends within the pool. |
| `max_ejected_fraction` | float | none | must be within `[0.0, 1.0]` if set | Caps the fraction of a pool's backends that may be excluded at once by circuit trips and outlier ejections combined. |

### `[listeners.health_check.outlier_detection]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `min_volume` | integer | `20` | must be > 0 | Minimum recorded outcomes a backend needs since the last round to be judged. |
| `min_hosts` | integer | `3` | must be ≥ 2 | Minimum backends meeting `min_volume` before detection activates for a round. |
| `stddev_factor` | float | `1.9` | must be > 0.0 | Standard deviations below the pool's mean success rate that mark a backend as an outlier. |

See [health-checking.md](health-checking.md) for circuit-breaker state transitions, flap backoff, and outlier detection/ejection mechanics.

## `[listeners.rate_limit]`

Also applies, with the identical shape, per-listener only (routes and canary pools do not have their own `rate_limit` — they share the listener's).

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `key` | string | required | `"source_ip"` or `"header:<name>"`; `"header:..."` is rejected on TCP listeners | Rate-limit bucket key. |
| `rate_per_sec` | float | required | must be > 0.0 | Sustained request rate per key. |
| `burst` | integer | required | must be > 0 | Burst capacity (token bucket size) per key. |
| `max_tracked_keys` | integer | `100000` | must be > 0 | Cap on distinct keys tracked; beyond this, new keys share one overflow budget. |

See [rate-limiting.md](rate-limiting.md) for the token-bucket algorithm and cluster-wide aggregation.

## `[listeners.load_balancing]`

Also applies, with the identical shape, to `[listeners.routes.load_balancing]` and `[listeners.canary.load_balancing]`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `strategy` | string | required | one of the five values below | Backend-selection algorithm. |

`strategy` values: `"round_robin"`, `"least_connections"`, `"weighted_round_robin"`, `"consistent_hash"`, `"peak_ewma_p2c"`. See [load-balancing.md](load-balancing.md) for the selection logic of each, including how `consistent_hash` uses `rate_limit.key` as its hash input and how `peak_ewma_p2c` combines decaying latency with pending-request count.

## `[[listeners.routes]]`

HTTP-only. Evaluated in declaration order; the first rule whose `path_prefix`/`host` match wins. A request matching no rule falls through to the listener's own `backends`/`health_check`/`load_balancing`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `path_prefix` | string | none (matches every path) | matched as a path *segment* prefix (`"/api"` matches `/api` and `/api/x`, not `/apiary`) | Path condition for this route. |
| `host` | string | none (matches every host) | case-insensitive exact match against the `Host` header | Host condition for this route. |
| `backends` | array of tables | `[]` | must be non-empty | Backend pool for this route. |
| `health_check` | table | required | `path` required; same nested rules as the listener's own `health_check` | Health check for this route's pool. |
| `load_balancing` | table | required | none | Strategy for this route's pool. |

A route does not have its own `dns_discovery` or `backend_tls` — it shares the listener's TLS/client policy and differs only in backends/health-check/strategy.

## `[[listeners.canary]]`

HTTP-only. Evaluated after `routes`, for requests that matched no route.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `percent` | integer | required | `1`–`99`; sum across all canary entries ≤ 99 | Absolute share of the listener's total request volume routed to this pool. |
| `backends` | array of tables | `[]` | must be non-empty | Backend pool for this canary entry. |
| `health_check` | table | required | `path` required; same nested rules as the listener's own `health_check` | Health check for this pool. |
| `load_balancing` | table | required | none | Strategy used *within* this pool (independent of `percent`, which routes traffic *to* it). |

## `[listeners.sticky]`

HTTP-only.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `cookie_name` | string | `"lb_sticky"` | none | Name of the cookie naming the pinned backend id (unsigned — backend ids are not secret). |
| `max_age_secs` | integer | none (session cookie) | none | If set, refreshed on every response; if unset, the cookie has no `Max-Age`/`Expires`. |

## `[listeners.cache]`

HTTP-only. Only `GET` requests with a `200` response and a declared `Content-Length` are ever cached.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `max_entry_bytes` | integer | `2097152` (2 MiB) | none | Responses larger than this (by `Content-Length`) are served but never cached. |
| `max_total_bytes` | integer | `67108864` (64 MiB) | none | Aggregate cache budget for this listener; once full, new entries are not admitted until something expires. |
| `default_ttl_secs` | integer | `60` | none | TTL used when the backend response has no usable `Cache-Control: max-age`. |

## `[listeners.waf]`

HTTP-only. A small, fixed, built-in pattern check — not a configurable rule engine.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `mode` | string | `"block"` | `"block"` or `"log"` | `block` returns `403` on a match; `log` records the match and forwards the request unmodified. |
| `inspect_headers` | boolean | `false` | none | Also inspects header values, not just path/query. |

## `[listeners.retry_budget]`

HTTP-only.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `rate_per_sec` | float | required | must be > 0.0 | Sustained retry rate allowed for this listener. |
| `burst` | integer | required | must be > 0 | Burst capacity for retries. |

## `[listeners.client_tcp_keepalive]` / `[listeners.backend_tcp_keepalive]`

Applies to both protocols. `client_tcp_keepalive` tunes the socket accepted from clients; `backend_tcp_keepalive` tunes the socket dialed to a backend — independently, since the two connections have different idle characteristics.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `time_secs` | integer | `60` | none | Idle time before the first keepalive probe (`TCP_KEEPIDLE`). |
| `interval_secs` | integer | `10` | none | Time between probes once started (`TCP_KEEPINTVL`). |
| `retries` | integer | `6` | none | Unanswered probes before the connection is considered dead (`TCP_KEEPCNT`). |

Omitting the table entirely (the default for both) leaves `SO_KEEPALIVE` untouched — OS defaults, not "keepalive off."

## `[cluster]`

Absent by default: no peer listener, no coordination — single-node behavior. See [cluster-coordination.md](cluster-coordination.md) for the gossip protocol this configures.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `node_id` | string | required | must not be empty (after trimming) | This node's identifier in gossip messages. |
| `listen` | socket address | required | must not collide with any listener's `listen` or with `admin.listen` | Bind address for the peer gossip port. |
| `peers` | array of socket addresses | `[]` | must not contain this node's own `listen` address | Other nodes' gossip addresses. |
| `sync_interval_ms` | integer | `200` | must be > 0 | Interval between gossip pushes. |
| `window_secs` | integer | `10` | must be > 0 | Sliding window width for aggregated counters. |
| `shared_secret_env` | string | none | exactly one of `shared_secret_env`/`shared_secret` required; named env var must be set and non-empty | Environment variable holding the HMAC pre-shared secret. |
| `shared_secret` | string | none | exactly one of `shared_secret_env`/`shared_secret` required; must not be empty | Literal HMAC pre-shared secret (config files are not meant to hold this in production). |
| `tls` | table | none | see below | Mutual TLS for the peer channel; absent means HMAC-authenticated but unencrypted. |

Unlike `admin`'s token, exactly one of `shared_secret_env`/`shared_secret` is *mandatory* once `[cluster]` is present — the peer port influences rate-limiting decisions, so leaving it unauthenticated is a denial-of-service vector.

### `[cluster.tls]`

Every node presents the same certificate/key to every peer (gossip is symmetric). Peer identity is verified via standard WebPKI chain validation against `ca_file`.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `cert_file` | path | required | none | This node's certificate, presented to every peer. |
| `key_file` | path | required | none | This node's private key. |
| `ca_file` | path | required | none | CA used to verify peers' certificates; every peer must use the same signing CA. |
| `handshake_timeout_ms` | integer | `5000` | none | Max time to complete the peer TLS handshake. |

## `[admin]`

Absent by default: no metrics/health endpoints at all. See [operations.md](operations.md) for the endpoints exposed and [metrics-reference.md](metrics-reference.md) for what `/metrics` reports.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `listen` | socket address | required | must not collide with any listener's `listen` or with `cluster.listen` | Bind address for the admin/metrics listener. Bind privately — this surface exposes internal topology. |
| `token_env` | string | none | at most one of `token_env`/`token`; named env var must be set and non-empty | Environment variable holding the admin bearer token. |
| `token` | string | none | at most one of `token_env`/`token`; must not be empty | Literal bearer token. |

Unlike `cluster`'s secret, leaving *both* `token_env` and `token` unset is valid — it means the admin listener stays unauthenticated, preserving pre-existing behavior for configs that never set either.

## `[logging]`

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `format` | string | `"json"` | `"json"` or `"pretty"` | Log output format. |
| `log_requests` | boolean | `false` | none | Emits an access-log line per handled request. Off by default: at high request rates this is a capacity decision, not a preference. |
| `sample_rate` | float | `0.01` | must be within `[0.0, 1.0]` | Fraction of requests logged when `log_requests` is enabled. |

## `[tracing]`

Absent by default: spans are still created internally but nothing exports them.

| Field | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `otlp_endpoint` | string | required | must not be empty | OTLP/HTTP collector endpoint (e.g. `http://localhost:4318`); plain `http://` is deliberately supported, not just `https://`. |
| `service_name` | string | none | none | Service name attached to exported spans. |
| `sample_ratio` | float | `1.0` | must be within `[0.0, 1.0]` | Fraction of traces sampled. |

## Validation rules

`Config::parse()` calls `Config::validate()`, which runs every check below before the process binds anything. A single violation aborts startup with a message naming the offending listener/field; nothing is partially applied.

**Global**
- At least one `[[listeners]]` entry is required.
- Listener `name` values must be unique; listener `listen` addresses must be unique.
- `cluster.node_id` (if `[cluster]` is present) must not be empty, `sync_interval_ms` and `window_secs` must be positive, `peers` must not contain the node's own `listen`, `cluster.listen` must not collide with any listener's `listen`, and exactly one of `shared_secret_env`/`shared_secret` must be set.
- `admin.listen` (if `[admin]` is present) must not collide with any listener's `listen` or with `cluster.listen`; at most one of `token_env`/`token` may be set.
- `logging.sample_rate` must be within `[0.0, 1.0]`.
- `tracing.otlp_endpoint` (if `[tracing]` is present) must not be empty, and `sample_ratio` must be within `[0.0, 1.0]`.

**Per listener (both protocols)**
- Exactly one of `backends`/`dns_discovery` supplies the backend set; if `dns_discovery`, its `name` must be non-empty and `port` positive.
- Backend `id` values must be unique across the listener's own `backends`, every `routes[].backends`, and every `canary[].backends`.
- `rate_limit.rate_per_sec` and `.burst` must be positive; `.max_tracked_keys` must be positive.
- `retry_budget.rate_per_sec`/`.burst` (if set) must be positive.
- `health_check.flap_backoff_multiplier` must be ≥ 1.0; `unhealthy_latency_ms`/`unhealthy_request_count` must be positive if set; `outlier_detection` (if set) requires `min_volume > 0`, `min_hosts >= 2`, `stddev_factor > 0.0`; `max_ejected_fraction` (if set) must be within `[0.0, 1.0]`.
- `max_connections`/`max_connections_per_ip` must both be positive, and the per-IP cap must not exceed the global cap.
- `header_read_timeout_ms`, `body_read_timeout_ms`, `write_timeout_ms`, and `proxy_protocol_timeout_ms` must all be positive.

**HTTP listeners only**
- `health_check.path` is required.
- `connect_timeout_ms`/`idle_timeout_ms` (TCP-only fields) must be unset.
- Every route needs a non-empty `backends` and a `health_check.path`; the same `flap_backoff_multiplier`/`unhealthy_*`/`outlier_detection`/`max_ejected_fraction` rules apply per route.
- Every canary pool needs a non-empty `backends`, a `health_check.path`, the same health-check sub-rules, `percent` within `1..=99`, and the sum of every pool's `percent` must be at most 99.

**TCP listeners only**
- `health_check.path` must be unset (nothing to probe with a path).
- `forward_timeout_ms`, `max_request_body_bytes`, `write_timeout_ms`, `websocket_idle_timeout_ms`, `compression`, `routes`, `canary`, `sticky`, `cache`, `waf`, and `retry_budget` must all be unset/empty/false — each is HTTP-only.
- `rate_limit.key` must not be `"header:..."` — a TCP listener has no headers to read.

**`backend_tls` (either protocol, when set)**
- If `dns_discovery` is used, its `server_name` is required, must not be an IP literal, and must combine with `port` into a valid authority.
- Every static backend needs `server_name`, which must not be an IP literal and must combine with the backend's port into a valid authority.
- On HTTP listeners, no two backends in the listener's own `backends` list may share a `server_name`.

**`tls` (when set)**
- `hsts_max_age_secs` must be `0` on a TCP listener.
- `certificates` must be non-empty.
- A certificate with `acme` set must have exactly one `hostnames` entry, and `acme.directory_url`/`contact_email` must be non-empty (`fallback_directory_url`/`staging_directory_url` must be non-empty if set).

**`http2` (when set)**
- Rejected outright on a TCP listener.
- `max_concurrent_streams` must be positive.
- `backend_h2c` cannot be combined with `backend_tls`.

## Reload behavior

Sending `SIGHUP` (Unix only — there is no equivalent signal path on Windows) reloads the config file in place. [`reload.rs`](../crates/lb-server/src/reload.rs) validates the entire new file, diffs it against the running config, and either applies exactly the listeners that changed or refuses the whole reload with no partial effect.

**Always refused, regardless of what else changed:**
- Any change to `[server]`, `[admin]`, `[cluster]` (including `[cluster.tls]`), `[logging]`, or `[tracing]` — these are process-wide with no live-swappable state.
- Adding or removing a listener, or changing a listener's `protocol` or `listen` address — new bind/unbind lifecycle is not supported live.
- On any listener whose identity is unchanged, a change to: `tls`, `backend_tls`, `http2`, `max_connections`, `max_connections_per_ip`, `header_read_timeout_ms`, `write_timeout_ms`, `compression`, `proxy_protocol`, `proxy_protocol_timeout_ms`, or `client_tcp_keepalive`. These live on the listener's accept-loop runtime, not the swappable per-request context, so changing any of them refuses the entire reload with a message naming the listener.

**Applies live (no restart) once the fields above are unchanged:** everything else on a listener — `backends`, `dns_discovery`, `health_check` (including `outlier_detection`), `rate_limit`, `load_balancing`, `routes`, `canary`, `sticky`, `cache`, `waf`, `retry_budget`, `forward_timeout_ms`, `max_request_body_bytes`, `body_read_timeout_ms`, `websocket_idle_timeout_ms`, `connect_timeout_ms`, `idle_timeout_ms`, and `backend_tcp_keepalive`. A changed listener is rebuilt (new backend pool, new circuit breakers only for genuinely new backends, new compiled routes/canary pools) and atomically swapped in; live state that survives an unrelated field's reload includes manually-drained backends and open circuit breakers — only listeners whose config actually differs are rebuilt at all. TLS certificate *content* (the files on disk) reloads independently on its own periodic schedule (`reload_interval_secs`), unrelated to SIGHUP.

A reload that fails to parse, fails validation, or touches a restart-only field changes nothing and logs the reason; the process keeps serving the previous config.

## Minimal example

```toml
[[listeners]]
name = "web"
protocol = "http"
listen = "0.0.0.0:8080"

  [[listeners.backends]]
  id = "web1"
  address = "127.0.0.1:9001"

  [listeners.health_check]
  path = "/health"
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
```

This is the smallest config the parser accepts: one HTTP listener, one backend, and the three tables (`health_check`, `rate_limit`, `load_balancing`) that have no defaults. See [`config.example.toml`](../config.example.toml) for an annotated, fully-populated reference covering every section on this page, and [`examples/`](../examples/) for runnable configs (`http-basic.toml`, `tcp-passthrough.toml`, `tls-backend-reencrypt.toml`, `dns-discovery.toml`, `cluster-node1.toml`/`cluster-node2.toml`). For a walkthrough of running one of these, see [getting-started.md](getting-started.md).
