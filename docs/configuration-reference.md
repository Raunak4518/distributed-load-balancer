# Configuration Reference

All configuration lives in a single TOML file. The configuration is fully validated at startup. If any constraint is violated, the load balancer exits with an error.

## `[server]`

Global server settings.

- `drain_timeout_ms` (integer, default: 10000): The maximum time to wait for in-flight requests to finish when shutting down. Connections exceeding this deadline are forcefully aborted.

## `[logging]`

- `format` (string, default: "pretty"): Output format. `"pretty"` for human-readable ANSI output, `"json"` for structured logging.
- `log_requests` (boolean, default: false): Emits an access log entry for every handled request.
- `sample_rate` (float, default: 1.0): The fraction of requests to log when `log_requests` is enabled. Uses deterministic 1-in-N sampling rather than per-request random rolls.

## `[admin]`

The private listener for observability and health checks.

- `listen` (string, required): The bind address (e.g., `"127.0.0.1:9090"`).

Exposes:
- `GET /metrics`: Prometheus metrics.
- `GET /healthz`: Always 200 OK. Liveness.
- `GET /ready`: 200 OK if any backend in any pool is eligible, 503 otherwise. Readiness.

## `[[listeners]]`

Defines an entry point. You can configure multiple listeners by repeating this block.

- `name` (string, required): A unique identifier for the listener. Used in metrics labels and log context.
- `protocol` (string, required): `"http"` or `"tcp"`.
- `listen` (string, required): The bind address (e.g., `"0.0.0.0:443"`).
- `max_connections` (integer, default: 8192): Global concurrent connection cap.
- `max_connections_per_ip` (integer, default: 64): Concurrent connection cap per source IP.
- `header_read_timeout_ms` (integer, default: 5000): HTTP/1.1 slowloris defense. Max time to read request headers.
- `forward_timeout_ms` (integer, default: 30000): Max time to wait for a backend response (HTTP only).
- `max_request_body_bytes` (integer, default: 10485760): Request body size limit (HTTP only).
- `body_read_timeout_ms` (integer, default: 30000): Max time a client can take to send the body (HTTP only).
- `idle_timeout_ms` (integer, default: 60000): Max time a TCP session can remain idle before being closed (TCP only).
- `connect_timeout_ms` (integer, default: 2000): Max time to establish a TCP connection to a backend (TCP only).

## `[listeners.tls]`

Enables edge TLS termination.

- `certificates` (array of objects, required): The certificates to load. Each object must have `cert_file` and `key_file`.
- `handshake_timeout_ms` (integer, default: 5000): Max time to complete the TLS handshake.
- `hsts_max_age_secs` (integer, default: 0): Adds `Strict-Transport-Security: max-age=<seconds>` to HTTP responses. Must be 0 for TCP listeners.
- `reload_interval_secs` (integer, default: 3600): Interval for checking certificate files for modifications.

## `[listeners.backend_tls]`

Enables re-encryption to backends. Every backend in this listener must configure a `server_name`.

- `ca_file` (string, optional): Path to a custom CA bundle. If omitted, the system native root store is used.
- `danger_accept_invalid_certs` (boolean, default: false): Disables certificate verification. Emits a warning at startup.

## `[listeners.http2]`

HTTP/2 connection settings.

- `enabled` (boolean, default: true): Advertises `h2` in ALPN negotiation.
- `max_concurrent_streams` (integer, default: 128): Stream limit per connection.
- `max_pending_accept_reset_streams` (integer, default: 20): HTTP/2 Rapid Reset mitigation. Matches h2's own built-in bound: a looser value would be inert, and a tighter one starts cutting clients that cancel streams legitimately.
- `max_local_error_reset_streams` (integer, default: 128): Limits server-initiated resets.
- `max_header_list_size` (integer, default: 16384): Bounds HPACK state.
- `max_frame_size` (integer, default: 16384): Max frame payload.
- `keep_alive_interval_secs` (integer, default: 20): Interval for HTTP/2 PING frames.
- `keep_alive_timeout_secs` (integer, default: 10): Timeout for HTTP/2 PING responses.
- `backend_h2c` (boolean, default: false): Enables prior-knowledge HTTP/2 to plaintext backends.

## `[[listeners.backends]]`

Defines a backend for the listener.

- `id` (string, required): A unique identifier for the backend. Used in metrics.
- `address` (string, required): IP and port (e.g., `"10.0.0.1:8080"`).
- `weight` (integer, default: 1): Relative weight for load balancing.
- `server_name` (string, conditional): The hostname expected on the backend's certificate. Required if the listener configures `[listeners.backend_tls]`.

## `[listeners.health_check]`

- `path` (string, conditional): The GET path for HTTP probes. Required for HTTP listeners, invalid for TCP listeners.
- `interval_ms` (integer, required): Time between health probes.
- `timeout_ms` (integer, required): Per-probe timeout.
- `failure_threshold` (integer, required): Consecutive failures before the circuit opens.
- `cooldown_ms` (integer, required): Time the circuit remains open before a test request is allowed.

## `[listeners.rate_limit]`

- `key` (string or object, required): `"source_ip"` or `{ header = "Header-Name" }`.
- `rate_per_sec` (float, required): Sustained requests per second.
- `burst` (integer, required): Max burst capacity.
- `max_tracked_keys` (integer, default: 100000): Cap on unique keys tracked in memory.

## `[listeners.load_balancing]`

- `strategy` (string, required): Must be `"round_robin"`.

## `[cluster]`

Configures distributed rate limiting.

- `node_id` (string, required): Unique identifier for this node.
- `listen` (string, required): Bind address for the peer gossip port.
- `peers` (array of strings, required): List of peer addresses to push to.
- `window_secs` (integer, required): Sliding window width for aggregation.
- `secret` (string or object, required): Pre-shared HMAC key. Either inline `"secret"` or `{ file = "path/to/key" }`.
- `sync_interval_ms` (integer, default: 500): Interval for gossip pushes.
