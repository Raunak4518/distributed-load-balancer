# Metrics Reference

The load balancer exposes Prometheus metrics on the admin port at `GET /metrics`.

## Request Metrics

### `lb_requests_total` (Counter)
Total requests handled.
- **Labels:**
  - `listener`: The listener name.
  - `protocol`: `"h2"`, `"http/1.1"`, or `"tcp"`.
  - `status`: `"2xx"`, `"3xx"`, `"4xx"`, `"5xx"`, or `"unknown"`.

### `lb_request_duration_seconds` (Histogram)
End-to-end request latency as seen by the client.
- **Labels:** `listener`
- **Buckets:** Dense in the millisecond to low-second range to accurately capture tail latency.

### `lb_active_connections` (Gauge)
Currently open client connections.
- **Labels:** `listener`

### `lb_connections_total` (Counter)
Total client connections accepted.
- **Labels:** `listener`

### `lb_connections_rejected_total` (Counter)
Connections rejected before protocol handling.
- **Labels:**
  - `listener`: The listener name.
  - `reason`: `"max_connections"` (global cap) or `"per_ip"` (source IP cap).

### `lb_request_timeouts_total` (Counter)
Requests that timed out.
- **Labels:**
  - `listener`: The listener name.
  - `phase`: `"header"` (slowloris) or `"body"` (slow sender).

## Rate Limiting Metrics

### `lb_ratelimit_rejected_total` (Counter)
Requests rejected by rate limiting.
- **Labels:**
  - `listener`: The listener name.
  - `layer`: `"local"` (GCRA burst limit) or `"cluster"` (global G-Counter limit).

### `lb_ratelimit_tracked_keys` (Gauge)
Number of distinct keys currently tracked by the local GCRA.
- **Labels:** `listener`

## Backend and Health Metrics

### `lb_backend_healthy` (Gauge)
Active health probe status. `1` for healthy, `0` for unhealthy.
- **Labels:**
  - `listener`: The listener name.
  - `backend`: The backend ID.

### `lb_backend_circuit_state` (Gauge)
The current state of the circuit breaker.
- `0`: Closed (normal operation).
- `1`: Open (failing, excluded).
- `2`: HalfOpen (testing recovery).
- **Labels:** `listener`, `backend`.

### `lb_backend_requests_total` (Counter)
Outcomes of forward attempts to a specific backend.
- **Labels:**
  - `listener`: The listener name.
  - `backend`: The backend ID.
  - `result`: `"success"`, `"failure"` (connect error), or `"timeout"`.

### `lb_upstream_duration_seconds` (Histogram)
Latency of backend responses.
- **Labels:** `listener`, `backend`.

## TLS Metrics

### `lb_tls_handshakes_total` (Counter)
Outcomes of inbound TLS handshakes.
- **Labels:**
  - `listener`: The listener name.
  - `result`: `"success"`, `"failed"` (client error), or `"timeout"`.

### `lb_tls_handshake_duration_seconds` (Histogram)
Time taken to complete inbound TLS handshakes.
- **Labels:** `listener`

### `lb_tls_certificate_reloads_total` (Counter)
Outcomes of the certificate hot-reload task.
- **Labels:**
  - `listener`: The listener name.
  - `result`: `"success"`, `"unchanged"`, or `"error"`.

### `lb_tls_certificate_expiry_timestamp_seconds` (Gauge)
The Unix timestamp when the active certificate expires. Alert when this drops below a safe threshold.
- **Labels:** `listener`

### `lb_backend_tls_verification_disabled` (Gauge)
Set to `1` if `danger_accept_invalid_certs` is enabled for the listener.
- **Labels:** `listener`

## Cluster Metrics

### `lb_cluster_peer_sync_total` (Counter)
Number of gossip rounds executed.
- **Labels:**
  - `direction`: `"tx"` (sent) or `"rx"` (received).
  - `result`: `"success"`, `"error"`, `"auth_failure"`, or `"own_node_id"`.

### `lb_cluster_tracked_keys` (Gauge)
Number of distinct keys currently tracked in the sliding window.
