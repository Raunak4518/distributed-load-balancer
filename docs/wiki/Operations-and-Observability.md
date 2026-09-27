# Operations and Observability

Operating the load balancer requires understanding how it exposes its internal state, how it handles configuration changes, and how it shuts down.

## Prometheus Metrics

The system exposes a Prometheus-compatible metrics endpoint (by default at `0.0.0.0:9090/metrics`).

### Key Metrics
- `lb_requests_total{listener="http-main", status="200"}`: A counter of finished requests.
- `lb_request_duration_seconds{listener="http-main"}`: A histogram of request latencies.
- `lb_active_connections{listener="tcp-db"}`: A gauge tracking currently connected clients.
- `lb_rate_limit_rejections_total`: A counter of requests dropped due to GCRA limits.
- `lb_circuit_breaker_trips_total{backend="10.0.0.5"}`: A counter incrementing each time a backend circuit trips to Open.

Because Prometheus metrics are pulled, not pushed, the `lb-metrics` crate maintains these as atomic counters in memory.

## Healthz and Ready Endpoints

The metrics server also exposes two probe endpoints for Kubernetes (or other orchestrators):
- `GET /healthz`: Always returns `200 OK`. Indicates the process is running.
- `GET /ready`: Returns `200 OK` if the proxy has finished its initial startup (bound to ports, loaded certificates).

## Graceful Shutdown

When the binary receives a `SIGINT` (Ctrl-C) or `SIGTERM` (from Kubernetes), it initiates a graceful shutdown sequence.

1. **Stop Accepting:** The listener loops stop accepting new sockets.
2. **Drain Connections:** Existing HTTP and TCP tasks are given a grace period (e.g., 30 seconds) to finish their inflight work.
3. **Terminate:** If tasks do not complete within the grace period, the Tokio runtime is forcefully shut down, dropping all remaining sockets.

This logic is implemented in `lb-server/src/signal.rs` using a `tokio::sync::watch` channel broadcast to all spawned tasks.

## Troubleshooting Guide

### Symptom: `429 Too Many Requests`
- **Cause:** The client exceeded the GCRA limit.
- **Action:** Check `lb_rate_limit_rejections_total`. If it's cluster-wide, check the gossip logs to ensure CRDTs are synchronizing.

### Symptom: TCP connections dropped instantly
- **Cause:** TCP rate limiting drops sockets because there is no L4 equivalent to a 429 response. Alternatively, the global or IP connection limit was hit.
- **Action:** Check the `lb_active_connections` gauge.

### Symptom: Backend marked unhealthy but it's alive
- **Cause:** The active health check failed. If `backend_tls` is enabled, verify the backend's certificate has not expired and matches the `sni_override`. The health checker uses the exact same TLS configuration as the request path.
- **Action:** Read the proxy logs. Health check failures emit `WARN` logs with the specific `hyper` or `rustls` error.

### Symptom: Certificate not reloading
- **Cause:** The background reloader relies on the filesystem modification timestamp (`mtime`). If you overwrote the file in a way that preserved the old `mtime`, the reloader will ignore it.
- **Action:** `touch cert.pem`.
