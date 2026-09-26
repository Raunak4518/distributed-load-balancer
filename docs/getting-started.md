# Getting Started

This walks through building the load balancer, pointing it at two throwaway HTTP backends, and watching it balance traffic, expose metrics, and react to a backend going down. It should take about ten minutes.

## 1. Prerequisites

- A **stable** Rust toolchain. The repository pins the `stable` channel via `rust-toolchain.toml` (with the `rustfmt` and `clippy` components); no minimum version is declared beyond that, so whatever `stable` resolves to on your machine will build it.
- `python3` (or `python` on Windows) to stand up two disposable backends — any HTTP server works, this just avoids installing one.
- `curl`.

## 2. Build, or install a release artifact

From the repository root:

```sh
cargo build --release -p lb-server
```

This produces `target/release/lb-server` (`lb-server.exe` on Windows). Apart from `--check-config`, `--version` and `--help`, the binary takes a single argument: the config path.

If you'd rather not build from source, packaged artifacts (`.deb`, `.rpm`, and a systemd unit) are produced in CI — see [operations.md](operations.md) for the full list and how to install one.

## 3. Load-balance two backends

### Start two backends

Each backend needs to answer `GET /health` with a `2xx` status — that's what the active health checker requires (anything else counts as unhealthy) — and it helps to make each one distinguishable so you can see the load balancer alternate between them. Create two small directories and serve each with Python's built-in HTTP server:

```sh
mkdir -p /tmp/backend1 /tmp/backend2
touch /tmp/backend1/health /tmp/backend2/health
echo "web1" > /tmp/backend1/index.html
echo "web2" > /tmp/backend2/index.html

(cd /tmp/backend1 && python3 -m http.server 9001) &
(cd /tmp/backend2 && python3 -m http.server 9002) &
```

(On Windows PowerShell, run each `python -m http.server` in its own window instead of backgrounding with `&`.)

### Write a config

Save this as `getting-started.toml`. Every field here is read by `crates/lb-core/src/config.rs`; the ones without a default in that file — `[[listeners]]` itself, each backend's `id`/`address`, `health_check.path`/`interval_ms`/`timeout_ms`/`failure_threshold`/`cooldown_ms`, and all of `[listeners.rate_limit]` (`key`, `rate_per_sec`, `burst`) and `[listeners.load_balancing]` (`strategy`) — are mandatory; a config missing any of them is rejected before the process ever binds a socket.

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

This is `examples/http-basic.toml` plus an `[admin]` section, needed for step 4 below. `rate_limit` and `load_balancing` are their own mandatory sections (not optional extras) — the parser rejects the file without them.

### Validate, then run

```sh
./target/release/lb-server --check-config getting-started.toml
```

prints `getting-started.toml: valid` and exits 0 if the file parses and passes validation, or a description of what's wrong on stderr with a non-zero exit otherwise — nothing is bound either way. Then run it for real:

```sh
./target/release/lb-server getting-started.toml
```

(With no argument at all, `lb-server` looks for `config.toml` in the current directory — passing the path explicitly avoids relying on that.)

### Send requests

```sh
for i in 1 2 3 4; do curl -s http://127.0.0.1:8080/; done
```

You should see the response body alternate `web1`, `web2`, `web1`, `web2` — `round_robin` cycling through both backends in the order they're declared.

## 4. Admin endpoints

The `[admin]` section above binds a second, unauthenticated listener at `127.0.0.1:9090` serving metrics and health/backend-status routes (`crates/lb-metrics/src/admin.rs`, extended by `crates/lb-server/src/admin_backends.rs`). It is deliberately separate from the traffic listener and exposes internal topology — never bind it to a public interface, and see `admin.token`/`admin.token_env` for adding a bearer token.

```sh
curl http://127.0.0.1:9090/metrics   # Prometheus exposition format
curl http://127.0.0.1:9090/ready     # 200 "ready" if at least one backend is eligible, else 503
curl http://127.0.0.1:9090/backends  # JSON: every listener's backends and their live state
```

`GET /backends` returns something like:

```json
{
  "web": [
    {"id": "web1", "route": "default", "address": "127.0.0.1:9001", "active_healthy": true, "circuit_open": false, "manually_drained": false, "eligible": true, "active_conns": 0},
    {"id": "web2", "route": "default", "address": "127.0.0.1:9002", "active_healthy": true, "circuit_open": false, "manually_drained": false, "eligible": true, "active_conns": 0}
  ]
}
```

The full metric catalog is in [metrics-reference.md](metrics-reference.md).

## 5. Stop a backend and watch health checking react

Stop the `web2` process (`Ctrl+C` its terminal, or `kill` it). The active health checker probes each backend's `health_check.path` on `interval_ms` (2000ms here); a single failed probe (connection refused counts) immediately flips that backend's health flag — there's no threshold delay on the active check itself, unlike the passive circuit breaker's `failure_threshold`, which governs a different signal (forwarded-request outcomes, not probe results). Within a couple of seconds:

- The `lb_backend_healthy{listener="web",backend="web2"}` gauge in `/metrics` drops from `1` to `0`.
- `GET /backends` shows `web2` with `"active_healthy": false` and `"eligible": false`.
- Repeating the `curl` loop from step 3 now returns `web1` every time — `web2` is out of rotation without any config change.

Restart the `web2` python process and both flip back within one health-check interval.

## 6. Edit the config and reload

Change `rate_per_sec` (or add a third backend) in `getting-started.toml`, then reload without restarting:

```sh
kill -HUP <pid-of-lb-server>
```

The process re-reads the file and applies the change to the affected listener in place. This only works on Unix (Linux/macOS) — `SIGHUP` handling is compiled in under `#[cfg(unix)]`; on other platforms the reload task is a no-op and you'll need to restart the process instead. Not everything is reloadable: changing a listener's `protocol`/`listen` address, or anything under `[server]`, `[admin]`, `[cluster]`, `[logging]`, `[tracing]`, `tls`, `backend_tls`, `http2`, or the per-listener connection-limit/timeout settings, is refused with a clear log message rather than silently applied — those require a restart.

## 7. Next steps

Other example configs in `examples/`, each runnable the same way as above:

- [`examples/http-basic.toml`](../examples/http-basic.toml) — the minimal HTTP listener this page is based on: two backends, round-robin.
- [`examples/tcp-passthrough.toml`](../examples/tcp-passthrough.toml) — an L4 (raw TCP) listener load-balancing a non-HTTP service (e.g. Postgres); health checking is a plain TCP connect, no `path`.
- [`examples/tls-backend-reencrypt.toml`](../examples/tls-backend-reencrypt.toml) — terminates TLS at the edge and re-encrypts to the backends over TLS with `server_name`-based verification.
- [`examples/dns-discovery.toml`](../examples/dns-discovery.toml) — backends resolved from a DNS name on a poll interval instead of a static list.
- [`examples/cluster-node1.toml`](../examples/cluster-node1.toml) and [`examples/cluster-node2.toml`](../examples/cluster-node2.toml) — a two-node pair sharing rate-limit state over an authenticated gossip channel (`[cluster]`, `LB_CLUSTER_SECRET`).

Further reading:

- [configuration-reference.md](configuration-reference.md) — every config field, exhaustively.
- [architecture.md](architecture.md) — how the pieces fit together.
- [request-lifecycle.md](request-lifecycle.md) — what happens to one request end to end.
- [load-balancing.md](load-balancing.md) — the five strategies, routes, canary pools, sticky sessions and DNS discovery.
- [health-checking.md](health-checking.md) — active checks, the circuit breaker, and outlier detection.
- [rate-limiting.md](rate-limiting.md) — per-key limits and cross-node coordination.
- [cluster-coordination.md](cluster-coordination.md) — the gossip protocol behind `[cluster]`.
- [tls.md](tls.md) — edge termination and backend re-encryption in depth.
- [edge-hardening.md](edge-hardening.md) — connection limits, timeouts, HTTP/2 abuse limits, PROXY protocol, the WAF, the admin token.
- [http-features.md](http-features.md) — HTTP/2, header handling, response caching, compression, WebSocket.
- [metrics-reference.md](metrics-reference.md) — every exported metric.
- [operations.md](operations.md) — deployment, packaging, and running this in production.
- [benchmarks.md](benchmarks.md) — measured throughput and latency.
