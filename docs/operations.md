# Operations

This page covers running `lb-server` in production: how it is packaged and deployed, its command-line interface and exit codes, how configuration reload and graceful shutdown behave, the admin API surface, logging and trace export, and where to look when something goes wrong. For the config file format itself see [`configuration-reference.md`](configuration-reference.md); for the metric catalog see [`metrics-reference.md`](metrics-reference.md).

## Deployment

### Release artifacts

[`release.yml`](../.github/workflows/release.yml) runs on every `v*` tag push and produces, per release:

- Static binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (built with `cross`), and for `aarch64-apple-darwin` / `x86_64-apple-darwin` (built natively on `macos-14`). Each is packaged as `lb-server-<target>.tar.gz` containing the single `lb-server` binary.
- `.deb` and `.rpm` packages, built with `cargo-deb` and `cargo-generate-rpm` from the metadata in [`crates/lb-server/Cargo.toml`](../crates/lb-server/Cargo.toml).
- A multi-arch (`linux/amd64`, `linux/arm64`) container image pushed to `ghcr.io/<owner>/<repo>` (lowercased), tagged with the semver tag and `latest`.
- A GitHub Release collecting all of the above (`softprops/action-gh-release`), with auto-generated release notes.

The `.deb`/`.rpm` packages both install the same three files: the `lb-server` binary to `/usr/bin/lb-server`, the systemd unit to `/lib/systemd/system/lb-server.service` (`.deb`) or `/usr/lib/systemd/system/lb-server.service` (`.rpm`), and `config.example.toml` to `/etc/lb-server/config.toml` (marked as a conffile on the `.deb`, so a reinstall does not clobber a locally edited config). Neither package ships a maintainer script that creates a system user — the systemd unit below runs as `User=lb-server`/`Group=lb-server`, which the operator must create before starting the service: `useradd --system --no-create-home --shell /usr/sbin/nologin lb-server`.

### Docker image

The [`Dockerfile`](../Dockerfile) is a two-stage build: `rust:1-slim-bookworm` compiles `lb-server` in release mode, and the runtime stage is `debian:bookworm-slim` with only `ca-certificates` added. The binary runs as an unprivileged, home-less system user (`lb`), from a working directory of `/etc/lb-server`. `config.example.toml` is baked in at `/etc/lb-server/config.toml`; the entrypoint is `lb-server` and the default command argument is `config.toml` (relative to that working directory), so a real deployment overrides the config by mounting a volume over `/etc/lb-server/config.toml` (or the whole directory, for TLS certificates alongside it) rather than passing a different command-line argument. The image declares no `EXPOSE` and no named volume — listener ports and any TLS/cert paths are whatever the mounted config says, and must be published/mounted explicitly on `docker run`.

### systemd unit

[`packaging/systemd/lb-server.service`](../packaging/systemd/lb-server.service) is a `Type=simple` unit:

- `ExecStartPre` runs `lb-server --check-config /etc/lb-server/config.toml`, so a broken config fails the unit before the old process is ever stopped (see `Restart=on-failure` below — a failed `ExecStartPre` counts as a failed start).
- `ExecReload=/bin/kill -HUP $MAINPID` — `systemctl reload lb-server` sends `SIGHUP`, triggering the hot-reload path described below; it does not restart the process.
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the unprivileged `lb-server` user bind ports below 1024 without running as root.
- Hardening: `NoNewPrivileges=true`, `ProtectSystem=strict` (the whole filesystem read-only except explicitly listed paths), `ProtectHome=true`, `PrivateTmp=true`, and `ReadOnlyPaths=/etc/lb-server` (belt-and-suspenders on top of `ProtectSystem=strict` for the config directory specifically).
- `Restart=on-failure` with `RestartSec=2`.

Because the unit hardcodes `/etc/lb-server/config.toml`, that is where a config lives on a systemd-managed host; TLS certificate files referenced from it must also be readable under whatever `ProtectSystem=strict` permits (typically `/etc/lb-server/...` alongside the config, or a path added via a drop-in `ReadOnlyPaths=`).

### Manual install

[`scripts/install.sh`](../scripts/install.sh) downloads the release tarball for the running OS/architecture (Linux musl or macOS, `x86_64`/`aarch64`) from the latest (or `$VERSION`-pinned) GitHub release and installs the single binary to `$INSTALL_DIR` (default `/usr/local/bin`). It does not install the systemd unit or a config file — pair it with a config of your own and, on Linux, the unit above if you want it supervised.

## Command-line interface

`lb-server` takes at most one positional argument or one recognized flag, per [`main.rs`](../crates/lb-server/src/main.rs):

| Invocation | Behavior |
|---|---|
| `lb-server [CONFIG_PATH]` | Loads `CONFIG_PATH` (default `config.toml` in the working directory), initializes logging/tracing from it, and runs until a shutdown signal. |
| `lb-server --check-config CONFIG_PATH` | Parses and validates `CONFIG_PATH` and exits without binding anything. Prints `<path>: valid` on success. |
| `lb-server --version` / `-V` | Prints `lb-server <version>` and exits. |
| `lb-server --help` / `-h` | Prints usage and exits. |
| Anything else (unrecognized flags, more than one argument) | Prints the same usage text as `--help`. |

Exit codes are not finer-grained than success/failure: `0` for `--version`, `--help`, an unrecognized invocation (it falls back to help rather than erroring), a successful `--check-config`, or a clean shutdown; a non-zero code for a config that fails to load or validate, a tracing/logging initializer that fails to build (e.g. an unreachable OTLP endpoint at construction time), or [`run`](../crates/lb-server/src/lib.rs) returning an I/O error — most commonly a listener, cluster, or admin port that failed to bind. A config or tracing-init failure is reported on stderr (there is no subscriber yet to log through); a startup bind failure is logged through whatever subscriber did get built, naming the specific listener.

## Configuration reload (SIGHUP)

Sending `SIGHUP` (`systemctl reload lb-server`, or `kill -HUP <pid>` directly) re-reads the config file passed on the command line and applies whatever changed, without dropping a single in-flight connection on an unaffected listener. This is Unix-only — `SIGHUP` does not exist on Windows, and no reload path is spawned there. It is also only spawned when `lb-server` was started with a config *path* (not applicable to library embedders that construct a `Config` in memory).

The logic lives in [`reload.rs`](../crates/lb-server/src/reload.rs)'s `apply_reload`, and follows one rule: validate everything a change would touch before touching anything, and apply all-or-nothing. A reload that would be partially applied is treated as worse than one that is refused outright.

**Refused outright, with no listener touched**, if any of the following changed:

- `[server]`, `[admin]`, `[cluster]`, `[logging]`, or `[tracing]` — process-wide sections with no live-swappable state to reload into.
- Adding, removing, or re-addressing a listener (a changed `protocol` or `listen` for an existing name, or a new/removed listener name).
- On an existing listener: `tls`, `backend_tls`, `http2`, `max_connections`, `max_connections_per_ip`, `header_read_timeout_ms`, `write_timeout_ms`, `compression`, `proxy_protocol`, `proxy_protocol_timeout_ms`, or `client_tcp_keepalive`. These are read by the accept loop itself (`ListenerRuntime`) rather than through the swappable per-listener context, so changing them needs a restart. TLS certificate *content* is the exception: it already reloads on its own schedule, independent of `SIGHUP` — see [`tls.md`](tls.md).
- A listener's backend connector failing to build for the *new* config (e.g. an invalid `backend_tls` setting resolved at reload time) — refused before anything is swapped, still serving the previous config.

Refusal is reported only as a `tracing::error!` log line naming the reason (e.g. `"[cluster] changed -- requires a restart"` or `"listener '<name>': ... -- requires a restart"`); there is no admin-API surface for reload status, and the process keeps running under the old config.

**Applied live**, per changed listener: `backends`, `dns_discovery`, `health_check`, `rate_limit`, `load_balancing`, routes, canary pools, and other fields not in the restart-only list above. Applying rebuilds that one listener's context (backend pool, health checker, rate limiter, etc.), spawns its new background tasks, atomically swaps the `ArcSwap` the accept loop reads from, and aborts the listener's *old* background tasks — connections already being served keep running against the snapshot they loaded at accept time; only the *next* connection sees the new context. Listeners not named in the diff are never touched. If the new config is byte-for-byte identical to the running one, the reload is reported as applied with an empty changed-listener list.

State that survives a reload of the *same* listener, because it lives in structures the reload never rebuilds unless the field feeding them changed: a backend's manual drain (set via the admin API, see below) and a circuit breaker's open/cooldown state both survive an unrelated field's reload on the same listener.

Concurrent `SIGHUP`s (or a `SIGHUP` racing a second one before the first finishes) are safe: the stored config and the live per-listener state are updated together under one lock, so two overlapping reloads never leave the config that a later reload will diff against disagreeing with what is actually running.

## Graceful shutdown

`SIGTERM` or `SIGINT` (Ctrl-C) on Unix, or `Ctrl-C`/`Ctrl-Break` on Windows, trigger shutdown ([`shutdown.rs`](../crates/lb-server/src/shutdown.rs)). One shutdown signal fans out to every listener's accept loop via a `tokio::sync::watch` channel ([`lib.rs`](../crates/lb-server/src/lib.rs)):

1. Each listener stops calling `accept()` — the OS backlog absorbs a few more inbound connection attempts and then itself refuses further ones; no explicit `close()` races the drain.
2. Connections already accepted keep running exactly as before (no forced `Connection: close` or HTTP/2 `GOAWAY` is sent) until they finish on their own or the listener's drain deadline elapses.
3. Each listener waits up to `[server].drain_timeout_ms` (default `10000`, i.e. 10s) for its own connections to finish, independently of every other listener.
4. Any connection still running when that deadline passes is aborted; a request in flight on it sees the connection drop rather than a response.
5. Once every listener has drained (or timed out), cluster peer tasks, the admin server, TLS cert reloaders, and the `SIGHUP` reloader are aborted, and the process exits.

## Admin API

The admin API is entirely optional: it only exists when `[admin]` is configured, and binds to its own `listen` address — deliberately separate from every traffic listener, since it exposes internal topology (backend addresses, health, in-flight counts) and must not face the public internet. Serving is [`lb_metrics::admin`](../crates/lb-metrics/src/admin.rs); the `/backends` routes are implemented in [`admin_backends.rs`](../crates/lb-server/src/admin_backends.rs) as an extension point, since `lb-metrics` itself knows nothing of `BackendPool`.

If `[admin].token` or `[admin].token_env` is set, every route below requires `Authorization: Bearer <token>`, checked with a constant-time comparison; a missing or wrong token gets `401 Unauthorized` with a `WWW-Authenticate: Bearer` header. If neither is set, the admin listener is unauthenticated (a startup warning is logged, and the `lb_admin_auth_disabled` gauge — see [`metrics-reference.md`](metrics-reference.md) — is set to `1`).

| Method & path | Purpose |
|---|---|
| `GET /metrics` | Prometheus text exposition of every metric. |
| `GET /healthz` | Liveness: always `200 OK` if the admin server is answering at all. Deliberately independent of backend health — a failing liveness probe restarts the *process*, and restarting cannot fix an unhealthy backend, so coupling them would turn a partial outage into a crash loop. |
| `GET /ready` | Readiness: `200 OK` if at least one listener has at least one eligible backend to forward to, else `503 Service Unavailable` with body `no eligible backend`. An instance with every backend down leaves rotation (fails readiness) but stays alive, since restarting it cannot bring the backends back. |
| `GET /backends` | JSON: every listener, each with its pools (`default`, `route:<n> (...)`, `canary:<n> (<percent>%)`), each backend's `id`, `address`, `active_healthy`, `circuit_open`, `manually_drained`, `eligible`, and `active_conns`. |
| `POST /backends/{listener}/{backend_id}/drain` | Marks a backend manually drained: it drops out of `eligible_backends()` for new traffic, without touching in-flight connections and without needing a config change (a manual drain is distinct from the health checker's own `active_healthy`, so a passing health probe cannot silently undo it). |
| `POST /backends/{listener}/{backend_id}/undrain` | Reverses the above. |

Any other path is `404 Not Found`, as is a `POST` to `/backends/...` naming an unknown `listener` or `backend_id`.

```bash
# Liveness / readiness
curl http://127.0.0.1:9090/healthz
curl -i http://127.0.0.1:9090/ready

# Metrics scrape
curl http://127.0.0.1:9090/metrics

# Inspect backend state (with an admin token configured)
curl -H "Authorization: Bearer $LB_ADMIN_TOKEN" http://127.0.0.1:9090/backends

# Drain / undrain a backend ahead of a deploy
curl -X POST -H "Authorization: Bearer $LB_ADMIN_TOKEN" \
  http://127.0.0.1:9090/backends/web/web1/drain
curl -X POST -H "Authorization: Bearer $LB_ADMIN_TOKEN" \
  http://127.0.0.1:9090/backends/web/web1/undrain
```

## Logging and tracing

### Logging

Set up once at startup from `[logging]`, by [`lb_tracing::init`](../crates/lb-tracing/src/lib.rs) — a config that fails to build here is fatal (reported on stderr, since no subscriber exists yet to log through). Level filtering is `tracing-subscriber`'s `EnvFilter`, read from the process environment (`RUST_LOG`, e.g. `RUST_LOG=lb_proxy=debug,info`); with no filter set it defaults to `info`.

```toml
[logging]
format      = "json"   # or "pretty"; defaults to "json"
log_requests = false    # per-request access logging; off by default (see below)
sample_rate  = 0.01     # fraction of access-logged requests actually emitted, 0.0-1.0
```

`log_requests` gates per-request access logging separately from the `RUST_LOG` level filter — it defaults to `false` because at high request rates one line per request is a capacity decision, not just a verbosity preference. When enabled, `sample_rate` (default `0.01`) further thins those log lines with a deterministic 1-in-N counter, computed once at startup from the configured rate — not a per-request floating point roll.

Changing `[logging]` requires a restart; it is one of the sections `SIGHUP` refuses (see above).

### OpenTelemetry tracing

Spans are created unconditionally by the data-plane code (`http_request`, with `request_id`, `method`, `path` fields, per HTTP request in [`lb-proxy`](../crates/lb-proxy/src/service.rs); `tcp_session`, with a `peer` field, per TCP session in [`lb-tcp`](../crates/lb-tcp/src/session.rs)) — that cost is what `tracing` is designed to make cheap when nothing is subscribed. Whether anything is actually exported is controlled entirely by `[tracing]`, which is optional and off by default:

```toml
[tracing]
otlp_endpoint = "http://localhost:4318"   # OTLP/HTTP collector; plain http:// is expected
service_name  = "lb-server"                # defaults to "lb-server" if omitted
sample_ratio  = 1.0                         # fraction of traces sampled, 0.0-1.0
```

Export is OTLP over plain HTTP (not HTTPS) via a minimal hand-rolled blocking client ([`http.rs`](../crates/lb-tracing/src/http.rs)), used because the batch span processor runs its exporter on its own OS thread rather than inside the Tokio runtime. This scopes `otlp_endpoint` to a same-trust-domain collector (a local agent or sidecar); front a remote collector with your own TLS-terminating proxy if you need encryption in transit. Exports are bounded by a 5-second send timeout. `TracingGuard::shutdown` (called from [`main.rs`](../crates/lb-server/src/main.rs) after `run()` returns) flushes any buffered span batch before the process exits — OTel's exporters do not flush on `Drop`, so skipping this would silently drop the last batch. Changing `[tracing]` also requires a restart.

## Capacity and tuning

Per-listener connection and timeout limits (`max_connections`, `max_connections_per_ip`, `header_read_timeout_ms`, `write_timeout_ms`, HTTP/2 stream limits, and the rest of the hardening surface) are covered in [`edge-hardening.md`](edge-hardening.md), including which of them require a restart to change (the same restart-only list as the reload section above). For throughput/latency numbers under load and how to reproduce them, see [`benchmarks.md`](benchmarks.md).

## Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Client sees `503`, body `no eligible backend` | Every backend on that route/listener is unhealthy, circuit-open, or manually drained | `GET /backends` for that listener's `eligible`/`active_healthy`/`circuit_open`/`manually_drained` fields; `GET /ready` will also be `503` |
| Client sees `429` | Local (`GCRA`) or cluster-wide rate limit exceeded for that key | `lb_ratelimit_rejected_total{listener,layer="local"|"cluster"}` in `/metrics` (see [`metrics-reference.md`](metrics-reference.md)); a local-limit denial carries a `Retry-After` header, a cluster-limit denial does not |
| Cluster nodes report peer-sync errors / counts look wrong across nodes | Peer HMAC authentication failing (mismatched shared secret), or a peer mTLS handshake failing | `warn`-level log lines `rejected an unauthenticated peer message` or `peer tls handshake failed`, naming the peer; see [`cluster-coordination.md`](cluster-coordination.md) |
| Peer-sync updates from one node are being silently dropped | That peer's clock is far enough ahead to exceed the future-skew tolerance | `lb_cluster_future_skew_rejections_total{peer}` |
| TLS certificate file was updated on disk but the listener keeps serving the old one | The reloader polls file `mtime`+size on an interval (`[listeners.tls].reload_interval_secs`, default 60s) and only swaps if both the load succeeds *and* something changed; a failed load (mismatched key, malformed PEM) is refused and the previous certificate keeps serving | `lb_tls_certificate_reloads_total{listener,outcome="rejected"}` and the accompanying `tracing::error!` log line naming the reason; see [`tls.md`](tls.md) |
| `SIGHUP` was sent but nothing changed | The diff touched a restart-only field or a process-wide section (`[server]`/`[admin]`/`[cluster]`/`[logging]`/`[tracing]`, a listener's `tls`/`http2`/connection limits/etc., or a listener being added/removed/re-addressed) | The `tracing::error!("reload refused...")` log line naming exactly what changed — there is no admin-API reload status |
| Admin API returns `401` for every request | No or wrong bearer token presented, or `[admin].token`/`token_env` misconfigured | `lb_admin_auth_failures_total`; check which of `token`/`token_env` is set, and that the variable named by `token_env` is present in the service's environment (for systemd, via `Environment=` or `EnvironmentFile=`) |
| Admin port is reachable by anyone, unauthenticated, and that is not intended | `[admin]` has neither `token` nor `token_env` set | The startup `tracing::warn!` line and `lb_admin_auth_disabled` in `/metrics` (see [`metrics-reference.md`](metrics-reference.md)) |
| Config reload log never appears at all | `SIGHUP` reload is Unix-only, or the process was started without a config *path* (e.g. embedded) | Platform (no-op on Windows by design); confirm the process was started as `lb-server <path>`, not with an in-memory config |
