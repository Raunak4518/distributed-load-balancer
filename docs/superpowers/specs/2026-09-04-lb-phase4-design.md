# Distributed Load Balancer — Phase 4 Design (Measurement & Safety Net)

**Date:** 2026-09-04
**Status:** Approved for implementation planning
**Builds on:** Phases 1–3 (L7 HTTP, L4 TCP, multi-node coordination), all shipped.
**Scope:** Observability, health endpoints, CI, and a benchmark baseline. No behaviour changes to the data plane.

## 1. Why This Phase Is First

The project is now targeting **edge-facing production traffic at 50k+ req/s under a strict SLA**. Two hard dependencies fall out of that, and both belong here:

1. **You cannot tune what you cannot measure.** Phase 7 will fix specific hot-path costs (per-request allocations, contended mutexes). Doing that work without a baseline is guesswork, and "optimisations" that are actually regressions are the normal outcome of guessing.
2. **You cannot safely ship changes to critical-path infrastructure without a test gate.** There is currently no CI. Every subsequent phase modifies code that all production traffic flows through.

There is also an operational floor to clear: today, diagnosing a running instance means reading `eprintln!` on stderr. That is not an operable system, regardless of how correct the logic is.

**This phase deliberately changes no data-plane behaviour.** It adds the instruments. That separation is intentional — it means any behavioural change observed after this phase came from a later phase, not from the act of measuring.

## 2. Metrics (Prometheus)

### 2.1 The exposition surface lives on a separate admin listener

`/metrics`, `/healthz` and `/ready` are served from a **dedicated admin listener**, never from a traffic listener.

This is a security decision, and the same reasoning as the Phase 3 peer port: at the edge, the traffic listener faces the public internet, and metrics leak internal topology — backend identifiers, backend health, cluster peer names, traffic volumes. Serving them on the public port would hand an attacker a map. **The admin listener must be bound to a private interface**, and this is documented rather than assumed.

```toml
[admin]
listen = "127.0.0.1:9090"
```

Omitting `[admin]` disables metrics and health endpoints entirely (and is the default), so Phases 1–3 behaviour is unchanged when the section is absent.

### 2.2 Metric set

Named per Prometheus conventions (`_total` for counters, base units, no units in label values).

**Traffic (RED: rate, errors, duration)**
| Metric | Type | Labels |
|---|---|---|
| `lb_requests_total` | counter | `listener`, `protocol`, `status` |
| `lb_request_duration_seconds` | histogram | `listener` |
| `lb_active_connections` | gauge | `listener` |
| `lb_connections_total` | counter | `listener` |

**Rate limiting**
| Metric | Type | Labels |
|---|---|---|
| `lb_ratelimit_rejected_total` | counter | `listener`, `layer` |

`layer` is `local` or `cluster`. Separating them is not cosmetic: it answers "is this node's own limiter rejecting, or is the cluster budget exhausted?" — two very different operational situations with different fixes.

**Backends**
| Metric | Type | Labels |
|---|---|---|
| `lb_backend_healthy` | gauge | `listener`, `backend` |
| `lb_backend_requests_total` | counter | `listener`, `backend`, `outcome` |
| `lb_upstream_duration_seconds` | histogram | `listener`, `backend` |
| `lb_backend_circuit_state` | gauge | `listener`, `backend` |

`outcome` is `success`/`failure`/`timeout`; `circuit_state` is `0`=closed, `1`=open, `2`=half-open.

**Cluster**
| Metric | Type | Labels |
|---|---|---|
| `lb_cluster_peer_sync_total` | counter | `peer`, `outcome` |
| `lb_cluster_tracked_keys` | gauge | — |

`lb_cluster_tracked_keys` exists specifically to make rate-limit key cardinality observable. That is the memory-growth risk in the design, and Phase 5 will bound it — you want the graph before you set the limit.

### 2.3 Label cardinality is a hard constraint

**No client-controlled value may ever become a label.** Not client IP, not API key, not request path, not `Host`. Every label above is drawn from config (listener names, backend ids, peer addresses) and is therefore bounded by deployment size.

This is the single most common way teams take down their own monitoring: an unbounded label turns one metric into millions of time series and kills Prometheus. Since this LB rate-limits *by client IP*, the temptation to label by it is real and specific — so the rule is stated here, and the implementation must not offer a way to do it.

### 2.4 Metric recording must not become the bottleneck

At 50k req/s, instrumentation sits on the hot path. Counters and gauges must be atomic operations, never mutex-guarded; label lookups must be resolved **once at wiring time** into concrete metric handles stored alongside each listener's context, not looked up by string on every request. Recording a request must cost a handful of atomic increments and one histogram observation.

## 3. Structured Logging

`tracing` + `tracing-subscriber` with a JSON formatter, level controlled by `RUST_LOG`. All existing `eprintln!` calls are replaced.

**Per-request access logging is off by default.** At 50k req/s, logging every request is 50,000 lines/second — hundreds of gigabytes a day, and enough I/O to affect latency. This is a real production trap, so the default is off and the configuration is explicit about cost:

```toml
[logging]
format         = "json"    # or "pretty" for local development
log_requests   = false
sample_rate    = 0.01      # fraction of requests logged when log_requests = true
```

**Request IDs:** each request gets a generated id, attached to its tracing span and returned in an `X-Request-Id` response header so a user-reported failure can be traced to a log line. An inbound `X-Request-Id` is **not trusted or propagated by default** — at the edge it is attacker-controlled and could be used to forge or collide log entries. Accepting upstream ids is a later, opt-in concern for when something trusted sits in front.

Errors and lifecycle events (startup, shutdown, config problems, backend health transitions, circuit-breaker trips, peer sync failures) are always logged regardless of the request-logging setting. Those are low-volume and high-value.

## 4. Health Endpoints

Two endpoints with genuinely different meanings — conflating them is a common and damaging mistake:

- **`/healthz` (liveness)** — "is this process functioning?" Returns 200 whenever the server is running with its listeners bound. It deliberately **does not** consider backend health. Liveness failure causes an orchestrator to *kill and restart* the process, and restarting a load balancer cannot fix an unhealthy backend — it would turn a partial outage into a crash loop.
- **`/ready` (readiness)** — "should this instance receive traffic?" Returns 200 only if at least one backend is eligible on at least one listener; 503 otherwise. Readiness failure removes the instance from rotation *without* killing it, which is the correct response to having nowhere to forward.

Both are plain, unauthenticated, and cheap — they are on the private admin listener.

## 5. Continuous Integration

GitHub Actions on push and pull request:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings`
3. `cargo test --workspace --features lb-core/test-util`

Cargo registry and build artifacts are cached to keep runs fast. The three commands mirror exactly what has been run by hand at the end of every phase so far; CI makes that gate automatic rather than dependent on discipline.

## 6. Benchmark Baseline

Two complementary layers, because they answer different questions.

### 6.1 Micro-benchmarks (`criterion`)

Targeted at precisely the four hot-path costs identified in the current code, so Phase 7 can prove its fixes rather than assert them:

- `BackendPool::eligible_backends()` — allocates a `Vec` and clones every `BackendId` (each holding a `String`) on every pick.
- `Gcra::check()` — `key.to_string()` allocation per call.
- `ListenerCoordinator::try_admit()` — `format!()` allocation per call.
- The circuit-breaker refresh loop — two mutex acquisitions per backend per request, contended across worker threads.

Each is benchmarked at representative backend counts (1, 5, 20) so the scaling behaviour is visible, not just the single-backend case.

### 6.2 End-to-end load harness

A small load generator **in-repo** (a Rust binary), rather than an external tool. Two reasons: it runs anywhere `cargo` runs with no separate installation, and it can be wired into CI later. It reports throughput, p50/p95/p99/p99.9 latency, and error counts against a running instance.

**An honest caveat that belongs in the results, not a footnote:** a laptop running the load generator, the load balancer, and the backends on one machine cannot produce a trustworthy absolute 50k req/s figure — the client competes with the server for the same cores, and loopback is not a network. These numbers are a **relative baseline** for detecting regressions and validating Phase 7's improvements. Establishing true capacity requires a separate load-generation host and production-like hardware, and that is called out as a prerequisite before any SLA commitment is made on the basis of these figures.

## 7. Out of Scope

- Any data-plane behaviour change, including the performance fixes themselves (Phase 7).
- OpenTelemetry / distributed tracing spans (Prometheus was the chosen stack; the `tracing` foundation laid here makes OTel an additive change later).
- Alerting rules and Grafana dashboards beyond a starter dashboard and example alert rules shipped as documentation.
- Authentication on the admin listener — it is private-interface-bound, consistent with the Phase 3 peer port. Revisit if it must ever be exposed.

## 8. Testing Strategy

- **Metrics**: a request through a listener increments `lb_requests_total` with the right `status` label; a rate-limited request increments `lb_ratelimit_rejected_total` with `layer="local"` and, when clustered, `layer="cluster"`; an unhealthy backend flips `lb_backend_healthy` to 0.
- **Cardinality guard**: a test asserts the metric label sets contain no client-derived values — encoding §2.3 as an executable rule rather than a comment.
- **Health semantics**: `/healthz` returns 200 while the process is up *even when every backend is down*; `/ready` returns 503 in exactly that situation. This pair is the whole point of the distinction, so it is tested directly.
- **Admin isolation**: `/metrics` is **not** reachable on a traffic listener — a request to `/metrics` on the proxy port is forwarded to a backend like any other path, and does not expose metrics.
- **Logging**: JSON output parses as JSON and carries the request id; access logging is silent when disabled.
- **Exposition format**: `/metrics` output parses as valid Prometheus text format.
- All 102 existing tests continue to pass unchanged, confirming no data-plane behaviour moved.

## 9. Decisions Log

- **Separate admin listener over serving metrics on the traffic port**: at the edge, metrics describe internal topology; exposing them publicly hands out a map. Same reasoning as the Phase 3 peer port.
- **Prometheus text exposition over OTel**: matches the stated stack (Prometheus + Grafana), and avoids a heavier dependency. `tracing` still underpins logging, so OTel remains an additive change.
- **Access logging off by default**: 50k req/s makes per-request logging a genuine capacity problem, not a preference. Off by default with explicit sampling makes the cost a deliberate choice.
- **Inbound `X-Request-Id` not trusted**: at the edge it is attacker-controlled; accepting it lets a client forge or collide log entries.
- **Liveness excludes backend health**: otherwise a backend outage triggers an LB crash loop, converting a partial outage into a total one.
- **Metric handles resolved at wiring time**: string label lookups on a 50k req/s hot path would make the observability layer its own bottleneck.
- **In-repo load generator over `wrk`/`oha`**: runs anywhere `cargo` does, works on this Windows development machine, and can move into CI.
- **Laptop benchmarks labelled relative, not absolute**: publishing a co-located loopback figure as a capacity number would be misleading, and SLA decisions must not be made from it.
