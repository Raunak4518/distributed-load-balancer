# Benchmarks

This page documents the `crates/lb-bench` suite: four binaries covering hot-path micro-benchmarks, end-to-end HTTP behavior through a real `lb-server` process, cluster rate-limit convergence, and an HTTP/2 Rapid Reset stress test. It also records every measured result this project currently has evidence for, with its source and date, and flags README claims that have no backing data on disk.

## The benchmark suite

All four binaries live in `crates/lb-bench` ([`Cargo.toml`](../crates/lb-bench/Cargo.toml)) and build with:

```
cargo build --release -p lb-bench
```

This produces `lb-bench`, `lb-bench-e2e`, `lb-bench-cluster`, and `lb-bench-h2-stress` in `target/release/`. The two binaries that drive a real proxy (`lb-bench-e2e`, `lb-bench-h2-stress`) locate `lb-server` next to themselves at runtime and exit with an error if it hasn't been built in the same profile — build it first with `cargo build -p lb-server` (or `--release`, matching how `lb-bench` itself was invoked).

### `lb-bench` — hot-path micro-benchmarks ([`main.rs`](../crates/lb-bench/src/main.rs))

In-process, single-threaded, hand-rolled benchmarks (no `criterion`; its dependency tree did not build on the project's development machine). Every benchmark warms up for `iterations/10` calls before timing `iterations` calls and reports ns/op and ops/s. Takes no CLI arguments — running it executes every benchmark below in sequence:

- `BackendPool::eligible_backends()` at 1/5/20 backends — allocates a `Vec` and clones every `BackendId`.
- `RoundRobin::pick()` at 1/5/20 backends.
- `ConsistentHash::pick()` at 10/100/1000 backends (cached-ring case).
- `Gcra::check()` — single-key rate-limit check.
- `ListenerCoordinator::try_admit()` — single-key cluster admission check.
- Circuit-breaker refresh loop at 1/5/20 backends — the per-request state refresh `lb-proxy` runs before picking a backend.
- TLS handshake cost ([`tls.rs`](../crates/lb-bench/src/tls.rs)) — full and session-resumed handshakes, driven in memory between a rustls `ClientConnection` and `ServerConnection` (no socket), so the number is handshake CPU only. Only ECDSA P-256 is measured; RSA would require `rcgen`'s `aws_lc_rs` feature, which pulls a C toolchain the workspace's `ring` pin avoids.
- Backend-pool scaling: `pick()` for every load-balancing strategy (round robin, least connections, weighted round robin, consistent hash, peak-EWMA+P2C) and `BackendPool::apply_resolved()`, across 1/5/20/100/500/1000 backends, with iteration counts scaled down as backend count grows.
- A rough per-backend memory-floor estimate from `size_of` on the public pool types.
- `pick()` latency while `apply_resolved()` runs concurrently once per second (simulating DNS re-resolution) — 4 picker threads hammering `pick()` for 2.5s per pool size, reporting p50/p99 (sampled 1-in-64) and true max latency.
- `CounterStore` scaling (`snapshot_own()`/`merge()` cost, snapshot size, per-key memory) at 100/1,000/10,000/100,000 tracked keys.

See [load-balancing.md](load-balancing.md) for what each strategy does, [rate-limiting.md](rate-limiting.md) for GCRA, and [cluster-coordination.md](cluster-coordination.md) for `CounterStore` and `ListenerCoordinator`.

### `lb-bench-e2e` — end-to-end proxy benchmarks ([`e2e_main.rs`](../crates/lb-bench/src/e2e_main.rs))

Spawns real backend HTTP/1.1 servers (in-process hyper), writes a temporary TOML config, spawns a real `lb-server` as a separate OS process, and drives load against it over loopback TCP with a closed-loop client (N persistent connections via one pooled `hyper_util` client). CLI modes:

| Invocation | What it runs |
|---|---|
| `lb-bench-e2e` | Single run against `round_robin` (default strategy): throughput/latency matrix + a failure scenario. |
| `lb-bench-e2e --strategy <name>` | Same, against one of `round_robin`, `least_connections`, `weighted_round_robin`, `consistent_hash`, `peak_ewma_p2c`. |
| `lb-bench-e2e --compare-all-strategies` | Fixed workload (4 backends, concurrency 128, 5s + 2s warmup) run once per strategy, reporting req/s and p50/p95/p99/p999. |
| `lb-bench-e2e --heterogeneous` | Two scenarios against a fixed 10/20/100/500ms backend latency mix: a static comparison across `round_robin`/`least_connections`/`peak_ewma_p2c`, and a dynamic one where backend C jumps to 300ms at t=10s and recovers at t=20s (`round_robin` and `peak_ewma_p2c` only), sampling per-backend traffic share every second. |
| `lb-bench-e2e --retry-amplification` | Backend-request amplification under retries: fail rates 0/50/100% crossed with three retry-budget modes (unbudgeted default, budgeted 200 r/s burst 50, near-zero budget as a stand-in for "disabled"), reporting client requests, backend requests, amplification factor, and error rate. |
| `lb-bench-e2e --reliability` | Circuit-breaker/outlier-detection characterization: one backend degrades (100/500/2000ms added latency, or 30% intermittent failure) for 8s after a 3s baseline, then recovers for 5s, sampled every 100ms via the admin `/metrics` endpoint. Reports time-to-detection, time-to-ejection, traffic share before/during degradation, time-to-recovery, false-ejection flag, and max deviation among the healthy backends. |
| `lb-bench-e2e --convergence` | Cold-start convergence of `peak_ewma_p2c` from zero samples against the 10/20/100/500ms mix, sampled at 100/1,000/10,000 total requests; then a discovery-speed run where a fifth backend is undrained via the admin API into an already-warmed pool, sampling its traffic share every 500 requests until it settles within 3 percentage points of its own steady state. |
| `lb-bench-e2e --failure-patterns` | `peak_ewma_p2c` against five backend-C degradation shapes (gradual ramp 10→300ms, periodic 200ms spikes to 400ms, randomized 0–400ms per-request jitter, fractional slow requests at 1/10/50%, and a full 4s stall), sampling backend C's traffic share on a 250ms–1s tick depending on scenario. |
| `lb-bench-e2e --concurrency-signal` | Isolates the pending-load signal from the latency signal: backend A/C never slow down under load, B/D add 3ms of latency per in-flight request on top of a fast (10ms) or slow (150ms) base, compared across `round_robin`/`least_connections`/`peak_ewma_p2c`. |
| `lb-bench-e2e --help` / `-h` | Prints usage. |

Every mode except `--help` prints a methodology block (host CPU/cores/RAM, OS, rustc version, and the loopback/single-machine caveat — see [`print_methodology()`](../crates/lb-bench/src/e2e_main.rs)) before running, and persists results afterward (see "Where results are written" below).

### `lb-bench-cluster` — cluster rate-limit convergence ([`cluster_main.rs`](../crates/lb-bench/src/cluster_main.rs))

Takes no CLI arguments; running it executes the full matrix below in one pass. Every node is a real `ClusterNode` driven over real `tokio::net::TcpListener` sockets (`spawn_peer_listener`/`spawn_sync_loop`), run in-process as separate tokio tasks rather than separate OS processes. Gossip traffic is routed through a small per-directed-pair TCP relay the harness owns, so every push (and, for the partition scenario, every drop) can be counted without touching `lb-cluster`'s production code.

1. **Convergence matrix**: node counts {3, 5, 10} crossed with gossip intervals {100ms, 500ms, 1000ms, 5000ms} — 12 combinations. Each combination bursts all nodes simultaneously against one shared cluster-wide rate-limit key (configured limit 100, each node attempting 20 req/s for 2.5s), then polls until every node's local view agrees with the true total or a settle timeout elapses. Reports the true total, the theoretical bound (`configured_limit + convergence_over_admission_bound(...)`), whether the empirical total stayed within that bound, convergence time, and gossip message counts.
2. **Partition-and-restore scenario** (fixed N=5, 500ms gossip): splits nodes into group A={0,1} and group B={2,3,4}, bursts against the shared key while partitioned (confirming each side keeps admitting locally and the two views diverge), then restores connectivity and confirms the CRDT max-merge reconciles to the true total with no lost or double-counted admissions.
3. **`CounterStore` resource scale**: 2 nodes, 200ms gossip, node-0 pre-loaded with {100, 1,000, 10,000, 100,000} tracked keys, measuring gossip message rate and bytes/message over a 3s window per key count.

`lb-bench-cluster` prints all of this to stdout but does **not** call the results writer — it has no `results/<timestamp>/` output, unlike the other three binaries.

### `lb-bench-h2-stress` — HTTP/2 Rapid Reset stress ([`h2_stress_main.rs`](../crates/lb-bench/src/h2_stress_main.rs))

Takes no CLI arguments. Spawns a fast in-process HTTP/1.1 backend, generates a throwaway self-signed ECDSA certificate, writes a TLS-enabled config with `max_pending_accept_reset_streams` at its configured default (20, the configured default — see [edge-hardening.md](edge-hardening.md)), and spawns a real `lb-server`. It connects over real TLS+HTTP/2 (`h2` crate) and:

1. **Locates the activation point**: opens a connection, sends one request that completes normally (a "primer"), then floods `n` pending resets (send a request, immediately drop the response future without reading it — an HTTP/2 stream reset) for `n` in `{1, 5, 10, 15, 18, 19, 20, 21, 22, 25, 30}`, recording whether the connection survives 2 seconds after the flood.
2. **Sustained attack**: 200 connections × (activation-point-plus-5) resets each, sampling process CPU and RSS (via PowerShell `Get-Process` on Windows, `/proc/<pid>/stat`+`status` elsewhere) before and during the attack, and scraping `lb_requests_total{protocol="http2",status="2xx"}` from the admin `/metrics` endpoint before and after to show how few of the flooded streams ever reach that counter.

Persists results under mode `rapid-reset-stress` with `max_pending_accept_reset_streams` recorded as a parameter.

## Where results are written

`lb-bench-e2e` and `lb-bench-h2-stress` (and, per the matrix above, *not* `lb-bench-cluster`) write every run's results through [`results.rs`](../crates/lb-bench/src/results.rs) to a fresh directory:

```
results/<UTC-timestamp>/metadata.json
results/<UTC-timestamp>/results.csv
```

`metadata.json` captures the run's `mode` (e.g. `"run"`, `"heterogeneous"`, `"rapid-reset-stress"`), the current `git_sha` (via `git rev-parse HEAD`, `"unknown"` if unavailable), `rustc_version`, `os` (`std::env::consts::OS`), `logical_cores` (`std::thread::available_parallelism()`), and a `params` map (e.g. `{"strategy": "round_robin"}`). `results.csv` has three columns — `scenario`, `metric`, `value` — one row per recorded data point (e.g. `throughput_matrix/conc=128,req_s,6188.94`). The `results/` directory is gitignored; nothing here is checked in, so this page's numbers below cite the run's timestamp, git SHA, and machine context explicitly rather than assuming any particular run is preserved.

## Methodology and its limits

- **Warmup and repetition.** `lb-bench`'s micro-benchmarks run `iterations/10` warmup calls before timing; `lb-bench-e2e`'s closed-loop runs discard a warmup period (commonly 2s) before recording latencies and error counts.
- **Real process, real sockets, one exception.** `lb-bench-e2e` and `lb-bench-h2-stress` spawn a genuine `lb-server` OS process and drive it over real loopback TCP/TLS. `lb-bench-cluster` runs its `ClusterNode`s in-process as tokio tasks rather than separate processes (though still over real TCP sockets for gossip). `lb-bench`'s TLS handshake benchmark is the one exception to "real sockets": it drives rustls in memory with no I/O at all, specifically to isolate handshake CPU from loopback/syscall overhead.
- **Loopback only.** No benchmark here models real network latency, loss, or a separate load-generation host — the client and server (and, for `lb-bench-e2e`, the backends) compete for the same machine's CPU. Every result in this document is this-machine, not a general capacity claim.
- **Single physical machine, whatever build profile was invoked.** None of the four binaries mandate `--release`; a debug build will report proportionally worse numbers. All results below were release builds unless stated otherwise.
- **Windows process sampling is coarser than Linux's.** CPU-seconds and RSS come from `Get-Process` on Windows versus `/proc/<pid>/stat`/`status` on Linux/other platforms; the Linux path additionally reports thread count, open FDs, and context-switch deltas, which the Windows path does not.
- **Contention is largely unmeasured** outside the one explicit concurrent case (`pick()` under concurrent `apply_resolved()`, 4 picker threads). Every other `lb-bench` micro-benchmark is single-threaded and uncontended; a lock or atomic's real cost under production concurrency is higher than an uncontended measurement can show.
- **`lb-bench-cluster`'s in-process topology** means all N simulated nodes and their relays share one process's CPU and memory — a real multi-host cluster's gossip behavior (and, in particular, real network partitions rather than a relay flag) is not exercised.

## Results

Every number below is taken from a real source on disk or in this repository's history — [`BASELINE.md`](BASELINE.md) (the raw historical micro-benchmark log this page summarizes) or the "Evaluation Findings" section of `README.md` — plus real `results/<timestamp>/` output found locally at the time this page was written. No number here is extrapolated or invented; where a claim exists without data to back it, it is listed at the end of this section instead of stated as measured.

### Micro-benchmarks (from `docs/BASELINE.md`)

Hardware for all figures in this subsection: a Windows 11 developer laptop, single-threaded, uncontended, release profile, 200,000 iterations per measurement unless noted. Run-to-run noise on this machine was measured directly at up to **±18%** between two back-to-back runs of the identical binary — read every ns/op figure below against that noise floor, not as a precise value.

Latest known per-operation cost at 5 backends, after all `docs/BASELINE.md`-recorded optimizations (captured 2026-09-06 through the `Arc<str>` interning change):

| Operation | ns/op (5 backends) | ns/op (20 backends) | Note |
|---|---:|---:|---|
| `BackendPool::eligible_backends()` | ~382–401 | ~1,184–1,260 | `BackendId` interned as `Arc<str>`; clones are now pointer clones, not `String` allocations. |
| `RoundRobin::pick()` | ~391–396 | — | Dominated by `eligible_backends()`. |
| Circuit-breaker refresh loop | ~465–512 | ~1,688–1,690 | Lock-free (`AtomicU8`/`AtomicU64` state); the remaining cost is `eligible_backends()`-style allocation in the bench's own loop, not the breaker itself. |
| `Gcra::check()` | ~100–109 | — | Borrowed-key lookup first; only a first-seen key allocates. |
| `ListenerCoordinator::try_admit()` | ~377–404 | — | Two of its two internal `to_string()` allocations removed; the outer `format!()` namespacing a key remains (see `docs/BASELINE.md` for why it resists removal without a larger `CounterStore` change). |

TLS handshake cost (measured 2026-09-06, same machine, in-memory rustls `ClientConnection`/`ServerConnection` with no socket):

| Case | ns/op | handshakes/s |
|---|---:|---:|
| Full handshake (ECDSA P-256) | 1,013,109 | 987 |
| Resumed handshake (TLS 1.3 ticket) | 747,654 | 1,338 |

This is client + server cost on one thread; a real server pays roughly half, so 987/s is a conservative floor rather than a capacity claim. Only P-256 is measured (see "Methodology" above for why RSA is absent). Reproduce with `cargo build --release -p lb-bench && ./target/release/lb-bench` (handshake cost is one of several sections this prints).

**Headline conclusion recorded in `docs/BASELINE.md`:** per-request bookkeeping (pick + circuit refresh + GCRA + cluster admission) at 5 backends totals roughly 2 µs; a single full TLS handshake costs roughly 500 times that. Connection reuse (keep-alive, HTTP/2 multiplexing) and session resumption dominate the actual cost story for a TLS-terminating edge far more than any of the bookkeeping allocations above.

### End-to-end throughput/latency (single strategy run)

Source: `results/2026-09-16T21-05-05Z/` (git `db5633f6`, Windows, 16 logical cores, `rustc 1.98.0`). Mode `run`, strategy `round_robin`, default `lb-bench-e2e` invocation (no flags).

Throughput/latency matrix (4 backends, closed-loop, 5s measured + 2s warmup per concurrency level):

| Concurrency | req/s | total reqs | err% | p50 (ms) | p95 (ms) | p99 (ms) | p999 (ms) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 565 | 2,826 | 0 | 1.66 | 2.42 | 3.35 | 8.17 |
| 8 | 3,327 | 16,643 | 0 | 2.29 | 3.37 | 4.24 | 6.93 |
| 32 | 6,087 | 30,462 | 0 | 5.06 | 7.53 | 9.41 | 13.07 |
| 128 | 6,189 | 31,031 | 0 | 20.24 | 29.31 | 33.93 | 41.02 |
| 256 | 5,069 | 25,534 | 0 | 47.98 | 78.26 | 103.03 | 126.53 |

Failure scenario (concurrency 64, 16s, backend[0] killed at t=5s): 90,823 total requests, 0 errors, p50 10.83ms / p95 16.87ms / p99 20.86ms / p999 27.81ms.

Reproduce: `cargo build --release -p lb-bench -p lb-server && ./target/release/lb-bench-e2e`.

### Cold-start convergence and discovery speed (`peak_ewma_p2c`)

Source: a local `results/2026-09-22T22-59-01Z/` directory found on disk (git `3172bbbb`, Windows, 16 logical cores) — note this is a different commit than the run above, so it is not directly comparable to it.

Convergence checkpoints against the 10/20/100/500ms (A/B/C/D) mix, from a cold `peak_ewma_p2c` start:

| Checkpoint (requests) | A% | B% | C% | D% |
|---:|---:|---:|---:|---:|
| 100 | 43.1 | 28.4 | 13.7 | 14.7 |
| 1,000 | 47.9 | 31.6 | 18.2 | 2.3 |
| 10,000 | 47.6 | 33.4 | 17.9 | 1.1 |

Traffic visibly shifts away from the slowest backend (D, 500ms) as sample count grows, consistent with the qualitative "converges over time" description recorded in `docs/BASELINE.md`.

Discovery speed: a fifth backend (E, 5ms, undrained into an already-warmed pool) reached a steady-state traffic share of **36.9%** and stayed within 3 percentage points of that share from request #20,007 onward in this run (its share fluctuated between roughly 32% and 41% across the sampled windows before settling).

Reproduce: `./target/release/lb-bench-e2e --convergence`.

### Concurrency-signal isolation (round_robin vs. least_connections vs. peak_ewma_p2c)

Source: a local `results/2026-09-22T23-01-25Z/` directory found on disk (git `3172bbbb`, same machine as the convergence run above). Backends A/C never slow under their own load; B/D add 3ms of latency per in-flight request on top of a fast (10ms, A/B) or slow (150ms, C/D) base delay.

| Strategy | A% | B% | C% | D% | req/s | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| round_robin | 25.0 | 25.0 | 25.0 | 25.0 | 523 | 152.5 | 270.0 | 271.4 |
| least_connections | 69.9 | 17.7 | 7.0 | 5.4 | 1,427 | 16.5 | 198.7 | 206.1 |
| peak_ewma_p2c | 49.2 | 31.1 | 11.4 | 8.2 | 880 | 62.7 | 192.0 | 207.0 |

`round_robin` ignores both signals, so its even split is the no-adaptation baseline. `least_connections` reacts to pending load alone and pushes the most traffic toward the fast, low-load backend (A); `peak_ewma_p2c` (latency + pending load) lands between round-robin and least-connections on A's share, showing the latency term partially offsetting the pending-load term rather than one dominating.

Reproduce: `./target/release/lb-bench-e2e --concurrency-signal`.

### Adaptive routing under failure patterns (`peak_ewma_p2c`, backend C degraded)

Source: a local `results/2026-09-22T23-00-39Z/` directory found on disk (git `3172bbbb`, same machine as above). Each pattern samples backend C's share of traffic on a short tick; baseline share (all backends equal, before degradation starts) is roughly 21–26% depending on the pattern's sampling tick.

| Pattern | Baseline C share | Trough C share during degradation | Notes |
|---|---:|---:|---|
| Gradual ramp (10→300ms over 6s, holds 3s, ramps back over 3s) | ~24.6% | ~0.23% (t=13s) | Share falls roughly in step with rising latency, not a sharp cutoff. |
| Periodic spikes (200ms spike to 400ms every 2s) | ~22% | 0% during each spike window | Share recovers to ~13–15% between spikes, not fully back to baseline — spikes are frequent enough that the EWMA doesn't fully forget them. |
| Randomized per-request jitter (0–400ms, 6s) | ~25.9% | ~0.4% (t=8s) | |
| Fractional slow requests, 1% at +2000ms | ~26.8% | ~4.9% (t=5s) | Even a 1% slow-tail is enough to measurably suppress C's share. |
| Fractional slow requests, 10% at +2000ms | ~22.5% | ~0.23% (t=4s) | |
| Fractional slow requests, 50% at +2000ms | ~26.2% | 0% (t=4s, t=6s, t=8s, t=9s) | |
| Full stall (4s, 6s duration) | ~22.7% | 0% (t=4s–5s, and again t=8s–10s) | Share does not meaningfully recover within the 12s window even after the stall ends at t=8s. |

Reproduce: `./target/release/lb-bench-e2e --failure-patterns`.

### HTTP/2 Rapid Reset stress

No local `results/` directory for a `rapid-reset-stress` run and no numeric findings in `README.md`'s "Evaluation Findings" section were found while writing this page — see the gap listed below. The harness and its methodology are documented above; reproduce with `cargo build --release -p lb-bench -p lb-server && ./target/release/lb-bench-h2-stress` and read the printed activation point and the `lb_requests_total{protocol="http2",status="2xx"}` before/after delta directly, or persist a fresh `results/<timestamp>/` run under mode `rapid-reset-stress`.

### Cluster convergence

`lb-bench-cluster` prints its 12-combination convergence matrix, partition-and-restore scenario, and `CounterStore` scale scenario to stdout, but (per "Where results are written" above) does not persist a `results/` directory, and none was found locally. `README.md`'s "Evaluation Findings" reports "within its documented overshoot bound in 11 of 12 tested (node-count, gossip-interval) combinations... the one exception (3 nodes, 100ms interval) exceeded it marginally (105 vs. 104 predicted)" — this is a specific, falsifiable claim consistent with the 3×4 matrix `cluster_main.rs` actually runs, but no `results/` CSV backs the exact figures, so it is reported here as a README claim, not as data this page independently verified. Reproduce with `cargo build --release -p lb-bench && ./target/release/lb-bench-cluster`.

## Claims reported but not locally verified

The following claims from `README.md`'s "Evaluation Findings" section describe real scenarios this suite is built to run, but no corresponding `results/<timestamp>/` directory was found on disk to verify the exact figures while writing this page. They are reported here as-is, attributed to the README, not restated as independently measured:

- Peak-EWMA+P2C "matched least-connections' throughput while cutting p99 latency from 507ms to 125ms" on the static 10/20/100/500ms heterogeneous mix (`lb-bench-e2e --heterogeneous`).
- The gossip cluster rate limiter's "11 of 12" within-bound combinations and the "105 vs. 104 predicted" exception at 3 nodes / 100ms gossip (`lb-bench-cluster`).
- The retry-budget amplification-prevention claim under partial/total backend failure (`lb-bench-e2e --retry-amplification`) — no amplification-factor numbers were found locally.
- "Circuit-breaker detection/ejection/recovery times scale plausibly with failure severity" across the four reliability scenarios (`lb-bench-e2e --reliability`) — no detection/ejection/recovery timing numbers were found locally.
- The DNS-discovered-backend readiness race and missing-circuit-breaker findings, and the graceful-shutdown/live-reload correctness claims, are qualitative behavioral findings rather than benchmark numbers; this page does not attempt to assign them a measured figure.

## See also

- [load-balancing.md](load-balancing.md) — the strategies benchmarked here (round robin, least connections, weighted round robin, consistent hash, peak-EWMA+P2C).
- [health-checking.md](health-checking.md) — circuit breaker and outlier detection, exercised by `--reliability` and `--failure-patterns`.
- [rate-limiting.md](rate-limiting.md) — GCRA and retry budgets, exercised by `--retry-amplification` and the `Gcra::check()` micro-benchmark.
- [cluster-coordination.md](cluster-coordination.md) — the gossip protocol and CRDT counter store exercised by `lb-bench-cluster`.
- [tls.md](tls.md) — handshake and session resumption behavior behind the TLS handshake micro-benchmark.
- [edge-hardening.md](edge-hardening.md) — `max_pending_accept_reset_streams` and the Rapid Reset mitigation exercised by `lb-bench-h2-stress`.
- [metrics-reference.md](metrics-reference.md) — `lb_requests_total`, `lb_tls_handshakes_total`, and the admin `/metrics` endpoint these harnesses scrape.
- [operations.md](operations.md) — why none of the figures on this page support a capacity or SLA claim on their own.
