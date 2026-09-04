# Distributed Load Balancer — Phases 1–5

A single-node load balancer that proxies both **HTTP (L7)** and **raw TCP (L4)**
traffic, with GCRA rate limiting, round-robin backend selection, and active +
passive (circuit breaker) health checking, built from scratch on `hyper`/`tokio`.

One process runs any number of listeners, each with its own protocol, backend
pool, rate limit, and health checks — so it can front an HTTP API on :8080 and
a Postgres cluster on :5432 at the same time.

Run several nodes with a `[cluster]` section and the rate limit is enforced
*globally* rather than per node.

Design documents for each phase (L7 HTTP, L4 TCP, multi-node coordination,
observability, edge hardening) are kept outside version control, under
`docs/superpowers/` in the working tree.

## Run it

1. Copy `config.example.toml` to `config.toml` and point the listeners at your
   real backends.
2. `cargo run -p lb-server -- config.toml`

## Workspace layout

- `lb-core` — shared types and the `RateLimiter`/`LoadBalancer`/`HealthProbe`/`Clock` traits (no I/O)
- `lb-ratelimit` — GCRA rate limiter
- `lb-balancer` — round-robin `LoadBalancer`
- `lb-healthcheck` — active probes (HTTP + TCP-connect) and the passive circuit breaker
- `lb-proxy` — the L7 HTTP data plane
- `lb-tcp` — the L4 TCP data plane
- `lb-cluster` — CRDT counters and peer sync for cluster-wide rate limiting
- `lb-metrics` — Prometheus registry and the private admin listener
- `lb-bench` — hot-path micro-benchmarks
- `lb-server` — the binary: config loading, listener wiring, graceful shutdown

## L4 vs L7 — what differs

At L4 you move bytes, not requests, and that shapes everything:

| | HTTP (L7) | TCP (L4) |
|---|---|---|
| Unit of work | one request | one connection |
| Rate-limit key | source IP or a header | source IP only |
| Over the limit | `429` + `Retry-After` | connection closed, silently |
| Health probe | `GET /health` → 2xx | TCP connect succeeds |
| Retry on failure | needs body buffering | free — no bytes have moved yet |

A few consequences worth knowing:

- A TCP-connect health probe is **indistinguishable from a real client** at the
  backend — there is no path or header to mark it with.
- The byte pump enforces an *idle* timeout, not a maximum lifetime: a nine-hour
  Postgres session is normal, a stalled one is not.
- Both directions run under `try_join!`, so a half-closed connection (one side
  done, the other still streaming) keeps working.

## Running more than one node

A single node enforces `rate_per_sec` correctly. Three nodes, each enforcing it
locally, let a client through at `3 × rate_per_sec` — the limit is silently
multiplied by the node count. Adding a `[cluster]` section makes it global.

Each node counts the requests it admits into one-second buckets and pushes
those counts to its peers. The counters are a **G-Counter CRDT**: counts are
summed *across* nodes (consumption is additive) and merged with `max` *within*
a node's own cell (which only ever grows, and has exactly one writer). That
merge is commutative, associative and idempotent, so it survives reordered,
duplicated and delayed messages — which is what a network does to you.

**The guarantee is approximate and bounded**, deliberately. Between sync rounds
the cluster may over-admit by up to `peers × requests-per-peer-per-sync-interval`.
An exact limit needs a round trip to shared state on *every* request; this design
keeps coordination off the request path entirely. Under a network partition it
favours availability: both halves keep serving, and the global limit is
temporarily exceeded.

Two properties worth knowing:

- Bucket boundaries use **wall-clock** seconds, because they must line up
  across machines — so nodes need roughly-agreeing clocks (NTP). Skew degrades
  accuracy gracefully rather than breaking safety.
- A dead peer needs no special handling: its buckets simply age out of the
  window, which is correct, since a node that is down is not admitting traffic.

The peer port is **authenticated**: every message carries an HMAC-SHA256 tag
over its payload, verified in constant time before parsing or merging, keyed
by a shared secret. A secret is required whenever `[cluster]` is configured —
a misconfigured cluster fails to start rather than running open. Supply it
via `shared_secret_env` so it never lands in a config file in version
control, and still bind the port to a private interface.

## Observability

Add an `[admin]` section to expose `/metrics` (Prometheus text format),
`/healthz` and `/ready`:

```toml
[admin]
listen = "127.0.0.1:9090"
```

**This is a separate listener, deliberately.** Metrics describe internal
topology — backend names, health, traffic volumes — so serving them on an
edge-facing traffic port would hand an attacker a map. Bind it privately.

`/healthz` and `/ready` mean different things, and conflating them is a
common and damaging mistake. Liveness returns 200 whenever the process is
running and **ignores backend health**: a failing liveness probe restarts the
process, and restarting cannot fix an unhealthy backend — it would turn a
partial outage into a crash loop. Readiness returns 503 when there is nowhere
to forward, removing the instance from rotation without killing it.

Rate-limit rejections are counted by `layer` (`local` vs `cluster`), which
answers a question you will actually ask during an incident: is this node's
own limiter rejecting, or is the cluster budget exhausted?

**No metric label ever carries a client-controlled value** — not IP, path, or
header. An unbounded label turns one metric into millions of time series and
kills Prometheus. A test enforces this rather than a comment.

Logging is `tracing` with JSON output. Per-request access logging is **off by
default**: at 50k req/s that is 50,000 lines a second, which is a capacity
decision rather than a preference. Enable it with `log_requests` and a
`sample_rate`. Every response carries an `X-Request-Id`; an inbound one is
never trusted, since at the edge it is attacker-controlled.

## Edge hardening

Everything below assumes hostile clients, because at the edge anyone can
connect.

**Connection caps.** Each listener has a global cap and a per-source cap. The
global permit is acquired *before* `accept()`, so at capacity the process
stops accepting and the kernel refuses on its behalf — rather than spending a
file descriptor and a task on a connection it means to discard. The per-source
cap exists because a global cap alone protects the process but not its users:
one attacker could otherwise consume the whole budget.

**Timeouts, because size limits are not bounds.** `max_request_body_bytes`
caps how *much* a client sends; it says nothing about how *long* it may take.
1 MiB at one byte per second is eleven days. `header_read_timeout_ms` caps the
request head (the classic slowloris) and `body_read_timeout_ms` caps the body.

**Bounded rate-limit memory.** The key map is capped; past the cap, newcomers
share a single overflow budget. Rejecting them would deny legitimate new
users during an attack, and LRU eviction would let an attacker evict
established clients — this way incumbents keep their own limits and a spray
attack collectively gets one client's worth of throughput.

Two limitations worth stating rather than discovering:

- A client that reads the **response** slowly still occupies a connection.
  hyper's server offers no write-side deadline, so the connection cap bounds
  the damage rather than preventing it.
- SYN floods and volumetric DDoS belong upstream of any userspace process, in
  the network or a scrubbing provider. This is not a defence against them.

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phases 1–5 are complete: L7 HTTP, L4 TCP, multi-node coordination,
observability, and edge hardening.

Deliberately deferred: TLS termination, HTTP/2, DNS-based backend resolution
(addresses are static `IP:port` today), config hot-reload, an admin control
API, UDP, PROXY protocol, write-side timeouts for slow readers, mTLS on the
peer channel, dynamic cluster membership (the peer list is static), and
shared health state — the last of these is deliberate, since per-node
reachability is real information rather than noise to be averaged away.
