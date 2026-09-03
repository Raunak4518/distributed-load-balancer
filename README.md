# Distributed Load Balancer — Phases 1–3

A single-node load balancer that proxies both **HTTP (L7)** and **raw TCP (L4)**
traffic, with GCRA rate limiting, round-robin backend selection, and active +
passive (circuit breaker) health checking, built from scratch on `hyper`/`tokio`.

One process runs any number of listeners, each with its own protocol, backend
pool, rate limit, and health checks — so it can front an HTTP API on :8080 and
a Postgres cluster on :5432 at the same time.

Run several nodes with a `[cluster]` section and the rate limit is enforced
*globally* rather than per node.

Design docs:
- [Phase 1 — L7 HTTP](docs/superpowers/specs/2026-09-03-lb-phase1-design.md)
- [Phase 2 — L4 TCP](docs/superpowers/specs/2026-09-04-lb-phase2-design.md)
- [Phase 3 — multi-node coordination](docs/superpowers/specs/2026-09-04-lb-phase3-design.md)

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

The peer port accepts **unauthenticated** input that influences rate-limiting
decisions. Bind it to a private interface. Authentication for the peer channel
is not implemented.

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phases 1–3 are complete. Deliberately deferred: TLS termination, config
hot-reload, metrics/structured logging, admin API, UDP, PROXY protocol,
dynamic cluster membership (the peer list is static), authentication on the
peer channel, and shared health state (each node health-checks independently,
which is deliberate — per-node reachability is real information).
