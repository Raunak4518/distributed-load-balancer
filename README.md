# Distributed Load Balancer — Phases 1 & 2

A single-node load balancer that proxies both **HTTP (L7)** and **raw TCP (L4)**
traffic, with GCRA rate limiting, round-robin backend selection, and active +
passive (circuit breaker) health checking, built from scratch on `hyper`/`tokio`.

One process runs any number of listeners, each with its own protocol, backend
pool, rate limit, and health checks — so it can front an HTTP API on :8080 and
a Postgres cluster on :5432 at the same time.

Design docs:
- [Phase 1 — L7 HTTP](docs/superpowers/specs/2026-09-03-lb-phase1-design.md)
- [Phase 2 — L4 TCP](docs/superpowers/specs/2026-09-04-lb-phase2-design.md)

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

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phases 1 and 2 are complete. Deliberately deferred: TLS termination, config
hot-reload, metrics/structured logging, admin API, UDP, PROXY protocol, and
multi-node coordination (Phase 3).
