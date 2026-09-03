# Distributed Load Balancer — Phase 1

A single-node L7 HTTP load balancer with a GCRA rate limiter, round-robin
backend selection, and active + passive (circuit breaker) health checking,
built from scratch on `hyper`/`tokio`.

See [`docs/superpowers/specs/2026-09-03-lb-phase1-design.md`](docs/superpowers/specs/2026-09-03-lb-phase1-design.md)
for the full design and the reasoning behind each choice.

## Run it

1. Copy `config.example.toml` to `config.toml` and point `[[backends]]` at
   your real backend addresses.
2. `cargo run -p lb-server -- config.toml`

## Workspace layout

- `lb-core` — shared types and the `RateLimiter`/`LoadBalancer`/`Clock` traits (no I/O)
- `lb-ratelimit` — GCRA rate limiter
- `lb-balancer` — round-robin `LoadBalancer`
- `lb-healthcheck` — active checker + passive circuit breaker
- `lb-proxy` — the `hyper` service that handles one request end to end
- `lb-server` — the binary: config loading, wiring, graceful shutdown

## Test

`cargo test --workspace --features lb-core/test-util`

## Scope

Phase 1 only — see the design doc for what's deliberately deferred (TLS,
config hot-reload, metrics/logging/admin API, L4 proxying, multi-node
coordination) and why.
