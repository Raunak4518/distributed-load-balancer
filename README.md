# Distributed Load Balancer — Phases 1–6

A single-node load balancer that proxies both **HTTP (L7)** and **raw TCP (L4)**
traffic, with GCRA rate limiting, round-robin backend selection, active +
passive (circuit breaker) health checking, and TLS in both directions —
terminating on any listener and, optionally, re-encrypting onward to
backends — built from scratch on `hyper`/`tokio` and `rustls`.

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
| Health probe | `GET /health` → 2xx | TCP connect succeeds — and, on a listener with `backend_tls`, a completed TLS handshake too |
| Retry on failure | needs body buffering | free — no bytes have moved yet |

A few consequences worth knowing:

- A TCP-connect health probe is **indistinguishable from a real client** at the
  backend — there is no path or header to mark it with. With `backend_tls`
  set, this gets *more* true, not less: the probe now completes a real TLS
  handshake through the same transport real connections use, so a backend
  whose certificate has expired or cannot be verified fails the probe exactly
  the way it fails a real client, and drops out of rotation instead of
  probing healthy while every real connection to it is refused. See **TLS**
  below.
- The byte pump enforces an *idle* timeout, not a maximum lifetime: a nine-hour
  Postgres session is normal, a stalled one is not.
- Both directions run under `try_join!`, so a half-closed connection (one side
  done, the other still streaming) keeps working.

## TLS

Add a `[listeners.tls]` section to terminate TLS on any listener — HTTP or
TCP, the same code path serves both — and a `[listeners.backend_tls]`
section to re-encrypt onward to that listener's backends. `config.example.toml`
has a commented, complete example of both.

**Certificates come from files and reload without a restart.**
`reload_interval_secs` (default 60) polls `cert_file`/`key_file` for changes;
a renewed certificate takes effect on the next tick. This matters because a
restart-to-renew design is an outage generator on a schedule: certificates
from a 90-day CA get renewed roughly monthly, and requiring a coordinated
restart to pick up each one turns routine certificate hygiene into a
recurring deploy. Reload is safe by construction — every certificate in a
batch is loaded and fully validated *before* anything is swapped, so a
broken renewal (a truncated file, a key that no longer matches its
certificate) leaves the previous certificate serving instead of taking the
listener down. A certificate that is a few hours stale beats no certificate
at all.

**The handshake gets its own timeout**, `handshake_timeout_ms` (default
5000 ms), because nothing in Phase 5 covers this window. `header_read_timeout_ms`
is a hyper setting, and hyper never sees a connection until its TLS
handshake has completed — without a dedicated timeout here, a client that
connects and then sends nothing would hold the connection open forever.

**SNI selects the certificate; an unmatched name is rejected, not defaulted.**
With one certificate configured it is served regardless of what SNI was
requested — there is nothing to choose between. With more than one, an exact
hostname match always wins over a single-level wildcard match (`*.example.com`
matches `a.example.com`, never `a.b.example.com` and never the bare
`example.com`, per RFC 6125), and a `ClientHello` whose SNI matches nothing
configured is handed no certificate at all rather than a default one.
Serving a mismatched certificate produces a browser error anyway, so a
silent fallback would only turn a clear failure into a confusing one.
(`min_version` defaults to TLS 1.2 for broad client compatibility; raise it
to `"1.3"` once you control every client that connects.)

**Backend re-encryption verifies by default.** `[listeners.backend_tls]`
turns on TLS to the backends themselves, with certificate verification
enabled unless explicitly disabled — encryption without authentication does
not address the threat that motivates it: if the network isn't trusted to
carry plaintext, it isn't trusted not to sit in the middle of a TLS session
either. Trust roots come from `ca_file` (the common case here — an internal
PKI) or the system trust store when `ca_file` is omitted. Every backend
needs a `server_name`, and it is deliberately a separate field from
`address`: the TCP dial is always pinned to `address`, and `server_name` is
used *only* for the TLS SNI extension and hostname verification. That split
is load-bearing, not cosmetic — an earlier iteration of this phase let a
stock connector DNS-resolve `server_name` to pick the dial target, which
silently bypassed the operator-configured `address` whenever DNS for that
name pointed somewhere else. `danger_accept_invalid_certs` is a deliberately
ugly escape hatch for a fleet that meets self-signed backend certificates on
day one: it logs a warning at every process startup and sets the
`lb_backend_tls_verification_disabled` gauge, specifically so it cannot hide
in a config file for two years.

**Health probes now use the same client and transport as real traffic.** At
L7, the health probe shares the exact client instance the proxy forwards
real requests with — same connection pool, same trust roots, same
verification policy — instead of a separate plaintext client of its own. At
L4, the TCP-connect probe performs a TLS handshake through the same outbound
transport the data plane wraps real connections with, whenever the listener
re-encrypts. Practically: a backend whose certificate has expired or cannot
be verified now fails its health probe and drops out of rotation, instead of
probing healthy while every real request to it fails and the dashboard shows
green.

**Two performance notes for picking a certificate and reasoning about
scale — operator guidance, not enforced by any code here:**

- An ECDSA P-256 certificate's server-side handshake is roughly 5–10x
  cheaper in CPU than an RSA-2048 one. This project accepts whatever key
  type a loaded certificate uses, so the choice is entirely yours to make at
  issuance time — it is not a config setting here.
- TLS session resumption (the session cache and TLS 1.3 tickets alike) is
  **per process**. A client that resumes a session against one cluster node
  and is then routed to another — by something in front of this load
  balancer, or simply because there is no session affinity — pays a full
  handshake there. Session state is never shared across nodes; doing so
  safely is a harder, security-sensitive problem left for later.

**One config setting is accepted but not yet wired up.** `hsts_max_age_secs`
is parsed and validated today — it defaults to 0 (off), and is rejected
outright on a TCP listener, which has no HTTP response to carry a header on.
The 0 default is deliberate: a browser that receives an HSTS header caches
the policy for the *entire* max-age with no way for the server to revoke it
early, so turning this on is close to irreversible — a misissued or expiring
certificate becomes completely unreachable rather than merely broken. As
shipped in Phase 6, however, no code path yet emits a
`Strict-Transport-Security` header from this setting — it is validated
configuration with no observable effect. Treat it as reserved, not
functional, until header emission lands.

New metrics: `lb_tls_handshakes_total{listener,outcome}` (`success` /
`failed` / `timeout`), `lb_tls_handshake_duration_seconds{listener}`,
`lb_tls_certificate_expiry_timestamp_seconds{listener,cert}` (alert on this
one — an expired certificate is a total outage with a knowable date),
`lb_tls_certificate_reloads_total{listener,outcome}` (`applied` /
`unchanged` / `rejected`), and `lb_backend_tls_verification_disabled{listener}`.

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

**As of Phase 6, "nowhere to forward" includes a backend whose TLS
certificate cannot be verified.** Health probes run over the same client and
transport as real traffic (see **TLS** above), so a backend with an expired
or untrusted certificate fails its probe exactly as it would fail a real
request. If that leaves a listener with zero eligible backends, `/ready`
returns 503 for it — correct behaviour, since readiness means "somewhere to
forward" and a backend the data plane cannot actually reach is nowhere to
forward, but a real behavioural change from Phase 5 worth knowing before an
operator sees it in production instead of in these notes.

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

Phases 1–6 are complete: L7 HTTP, L4 TCP, multi-node coordination,
observability, edge hardening, and TLS in both directions (see **TLS**
above).

Deliberately deferred: HTTP/2, DNS-based backend resolution (addresses are
static `IP:port` today), config hot-reload beyond TLS certificates (backends,
rate limits and everything else still need a restart), an admin control API,
UDP, PROXY protocol, write-side timeouts for slow readers, mTLS
(client-certificate authentication — whether on a traffic listener or the
peer channel), an HTTP→HTTPS redirect listener, in-process ACME (Phase 6
reloads whatever certificate is already on disk; something else still has to
put it there and renew it), OCSP stapling, dynamic cluster membership (the
peer list is static), and shared health state — the last of these is
deliberate, since per-node reachability is real information rather than
noise to be averaged away.
