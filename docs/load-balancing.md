# Load Balancing

This page covers how the proxy chooses a backend for a request: eligibility rules that gate every strategy, the five selection strategies and how they differ, path/Host-based routing, canary traffic splits, sticky sessions, DNS-based backend discovery, and how retries interact with backend selection. For measured throughput/latency differences between strategies, see [benchmarks.md](benchmarks.md).

## Backend Eligibility

A backend is a candidate for selection only if `BackendPool` reports it eligible. Eligibility is the AND of four independent flags, checked on every `pick()`:

- **`active_healthy`** — the active health checker's last probe result (see [health-checking.md](health-checking.md)).
- **`circuit_open`** — `false` when the per-backend circuit breaker is closed or half-open-and-untested; `true` while it is open.
- **`manually_drained`** — set by an operator (e.g. the admin API's drain endpoint), independent of health checks so a drain is never silently undone by the next passing probe.
- **`outlier_ejected`** — set by the pool's `OutlierDetector` when a backend's success rate falls too far below its peers.

All four are exposed independently (`is_active_healthy`, `is_circuit_open`, `is_manually_drained`, `is_outlier_ejected`) so an operator can see *why* a backend is out of rotation, but a strategy only ever sees the combined result through `BackendPool::eligible_backends()` / `eligible_with_weights()`.

A backend that joined the pool while the process was serving (a later DNS poll, or a config reload) is also held back until its first health probe completes, unless no confirmed backend in the pool is eligible — see [awaiting the first probe](health-checking.md#awaiting-the-first-probe).

If `health_check.max_ejected_fraction` is configured, a circuit trip or outlier ejection that would push the ejected share of the pool above that fraction is refused outright — the flag never flips, and the backend stays eligible. Recovery (clearing a flag) is never blocked. See [health-checking.md](health-checking.md) for the breaker and outlier detector themselves; this fraction only gates the pool-level flags they write.

**When nothing is eligible**, every strategy's `pick()` returns `None`. The HTTP proxy responds `503 Service Unavailable` ("no healthy backend") without attempting to forward the request. This applies identically to the default pool, a route's pool, and a canary pool — each is checked independently.

Source: [`pool.rs`](../crates/lb-core/src/pool.rs), [`balancer.rs`](../crates/lb-core/src/balancer.rs).

## Selection Strategies

All five strategies implement the same `LoadBalancer` trait: `pick(pool, key) -> Option<BackendId>`, plus an optional `record_latency(id, latency)` hook called after every attempt (success or failure) — only Peak EWMA + P2C uses it. `key` is whatever the listener's `rate_limit.key` already resolves to for that request (`source_ip`, or the configured request header) — passed straight through rather than separately configured, so a listener's existing identity choice doubles as its hashing/affinity identity for strategies that need one.

Set per listener (or per route, or per canary pool) with:

```toml
[listeners.load_balancing]
strategy = "round_robin"
```

Valid values: `"round_robin"`, `"least_connections"`, `"weighted_round_robin"`, `"consistent_hash"`, `"peak_ewma_p2c"`. `strategy` is required — there is no default.

### Round Robin (`round_robin`)

Cycles through the eligible backends in order. An `AtomicUsize` cursor is incremented on every pick and taken modulo the number of currently-eligible backends.

- **Algorithm:** `eligible_backends()` (built fresh on every call) indexed by `cursor.fetch_add(1) % len`.
- **Complexity:** O(N) per pick, where N is the pool's total backend count — the eligible list is rebuilt, not cached, on every call. Rebuilding rather than caching means a health/circuit/drain/outlier change is reflected on the very next pick with nothing to invalidate.
- **When to use:** default choice for a pool of backends with roughly uniform capacity and per-request cost, and no need for session affinity.
- **Config:** `strategy = "round_robin"`.

Source: [`round_robin.rs`](../crates/lb-balancer/src/round_robin.rs).

### Least Connections (`least_connections`)

Picks the eligible backend with the fewest in-flight requests/connections.

- **Algorithm:** `min_by_key` over `eligible_backends()` by `BackendPool::active_count`, which only reflects reality because every forwarded attempt is wrapped in `BackendPool::track_active` for its duration. Ties (including the common all-idle case) go to whichever backend sorts first in pool order — deliberately not randomized.
- **Complexity:** O(N) per pick.
- **When to use:** request cost or duration varies significantly between requests (long-lived connections, streaming, widely varying handler latency), where a raw round-robin count would leave some backends carrying disproportionately more concurrent work.
- **Config:** `strategy = "least_connections"`.

Source: [`least_connections.rs`](../crates/lb-balancer/src/least_connections.rs).

### Weighted Round Robin (`weighted_round_robin`)

Round robin biased by each backend's configured `weight`.

- **Algorithm:** reads `eligible_with_weights()`, clamps each weight to 1000, sums them, and takes the cursor modulo that total; a single pass over the (backend, weight) pairs finds which backend's cumulative range the rolled value falls into. A weight of `0` removes a backend from the rotation entirely without removing its config entry — a drain switch that survives a config reload. A default weight of 1 across all backends makes this behave exactly like plain round robin.
- **Complexity:** O(N) per pick (one allocation of the weighted pairs, one sum, one scan). The clamp to 1000 bounds the modulus and scan cost regardless of a misconfigured or overflowing weight; it does not materialize a per-weight-unit list.
- **When to use:** backends with different capacity (different instance sizes, different max throughput) where traffic should be biased proportionally rather than split evenly.
- **Config:** `strategy = "weighted_round_robin"`; `weight` (u32, default 1) on each `[[listeners.backends]]` entry.

Source: [`weighted_round_robin.rs`](../crates/lb-balancer/src/weighted_round_robin.rs).

### Consistent Hashing (`consistent_hash`)

Hashes the request key onto a ring of virtual nodes so the same key keeps landing on the same backend as the backend set changes.

- **Ring construction:** every backend (eligible or not) contributes `weight.min(100) * 10` virtual points to the ring — 10 virtual nodes per unit of weight, weight capped at 100 before scaling. Each point's position is `hash(id + "\0" + virtual_node_index)`, and all points are sorted by hash value.
- **Caching:** the ring is cached as an `Arc<Ring>` behind an `RwLock`, keyed by the pool's identity and its `version()` counter. `version()` only advances on `apply_resolved` with an actual membership or weight change — never on a health/circuit/drain/outlier flip, which happen far more often and must stay cheap. A `pick()` on a warm ring never hashes or sorts on the request path; it clones the cached `Arc` (a refcount bump) and binary-searches it.
- **Hash key:** the same string passed as `pick`'s `key` argument — i.e. this listener's `rate_limit.key` (`source_ip`, or the configured header's value). There is no separate hash-key setting.
- **Lookup:** binary search (`partition_point`) finds the first ring point at or after `hash(key)`, then walks forward (wrapping) until it finds a point whose backend is currently eligible. Because the ring includes ineligible backends' points, a key that would have landed on a down backend simply falls through to the next hash-adjacent one, which is what keeps remapping minimal — removing one of four backends remaps only about a quarter of keys, not nearly all of them, unlike a plain `hash(key) % len`.
- **Complexity:** O(log R) for the binary search plus O(k) for the eligibility walk, where R is the ring's total point count (bounded by `100 * 10` per backend) and k is the number of consecutive ineligible points encountered; ring construction is O(R log R) but amortized across picks between membership changes.
- **When to use:** session or cache affinity is wanted, but membership changes over time (autoscaling, DNS-based discovery) and remapping every key on every change is unacceptable.
- **Config:** `strategy = "consistent_hash"`; `weight` controls ring share (capped at 100, a different cap from weighted round robin's 1000).

Source: [`consistent_hash.rs`](../crates/lb-balancer/src/consistent_hash.rs).

### Peak EWMA + Power-of-Two-Choices (`peak_ewma_p2c`)

Samples two eligible backends at random and picks whichever looks cheaper right now, where cost combines a decaying latency estimate with current load.

- **Algorithm:** draws two distinct indices from an xorshift PRNG over the eligible list (falling straight through with no sampling when there are 0 or 1 eligible backends). If exactly one of the two has never had a latency sample recorded, that one wins outright — this is what keeps the scheme from converging permanently onto whichever backend happened to be sampled first; without it, one ordinary real sample would permanently beat every other backend's still-default estimate on every future comparison. Otherwise, the backend with the lower `estimate_nanos * (pending_requests + 1)` wins — the same cost function Finagle's and Linkerd's Peak EWMA balancers use.
- **Decay:** `record_latency` updates a per-backend EWMA with `weight = exp(-elapsed / decay)`; `new_estimate = prev * weight + sample * (1 - weight)`. The decay time constant is fixed at 10 seconds and is not currently exposed as a configuration field — every instance is built with this default. A backend with no sample yet is treated as a fixed default of 1 second (not zero), so a cold or just-recovered backend competes on equal footing instead of being flooded because it looks free.
- **Penalty:** the `pending + 1` multiplier is the "power" behind power-of-two-choices here — it makes a backend with several slow requests already outstanding look expensive immediately, even before its own decaying estimate has caught up.
- **Complexity:** O(1) per pick — two random draws, two hash-map lookups, one comparison — independent of pool size.
- **When to use:** backends have materially different or fluctuating real-world responsiveness (mixed instance types, GC pauses, uneven downstream dependencies) and a config-time weight cannot capture that; this is the only strategy that reacts to measured latency and current in-flight load rather than a static rule.
- **Config:** `strategy = "peak_ewma_p2c"`. No per-strategy tuning fields exist yet; decay and the cold-start estimate are compiled-in constants.

Source: [`peak_ewma_p2c.rs`](../crates/lb-balancer/src/peak_ewma_p2c.rs).

### Comparison

| Strategy | Config value | Uses request key | Session affinity across churn | Latency-aware | Per-pick cost |
|---|---|---|---|---|---|
| Round Robin | `round_robin` | no | no | no | O(N) |
| Least Connections | `least_connections` | no | no | indirectly (in-flight count) | O(N) |
| Weighted Round Robin | `weighted_round_robin` | no | no | no | O(N) |
| Consistent Hashing | `consistent_hash` | yes | yes (minimal remap) | no | O(log R + k) |
| Peak EWMA + P2C | `peak_ewma_p2c` | no | no | yes | O(1) |

N = total backends in the pool; R = total ring points; k = consecutive ineligible points walked. See [benchmarks.md](benchmarks.md) for measured throughput and tail-latency comparisons across strategies under load.

## Routes

`[[listeners.routes]]` sends a request to an entirely different pool — its own backends, health checks, and load-balancing strategy — based on the request's path and/or `Host` header, independent of the listener's default pool. This is HTTP-only.

- **Path matching** is a path-*segment* prefix, not a bare `starts_with`: a route with `path_prefix = "/api"` matches `/api` and `/api/anything` but not `/apiary`. Matching is against the path component alone, never the query string.
- **Host matching** is a case-insensitive exact match against the request's `Host` header.
- Either field can be omitted (`None` matches everything for that dimension), so a route can match on path only, host only, or both.
- Routes are evaluated **in declaration order; the first rule whose path and host both match wins**, and route resolution happens before the default pool, the sticky cookie, and the canary split are even considered. A request matching no route falls through to the listener's own backends (and, from there, to any configured canary split).

Source: [`service.rs`](../crates/lb-proxy/src/service.rs) (`resolve_route`, `route_matches`, `CompiledRoute`).

## Canary / Weighted Traffic Split

`[[listeners.canary]]` splits the traffic that matched **no** route rule across one or more additional, independently health-checked and independently load-balanced pools, by percentage. This is HTTP-only and distinct from a backend's own `weight`, which biases selection *within* one pool — `percent` here is an absolute share of the listener's total request volume.

- Each pool declares `percent` (1-99); the sum across all canary pools must be at most 99, so the listener's own default pool always keeps at least 1% of traffic.
- The split is a deterministic roll: an `AtomicUsize` cursor incremented per request, taken modulo 100, bucketed against each pool's cumulative percentage — exact long-run convergence to the configured split with no random-number dependency.
- If sticky sessions are enabled and the request carries a cookie naming a backend that structurally belongs to the default pool or to one of the canary pools, that pool is used directly and the roll is skipped entirely. This is what keeps one client's whole session on whichever pool (default or canary) it first landed in, rather than re-rolling the split on every request.
- An empty `canary` list (the default) costs one `is_empty()` check and changes nothing about pre-existing behavior.

Source: [`service.rs`](../crates/lb-proxy/src/service.rs) (`resolve_default_or_canary_pool`, `CompiledCanaryPool`).

## Sticky Sessions

`[listeners.sticky]` layers session affinity on top of whatever strategy is configured, rather than being a strategy itself: once a client's request lands on a backend, the response carries a cookie naming it, and the next request from that client prefers that backend directly.

- **Cookie format:** `Set-Cookie: <cookie_name>=<percent-encoded backend id>; Path=/; HttpOnly; SameSite=Lax`, plus `Secure` when the listener terminates TLS, plus `Max-Age=<seconds>` when `max_age_secs` is configured (a session cookie — no `Max-Age` — otherwise). `cookie_name` defaults to `lb_sticky`.
- **Signing:** the cookie value is the raw backend id, **unsigned**. Backend ids are operator-chosen and already exposed unauthenticated via the admin API's backend listing, so they are not treated as secret. A forged or stale cookie can at worst name a real-but-ineligible or nonexistent backend.
- **Fallback:** on each request, the cookie is read and decoded; if it is absent, unparseable, or names a backend that `BackendPool::is_eligible` reports as not eligible, the request falls through to the listener's configured strategy exactly as if no cookie had been sent — never a hard error.
- The cookie is refreshed on every successful response, whether or not it matched an incoming pin, which both renews an active session's affinity and pins a first-time client from its very first response.
- Sticky is listener-level, not per-route: the same cookie applies uniformly to the default pool, every route's pool, and the canary split. A pin naming a backend outside the pool a given request resolved into simply fails eligibility and falls through.

Source: [`sticky.rs`](../crates/lb-proxy/src/sticky.rs).

## DNS-Based Backend Discovery

`[listeners.dns_discovery]` resolves a hostname on a poll interval instead of taking a static `[[listeners.backends]]` list; the two are mutually exclusive on one listener.

- **Polling:** a background task resolves `name`:`port` every `poll_interval_secs` (default 10s). A successful resolution replaces the pool's backend set via `BackendPool::apply_resolved`; a failed resolution logs a warning and leaves the previous backend set untouched.
- **Backend identity:** each resolved backend is assigned the id `dns:<resolved socket address>` (e.g. `dns:127.0.0.1:9001`), weight 1, and the configured `server_name` (required if `backend_tls` is set, and validated to not be a bare IP address). Because the id is derived from the resolved address, an address that reappears across polls is the same backend; an address that disappears and later reappears under a different IP is a new backend with fresh state.
- **In-flight state on churn:** `apply_resolved` diffs the new set against the previous one by id. A backend whose id persists across a poll keeps its health flag, circuit state, outlier-ejection flag, and in-flight connection count exactly as they were — DNS churn alone never resets them. A backend that drops out of the resolved set is removed from the pool immediately; an `ActiveConnGuard` for a request already in flight against it keeps decrementing safely on drop but no longer affects a live pool entry. Its active health-check task is aborted (not just detached — `AbortOnDrop` actually cancels it) as soon as it stops appearing in a poll. A newly-appearing address starts with a fresh circuit breaker, metrics and outlier tracking and its own health-check task, and is [held back until its first probe](health-checking.md#awaiting-the-first-probe) while another eligible backend exists.
- **Parity with static backends:** a DNS-discovered backend gets the same circuit breaker (including passive latency and concurrency thresholds), outlier detection and per-backend metrics as a statically configured one; see [health-checking.md](health-checking.md#dns-discovered-backends).
- The consistent-hash ring rebuilds only when the resolved set actually changes (see above); an identical re-resolution (same addresses) does not bump the pool's `version()` and does not trigger a ring rebuild.

Source: [`dns.rs` (lb-server)](../crates/lb-server/src/dns.rs), [`pool.rs`](../crates/lb-core/src/pool.rs) (`apply_resolved`), [`dns.rs` (lb-core)](../crates/lb-core/src/dns.rs).

## Retries and Backend Selection

The HTTP proxy allows at most one retry per request — two attempts total.

- **Different backend:** the retry excludes the backend that just failed, through `LoadBalancer::pick_excluding`. Each strategy applies its own logic to the remaining backends: round robin and weighted round robin rotate over them, least connections takes the least loaded, Peak EWMA samples two of them, and consistent hashing moves to the next backend on the ring, so a client's retry is itself deterministic. Only when the failed backend is the only eligible one is it retried, so a single-backend pool still gets its retry.
- The sticky-session pin, if present, is only honored on the **first** attempt — a pin that just failed is never retried against the same backend it named.
- **Idempotency:** a retry is only attempted for `GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, and `TRACE`. Any other method (notably `POST`, `PATCH`) fails out on the first error without a retry.
- **Retry budget:** `[listeners.retry_budget]` (`rate_per_sec`, `burst`) gates the retry itself, not the original request, via a token-bucket check under a single fixed key shared by the whole listener. A denied check aborts the retry (the first attempt's failure response is returned); an allowed check proceeds. This is HTTP-only — validated to be rejected on a TCP listener, whose own retry loop does not consult a listener-level budget.
- Every attempt, successful or not, reports its outcome back to the chosen strategy via `record_latency` (a no-op for every strategy except Peak EWMA + P2C), to the outlier detector if configured, and to the circuit breaker — so even a request that ultimately fails both attempts leaves the pool's eligibility state consistent for the next request.

Source: [`service.rs`](../crates/lb-proxy/src/service.rs) (`handle_inner`'s retry loop, `is_idempotent_method`).
