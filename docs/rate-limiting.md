# Rate Limiting

Every listener enforces a per-key GCRA (Generic Cell Rate Algorithm) limiter on the request path. If `[cluster]` is configured, a second, cluster-wide check runs after the local one; that check is documented in [`cluster-coordination.md`](cluster-coordination.md). This page covers the local limiter, its bounded key tracking, the response a limited client receives, and the retry budget, which reuses the same algorithm for a different purpose.

## GCRA algorithm

The limiter is [`Gcra`](../crates/lb-ratelimit/src/gcra.rs). Each tracked key holds a single value: its theoretical arrival time (TAT), stored as an `Instant`.

Two derived constants come from the listener's `rate_limit` config:

- `period = 1 / rate_per_sec` — the minimum spacing between permitted requests.
- `tau = period * burst` — how far into the future the TAT may run before a request is refused.

On each request, admission is:

```
tat        = max(stored_tat, now)
new_tat    = tat + period
allow_at   = new_tat - tau
if allow_at <= now:
    stored_tat = new_tat   # Allow
else:
    deny, retry_after = allow_at - now
```

A key with no stored TAT is initialized to `now` on its first request, which is why the first `burst` requests from a fresh key are always admitted back to back: each one only pushes `allow_at` `period` further out, and it takes `burst` requests before `allow_at` finally lands in the future.

### Worked example

`rate_per_sec = 10.0`, `burst = 3` → `period = 100ms`, `tau = 300ms`. All requests arrive at `t = 0`:

| Request | `stored_tat` before | `new_tat` | `allow_at` | Result |
|---|---|---|---|---|
| 1 | 0ms | 100ms | -200ms | Allow, `stored_tat = 100ms` |
| 2 | 100ms | 200ms | -100ms | Allow, `stored_tat = 200ms` |
| 3 | 200ms | 300ms | 0ms | Allow (`allow_at <= now`), `stored_tat = 300ms` |
| 4 | 300ms | 400ms | 100ms | Deny, `retry_after = 100ms` |

The fourth request must wait 100ms — one `period` — before the bucket admits again, at which point `now` will have caught up to `allow_at`.

## Configuration

```toml
[listeners.rate_limit]
key = "source_ip"          # or "header:X-Api-Key"
rate_per_sec = 10.0
burst = 20
max_tracked_keys = 100000  # optional, defaults to 100000
```

`key` selects what identifies a caller:

- `source_ip` — the connection's real peer address. This is always the raw peer IP, never a client-supplied header such as `X-Forwarded-For`; trusting a client-controlled header here would let any caller mint itself a fresh bucket just by changing it. See [`edge-hardening.md`](edge-hardening.md) for the separate, trusted-proxy-only path (`proxy_protocol`) that can change what "peer address" means.
- `header:<name>` — the named request header's value, or the literal string `unknown` if the header is absent. HTTP listeners only; a TCP listener has no headers, and its config is rejected at startup if `key` names one.

`rate_per_sec` and `burst` must both be positive; `max_tracked_keys` must be positive if set. See [`configuration-reference.md`](configuration-reference.md) for the full listener schema.

## Bounded key tracking and the overflow bucket

The limiter's state is a concurrent map from key to TAT. Nothing evicts a key on its own between sweeps (see below), so without a cap an attacker who sprays unique source IPs or header values could grow that map without bound.

`max_tracked_keys` caps distinct keys. Once the map is at capacity, every key that has not already been seen is redirected to one shared overflow bucket, keyed by the sentinel string `"\u{0}overflow"` — the NUL prefix cannot appear in an IP literal or an HTTP header value, so a client cannot forge a collision with it. Established keys keep their own individual budget; only newcomers share the overflow bucket once the map is full.

This is a deliberate three-way tradeoff:

- Rejecting every new key outright would deny legitimate new clients during an attack.
- Evicting an existing (LRU) key to make room would let an attacker evict established, well-behaved clients.
- Routing newcomers into one shared bucket means a spray of new keys collectively gets, at most, the throughput of a single client — while every established key is untouched.

The current tracked-key count is maintained as an atomic counter updated on insert, rather than computed from the map's real size on every request; `DashMap::len()` walks every shard, which measured several times slower than the rest of the admission check combined. This counter can lag the true count slightly during a concurrent sweep, which is acceptable since the cap is a safety bound, not an exact quota.

## Sweeper

A background task ([`sweeper.rs`](../crates/lb-ratelimit/src/sweeper.rs)) runs on a fixed interval and evicts keys whose TAT has fallen far enough behind the clock that the key is considered idle. In the deployed configuration this task runs every 30 seconds and evicts keys idle for more than 60 seconds; both intervals are set in `lb-server`'s wiring, not exposed as config fields. Each sweep also resynchronizes the atomic tracked-key counter against the map's real length.

## Response when limited

A request denied by the local limiter gets:

- Status `429 Too Many Requests`
- A `Retry-After` header, in whole seconds, from the denial's `retry_after` (rounded down — a sub-second wait is reported as `0`)
- Plain-text body `rate limit exceeded`

No other headers are added, and the backend is never contacted — rejection happens before route resolution, the cache, and the WAF check. See [`request-lifecycle.md`](request-lifecycle.md) for exactly where this check sits relative to the rest of the pipeline. A request that also fails the cluster-wide check (`cluster-coordination.md`) gets the same status and body, but no `Retry-After` header — the cluster coordinator's admission check does not return a wait time, only allow/deny.

## Retry budget

The retry budget is a second, independent use of the same `Gcra` type, configured separately per listener:

```toml
[listeners.retry_budget]
rate_per_sec = 5.0
burst = 10
```

It is optional; a listener with no `[listeners.retry_budget]` section retries without any budget check. When present, it gates the single retry the proxy may attempt after a backend connect or timeout failure on an idempotent request (`GET`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`) — a non-idempotent method, or a request already on its second attempt, never consults it. Unlike the per-caller rate limiter, the budget tracks exactly one key (an internal constant, not derived from the request), so it is constructed with `max_tracked_keys = 1`: it is a single shared bucket capping the *listener's* total retry rate, not a per-client allowance. A denied retry simply gives up and returns the original backend error to the client. See [`load-balancing.md`](load-balancing.md) for the rest of the retry and backend-selection mechanics.
