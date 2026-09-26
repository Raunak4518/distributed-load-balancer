# HTTP Features

This page documents the L7 behaviors an HTTP listener applies beyond plain request forwarding: protocol negotiation, header rewriting, response caching, response compression, and WebSocket/`Upgrade` proxying. Load balancing, health checking, rate limiting, and HTTP/2 abuse limits are documented separately and only cross-referenced here.

## HTTP/1.1 and HTTP/2

A listener's frontend protocol is decided once, at connection time, and never re-negotiated per request.

- **TLS listeners**: the protocol is chosen by ALPN during the TLS handshake. When `http2_enabled()` is true (see below), the server offers `["h2", "http/1.1"]` in that preference order; a client that offers both gets HTTP/2. When HTTP/2 is disabled, only `["http/1.1"]` is offered. The negotiated protocol is read directly off the completed handshake (`alpn_protocol()`), not sniffed from the byte stream.
- **Plaintext listeners are always HTTP/1.1.** There is no ALPN on a plaintext connection, and this project does not implement prior-knowledge h2c on the frontend: a plaintext listener refuses an HTTP/2 client-preface connection outright rather than accepting it. This is a deliberate choice, not an oversight — the edge is expected to terminate TLS for HTTP/2.
- HTTP/2 is only ever enabled for an HTTP listener with TLS configured. `http2_enabled()` returns `true` only when the listener's `protocol` is `http`, a `[listeners.tls]` section is present, and `[listeners.http2].enabled` is not explicitly `false` (it defaults to `true`). A `[listeners.http2]` section on a TCP listener or a plaintext HTTP listener is a config-validation error.

```toml
[[listeners]]
protocol = "http"
listen = "0.0.0.0:8443"

  [[listeners.tls.certificates]]
  name = "example"
  cert_file = "cert.pem"
  key_file = "key.pem"
  hostnames = ["example.com"]

  [listeners.http2]
  enabled = true
```

Per-connection HTTP/2 abuse limits (`max_concurrent_streams`, rapid-reset bounds, header/frame size caps, keepalive) are covered in [`edge-hardening.md`](edge-hardening.md); this page only covers protocol selection.

### Backend HTTP/2

- A **TLS backend** negotiates its own protocol via ALPN on the backend connection, independent of any listener setting; the pooled client offers both `h2` and `http/1.1` and takes whichever the backend's ALPN selects. A mixed fleet (some backends h2-capable, some not) works with no extra configuration.
- A **plaintext backend** has no ALPN to negotiate over, so it can only ever be reached as HTTP/2 via prior knowledge — no `Upgrade` dance, no preface sniffing, the connection simply starts with the HTTP/2 client preface. This is turned on per listener with `http2.backend_h2c = true`, and it is meaningful only when the backend is plaintext.
- **Incompatibility rule**: `http2.backend_h2c = true` combined with a `[listeners.backend_tls]` section is a config-validation error. A TLS backend already negotiates its protocol over ALPN; `backend_h2c` exists only because a plaintext backend has no such mechanism.

```toml
[listeners.http2]
backend_h2c = true
```

### Protocol metrics label

Every response is recorded under `lb_requests_total{listener, protocol, status}`, where `protocol` is `"http1"` or `"http2"` depending on which protocol the *frontend* connection negotiated (`http2` only ever appears on a TLS listener). This reflects the client-facing protocol, not the backend leg — a request proxied to an HTTP/1.1 backend over an HTTP/2 frontend connection is still counted as `protocol="http2"`. See [`metrics-reference.md`](metrics-reference.md) for the full metric.

Sources: [`http2.rs`](../crates/lb-core/src/http2.rs), [`config.rs`](../crates/lb-core/src/config.rs), [`lib.rs`](../crates/lb-server/src/lib.rs), [`wiring.rs`](../crates/lb-server/src/wiring.rs), [`forward.rs`](../crates/lb-proxy/src/forward.rs).

## Header handling

### Hop-by-hop stripping

`strip_hop_by_hop` removes headers that describe a single connection rather than the message, and it runs in both directions — once on the client's request before it is forwarded to the backend, and once on the backend's response before it is returned to the client. The same function is used both ways deliberately: these headers were never correct to forward, and one code path is one behavior to test.

Removed unconditionally: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`.

In addition, any header **named inside a `Connection` header** (comma-separated, case-insensitive — e.g. `Connection: keep-alive, X-Custom`) is treated as hop-by-hop for that hop and removed too, on top of the fixed list above.

This stripping is unconditional rather than gated on protocol: an HTTP/1.1 backend's response can now land on an HTTP/2 client stream (and vice versa), and HTTP/2 forbids hop-by-hop headers outright — a client may reject a response carrying one.

An `Upgrade`/`Connection: Upgrade` request bypasses this path entirely; see [WebSocket / Upgrade proxying](#websocket--upgrade-proxying) below.

### X-Request-Id

Every response gets an `x-request-id` header carrying a freshly generated UUIDv4. It is **never taken from an inbound request header** — at the edge, a client-supplied request ID is untrusted input that could be used to forge or collide log entries, so one is always minted server-side. This ID is used as the correlation key for the request's tracing span and (when access logging is sampled in) its access-log line, but it is **not forwarded to the backend** and is only added to the response the client sees.

### X-Forwarded-For / Forwarded

The proxy does **not inject** `X-Forwarded-For`, `Forwarded`, or `X-Forwarded-Proto`/`X-Forwarded-Host` into the backend request. Whatever such headers a client sends arrive at the backend unmodified (they are not hop-by-hop, so `strip_hop_by_hop` leaves them alone), but the load balancer adds nothing of its own. A backend that needs the real client IP must be given it some other way (e.g. via PROXY protocol upstream of this listener, if applicable to your deployment, or by trusting `X-Forwarded-For` only behind a controlled front end).

The one place `X-Forwarded-For` is read by the load balancer itself is as an optional rate-limit key source (`rate_limit.key = "header:X-Forwarded-For"`) — used only to bucket the local rate limiter, and explicitly never used in place of the real peer IP for that purpose unless configured to.

### HSTS injection

When a listener terminates TLS and `tls.hsts_max_age_secs` is configured above its default of `0`, every response from that listener gets `Strict-Transport-Security: max-age=<seconds>` added, regardless of status code — a rate-limited `429` or an upstream `503` gets the header exactly as a `200` does, because HSTS is a property of the host, not of any one response. Setting it to `0` (or omitting it) adds no header at all — `0` is deliberately not sent as `max-age=0`, since that has the opposite, actively-forgetting effect in a browser. HSTS on a TCP listener, or on an HTTP listener with no TLS, is a config-validation error.

```toml
[listeners.tls]
hsts_max_age_secs = 31536000
```

Sources: [`service.rs`](../crates/lb-proxy/src/service.rs), [`config.rs`](../crates/lb-core/src/config.rs).

## Response caching

An in-memory, listener-scoped cache that answers a repeated request straight from memory, skipping backend selection, the sticky pin, and the retry loop entirely. It is deliberately narrow, and every precondition below exists to make buffering a response safe to do at all — a response that fails any check is proxied exactly as it always was: streamed, uncached.

### What is cacheable

An entry is only stored, and only served, under all of the following:

- **Method**: only `GET`. Every other method bypasses the cache in both directions (never looked up, never stored).
- **Status**: only `200 OK`. Any other status is never cached.
- **Content-Length**: the response must declare an explicit `Content-Length`, and it must be within the cache's `max_entry_bytes`. A chunked or unknown-length response is never cached — its length can't be checked before the body is fully read, and buffering an unbounded body to find out would defeat the size cap it's trying to enforce.
- **`Cache-Control`** directives are read, case-insensitively, comma-split: `no-store`, `private`, and `no-cache` all suppress caching outright; `max-age=N` sets the entry's TTL (and `max-age=0`, or an unparseable value, also suppresses caching). Any other `Cache-Control` directive (`s-maxage`, `must-revalidate`, `stale-while-revalidate`, `no-transform`, ...) is not recognized and has no effect. A response with no `Cache-Control` header at all falls back to the cache's configured `default_ttl_secs`.

### Key composition

The cache key is `"{method}|{host}|{path_and_query}"`, where `host` is the request's `Host` header if present, else the request URI's authority (the fallback that keys an HTTP/2 request correctly when the client sent `:authority` rather than a `Host` header). This means:

- Two virtual hosts sharing the same path (matched via a `[[listeners.routes]]` `host` rule) never collide.
- Different query strings (`?page=2` vs `?page=3`) are distinct entries; header order elsewhere in the request has no effect on the key.
- A listener with routing rules still uses one cache, correctly partitioned by the key alone — there is no separate cache per route.

### TTL rules

- `Cache-Control: max-age=N` (N > 0) sets the TTL to N seconds.
- No `Cache-Control` header at all: the TTL is the cache's configured `default_ttl_secs`.
- `no-store`, `private`, `no-cache`, or `max-age=0`: not cached.
- Expiry is checked lazily on every `get` (an expired entry is removed on the read that finds it, so a request landing between sweeps still sees a correct miss) and reclaimed proactively by a periodic sweep (see below).

### Memory accounting and caps

Two independent size limits apply:

- `max_entry_bytes`: caps one entry's body size. A response whose declared `Content-Length` exceeds this is never cached.
- `max_total_bytes`: caps the cache's aggregate accounted size across all entries. Accounted size per entry is `320 bytes` fixed overhead + key length + body length +, per response header, `128 bytes` overhead plus that header's name and value lengths. This means headers are not free — a response with many or large headers (e.g. several `Set-Cookie` values) counts meaningfully toward the budget even with a tiny body, and a zero-length body still consumes its full header/key/overhead accounting.
- The total-bytes check is a **soft cap**: a brief overshoot under concurrent inserts racing the check is accepted rather than serialized against.

### No eviction policy

There is no LRU, LFU, or any other eviction algorithm. Once `max_total_bytes` is reached, **new entries are simply rejected** until something already stored expires and is reclaimed — existing live entries are never evicted to make room for a new one. An operator who wants headroom for new content under sustained load needs enough `max_total_bytes` for it, or an appropriately short `default_ttl_secs`/`Cache-Control: max-age`; there is no cache pressure mechanism beyond expiry.

### Sweep

A background task runs `sweep_expired()` on a fixed interval for the life of the listener, scanning every entry and removing any past its `expires_at`, reclaiming its share of `max_total_bytes`. This exists because lazy removal on `get` only reclaims space for keys someone still asks for — a cache full of short-TTL entries that traffic has moved on from would otherwise stay full (and keep rejecting new entries) indefinitely.

### Limitations: Set-Cookie, Authorization/Cookie, and Vary

State these plainly, since they differ from what many caches do by default:

- **A backend's own `Set-Cookie` header is cached and replayed verbatim** to every future client served from that entry, if the response is otherwise cacheable. The cache has no special-case exclusion for `Set-Cookie`. The one thing that is *not* cached is a load-balancer-injected sticky-session cookie — the cache-eligibility decision is made, and the response body buffered, before the sticky `Set-Cookie` is added to the outgoing response, specifically so a stored entry never carries one client's sticky pin.
- **`Authorization` and `Cookie` request headers are not treated specially.** There is no logic that skips caching a response to an authenticated or cookie-bearing request. If a backend returns `200` with a `Content-Length` and no `Cache-Control` ruling it out, its response is cached and can be served to a different client's request that hits the same key, regardless of what credentials either request carried.
- **`Vary` is not honored.** The cache key is method/host/path/query only; a response's `Vary` header (e.g. `Vary: Accept-Encoding`, `Vary: Cookie`) has no effect on key composition or on cache admission.

Operators enabling this cache on a route that serves personalized or authenticated content should rely on the backend sending `Cache-Control: private`/`no-store` for such responses — the load balancer will not detect that case on its own.

### Configuration

```toml
[listeners.cache]
max_entry_bytes = 2097152      # default: 2 MiB
max_total_bytes = 67108864     # default: 64 MiB
default_ttl_secs = 60          # default: 60
```

`cache` is an HTTP-only setting; a `[listeners.cache]` section on a TCP listener is a config-validation error.

### Metrics

`lb_cache_result_total{listener, result="hit"|"miss"}` counts every `GET` lookup against a configured cache. Cache hits skip backend selection entirely (proven in the load balancer's own test suite: a cache hit never calls into the `LoadBalancer`).

Sources: [`cache.rs`](../crates/lb-proxy/src/cache.rs), [`service.rs`](../crates/lb-proxy/src/service.rs), [`config.rs`](../crates/lb-core/src/config.rs).

## Response compression

Response bodies can be compressed on the way to the client, negotiated against the request's `Accept-Encoding`. This is built on `tower-http`'s `CompressionLayer` rather than a hand-rolled encoder, wrapped as a uniform tower middleware stack in front of `lb_proxy::handle` regardless of whether compression is enabled for the listener.

- **Algorithms**: gzip, brotli, deflate, and zstd (the crate's `compression-full` feature set).
- **Negotiation**: standard `Accept-Encoding` content negotiation — a client that sends no `Accept-Encoding` gets the body back unencoded even on a listener with compression enabled; this is negotiation, not something imposed on every response.
- **What is skipped**: `tower-http`'s default predicate (used as-is; this project does not customize it) skips responses that are already encoded and responses below its minimum size threshold, in addition to whatever the negotiated encoding otherwise excludes.
- **Toggle**: a per-listener boolean, off by default. When disabled, no response is ever encoded, even if the client explicitly requests it.

```toml
[[listeners]]
protocol = "http"
listen = "0.0.0.0:8080"
compression = true
```

`compression` is an HTTP-only setting; a `[[listeners]]` entry with `protocol = "tcp"` and `compression = true` is a config-validation error.

Sources: [`compression.rs`](../crates/lb-server/src/compression.rs), [`lib.rs`](../crates/lb-server/src/lib.rs), [`config.rs`](../crates/lb-core/src/config.rs).

## WebSocket / Upgrade proxying

### Detection

A request is treated as a protocol-upgrade request when its `Connection` header contains an `upgrade` token (case-insensitive, comma-separated — a client may send `Connection: keep-alive, Upgrade`) **and** its `Upgrade` header names something non-empty. Detection is generic, not specific to `websocket`: any HTTP/1.1 `Upgrade` request takes this path. An HTTP/2 client connection has no `Upgrade` header semantics and is naturally excluded rather than specially guarded against.

This check runs after rate limiting, the WAF, the response-cache lookup, and route resolution, and before the body read, the sticky pin, and the retry loop — none of which apply to a connection that is about to stop being ordinary HTTP.

> **Known limitation:** because the cache lookup precedes this check and keys only on method, host and path, a WebSocket handshake (a `GET`) on a listener with `[listeners.cache]` configured is answered from the cache if a plain `GET` response for the same URL is stored, and the upgrade never happens. Do not enable caching on a listener whose WebSocket endpoints also serve cacheable plain `GET` responses at the same path.

### Dedicated, non-pooled backend connection

The upgrade path dials its own one-off HTTP/1.1 connection to the backend directly (`hyper::client::conn::http1::handshake`), bypassing the shared pooled client entirely. The pooled client has no special handling for a `101` response before deciding whether to return a connection to its idle pool, so reusing it here would risk a genuinely dangerous bug: a socket mid-WebSocket-stream being handed to an unrelated pooled request. On a TLS backend, this dedicated connection also pins its own ALPN offer to `http/1.1` only, since the plain `hyper::client::conn::http1` handshake cannot parse an h2 byte stream and a pooled connection's usual `[h2, http/1.1]` ALPN list would risk exactly that mismatch.

Request headers (`Connection`, `Upgrade`, `Sec-WebSocket-*`, etc.) are forwarded to the backend **verbatim** — `strip_hop_by_hop` is deliberately not applied on this path, since those are exactly the headers the backend needs intact to answer the handshake.

v1 scope is HTTP/1.1 only on both legs: an h2 client's own upgrade mechanism (RFC 8441 extended CONNECT) is a materially different bootstrapping protocol and is not implemented. There is also no retry: one backend is picked and one attempt is made — unlike the ordinary request path's 2-attempt retry loop.

### 101 relay

If the backend answers with `101 Switching Protocols`, its response headers are relayed to the client verbatim and both sides' connections are handed off (`hyper::upgrade::on`) to a background byte-pump task that relays raw bytes bidirectionally until either side closes. If the backend answers with anything other than `101` (it declined, or doesn't support the upgrade), there is nothing to relay — the response is treated as an ordinary response and goes through the normal `strip_hop_by_hop` path instead.

The relay uses `try_join!`, not `select!`, on both directions: a half-close in one direction must not tear down the other side.

### Idle timeout

Once the WebSocket/Upgrade connection is established, `forward_timeout` and `body_read_timeout` no longer apply — a long-lived WebSocket session is expected to sit without exchanging bytes. Instead, a dedicated `websocket_idle_timeout` (default 300 seconds) bounds how long the relay may go with **no activity in either direction** before it is torn down.

```toml
[[listeners]]
protocol = "http"
listen = "0.0.0.0:8080"
websocket_idle_timeout_ms = 60000   # default: 300000 (5 minutes)
```

`websocket_idle_timeout_ms` is an HTTP-only setting; on a TCP listener, the equivalent protection is the listener's own `idle_timeout_ms`, and setting `websocket_idle_timeout_ms` there is a config-validation error.

### Metrics

`lb_websocket_upgrades_total{listener, result}` with `result` in `success`, `backend_declined`, `backend_unreachable` — recorded once per upgrade attempt, before the relay task starts.

Sources: [`upgrade.rs`](../crates/lb-proxy/src/upgrade.rs), [`service.rs`](../crates/lb-proxy/src/service.rs), [`config.rs`](../crates/lb-core/src/config.rs).

## Connection pooling to backends

Ordinary (non-upgrade) requests share a per-listener pooled `hyper_util` client (`hyper_util::client::legacy::Client`) rather than dialing a fresh backend connection per request. The pool is keyed per backend host and applies:

- A fixed connect timeout of 2 seconds and a fixed idle-connection timeout of 30 seconds — both constants, not configurable, since the per-request `forward_timeout` is the knob operators actually need and these two exist only to bound resource usage.
- A fixed cap of 32 idle connections kept per backend host; a connection beyond that cap is evicted from the idle pool (and redialed on the next request) rather than kept open.
- The same client instance backs both real traffic and this listener's active health probes when probing is client-based, so a probe can never observe a backend over a different transport (TLS trust roots, ALPN offer, pinned dial address) than real traffic does.
- A `dns_discovery` + `backend_tls` listener, where several backends can share one `server_name`, gets a separate per-backend client table instead (`per_backend_client`) rather than sharing one pool keyed only by host — a pool keyed by host alone would let connections to different backends be reused interchangeably.

The WebSocket/Upgrade path never uses this pool (see above) — it is the one request path with its own dedicated, non-pooled backend connection.

Sources: [`forward.rs`](../crates/lb-proxy/src/forward.rs).

## See also

- [`edge-hardening.md`](edge-hardening.md) — HTTP/2 abuse-resistance limits (rapid reset, concurrent streams, header/frame size caps).
- [`tls.md`](tls.md) — TLS termination, ALPN configuration, and certificate handling in more depth.
- [`request-lifecycle.md`](request-lifecycle.md) — where these features sit in the overall per-request flow, including rate limiting, WAF, and routing.
- [`metrics-reference.md`](metrics-reference.md) — full metric names and labels.
- [`configuration-reference.md`](configuration-reference.md) — complete field listing for every setting referenced above.
