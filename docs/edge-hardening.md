# Edge Hardening

This page catalogs every defense the load balancer applies against hostile or broken clients, before or instead of forwarding a request to a backend: connection admission control, slowloris-style read/write stalls, body size limits, HTTP/2 protocol limits (including the Rapid Reset mitigation for CVE-2023-44487), PROXY protocol trust handling, the built-in WAF, admin API authentication, and the DNS-pinned backend resolver. For the request path these defenses sit in front of, see [request-lifecycle.md](request-lifecycle.md); for the metrics they emit, see [metrics-reference.md](metrics-reference.md); for TLS-specific hardening (handshake timeout, cipher/version policy, certificate reload), see [tls.md](tls.md).

## Connection admission control

Two independent caps are enforced before a connection is handed to any protocol logic. Both are held for the entire lifetime of the connection, including a TLS handshake if one applies.

### Global cap

`max_connections` (default `10000`) is a `tokio::sync::Semaphore`. The accept loop acquires a permit **before** calling `accept()` — not after. At capacity the loop simply stops calling `accept()`; the kernel's own backlog absorbs and then refuses further connection attempts. This means a saturated load balancer never spends a file descriptor or a task on a connection it intends to discard. See [`lib.rs`](../crates/lb-server/src/lib.rs) (`serve_listener`).

Because saturated connections are refused by the kernel rather than by this process, there is no per-connection rejection to count. Instead, `lb_connections_rejected_total{reason="max_connections"}` is incremented each time the accept loop finds the cap saturated; treat a rising value as "the listener spent time at capacity", not as a count of refused clients.

### Per-IP cap

`max_connections_per_ip` (default `100`) is checked immediately after `accept()`, keyed on the TCP peer address of the socket. If the source IP is already at its limit, the socket is dropped with no response. The tracking map ([`limits.rs`](../crates/lb-server/src/limits.rs)) removes an IP's entry as soon as its count returns to zero — including on a rejected attempt, which creates no entry at all — so a client cycling through source addresses cannot grow the map without bound.

Rejections here increment `lb_connections_rejected_total{reason="max_per_ip"}`.

> **Behind a proxy:** on a listener with `proxy_protocol = true`, the per-IP slot is taken after the [PROXY protocol](#proxy-protocol) header is read, keyed on the real client address it announces, so every client behind one ELB or CDN node gets its own budget. Until the header arrives (at most `proxy_protocol_timeout_ms`), the connection is bounded by the global `max_connections` cap only.

```toml
[[listeners]]
max_connections = 10000
max_connections_per_ip = 100
```

`max_connections_per_ip` cannot exceed `max_connections`; both must be positive. Configuration validation rejects a listener that violates either.

## Slowloris defenses (read side)

Three independent timeouts bound how long a client may take to *send* data, at three different points in the request:

| Defense | Config field / default | Applies to | Response |
|---|---|---|---|
| Header read timeout | `header_read_timeout_ms` / `5000` | HTTP/1.1 request head | Connection dropped (hyper's `http1::Builder::header_read_timeout`) |
| HTTP/2 preface deadline | (reuses `header_read_timeout_ms`) | HTTP/2, until the client's preface and first SETTINGS frame have arrived | Connection dropped |
| Body read timeout | `body_read_timeout_ms` / `10000` | Request body, either protocol | `408 Request Timeout` |

### Header read timeout (HTTP/1.1)

A classic slowloris attack sends request headers one byte at a time to hold a connection slot open indefinitely. `header_read_timeout_ms` bounds the time hyper's HTTP/1.1 server is willing to wait for a complete request head; see the `.header_read_timeout(...)` call in [`lib.rs`](../crates/lb-server/src/lib.rs). There is deliberately no equivalent hyper setting for an *established* HTTP/2 connection — an idle h2 connection is normal, and the PING keepalive below (not a header-read timeout) is what distinguishes idle from dead.

### Preface deadline (HTTP/2)

hyper's own HTTP/2 PING keepalive only arms once the client's preface and initial `SETTINGS` frame have already arrived. A client that completes a TLS handshake, negotiates `h2` over ALPN, and then sends nothing — or only part of the preface — is never timed out by hyper on its own, and would hold its connection permit and per-IP slot forever. [`first_byte.rs`](../crates/lb-server/src/first_byte.rs) closes this gap: `FirstByteDeadline` wraps the stream in a deadline armed at construction (using `header_read_timeout_ms`, the same knob HTTP/1.1 uses) that is disarmed only once the client's full 24-byte connection preface and its complete first frame — the SETTINGS frame RFC 9113 requires next, header and payload — have been read. Sending one byte, or dribbling the preface, does not disarm it; the whole handshake must arrive within the deadline. From then on hyper's PING keepalive governs the established connection.


### Body read timeout

A size limit alone does not bound time — a client could send an admitted body at one byte per second. `body_read_timeout_ms` wraps the entire body read (`tokio::time::timeout` around `read_bounded`, in [`service.rs`](../crates/lb-proxy/src/service.rs)) and returns `408 Request Timeout` on expiry, distinguishing "took too long" from "sent too much" (413, below).

## Slowloris defenses (write side)

None of the read-side timeouts bound the opposite direction: a client that sends a normal request and then reads the response one byte at a time, or stops reading once its TCP receive window fills, can hold the connection task, its global permit, and its per-IP slot open indefinitely — hyper's server has no write timeout of its own.

`write_timeout_ms` (default `30000`) closes this gap. [`write_timeout.rs`](../crates/lb-server/src/write_timeout.rs) wraps the connection stream in `WriteIdleTimeout`, a continuous idle timeout (not a one-shot deadline): every write that makes progress resets the clock, so a slow-but-steady client is never punished, but a write that produces no progress within the timeout fails the connection. It composes transparently with `FirstByteDeadline` — each wrapper is a pure passthrough on the direction it doesn't own — and applies to both HTTP/1.1 and HTTP/2 connections on a listener.

```toml
[[listeners]]
write_timeout_ms = 30000
```

## Request body size limit

`max_request_body_bytes` (default `1048576`, i.e. 1 MiB) bounds how much of a request body the proxy will buffer, and the bound holds while reading: a request declaring a larger `Content-Length` is refused with `413 Payload Too Large` before any of its body is read, and a body without a declared length is read through a counting limiter that stops as soon as the limit is passed, so memory per request never exceeds the limit plus one frame. The request is never forwarded.

Only bodies up to `request_buffer_bytes` (default 64 KiB) are buffered whole; those can be retried on another backend. Once a body passes that size, what has been read is sent to the backend and the rest is streamed through as the client sends it, still counted against `max_request_body_bytes`: a client that goes over the limit mid-stream gets `413`, the upstream request is aborted, and `lb_requests_streamed_total` counts every streamed request. Memory per request is therefore bounded by `request_buffer_bytes` plus one frame, not by `max_request_body_bytes`. A streamed request is never retried, since its body has already been consumed; the upload as a whole must still finish within `body_read_timeout` (and `request_timeout_ms`, if set). This is enforced independently of the body read timeout below — a body can be rejected for being too large well before it would have timed out.

```toml
[[listeners]]
max_request_body_bytes = 1048576
```

## HTTP/2 limits

HTTP/2 is negotiated over ALPN during the TLS handshake and is on by default on every TLS listener; an operator who writes no `[listeners.http2]` section still gets every protection below at its default value ([`http2.rs`](../crates/lb-core/src/http2.rs)). A plaintext listener always stays HTTP/1.1 — `[listeners.http2]` is rejected on a `tcp` listener at config-parse time.

| Setting | Default | Purpose |
|---|---:|---|
| `max_concurrent_streams` | `128` | Concurrent streams (requests) per connection. |
| `max_pending_accept_reset_streams` | `20` | Rapid Reset mitigation (CVE-2023-44487) — see below. |
| `max_local_error_reset_streams` | `128` | Bounds resets this side is forced to send back to a client whose frames keep failing protocol validation. h2's own default is 1024; this is deliberately tighter. |
| `max_header_list_size` | `16384` | Bounds decoded HPACK/`CONTINUATION` header size. |
| `max_frame_size` | `16384` | Per-frame size ceiling. |
| `keep_alive_interval_secs` | `20` | Interval between PING frames on an established connection. |
| `keep_alive_timeout_secs` | `10` | Time to wait for a PING response before treating the connection as dead. |

```toml
[listeners.http2]
max_concurrent_streams = 128
max_pending_accept_reset_streams = 20
max_local_error_reset_streams = 128
max_header_list_size = 16384
max_frame_size = 16384
keep_alive_interval_secs = 20
keep_alive_timeout_secs = 10
```

### Rapid Reset (CVE-2023-44487)

In a Rapid Reset attack, a client opens an HTTP/2 stream and immediately sends `RST_STREAM` to cancel it, before the server has finished processing it. Because the stream is never concurrent with anything, this evades `max_concurrent_streams` entirely while still forcing the server to allocate and tear down per-stream state on every cycle. `max_pending_accept_reset_streams` bounds how many such resets the connection will tolerate before hyper's `h2` layer penalizes it.

The default of `20` is pinned deliberately in both directions: it is exactly h2's own built-in default (`DEFAULT_REMOTE_RESET_STREAM_MAX`), so a *looser* configured value would be inert — the `h2` crate enforces its own bound underneath regardless of what is asked for here — while a *stricter* value starts penalizing ordinary client-initiated cancellations (a browser navigating away, an abandoned image load), which is not something a mitigation should do as a side effect.

### Per-IP concurrency under HTTP/2

`max_connections_per_ip` bounds concurrent *connections* per source IP, but under HTTP/2 a single connection carries many concurrent streams, so a connection cap alone no longer bounds per-IP *work*. At the defaults, `max_connections_per_ip` (100) times `max_concurrent_streams` (128) puts the per-IP concurrency ceiling at 12,800 requests; since each in-flight request can buffer a body up to `max_request_body_bytes` (1 MiB by default), that is a per-IP memory ceiling on the order of 12.8 GiB — not the roughly 100 MiB that the same connection cap implies under HTTP/1.1, where one connection carries at most one in-flight request.

`max_concurrent_streams` does not by itself restore an HTTP/1.1-equivalent per-IP bound. The mandatory `[listeners.rate_limit]` section is what actually keeps admitted concurrency down in practice: it is checked before the request body is read (see [request-lifecycle.md](request-lifecycle.md)), and with `key = "source_ip"`, its `burst` value is the real per-IP concurrency bound under HTTP/2 — not `max_concurrent_streams`. Operators running HTTP/2 who want a tighter bound should size `rate_limit.burst` with this multiplication in mind rather than relying on the HTTP/2 stream limit alone. Rate limiting itself — key sources, the token-bucket algorithm, cluster-wide budgets — is covered in [rate-limiting.md](rate-limiting.md).

## PROXY protocol

`proxy_protocol = true` on a listener enables reading a PROXY protocol v1 (text) or v2 (binary) header at the start of every connection, before TLS or plaintext HTTP begins, letting a trusted front-end (load balancer, CDN, ELB) tell this listener the real client address instead of its own. Version is auto-detected from the first byte ([`proxy_protocol.rs`](../crates/lb-server/src/proxy_protocol.rs)).

`proxy_protocol_timeout_ms` (default `1000`) bounds how long the listener will wait for this header to arrive; expiry drops the connection.

### Trust model

This is a hard trust boundary, not a best-effort parse. A listener with `proxy_protocol = true` is meant to receive connections from exactly one trusted front-end that always sends this header first. Consequently:

- `proxy_protocol_trusted_cidrs` is **required** with `proxy_protocol = true`: the networks the front-end connects from. A connection whose TCP peer is outside every listed network is closed immediately after `accept()`, before a single byte of it is read, and counted as `lb_connections_rejected_total{reason="untrusted_proxy"}`. Without this, anyone who can reach the listener directly could send a forged header and pick their own client address — defeating per-IP limits, rate limiting keyed on `source_ip`, and `X-Forwarded-For`. To accept a header from any source anyway, list `"0.0.0.0/0"` and `"::/0"` explicitly. IPv4-mapped IPv6 peers (`::ffff:10.0.0.1`) are matched against IPv4 networks.

- A **missing or malformed header** (bad signature, truncated line, unparseable address, wrong protocol keyword, oversized v1 line, v2 length exceeding a 4096-byte sanity bound) is treated as **fatal** — the connection is dropped, never falls back to the raw TCP peer address.
- v1 `UNKNOWN` and v2 `LOCAL`/`AF_UNSPEC` are valid headers that carry no client identity (e.g. the front-end's own health check); these fall back to the raw TCP peer address, which is the correct behavior for a connection that genuinely has no downstream client.

The fatal-on-malformed choice is deliberate: falling back to the raw peer on a bad header would let an attacker who can reach the listener directly (bypassing the trusted front-end) simply omit the header and inherit whatever trust that implies, or send a forged header to bypass per-client rate limiting.

```toml
[[listeners]]
proxy_protocol = true
proxy_protocol_timeout_ms = 1000
proxy_protocol_trusted_cidrs = ["10.0.0.0/8"]   # the front-end's addresses
```

## Web application firewall

The built-in WAF ([`waf.rs`](../crates/lb-proxy/src/waf.rs)) is a small, fixed set of case-folded substring checks against a request's path and query string (and, if enabled, three specific headers), run before route resolution, the response cache, and any cluster-wide rate-limit budget consumption — a blocked request never touches any of that state.

Enable it per listener with `[listeners.waf]`:

```toml
[listeners.waf]
mode = "block"           # or "log"
inspect_headers = false
```

- **Rule set**: fixed, built-in token lists for three categories, checked in this order — SQL injection (`union select`, `' or '1'='1`, `or 1=1`, `drop table`, `insert into`, `xp_cmdshell`, `sleep(`, `benchmark(`, `;--`), XSS (`<script`, `javascript:`, `onerror=`, `onload=`, `<svg/onload`, `<img src=x`), and path traversal (`../`, `..\`, and three percent-encoded variants of `../`). The first category that matches wins; there is no operator-supplied rule syntax.
- **What is matched**: the request's path and query string always. If `inspect_headers = true`, also the literal values of `User-Agent`, `Referer`, and `Cookie` — no other header is inspected.
- **Block vs. log mode**: `mode = "block"` (the default when the section is present) returns `403 Forbidden` and never forwards the request. `mode = "log"` records the match (a `lb_waf_blocked_total{rule=...}` increment and a `warn`-level log line) but forwards the request exactly as if the section were absent — the "roll out in detection mode first" path for an operator who wants to see what the rules would have caught before enforcing them.
- **Limitations**: this is not a rule engine. There is no percent-decoding or other canonicalization before matching, so an encoded bypass (e.g. double-encoded traversal sequences not in the fixed list) is a real evasion. Matching is a plain case-insensitive substring search, not a regex or a parser, and the rule set is compiled in — it cannot be extended or tuned per deployment beyond `mode` and `inspect_headers`. HTTP-only: configuring `[listeners.waf]` on a `tcp` listener is rejected at config-parse time, since there is no path or query on a raw TCP stream.

Matches are recorded per rule: `lb_waf_blocked_total{listener, rule="sql_injection"|"xss"|"path_traversal"}`.

## Admin API authentication

The admin listener (`[admin]`) serves `/metrics`, `/healthz`, `/ready`, any `/backends/...` drain/undrain routes, and `/cache/.../purge` on a port meant to stay off the public internet. Configuring `token` or `token_env` under `[admin]` gates every one of those routes except the `/healthz` and `/ready` probes behind a bearer token:

```toml
[admin]
listen = "127.0.0.1:9090"
token_env = "LB_ADMIN_TOKEN"   # preferred: config files end up in version control
# token = "literal-value"      # alternative; at most one of the two may be set
```

- The token is read from the `Authorization: Bearer <token>` header and checked in [`admin.rs`](../crates/lb-metrics/src/admin.rs) before any route (including an extension route like `/backends/.../drain`) runs.
- The comparison uses `subtle::ConstantTimeEq` rather than a byte-wise `==`, specifically so that how much of a presented token matches the real one cannot be inferred from response timing.
- A missing or mismatched token — including one of a different length than the real token, which must not panic the constant-time comparison — returns `401 Unauthorized` with a `WWW-Authenticate: Bearer` header, and increments `lb_admin_auth_failures_total`.
- `token` and `token_env` are mutually exclusive; setting both is a config validation error. An empty resolved token is also rejected at startup.
- `[admin.tls]` serves the admin API over TLS, and `client_ca_file` makes it require a client certificate from that CA (mutual TLS), which on its own satisfies the non-loopback authentication rule. A token alone over plaintext can be sniffed by anything on the path, so prefer TLS whenever the admin port is reachable beyond the host.
- A second, read-only token (`read_token` / `read_token_env`) can be issued to dashboards and scrapers: it may read every route, but a write (`POST` to drain/undrain or cache purge) with it gets `403 Forbidden`. The full `token` can do both.
- Every admin request that is not a `GET`/`HEAD` — allowed or refused — is logged under the `lb_admin_audit` tracing target with its method, path, client address, role (`admin`, `read_only`, `unauthenticated`, or `none` for an unrecognized token), whether it was allowed, and the response status. Route that target to durable storage to keep an audit trail of who drained what.
- The admin listener accepts at most 64 connections at once (further ones wait in the kernel backlog) and closes any connection that has not sent a complete request head within 5 seconds, so it cannot be held open by idle or slowloris clients.
- `/healthz` and `/ready` answer without a token, so an orchestrator or load balancer can probe them without holding the secret. Each reveals one bit.
- A token is **required** when `admin.listen` is not a loopback address: startup fails unless `token`/`token_env` is set or `allow_unauthenticated = true` explicitly accepts an open admin port. A loopback-only admin listener may still run without one.

**No token configured is a valid, common state** — the admin listener runs exactly as unauthenticated as if this feature did not exist, which matters for anyone who fronts the admin port with their own network-level access control. This state is not silent: `lb_admin_auth_disabled` is set to `1` (and to `0` once a token is configured), and a `warn`-level log line is emitted at startup naming exactly what is reachable without a token (metrics, health, and backend drain/undrain) — a deliberate choice to make an unauthenticated admin port visible on a dashboard rather than a config gap nobody notices.

## DNS-pinned backend resolver

For a `backend_tls` listener, the outbound request URI's authority is the backend's configured `server_name` (so TLS certificate verification checks the name the operator intended, via SNI and hostname verification). Handed to a stock connector, that same authority would also be what gets **resolved and dialed** — meaning a stock `HttpConnector`'s default `Resolve` implementation would perform a real DNS lookup on `server_name` and connect to whatever it returns, silently reintroducing DNS-based backend selection and ignoring the operator-configured backend `address` entirely.

`PinnedResolver` ([`resolver.rs`](../crates/lb-proxy/src/resolver.rs)) replaces that default resolver with a fixed `server_name -> address` table built once per listener from that listener's own static backend list. It never performs a real DNS query. A name with no entry in the table is surfaced as an ordinary connector error (not a panic) — this should be unreachable in practice, since every request this proxy forwards uses a URI host that is always one of the listener's own configured `server_name` values, but the resolver does not trust that invariant blindly. This closes off a DNS-based SSRF/redirection vector: nothing in the request-forwarding path can cause this process to connect anywhere other than an operator-configured backend address, regardless of what any DNS server — compromised, misconfigured, or attacker-controlled — might answer for a backend's `server_name`.

## Bounded memory structures

Every structure that is keyed, directly or indirectly, by attacker-controlled input has an explicit bound:

- **Per-IP connection tracking** ([`limits.rs`](../crates/lb-server/src/limits.rs)): the map is keyed by source IP, but an entry is removed as soon as its count reaches zero — including on a rejected connection attempt, which never creates an entry in the first place — so cycling through source addresses cannot grow the map.
- **Rate-limit keys**: `rate_limit.max_tracked_keys` (default `100000`) caps how many distinct rate-limit keys (source IPs, or fixed-size hashes of header values) a listener tracks, so both the number and the size of tracked keys are bounded. Beyond this cap, additional distinct keys share one overflow budget rather than being individually rejected or causing an established key's state to be evicted. The cap is checked before insertion, so requests for new keys racing each other can exceed it by one small entry each. Full rate-limiting behavior is covered in [rate-limiting.md](rate-limiting.md).
- **Response cache**: `cache.max_entry_bytes` (default 2 MiB) rejects caching any single response larger than this — the response is still served, just not stored. `cache.max_total_bytes` (default 64 MiB) is a hard aggregate budget across every entry a listener's cache holds (bytes are reserved atomically before insertion, so concurrent inserts cannot overshoot it); once full, the least recently used entries are evicted to make room. Cache behavior in full is out of this page's scope.

## Request smuggling and Host confusion

The proxy never forwards a client's framing as-is: hyper parses the client side, the proxy reads the body itself (buffered or streamed, see above), and hyper frames the request to the backend again, so the proxy and the backend cannot disagree about where a request ends. The cases are pinned by [`smuggling_integration.rs`](../crates/lb-server/tests/smuggling_integration.rs), which sends each attack over a raw socket and records every byte the backend receives:

- **`Content-Length` together with `Transfer-Encoding: chunked`**: framed by chunked alone, the `Content-Length` is dropped before forwarding, and the connection is closed after the response (RFC 9112 §6.1), so bytes after the chunked body can never become a second request.
- **Two different `Content-Length` values**: `400`, nothing forwarded.
- **More than one `Host` header, an unparseable `Host`, or an HTTP/1.1 request with no `Host`**: `400`, nothing forwarded (RFC 9112 §3.2).
- **Absolute-form target (`GET http://a.example/`) or HTTP/2 `:authority`**: `Host` is rewritten to that authority before routing and forwarding, so the route the proxy picks and the host the backend sees can never differ.
- **Chunked request bodies** reach the backend with exactly one framing header.

## Overload shedding

`[server.overload]` ([`overload.rs`](../crates/lb-server/src/overload.rs)) watches connection-slot use, resident memory and file descriptors, and sheds work before the process runs out of any of them: first by closing HTTP/1.1 connections after their current response, then by answering new requests `503` with `Retry-After`, refusing new TCP connections, and failing `/ready` so the instance is taken out of rotation. The admin listener is never shed, so operators can still see what is happening. `lb_overload_level` and `lb_overload_pressure_permille{resource}` show the state; `lb_overload_rejected_total{listener}` counts refused work. See [`configuration-reference.md`](configuration-reference.md#serveroverload).

## Known residual risks

These are limitations the code itself documents, not a general security disclaimer:

- **The WAF is not a rule engine.** No percent-decoding or canonicalization is applied before matching, so an encoded or otherwise obfuscated payload can evade the fixed token lists. The rule set, and the header allowlist under `inspect_headers`, are compiled in and cannot be extended per deployment. See [`waf.rs`](../crates/lb-proxy/src/waf.rs).
- **`max_concurrent_streams` does not, by itself, restore an HTTP/1.1-equivalent per-IP memory bound under HTTP/2.** The actual per-IP concurrency ceiling under HTTP/2 comes from `[listeners.rate_limit]`'s `burst` (with `key = "source_ip"`), not from the HTTP/2 stream limit — see "Per-IP concurrency under HTTP/2" above.
