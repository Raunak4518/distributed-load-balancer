# Request Lifecycle

A trace through the code for HTTP (L7) and TCP (L4) request paths.

## HTTP

### Connection Acceptance
**File:** `crates/lb-server/src/lib.rs` (`serve_listener`)

The loop acquires a global semaphore permit before calling `accept()`. If the server is at capacity, the kernel backlog absorbs connections and eventually refuses them. This avoids spending a file descriptor on a connection that will just be dropped.

After `accept()`, the per-IP slot is checked. Rejections drop the socket immediately. Acceptances create an `IpGuard` that decrements the IP's connection count when dropped.

### Connection Task Spawn
**File:** `crates/lb-server/src/lib.rs` (`spawn_connection`)

Both guards (`OwnedSemaphorePermit`, `IpGuard`) move into the spawned task. They are held for the lifetime of the connection, including the TLS handshake.

### TLS Handshake
**File:** `crates/lb-server/src/lib.rs` (`spawn_connection`)

The TLS handshake runs inside the task. A slow handshake stalls that task, not all accepts. The limit guards are held across the handshake, so an attack consumes the connection budget until the handshake timeout fires.

- Success: Read ALPN protocol.
- Timeout: Connection dropped.
- Failure: Connection dropped.

### Protocol Dispatch
**File:** `crates/lb-server/src/lib.rs` (`drive`)

- **HTTP/2**: hyper's `http2::Builder` with limits for concurrent streams, Rapid Reset, and HPACK. The stream is wrapped in `FirstByteDeadline` to time out clients that negotiate `h2` and go silent.
- **HTTP/1.1**: hyper's `http1::Builder` with `header_read_timeout` for slowloris defense.

Both builders receive a `service_fn` wrapping `lb_proxy::handle`.

### Rate Limiting
**File:** `crates/lb-proxy/src/service.rs` (`handle_inner`)

The rate-limit key is extracted from the connection's peer IP or a configured HTTP header.

The local GCRA check runs in-process. If denied, a 429 Too Many Requests response is returned with a `Retry-After` header.

If the cluster is configured and the local limit allowed the request, the cluster-wide limit is checked. Denials return 429 without a `Retry-After` header, as the cluster has no concept of token refill time.

### Circuit-Breaker Refresh
**File:** `crates/lb-proxy/src/service.rs` (`handle_inner`)

The circuit breaker's Open → HalfOpen transition is evaluated lazily inside `is_open()`. The pool's `circuit_open` flag is a cached boolean.

Once per request, the loop refreshes the pool:
```rust
for id in ctx.pool.all_backend_ids() {
    if let Some(breaker) = ctx.circuit_breakers.get(id) {
        ctx.pool.set_circuit_open(id, breaker.is_open());
    }
}
```
Without this, a backend that trips its breaker would stay excluded forever, as nothing else would call `is_open()` to notice the cooldown elapsed.

### Body Reading
**File:** `crates/lb-proxy/src/service.rs` (`handle_inner`)

The request body is read within a size limit and a timeout. 
- Over size limit → 413 Payload Too Large.
- Timeout → 408 Request Timeout.

### Backend Selection and Forwarding
**File:** `crates/lb-proxy/src/service.rs` (`handle_inner`)

The round-robin balancer picks an eligible backend from the pool.

`build_outbound_request` determines the scheme and authority. A backend with TLS gets `https://{server_name}:{port}`. A plaintext backend gets `http://{address}`. Hop-by-hop headers are stripped.

The request is forwarded through a `hyper_util::Client`.
- **Success:** The circuit breaker records a success, the pool is updated immediately, hop-by-hop headers are stripped from the response, and the response is returned.
- **Failure:** The circuit breaker records a failure and the pool is updated. If this was the first attempt, the request is retried against a different backend. If it was the second attempt, a 502 Bad Gateway is returned.

### Response Processing
**File:** `crates/lb-proxy/src/service.rs` (`handle`)

After `handle_inner` returns, metrics are recorded. An `X-Request-Id` header is generated and injected.

If configured on a TLS listener, the `Strict-Transport-Security` header is injected. This is applied to all responses, including 429s and 503s, as HSTS is a property of the host.

Access logs are written if enabled, using deterministic 1-in-N sampling.

## TCP

### Acceptance and TLS
The accept loop and TLS handshake are identical to the HTTP path.

### Rate Limiting
**File:** `crates/lb-tcp/src/session.rs` (`handle_connection`)

The peer IP is used as the key. Rate-limited connections are dropped silently, as there is no L4 mechanism to explain the rejection.

### Backend Selection and Connection
**File:** `crates/lb-tcp/src/session.rs` (`handle_connection` and `establish`)

The circuit breaker state is refreshed exactly as in the HTTP path.

The balancer picks a backend. The proxy attempts a TCP connect. If backend TLS is configured, it asks the `OutboundTransport` to wrap the stream.

Success and failure are recorded in the circuit breaker. A failure on the first attempt triggers a retry to a different backend.

### Bidirectional Pump
**File:** `crates/lb-tcp/src/session.rs` (`handle_connection`)

Both streams are split into read and write halves.

```rust
tokio::try_join!(
    pump(client_read, backend_write, idle_timeout),
    pump(backend_read, client_write, idle_timeout),
)
```

`try_join!` is used instead of `select!`. Each direction must finish on its own. `select!` would tear down the connection on the first EOF, breaking protocols that half-close one direction while still reading the other.

## Retries

Both paths retry exactly once on a backend failure:
- **HTTP:** The body has already been read into memory, so sending the same bytes to a second backend is safe.
- **TCP:** No client byte has been read yet. The connection to the second backend is established before data flows.

Retries pick a different backend, as the failed backend's circuit breaker was just updated and will exclude it.

Rate-limit denials, body limit violations, and missing configuration are not retried.
