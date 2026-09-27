# Request Lifecycle

This page traces a request from the moment bytes arrive at the network interface to the moment the response is returned to the client.

## 1. Connection Acceptance

The entry point is `lb_server::accept_loop`. The loop runs continuously, accepting sockets from `tokio::net::TcpListener`.

Before `accept()` is even called, the system enforces the global connection limit using a Tokio `Semaphore`.
```rust
// Blocks until the semaphore has capacity.
let permit = limits.global_semaphore.acquire().await;
```
This protects the system from file descriptor exhaustion.

Next, the IP connection limit is checked via a `DashMap`. If an IP has exceeded its configured concurrent connections, the socket is dropped immediately, freeing the file descriptor.

## 2. Handshake and Dispatch

Once accepted, a `tokio::spawn` task is launched. If TLS is configured, the socket undergoes the `rustls` handshake.

The system defends against Slowloris attacks by wrapping the handshake in a strict `tokio::time::timeout`. If the client takes too long to negotiate TLS, the connection is aborted.

Following TLS negotiation (or immediately if plaintext), the protocol is determined. If TLS ALPN returns `h2` or `http/1.1`, or if the listener is explicitly configured for HTTP, the socket is handed to the HTTP data plane (`lb-proxy`). Otherwise, it is handed to the TCP data plane (`lb-tcp`).

## 3. Rate Limiting

The request reaches the data plane context. Before the router is consulted, the rate limiter evaluates the request.

For HTTP, the proxy can rate-limit based on the client IP or an HTTP header (e.g., `Authorization`). For TCP, only the IP is available.

1. **Local Limit:** The local GCRA algorithm checks if the request fits within the node's local token bucket.
2. **Distributed Limit:** If allowed locally, the proxy queries the `ClusterCoordinator`. The coordinator reads the most recent CRDT totals across the cluster. If the global total exceeds the limit, the request is rejected.

If rejected, HTTP clients receive a `429 Too Many Requests`. TCP clients simply have their sockets closed, because L4 has no concept of a 429 response.

## 4. Routing and Backend Selection

If the rate limit is satisfied, the proxy asks the configured `LoadBalancer` to pick a backend.

The load balancer evaluates the `BackendPool`. It filters out backends that are currently failing health checks (`active_healthy == false`) or whose circuit breakers have tripped (`circuit_open == true`). 

From the eligible remaining backends, the strategy (e.g., Round Robin) selects an ID.

## 5. Forwarding and Retries

The proxy attempts to connect to the selected backend. 

If `backend_tls` is enabled, the `OutboundTransport` performs a TLS handshake with the backend, validating the certificate against the configured root CAs and overriding the SNI if necessary.

### Handling Connection Failures

If the backend connection fails (e.g., `ECONNREFUSED` or a TLS validation error), the proxy reacts immediately:
1. It calls `circuit_breaker.record_failure()`, marking the backend as suspect.
2. It retries the request exactly once.

On the retry, it asks the router for a backend again. Because the circuit breaker was tripped in step 1, the failing backend is excluded from the new selection.

## 6. Pumping Bytes

For HTTP, `hyper` handles the streams.

For TCP, the proxy must manually pump bytes between the client and the backend. It uses `tokio::try_join!` on two independent `tokio::io::copy` futures (client -> backend, backend -> client).

```rust
// Both directions run concurrently. If either fails, both are dropped.
tokio::try_join!(
    tokio::io::copy(&mut client_read, &mut backend_write),
    tokio::io::copy(&mut backend_read, &mut client_write)
)?;
```
When one side half-closes (EOF), the other side's write half is shut down, ensuring the protocol completes cleanly.

## 7. Metrics and Finalization

After the request (or TCP session) finishes, the proxy records the duration, status code, and bytes transferred. These are emitted to the Prometheus `Metrics` registry. The `X-Request-Id` (if injected) is logged. Finally, the task exits, returning the global semaphore permit and releasing the IP connection count.
