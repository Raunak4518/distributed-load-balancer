# Edge TLS

The load balancer terminates TLS at the edge using `rustls`. It supports ALPN (Application-Layer Protocol Negotiation) to multiplex HTTP/1.1 and HTTP/2 over the same port, and it supports re-encrypting traffic to backends (`backend_tls`).

## Certificate Management and Hot-Reloading

A critical operational requirement is the ability to renew certificates (e.g., via Let's Encrypt / Certbot) without dropping active connections or restarting the proxy process.

To achieve this, the system stores the active `rustls::ServerConfig` inside an `ArcSwap`.

```rust
// In lb-tls/src/acceptor.rs
pub struct TlsAcceptor {
    config: ArcSwap<rustls::ServerConfig>,
}
```

A background task wakes up every hour, inspects the file modification timestamps of the configured `cert.pem` and `key.pem`. If the files have changed on disk, it parses the new certificate chain. If parsing succeeds, it swaps the `ArcSwap` pointer atomically.

New connections immediately use the new certificate. Existing connections are unaffected because they hold a clone of the old `Arc` (which keeps the old `ServerConfig` alive until the connection closes).

## ALPN and Protocol Dispatch

When a client connects to a TLS-enabled listener, the `rustls` handshake executes. The server advertises support for `h2` and `http/1.1`.

Once the handshake completes, the system inspects the negotiated ALPN protocol:
- If `h2`, the connection is handed to the HTTP engine and processed as HTTP/2.
- If `http/1.1`, it is processed as HTTP/1.1.
- If no ALPN is negotiated, the listener configuration dictates the fallback (usually HTTP/1.1 or raw TCP).

## Backend TLS and SNI Overrides

If `backend_tls` is enabled for a pool, the proxy must re-encrypt the traffic before sending it to the backend.

The `rustls` client requires a Server Name Indication (SNI) string to validate the backend's certificate. By default, it uses the backend's hostname. However, if the backend is configured via an IP address (e.g., `10.0.0.5`), SNI cannot be an IP. 

The configuration allows an `sni_override` (e.g., `internal.example.com`). The proxy resolves the IP, connects to `10.0.0.5`, but validates the certificate against `internal.example.com`.

This logic is completely hidden from the data plane via the `OutboundTransport` trait. The proxy simply calls `transport.wrap(stream, timeout)`.
