# TLS

The load balancer terminates TLS at the edge and optionally re-encrypts outbound traffic to backends.

## Edge Termination

Listeners with a `[listeners.tls]` section terminate TLS using `rustls`.

The `ring` crypto provider is installed once at startup in `lb_server::run`, before any `rustls` types are constructed. 

If a certificate or key file is invalid, startup fails immediately.

### Handshake

The TLS handshake executes inside the spawned connection task. Running the handshake before spawning would allow a slow client to stall the accept loop and block all other connections.

Both connection-limit guards (the global permit and the per-IP slot) are held during the handshake. The `handshake_timeout` ensures that a stalled handshake releases its budget.

### SNI Resolution

`SniResolver` implements rustls's `ResolvesServerCert`. It holds a `CertStore` containing hostnames and their corresponding certificate chains.

When a client provides an SNI hostname, the resolver looks it up. If the hostname is not found, it falls back to the first loaded certificate.

### Hot Reloading

A background task runs for each TLS listener. Every `reload_interval_secs`, the task compares the file modification timestamps of the certificate and key files. 

If the files have changed, the task parses them, builds a new `CertifiedKey`, and swaps it into the `SniResolver`'s store atomically using `ArcSwap`. A failed reload logs an error and leaves the previous certificate active. 

## Backend Re-encryption

Listeners with a `[listeners.backend_tls]` section re-encrypt outbound traffic. 

If a custom CA file is specified, it is loaded; otherwise, the system root store is used. The `danger_accept_invalid_certs` flag disables certificate verification. It is logged as a warning at startup and exported as a metric to ensure it is visible.

### DNS Pinning

To verify the backend's certificate, the forwarding URI must use the backend's `server_name` as the authority (`https://{server_name}:{port}`). 

If passed to a standard HTTP connector, the connector would resolve `server_name` via DNS. This would silently reintroduce DNS-based routing, bypassing the configured backend IP.

`PinnedResolver` replaces the DNS resolver with a static table mapping `server_name` to the configured `address`. It never makes a DNS query. 

### Scheme and Authority

`backend_scheme_and_authority` determines the scheme and authority for a backend. It is the single decision site for both traffic forwarding and health probes. 

If `backend_tls` is enabled, the scheme is `https` and the authority is the `server_name`. If disabled, the scheme is `http` and the authority is the `address`. A backend without a `server_name` on a re-encrypting listener returns `None` (though config validation prevents this from running).

### L4 Transport

`BackendTlsTransport` implements `OutboundTransport`. It wraps a TCP connection in a TLS handshake using the backend connector. The L4 TCP proxy calls this trait object without linking to a TLS stack.

## HSTS

If `hsts_max_age_secs` is greater than 0 on a TLS listener, every HTTP response includes the `Strict-Transport-Security` header. 

This applies to all responses, including 429s and 503s. Config validation rejects HSTS on TCP listeners.

## HTTP/2

HTTP/2 is negotiated via ALPN over TLS. Prior-knowledge h2c is not supported on plaintext listeners.

The `[listeners.http2]` section provides limits for concurrent streams, HPACK header list size, and frame size. It also bounds `max_pending_accept_reset_streams` to mitigate HTTP/2 Rapid Reset (CVE-2023-44487), where clients open and immediately cancel streams.

### FirstByteDeadline

HTTP/1.1 uses a `header_read_timeout` to defend against slowloris attacks. HTTP/2 does not read headers immediately; hyper's PING keep-alive only arms after the client's preface and SETTINGS arrive. A client can negotiate `h2` and stay silent, holding a connection slot.

`FirstByteDeadline` wraps the incoming stream. It runs a timeout that is disarmed as soon as the first byte arrives. This does not close the gap fully: the disarm condition is "a byte arrived," not "the preface completed," so a client that sends one byte and then stalls mid-preface still disarms the deadline and is bounded only by the per-IP connection cap, not by anything h2-specific. Raising the disarm threshold to the full 24-byte preface would only move the attacker's cost from one byte to 24 and close nothing structurally; a true deadline on handshake completion is not something hyper exposes.
