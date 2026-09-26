# TLS

The load balancer terminates TLS at the edge with [`rustls`](https://github.com/rustls/rustls), can obtain and renew its own edge certificates via ACME, re-encrypts traffic to backends, and authenticates cluster peer connections with mutual TLS. All four uses share the certificate-loading and error-handling code in [`lb-tls`](../crates/lb-tls/src).

## Edge termination

A listener terminates TLS when its config carries a `[listeners.tls]` table. TLS is implemented with `rustls`, using the `ring` cryptographic provider; the provider is installed process-wide, once, idempotently, the first time any TLS type is constructed ([`acceptor.rs`](../crates/lb-tls/src/acceptor.rs)).

```toml
[listeners.tls]
reload_interval_secs = 30      # default 60
handshake_timeout_ms = 5000    # default 5000
min_version = "1.2"            # "1.2" (default) or "1.3"
hsts_max_age_secs = 0          # default 0 (off)

[[listeners.tls.certificates]]
name = "primary"
cert_file = "/etc/lb/tls/primary.crt"
key_file = "/etc/lb/tls/primary.key"
hostnames = ["example.com", "*.example.com"]
```

### Protocol versions and cipher policy

`min_version` selects which rustls protocol-version set the server negotiates from: `"1.2"` (the default) builds the acceptor from `rustls::ALL_VERSIONS` (TLS 1.2 and 1.3 both offered); `"1.3"` restricts it to `rustls::version::TLS13` only. There is no config knob for the cipher suite list — the acceptor uses whatever suites the `ring` provider's default `CryptoProvider` supports, in rustls's own preference order. This project does not expose suite selection.

Session resumption is enabled unconditionally: the server keeps up to 20,480 sessions in an in-memory cache, and issues TLS 1.3 session tickets via `ring`'s ticketer. Ticket/session keys are per process — a client that lands on a different cluster node after a fresh connection always performs a full handshake there; keys are not shared across nodes.

### Certificate loading

Each `[[listeners.tls.certificates]]` entry names a PEM certificate chain and private key file plus the hostnames it serves. Loading ([`certs.rs`](../crates/lb-tls/src/certs.rs)) parses the chain and key, rejects a key that does not cryptographically match its certificate, and parses the leaf's `notAfter` for the expiry gauge (rustls itself does not expose validity dates, hence the separate `x509-parser` dependency). `hostnames` are normalized to ASCII lowercase at load time, so operator casing does not affect matching. Any failure — unreadable file, malformed PEM, mismatched key — fails startup outright rather than binding a port that can never complete a handshake.

### SNI and multiple certificates

`SniResolver` implements rustls's `ResolvesServerCert` over a `CertStore` built from the loaded certificates ([`resolver.rs`](../crates/lb-tls/src/resolver.rs)):

- With exactly one configured certificate, it is served regardless of the SNI the client sent (or no SNI at all) — there is nothing to choose between.
- With more than one, the requested SNI is matched first against exact hostnames, then against single-label wildcards (`*.example.com` matches `a.example.com`, not `a.b.example.com` or the bare `example.com`, per RFC 6125). Matching is case-insensitive.
- If none of several configured certificates match the requested SNI (or the client sent none), the handshake is rejected — there is no fallback to a default or first-loaded certificate.

### ALPN and HTTP/2

The protocols offered over ALPN are decided per listener at wiring time, not inside `lb-tls`: an HTTP listener that is running HTTP/2 (`http2_enabled()` — TLS present and not explicitly disabled) offers `["h2", "http/1.1"]`, in that preference order; an HTTP listener without HTTP/2 offers `["http/1.1"]` only; a TCP listener offers nothing, since at L4 the application protocol is unspecified. See [`http-features.md`](http-features.md) for how the negotiated protocol is served, and [`edge-hardening.md`](edge-hardening.md) for HTTP/2 stream/frame limits and the Rapid Reset mitigation.

### Handshake timeout

The handshake runs inside the spawned connection task, never in the accept loop, so one slow client cannot stall every other pending connection. It is bounded by `handshake_timeout_ms` (default 5000ms); a client that never completes the handshake is dropped and its connection-limit slots released.

### HSTS

When `hsts_max_age_secs` is greater than zero, every response from that listener carries `Strict-Transport-Security: max-age=<value>` — unconditionally, including error responses such as 429 or 503, since HSTS is a property of the host, not of a particular response. The default is 0 (off): a client must opt in, since browsers cache the policy for the full `max-age`. Config validation rejects `hsts_max_age_secs` on a TCP listener, where there is no HTTP response to add a header to.

### Hot reload

A background task per TLS listener polls on `reload_interval_secs` (default 60s; filesystem watching is deliberately not used — see [`reload.rs`](../crates/lb-tls/src/reload.rs) for why `inotify` has no portable Windows equivalent and atomic-rename deployment defeats naive watchers anyway). Each tick it compares the modification time and length of every certificate's `cert_file` and `key_file` against the last-seen values.

If any file changed, every certificate in the listener's `[listeners.tls]` table is reloaded and validated *before* anything is swapped in. If all load cleanly, the resolver's certificate store — held behind a `RwLock<Arc<CertStore>>` — is replaced with the new set in one write. If any certificate in the batch fails to load or its key does not match, the whole reload is rejected: no certificate is swapped, including ones in the same batch that loaded fine, and the previous store keeps serving. A stale certificate is preferred over a partially-applied one.

### Metrics

- `lb_tls_certificate_expiry_timestamp_seconds{listener, cert}` — the active certificate's `notAfter`, as a Unix timestamp, set on every successful reload. This is the primary expiry alerting signal.
- `lb_tls_certificate_reloads_total{listener, outcome}` — counter, `outcome` one of `applied`, `unchanged`, `rejected`.

See [`metrics-reference.md`](metrics-reference.md) for the full metric catalog.

## ACME (automatic certificates)

A certificate entry becomes ACME-managed by adding `[listeners.tls.certificates.acme]` ([`acme.rs`](../crates/lb-tls/src/acme.rs)):

```toml
[[listeners.tls.certificates]]
name = "acme-cert"
cert_file = "/var/lib/lb/acme/example.com.crt"
key_file = "/var/lib/lb/acme/example.com.key"
hostnames = ["example.com"]

  [listeners.tls.certificates.acme]
  directory_url = "https://acme-v02.api.letsencrypt.org/directory"
  contact_email = "ops@example.com"
  account_key_file = "/var/lib/lb/acme/account.json"
  renew_before_days = 30        # default 30
  check_interval_secs = 43200   # default 43200 (12h)
  # ca_bundle_file = "/etc/lb/acme-test-ca.pem"   # trust root for the ACME directory itself
  # fallback_directory_url = "..."
  # staging_directory_url = "..."
```

### Challenge type and domain scope

Only the **HTTP-01** challenge is implemented. An order is placed for a single domain — `hostnames[0]` of the certificate entry; additional entries in `hostnames` are not requested from the CA and will not be covered by the SANs on the issued certificate. There is no DNS-01 support.

The pending challenge's key authorization is held in an in-process `AcmeChallengeStore`, one instance shared by every HTTP listener in the process. Every HTTP listener answers `GET /.well-known/acme-challenge/<token>` from this shared store — ahead of rate limiting, WAF inspection, and routing — returning the key authorization with `200 OK` if the token is known, `404` otherwise ([`service.rs`](../crates/lb-proxy/src/service.rs)). For a public CA to validate ownership, at least one plaintext HTTP listener must be reachable on port 80 for the domain being issued.

### Directory trust, accounts, and bootstrap

`ca_bundle_file` supplies a custom PEM trust root for TLS to the ACME *directory* itself (used for a private or test ACME server such as Pebble); omitting it trusts the system root store. The ACME account is created on first use and its credentials cached as JSON at `account_key_file`; on a later start, existing credentials are reused if they still parse and authenticate, otherwise a new account is created.

If `cert_file`/`key_file` do not already exist when an ACME-managed listener starts, `ensure_bootstrap_certificate` writes a self-signed placeholder first, so the listener has something to serve before the first ACME order completes. That placeholder is deliberately generated already expired (`notBefore` = now − 2 days, `notAfter` = now − 1 day), which makes the renewal check below treat it as immediately due.

### Renewal timing

A background task per ACME certificate ([`spawn_acme_renewer`](../crates/lb-tls/src/acme.rs)) wakes every `check_interval_secs` (default 43,200s / 12h) and calls `needs_renewal`, which is true once the certificate's `notAfter` is less than `renew_before_days` (default 30 days) away — or the certificate file is missing or unparseable. This task only ever writes `cert_file`/`key_file`; it does not itself touch the `SniResolver`. The existing hot-reload task for that listener (see above) is what notices the new file's timestamp and swaps it in, so `reload_interval_secs` should stay short relative to `check_interval_secs`.

### Failure behavior

`retry_issuance` is the renewal task's retry ladder: it retries the primary `directory_url` once immediately (after `immediate_retry_delay`, 10s), then `fallback_directory_url` once if configured, then falls into exponential backoff (`initial_backoff` 60s, doubling, capped at `max_backoff` 3,600s) against `staging_directory_url` if configured, else the primary URL, until `give_up_after` (default 30 days) elapses — at which point the task logs the failure and waits for its next `check_interval_secs` tick to try the whole ladder again. A renewal failure never removes or invalidates the certificate currently in service.

## Backend re-encryption (TLS to backends)

A listener re-encrypts its outbound connections when its config carries `[listeners.backend_tls]` ([`connector.rs`](../crates/lb-tls/src/connector.rs)):

```toml
[listeners.backend_tls]
ca_file = "/etc/lb/tls/internal-ca.crt"   # omit to use the system trust store
danger_accept_invalid_certs = false        # default false
```

### Trust roots

If `ca_file` is set, only certificates chaining to that PEM bundle are trusted — the common case for an internal PKI. If omitted, the OS's native trust store (`rustls-native-certs`) is used. Either path fails startup if it resolves to zero usable trust anchors, rather than leaving an empty trust store in service (which would reject every backend at the first request).

`danger_accept_invalid_certs = true` disables certificate verification entirely via a custom `ServerCertVerifier` that accepts anything. It is logged as a warning at startup and exported as `lb_backend_tls_verification_disabled{listener}` (1 when disabled, 0 otherwise) so it is visible on a dashboard rather than buried in a config file indefinitely.

### server_name, SNI, and DNS pinning

Each backend can carry a `server_name` (`[[listeners.backends]]`); on a re-encrypting listener the forwarding authority is `https://{server_name}:{port}` — `server_name` is what the certificate verifier and the TLS `ClientHello`'s SNI check against, not the backend's configured `address`. Because a standard HTTP connector would resolve that authority via real DNS, `lb-proxy` builds its connector with a `PinnedResolver` that maps `server_name` to the configured `address` directly and never performs a DNS lookup — this is what stops re-encryption from silently reintroducing DNS-based routing. `backend_scheme_and_authority` is the single decision point for both proxied traffic and health probes: `https`/`server_name` when `backend_tls` is set, `http`/`address` otherwise.

### Backend ALPN

The backend `ClientConfig` offers `["h2", "http/1.1"]` over ALPN, in that preference order; a backend that speaks HTTP/2 gets it, one that only speaks HTTP/1.1 falls back, negotiated independently per connection (`hyper-rustls` reports the outcome to hyper's connection pool). One exception: the dedicated, non-pooled connection used for a WebSocket/`Upgrade` backend leg is restricted to `http/1.1` only, because `hyper::client::conn::http1` cannot parse an HTTP/2 byte stream.

### L4 (TCP listener) re-encryption

For TCP listeners, `BackendTlsTransport` implements `lb-core`'s `OutboundTransport` trait, wrapping the raw backend connection in the same connector's TLS handshake. The L4 proxy path only depends on the trait object and never links against a TLS crate directly ([`transport.rs`](../crates/lb-tls/src/transport.rs)). The handshake is bounded by the same connect timeout used for the TCP dial.

## Cluster peer mutual TLS

The cluster gossip channel can run over mutual TLS when `[cluster.tls]` is configured ([`peer.rs`](../crates/lb-tls/src/peer.rs)):

```toml
[cluster.tls]
cert_file = "/etc/lb/peer/node.crt"
key_file = "/etc/lb/peer/node.key"
ca_file = "/etc/lb/peer/ca.crt"
handshake_timeout_ms = 5000   # default 5000
```

If `[cluster.tls]` is absent, the peer channel stays HMAC-authenticated (see [`cluster-coordination.md`](cluster-coordination.md)) but unencrypted — every node id and rate-limit count on the wire is readable to anyone who can observe the link.

Unlike a listener, there is no SNI resolution and no set of certificates to choose between: gossip is symmetric (every node pushes to and accepts pushes from every peer), so a node presents the same single cert/key whichever role it is playing at the moment, and loads that pair once for its server role and once again for its client role (`PrivateKeyDer` deliberately has no `Clone`, so duplicating key material is a visible, separate load rather than an implicit copy).

Trust is standard WebPKI, both directions, against the same `ca_file`: the accepting side uses `WebPkiClientVerifier` to require and verify a client certificate; the connecting side verifies the server certificate against the same root and against `ServerName::IpAddress(peer_ip)` — a peer's certificate must carry that peer's gossip bind IP as a Subject Alternative Name, since peers are addressed by socket address, not hostname. A peer with no client certificate, or one from a different CA, fails the handshake.

## Security notes and limitations

- **The admin listener has no TLS.** `AdminConfig` (`[admin]`) has no TLS field at all — the admin HTTP listener (metrics, health endpoints, backend drain/undrain) is always plaintext. It must be bound to a private interface and never exposed to a public network; see [`edge-hardening.md`](edge-hardening.md) and [`operations.md`](operations.md).
- Cipher suites are not configurable; only the minimum protocol version (`min_version`) can be set.
- TLS session ticket keys are per-process and not shared across cluster nodes, so session resumption does not cross nodes.
- With more than one certificate configured on a listener, an SNI that matches none of them is rejected outright — there is no default/fallback certificate.
- An ACME-managed certificate is issued for a single domain (its entry's first `hostnames` value); listing additional hostnames on that entry does not extend what the ACME-issued certificate actually covers.
- The ACME HTTP-01 responder is wired into every HTTP listener process-wide and answers before rate limiting, WAF inspection, or backend routing — it is not scoped to one designated listener.
- `danger_accept_invalid_certs` removes all backend certificate verification (chain, expiry, hostname); it exists for migrating an already-deployed fleet that presents self-signed certificates and should be treated as temporary.

## Related pages

- [`configuration-reference.md`](configuration-reference.md) — full field listing and defaults for every config section.
- [`metrics-reference.md`](metrics-reference.md) — full metric catalog.
- [`edge-hardening.md`](edge-hardening.md) — connection limits, HTTP/2 abuse limits, and admin listener authentication.
- [`http-features.md`](http-features.md) — HTTP/1.1 and HTTP/2 serving, reached via the ALPN choice made here.
- [`cluster-coordination.md`](cluster-coordination.md) — the gossip protocol carried over the peer mutual TLS channel.
