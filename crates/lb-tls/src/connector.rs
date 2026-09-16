use crate::{install_crypto_provider, TlsError};
use lb_core::BackendTlsConfig;
use std::sync::Arc;

/// The client side of TLS: the load balancer connecting onward to backends.
///
/// Backend certificates are verified by default -- chain to a trusted root,
/// validity dates, hostname match. Encryption without authentication does
/// not address the threat that motivates it: if the network is not trusted
/// to carry plaintext, it is not trusted not to carry a machine-in-the-middle
/// either.
pub struct BackendConnector {
    config: Arc<rustls::ClientConfig>,
    verification_disabled: bool,
}

impl BackendConnector {
    pub fn new(cfg: &BackendTlsConfig) -> Result<Self, TlsError> {
        // `rustls::ClientConfig::builder()` needs a process-wide crypto
        // provider. This is the first thing in the process to build a
        // rustls client type, and it is reachable from any caller, not just
        // `lb_server::run` -- leaving the install as an undocumented
        // obligation on the caller is how you get a confusing runtime
        // panic. The call is idempotent, so `run` keeps its own -- that
        // stays the documented place, this is the one that cannot be
        // forgotten. Same reasoning, same call, as `TlsAcceptor::new`.
        install_crypto_provider();

        let mut config = if cfg.danger_accept_invalid_certs {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        } else {
            let roots = match &cfg.ca_file {
                // Internal PKI is the common case on the backend path, which
                // is the whole reason the file form exists.
                Some(path) => crate::certs::load_ca_roots(path)?,
                None => {
                    // System trust store. Same discipline as the ca_file
                    // branch above: an empty result here is exactly as
                    // dangerous as a ca_file that loads to zero certificates,
                    // just reachable through the sibling code path.
                    let mut roots = rustls::RootCertStore::empty();
                    apply_native_certs(&mut roots, rustls_native_certs::load_native_certs())?;
                    roots
                }
            };
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };

        // Order is preference. hyper-rustls reports the negotiated protocol to
        // hyper's connection pool, so a backend that speaks HTTP/2 gets it and one
        // that does not is served HTTP/1.1 -- per connection, which is why a mixed
        // TLS fleet needs no configuration at all.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(BackendConnector {
            config: Arc::new(config),
            verification_disabled: cfg.danger_accept_invalid_certs,
        })
    }

    /// Reported so the caller can log it at startup and set a gauge -- this
    /// must be visible on a dashboard, not buried in a config file for two
    /// years. `danger_accept_invalid_certs` is the *only* way verification
    /// gets disabled, so this is truthful by construction.
    pub fn verification_disabled(&self) -> bool {
        self.verification_disabled
    }

    /// For `lb-tcp`: TLS over a raw stream, no HTTP involved.
    pub fn tls_connector(&self) -> tokio_rustls::TlsConnector {
        tokio_rustls::TlsConnector::from(Arc::clone(&self.config))
    }

    /// For `lb-proxy`'s WebSocket/Upgrade backend leg: a dedicated,
    /// non-pooled connection that must stay HTTP/1.1, since
    /// `hyper::client::conn::http1` cannot parse an h2 byte stream. Unlike
    /// `tls_connector`/`wrap_https`, which let a backend negotiate `h2` over
    /// ALPN (`[h2, http/1.1]`, set in `new` above), this clones the config
    /// and restricts ALPN to `http/1.1` alone -- otherwise a backend that
    /// prefers h2 could still negotiate it on this one-off connection, and
    /// there would be no Upgrade mechanism available on it at all.
    pub fn tls_connector_http1_only(&self) -> tokio_rustls::TlsConnector {
        let mut config = (*self.config).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    /// For `lb-proxy`: wraps an already-built connector with this backend's
    /// TLS config, trust roots and verification policy.
    ///
    /// Takes the inner connector rather than building one internally (as an
    /// earlier version of this method did) because the caller must control
    /// how the *TCP dial* resolves its target. `lb-proxy` builds an
    /// `HttpConnector` pinned to a fixed `server_name -> address` table
    /// (`lb_proxy::resolver::PinnedResolver`) rather than the default
    /// (real-DNS) resolver -- otherwise the connector would resolve the
    /// forwarding URI's authority, which is `server_name` (chosen so SNI and
    /// hostname verification check the certificate's name), via real DNS
    /// instead of dialing the operator-configured `address`. This method's
    /// only remaining job is what it says: wrap whatever connector it is
    /// given with this backend's TLS config.
    pub fn wrap_https<H>(&self, http: H) -> hyper_rustls::HttpsConnector<H> {
        // `HttpsConnectorBuilder::with_tls_config` panics unless
        // `alpn_protocols` arrives empty -- it derives the list itself from
        // `enable_http1`/`enable_http2` below, so the `h2`/`http/1.1` list
        // `self.config` carries (for `tls_connector`, which bypasses this
        // builder entirely) has to be cleared on this clone first. The
        // builder reconstructs the identical order, `h2` before `http/1.1`.
        let mut tls_config = (*self.config).clone();
        tls_config.alpn_protocols.clear();
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            // `https_only()`, not `https_or_http()`: this connector only
            // ever wraps a `backend_tls` listener's client, so plaintext
            // egress should be structurally impossible here, not merely
            // caller-prevented. (`lb-proxy::forward::build_client`'s
            // `None` branch is the plaintext connector and stays
            // `https_or_http()` -- it is a different builder, for the case
            // where no backend TLS is configured at all.)
            .https_only()
            .enable_http1()
            // Negotiated per connection over ALPN (the list set above): a
            // backend that speaks `h2` gets it, one that only speaks
            // `http/1.1` gets that instead. hyper-rustls reports the outcome
            // to hyper's connection pool via `negotiated_h2()`, which is what
            // lets one `Client` serve a mixed TLS fleet with no extra
            // plumbing on `lb-proxy`'s side.
            .enable_http2()
            .wrap_connector(http)
    }
}

/// Adds every usable certificate from `result` to `roots`, then requires
/// that at least one landed.
///
/// An empty native trust store is exactly as dangerous as a `ca_file` that
/// loads to zero certificates: it leaves an empty `RootCertStore` in
/// service, which rejects every backend at the first request instead of
/// failing loudly at startup. That is plausible on a minimal or sandboxed
/// container -- this project's deploy target is still undecided -- so it is
/// checked the same way the `ca_file` branch checks it, not assumed away.
///
/// Individual unreadable/malformed entries, reported via `result.errors` or
/// a rejected `roots.add`, are tolerated on their own -- that mirrors
/// upstream's own guidance that OS certificate stores can contain entries
/// that don't parse. Only a totally empty result *after* processing is a
/// startup failure, and when it happens the enumeration errors (if any) are
/// folded into the message so the operator learns why, not just that it
/// happened.
///
/// Split out from `new` so this path can be exercised directly in a test:
/// `rustls_native_certs::load_native_certs()` reads the real platform
/// certificate store, which cannot practically be forced to return nothing
/// on a normal development machine.
fn apply_native_certs(
    roots: &mut rustls::RootCertStore,
    result: rustls_native_certs::CertificateResult,
) -> Result<(), TlsError> {
    for cert in result.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        let reason = if result.errors.is_empty() {
            "no certificates found".to_string()
        } else {
            result
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        };
        return Err(TlsError::Pem(format!(
            "system trust store contains no usable certificates: {reason}"
        )));
    }
    Ok(())
}

/// Accepts any certificate. Reachable only through
/// `danger_accept_invalid_certs`, which is named to say exactly that, logged
/// at every startup, and surfaced as a gauge.
///
/// It exists because teams migrating an existing fleet meet self-signed
/// certificates on day one, and an unsupported need gets patched in badly.
#[derive(Debug)]
struct NoVerification;

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::BackendConnector;
    use crate::test_support as support;

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. The counter makes collision impossible within this binary,
    // which is where every concurrent caller lives.
    fn tmpdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lbconn-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_ca_file_is_loaded() {
        let dir = tmpdir();
        let (cert_path, _key) = support::write_pair(&dir, "ca", &["ca.example.com"]);
        let c = BackendConnector::new(&lb_core::BackendTlsConfig {
            ca_file: Some(cert_path),
            danger_accept_invalid_certs: false,
        })
        .unwrap();
        assert!(!c.verification_disabled());
    }

    #[test]
    fn a_missing_ca_file_fails_loudly() {
        // Startup must not succeed with an empty trust store: every backend
        // would then fail verification at the first request instead.
        assert!(BackendConnector::new(&lb_core::BackendTlsConfig {
            ca_file: Some("/nonexistent/ca.crt".into()),
            danger_accept_invalid_certs: false,
        })
        .is_err());
    }

    #[test]
    fn the_danger_flag_is_reported() {
        let c = BackendConnector::new(&lb_core::BackendTlsConfig {
            ca_file: None,
            danger_accept_invalid_certs: true,
        })
        .unwrap();
        // Reported so the caller can log it at startup and set a gauge --
        // this must be visible on a dashboard, not buried in a config file.
        assert!(c.verification_disabled());
    }

    /// `BackendConnector::new(&BackendTlsConfig { ca_file: None, .. })` reads
    /// the *real* platform certificate store via
    /// `rustls_native_certs::load_native_certs()`, which this machine's
    /// store is never going to return empty -- so there is no way to drive
    /// that end-to-end path into the empty-store branch from a unit test.
    /// What *is* directly testable is the guard itself: `apply_native_certs`
    /// was split out from `new` specifically so a synthetic, empty
    /// `CertificateResult` (built with `Default`, no real OS call involved)
    /// can be fed straight to it.
    #[test]
    fn an_empty_native_trust_store_fails_construction() {
        let mut roots = rustls::RootCertStore::empty();
        let empty = rustls_native_certs::CertificateResult::default();
        // Startup must not succeed with an empty trust store here either --
        // same reasoning as `a_missing_ca_file_fails_loudly` above, just
        // reachable through the sibling (no ca_file) code path.
        assert!(super::apply_native_certs(&mut roots, empty).is_err());
    }

    /// A real control, not just "it constructs without error": the server
    /// offers both `h2` and `http/1.1` over ALPN, and `h2` is listed first in
    /// `BackendConnector::new`'s own default order -- a connector that did
    /// nothing special here would plausibly land on `h2`. This proves
    /// `tls_connector_http1_only` actually pins the choice.
    #[tokio::test]
    async fn tls_connector_http1_only_never_negotiates_h2() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);

        let tls_cfg = lb_core::TlsConfig {
            certificates: vec![lb_core::CertificateConfig {
                name: "backend".into(),
                cert_file: cert.clone(),
                key_file: key,
                hostnames: vec!["backend.internal".to_string()],
                acme: None,
            }],
            handshake_timeout_ms: Some(5_000),
            min_version: None,
            reload_interval_secs: None,
            hsts_max_age_secs: None,
        };
        let acceptor =
            std::sync::Arc::new(crate::TlsAcceptor::new(&tls_cfg, &[b"h2", b"http/1.1"]).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let connector = BackendConnector::new(&lb_core::BackendTlsConfig {
            ca_file: Some(cert),
            danger_accept_invalid_certs: false,
        })
        .unwrap();
        let tls_connector = connector.tls_connector_http1_only();
        let name = rustls::pki_types::ServerName::try_from("backend.internal").unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = tls_connector.connect(name, stream).await.unwrap();

        let (_, conn) = tls.get_ref();
        assert_eq!(conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
    }
}
