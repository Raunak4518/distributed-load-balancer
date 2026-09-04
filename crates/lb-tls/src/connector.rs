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

        let config = if cfg.danger_accept_invalid_certs {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match &cfg.ca_file {
                // Internal PKI is the common case on the backend path, which
                // is the whole reason the file form exists.
                Some(path) => {
                    let bytes = std::fs::read(path).map_err(|source| TlsError::Io {
                        path: path.display().to_string(),
                        source,
                    })?;
                    let certs: Vec<_> = rustls_pemfile::certs(&mut bytes.as_slice())
                        .collect::<Result<_, _>>()
                        .map_err(|e| TlsError::Pem(format!("{}: {e}", path.display())))?;
                    if certs.is_empty() {
                        // A ca_file that loads to zero roots is exactly as
                        // dangerous as one that failed to read: it leaves an
                        // empty trust store that rejects every backend at
                        // the first request. Fail startup instead.
                        return Err(TlsError::Pem(format!(
                            "{}: no certificates found",
                            path.display()
                        )));
                    }
                    for cert in certs {
                        roots
                            .add(cert)
                            .map_err(|e| TlsError::Pem(format!("{}: {e}", path.display())))?;
                    }
                }
                None => {
                    // System trust store. Same discipline as the ca_file
                    // branch above: an empty result here is exactly as
                    // dangerous as a ca_file that loads to zero certificates,
                    // just reachable through the sibling code path.
                    apply_native_certs(&mut roots, rustls_native_certs::load_native_certs())?;
                }
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };

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

    /// For `lb-proxy`: an HTTPS-capable connector for the hyper client.
    pub fn https_connector(
        &self,
    ) -> hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
        let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
        http.set_connect_timeout(Some(std::time::Duration::from_secs(2)));
        http.enforce_http(false);
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*self.config).clone())
            .https_or_http()
            .enable_http1()
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

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "lbconn-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
}
