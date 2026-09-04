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
                    // System trust store. Individual unreadable/malformed OS
                    // entries are safe to ignore -- `.certs` is what we add,
                    // `.errors` just means some native entries didn't parse.
                    for cert in rustls_native_certs::load_native_certs().certs {
                        let _ = roots.add(cert);
                    }
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
}
