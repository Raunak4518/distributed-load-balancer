use crate::error::TlsError;
use lb_core::CertificateConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// A certificate that has been loaded, validated, and had its expiry read.
#[derive(Debug)]
pub struct LoadedCert {
    pub name: String,
    pub hostnames: Vec<String>,
    pub key: Arc<rustls::sign::CertifiedKey>,
    /// Unix seconds of the leaf's `notAfter`, for the expiry gauge. An
    /// expired certificate is a total outage with a knowable date; this is
    /// what turns that into an alert.
    pub not_after_unix: i64,
}

pub fn load_certificate(cfg: &CertificateConfig) -> Result<LoadedCert, TlsError> {
    let cert_bytes = read(&cfg.cert_file)?;
    let key_bytes = read(&cfg.key_file)?;

    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem(format!("{}: {e}", cfg.cert_file.display())))?;
    if chain.is_empty() {
        return Err(TlsError::Pem(format!(
            "{}: no certificates found",
            cfg.cert_file.display()
        )));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .map_err(|e| TlsError::Pem(format!("{}: {e}", cfg.key_file.display())))?
        .ok_or_else(|| TlsError::NoKey(cfg.key_file.display().to_string()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::Pem(format!("{}: {e}", cfg.key_file.display())))?;

    let not_after_unix = leaf_not_after(&chain[0])?;
    let certified = rustls::sign::CertifiedKey::new(chain, signing_key);

    // A key that does not match its certificate would break TLS for every
    // client. Catching it here is what lets reload fail safe.
    certified
        .keys_match()
        .map_err(|e| TlsError::KeyMismatch(format!("certificate '{}': {e}", cfg.name)))?;

    Ok(LoadedCert {
        name: cfg.name.clone(),
        // Hostnames are normalized to ASCII lowercase at load time so that
        // matching is consistent regardless of the operator's casing in config.
        // This ensures a wildcard cert like *.Example.com does not silently
        // fail to serve legitimate clients asking for a.example.com.
        hostnames: cfg
            .hostnames
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        key: Arc::new(certified),
        not_after_unix,
    })
}

fn read(path: &std::path::Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// rustls does not expose certificate validity dates, so the leaf is parsed
/// directly. This is the whole reason `x509-parser` is a dependency.
fn leaf_not_after(leaf: &CertificateDer<'_>) -> Result<i64, TlsError> {
    use x509_parser::prelude::FromDer;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| TlsError::Expiry(e.to_string()))?;
    Ok(parsed.validity().not_after.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    // `#[path]` here is relative to the directory owned by this inline
    // `tests` module (src/certs/tests/), not the crate root — hence three
    // levels up to reach `crates/lb-tls/` and back down into `tests/`.
    #[path = "../../../tests/support/mod.rs"]
    mod support;

    fn cfg(dir: &std::path::Path, stem: &str, names: &[&str]) -> CertificateConfig {
        let (cert_file, key_file) = support::write_pair(dir, stem, names);
        CertificateConfig {
            name: stem.to_string(),
            cert_file,
            key_file,
            hostnames: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn loads_a_valid_pair() {
        let dir = std::env::temp_dir().join(format!("lbtls-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let loaded = load_certificate(&cfg(&dir, "ok", &["example.com"])).unwrap();
        assert_eq!(loaded.name, "ok");
        assert_eq!(loaded.hostnames, vec!["example.com".to_string()]);
        // rcgen's default validity is comfortably in the future.
        assert!(loaded.not_after_unix > 0);
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_rejected() {
        let dir = std::env::temp_dir().join(format!("lbtls-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = cfg(&dir, "a", &["a.example.com"]);
        // Point at a different pair's key.
        let other = cfg(&dir, "b", &["b.example.com"]);
        c.key_file = other.key_file;

        // This is the check that makes hot reload safe: swapping in a cert
        // whose key does not match would break TLS for every client.
        assert!(matches!(
            load_certificate(&c),
            Err(TlsError::KeyMismatch(_))
        ));
    }

    #[test]
    fn a_malformed_certificate_is_rejected_not_panicked_on() {
        let dir = std::env::temp_dir().join(format!("lbtls-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = cfg(&dir, "bad", &["example.com"]);
        std::fs::write(&c.cert_file, b"this is not a certificate").unwrap();
        c.name = "bad".into();
        assert!(matches!(load_certificate(&c), Err(TlsError::Pem(_))));
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let c = CertificateConfig {
            name: "gone".into(),
            cert_file: "/nonexistent/nope.crt".into(),
            key_file: "/nonexistent/nope.key".into(),
            hostnames: vec![],
        };
        match load_certificate(&c) {
            Err(TlsError::Io { path, .. }) => assert!(path.contains("nope.crt")),
            other => panic!("expected an Io error naming the path, got {other:?}"),
        }
    }

    /// Unique-enough directory suffix without pulling in a uuid dependency.
    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
