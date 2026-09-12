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

/// Reads and parses a cert chain + private key, before either is committed
/// to any particular rustls use (a `CertifiedKey` for a resolver, or the raw
/// `(chain, key)` pair `with_single_cert`/`with_client_auth_cert` want) --
/// shared by `load_certificate` below and `peer::PeerTls`, which needs the
/// raw pair directly and has no resolver of its own (one node, one gossip
/// identity, no SNI to resolve against).
pub(crate) fn load_chain_and_key(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let cert_bytes = read(cert_file)?;
    let key_bytes = read(key_file)?;

    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem(format!("{}: {e}", cert_file.display())))?;
    if chain.is_empty() {
        return Err(TlsError::Pem(format!(
            "{}: no certificates found",
            cert_file.display()
        )));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .map_err(|e| TlsError::Pem(format!("{}: {e}", key_file.display())))?
        .ok_or_else(|| TlsError::NoKey(key_file.display().to_string()))?;

    Ok((chain, key))
}

/// Loads every trust anchor in `ca_file` into a fresh `RootCertStore`.
///
/// Shared by `BackendConnector` (backend trust roots) and `peer::PeerTls`
/// (mutual peer trust roots) -- same failure discipline in both: an empty
/// result after loading (unreadable file, or a file with zero certificates
/// in it) fails loudly rather than leaving an empty trust store that
/// rejects everyone at the first connection.
pub(crate) fn load_ca_roots(ca_file: &std::path::Path) -> Result<rustls::RootCertStore, TlsError> {
    let bytes = read(ca_file)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem(format!("{}: {e}", ca_file.display())))?;
    if certs.is_empty() {
        return Err(TlsError::Pem(format!(
            "{}: no certificates found",
            ca_file.display()
        )));
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| TlsError::Pem(format!("{}: {e}", ca_file.display())))?;
    }
    Ok(roots)
}

pub fn load_certificate(cfg: &CertificateConfig) -> Result<LoadedCert, TlsError> {
    let (chain, key) = load_chain_and_key(&cfg.cert_file, &cfg.key_file)?;

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
    use crate::test_support as support;

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

    /// Spec section 8, test 11 calls the expiry gauge "the most valuable
    /// metric here" and it is the sole reason `x509-parser` is a dependency.
    /// `loads_a_valid_pair` above only checks `not_after_unix > 0`, which is
    /// true for any certificate that parses at all — it would not catch
    /// `leaf_not_after` reading `notBefore` instead of `notAfter`, returning
    /// a hardcoded constant, or returning milliseconds instead of Unix
    /// seconds. This pins the value against what is actually known about
    /// the generated certificate instead of merely its presence.
    #[test]
    fn not_after_unix_matches_the_certificates_actual_notafter() {
        let dir = std::env::temp_dir().join(format!("lbtls-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let loaded = load_certificate(&cfg(&dir, "expiry", &["example.com"])).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // rcgen 0.13's default validity window runs from 1975-01-01 to
        // 4096-01-01 (see rcgen::CertificateParams::default), so a freshly
        // generated leaf's notAfter is roughly two thousand years out from
        // "now". Two bounds relative to "now", not an exact literal (which
        // would pin us to one rcgen release's choice of default), are
        // enough to catch every wrong-value failure mode described above:
        //   - "comfortably in the future" (now + 10 years) rules out
        //     notBefore (1975, in the past of any "now" this suite runs at)
        //     and a zero/small placeholder constant.
        //   - "not absurdly far" (under year 9999) rules out seconds
        //     swapped for milliseconds, which would land the value roughly
        //     two million years out, not two thousand.
        let ten_years_secs = 10 * 365 * 24 * 3600;
        let year_9999_unix = 253_402_300_799_i64;
        assert!(
            loaded.not_after_unix > now + ten_years_secs,
            "not_after_unix {} is not comfortably in the future of now ({}); \
             leaf_not_after may be reading notBefore, a placeholder, or the \
             wrong field entirely",
            loaded.not_after_unix,
            now
        );
        assert!(
            loaded.not_after_unix < year_9999_unix,
            "not_after_unix {} is implausibly far in the future; likely a \
             seconds-vs-milliseconds (or other unit) bug in leaf_not_after",
            loaded.not_after_unix
        );
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
    ///
    /// The clock alone is not unique: Windows' system time has ~15.6 ms
    /// granularity, so concurrent tests routinely read the same nanosecond
    /// value, land in the same directory, and overwrite each other's
    /// cert/key files. The counter makes collision impossible within this
    /// binary, which is where every concurrent caller lives.
    fn uuid_like() -> String {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{nanos}-{}",
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }
}
