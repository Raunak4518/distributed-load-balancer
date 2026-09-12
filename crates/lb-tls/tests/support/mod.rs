/// A throwaway self-signed certificate for `names`.
///
/// Generated per test run rather than checked in: no private key — even a
/// worthless one — belongs in version control, and nothing generated can
/// expire and rot the suite.
pub fn self_signed(names: &[&str]) -> (String, String) {
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    // rcgen 0.13.2's `CertifiedKey` names this field `key_pair`, not
    // `signing_key` (an older/renamed field in some rcgen pre-release docs).
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

/// Writes a cert/key pair to `dir` and returns the two paths.
pub fn write_pair(
    dir: &std::path::Path,
    stem: &str,
    names: &[&str],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let (cert_pem, key_pem) = self_signed(names);
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    (cert_path, key_path)
}

/// A throwaway signing CA, for tests that need certificates chaining to a
/// *shared* trust anchor rather than independently self-signed leaves --
/// `peer::PeerTls`'s mutual-auth model, where every node's cert must chain
/// to the same CA every other node trusts.
pub struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Ca {
    pub fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }
}

/// Writes a cert/key pair signed by `ca` to `dir`, carrying `subject_alt_name`
/// (an IP literal or a DNS name -- `rcgen::CertificateParams::new` picks the
/// SAN type from whether the string parses as an `IpAddr`) and returns the
/// two paths. `peer::PeerTls` verifies peers by IP SAN, since gossip peers
/// are addressed by `SocketAddr`, not hostname.
pub fn write_peer_pair(
    dir: &std::path::Path,
    stem: &str,
    ca: &Ca,
    subject_alt_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let params = rcgen::CertificateParams::new(vec![subject_alt_name.to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path)
}
