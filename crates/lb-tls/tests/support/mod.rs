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
