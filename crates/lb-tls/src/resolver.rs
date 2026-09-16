use crate::LoadedCert;
use std::sync::{Arc, RwLock};

pub struct CertStore {
    certs: Vec<LoadedCert>,
}

impl CertStore {
    pub fn new(certs: Vec<LoadedCert>) -> Self {
        CertStore { certs }
    }

    pub fn certs(&self) -> &[LoadedCert] {
        &self.certs
    }

    pub fn resolve(&self, sni: Option<&str>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // One certificate: serve it whatever was asked for. There is nothing
        // to choose between, and this is how a single-vhost nginx behaves.
        if self.certs.len() == 1 {
            return Some(Arc::clone(&self.certs[0].key));
        }
        let requested = sni?.to_ascii_lowercase();

        // Exact before wildcard, so a specific certificate always wins over
        // one that merely covers the same name.
        self.certs
            .iter()
            .find(|c| c.hostnames.iter().any(|h| exact_match(h, &requested)))
            .or_else(|| {
                self.certs
                    .iter()
                    .find(|c| c.hostnames.iter().any(|h| wildcard_match(h, &requested)))
            })
            .map(|c| Arc::clone(&c.key))
    }
}

fn exact_match(pattern: &str, requested: &str) -> bool {
    pattern.eq_ignore_ascii_case(requested)
}

/// `*.example.com` matches `a.example.com` but neither `a.b.example.com` nor
/// `example.com`, per RFC 6125. The single-label rule is deliberate:
/// multi-level wildcards are not issued by public CAs, and honouring them
/// would silently widen what a certificate is trusted for.
fn wildcard_match(pattern: &str, requested: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(label) = requested.strip_suffix(suffix) else {
        return false;
    };
    // `label` is everything before the suffix; it must be exactly one
    // non-empty label followed by the separating dot.
    matches!(label.strip_suffix('.'), Some(l) if !l.is_empty() && !l.contains('.'))
}

/// Serves whatever `CertStore` is current. The lock is taken once per
/// *handshake*, never per request, so its cost is irrelevant beside the
/// asymmetric crypto happening around it.
#[derive(Debug)]
pub struct SniResolver {
    store: RwLock<Arc<CertStore>>,
}

impl SniResolver {
    pub fn new(store: Arc<CertStore>) -> Self {
        SniResolver {
            store: RwLock::new(store),
        }
    }

    pub fn swap(&self, next: Arc<CertStore>) {
        // Poisoning would mean a panic while holding the lock. The stored
        // value is a plain Arc that cannot be left half-updated, so recovering
        // is safe and strictly better than taking the process down with it.
        let mut guard = self.store.write().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }

    pub fn current(&self) -> Arc<CertStore> {
        Arc::clone(&self.store.read().unwrap_or_else(|e| e.into_inner()))
    }
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("count", &self.certs.len())
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // hello.server_name() is attacker-controlled text. It is used only to
        // pick a certificate — never logged unsampled, never a metric label.
        self.current().resolve(hello.server_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as support;

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. The counter makes collision impossible within this binary,
    // which is where every concurrent caller lives.
    fn store(specs: &[(&str, &[&str])]) -> CertStore {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lbsni-{}-{}",
            nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let certs = specs
            .iter()
            .map(|(name, hosts)| {
                let (cert_file, key_file) = support::write_pair(&dir, name, hosts);
                crate::load_certificate(&lb_core::CertificateConfig {
                    name: name.to_string(),
                    cert_file,
                    key_file,
                    hostnames: hosts.iter().map(|s| s.to_string()).collect(),
                    acme: None,
                })
                .unwrap()
            })
            .collect();
        CertStore::new(certs)
    }

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn a_single_certificate_is_served_regardless_of_sni() {
        // Nothing to choose between, and the client is better placed than we
        // are to decide whether the name it got is acceptable.
        let s = store(&[("only", &["example.com"])]);
        assert!(s.resolve(Some("example.com")).is_some());
        assert!(s.resolve(Some("something-else.test")).is_some());
        assert!(s.resolve(None).is_some());
    }

    #[test]
    fn sni_selects_among_several_certificates() {
        let s = store(&[("a", &["a.example.com"]), ("b", &["b.example.com"])]);
        let a = s.resolve(Some("a.example.com")).unwrap();
        let b = s.resolve(Some("b.example.com")).unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "both names resolved to one certificate"
        );
    }

    #[test]
    fn an_unmatched_sni_is_rejected_rather_than_given_a_default() {
        // Serving a mismatched certificate produces a browser error anyway,
        // so a fallback would turn a clear failure into a confusing one.
        let s = store(&[("a", &["a.example.com"]), ("b", &["b.example.com"])]);
        assert!(s.resolve(Some("c.example.com")).is_none());
        assert!(s.resolve(None).is_none());
    }

    #[test]
    fn a_wildcard_matches_exactly_one_label() {
        let s = store(&[("w", &["*.example.com"]), ("other", &["other.test"])]);
        assert!(s.resolve(Some("a.example.com")).is_some());
        // Multi-level must NOT match: public CAs do not issue such certs, and
        // treating one label as many silently widens what a cert covers.
        assert!(s.resolve(Some("a.b.example.com")).is_none());
        // A wildcard does not cover the bare parent domain.
        assert!(s.resolve(Some("example.com")).is_none());
    }

    #[test]
    fn matching_is_case_insensitive() {
        let s = store(&[("a", &["a.example.com"]), ("b", &["b.example.com"])]);
        assert!(s.resolve(Some("A.Example.COM")).is_some());
    }

    #[test]
    fn an_exact_match_wins_over_a_wildcard() {
        let s = store(&[("wild", &["*.example.com"]), ("exact", &["a.example.com"])]);
        // `a.example.com` is covered by BOTH entries. Precedence means it must
        // resolve to the specific certificate, not the wildcard one.
        let exact_hit = s.resolve(Some("a.example.com")).unwrap();
        // `z.example.com` can only be the wildcard.
        let wildcard_hit = s.resolve(Some("z.example.com")).unwrap();
        assert!(
            !Arc::ptr_eq(&exact_hit, &wildcard_hit),
            "a.example.com resolved to the wildcard certificate instead of its own"
        );
    }

    #[test]
    fn configured_patterns_are_case_insensitive() {
        // Hostnames are normalized to lowercase at load time, so a certificate
        // configured with an uppercase pattern (a plausible operator input)
        // must still match lowercase SNI from clients.
        let s = store(&[("upper", &["*.EXAMPLE.COM"]), ("exact", &["A.EXAMPLE.COM"])]);
        // Wildcard with uppercase pattern must match lowercase SNI.
        assert!(s.resolve(Some("a.example.com")).is_some());
        assert!(s.resolve(Some("z.example.com")).is_some());
        // Exact uppercase pattern must match lowercase SNI.
        assert!(s.resolve(Some("b.example.com")).is_some());
    }
}
