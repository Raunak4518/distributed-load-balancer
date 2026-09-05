use crate::{load_certificate, CertStore, SniResolver};
use lb_core::CertificateConfig;
use std::sync::Arc;
use std::time::Duration;

/// Modification time plus size. Two signals rather than one because mtime
/// granularity is coarse on some filesystems and a same-second rewrite of a
/// different length would otherwise go unnoticed.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct FileStamp {
    modified: std::time::SystemTime,
    len: u64,
}

fn stamp(path: &std::path::Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: meta.modified().ok()?,
        len: meta.len(),
    })
}

pub struct ReloadReport {
    pub applied: bool,
    pub rejected: Option<String>,
}

/// Reloads if any file changed. Returns what happened so the caller can
/// count it.
///
/// The load-bearing rule: every certificate is loaded and validated *before*
/// anything is swapped. If the new material is malformed or its key does not
/// match, the old store keeps serving. A reload that breaks TLS is strictly
/// worse than a certificate that is a few hours stale.
pub fn reload_once(
    certs: &[CertificateConfig],
    resolver: &SniResolver,
    stamps: &mut Vec<Option<FileStamp>>,
) -> ReloadReport {
    stamps.resize(certs.len() * 2, None);

    let current: Vec<Option<FileStamp>> = certs
        .iter()
        .flat_map(|c| [stamp(&c.cert_file), stamp(&c.key_file)])
        .collect();

    if current == *stamps {
        return ReloadReport {
            applied: false,
            rejected: None,
        };
    }

    let mut loaded = Vec::with_capacity(certs.len());
    for cfg in certs {
        match load_certificate(cfg) {
            Ok(c) => loaded.push(c),
            Err(err) => {
                // Do NOT record the new stamps: leaving them stale means the
                // next tick retries, so a half-written file that is finished
                // a moment later is picked up without operator action.
                return ReloadReport {
                    applied: false,
                    rejected: Some(format!("certificate '{}': {err}", cfg.name)),
                };
            }
        }
    }

    resolver.swap(Arc::new(CertStore::new(loaded)));
    *stamps = current;
    ReloadReport {
        applied: true,
        rejected: None,
    }
}

/// Polls rather than watching the filesystem: renewal is not
/// latency-sensitive, `inotify` has no portable Windows equivalent worth a
/// dependency, and the atomic-rename pattern certbot and cert-manager use
/// defeats naive watchers anyway.
///
/// `listener_name` labels both metrics below. It is not part of the brief's
/// original signature, but is required to avoid two bugs at once: without it,
/// `tls_certificate_expiry_timestamp_seconds` (labels `listener`, `cert`)
/// could only be called with one value, panicking on the first tick, and two
/// listeners that happen to name a certificate the same way would silently
/// clobber each other's gauge.
pub fn spawn_reloader(
    listener_name: String,
    certs: Vec<CertificateConfig>,
    resolver: Arc<SniResolver>,
    interval: Duration,
    metrics: Arc<lb_metrics::ListenerMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stamps: Vec<Option<FileStamp>> = Vec::new();
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let report = reload_once(&certs, &resolver, &mut stamps);
            if report.applied {
                for cert in resolver.current().certs() {
                    metrics
                        .tls_certificate_expiry_timestamp_seconds
                        .with_label_values(&[&listener_name, &cert.name])
                        .set(cert.not_after_unix);
                }
                tracing::info!(
                    listener = %listener_name,
                    certificates = certs.len(),
                    "certificates reloaded"
                );
                metrics.tls_certificate_reloads_applied.inc();
            } else if let Some(reason) = &report.rejected {
                tracing::error!(
                    listener = %listener_name,
                    reason = %reason,
                    "certificate reload REJECTED — continuing with the previous \
                     certificate, which will eventually expire"
                );
                metrics.tls_certificate_reloads_rejected.inc();
            } else {
                metrics.tls_certificate_reloads_unchanged.inc();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as support;

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. That is not just litter here: some of these tests hold their
    // files across a 1+ second sleep while asserting on reload behavior, so
    // a collision fails an assertion that has nothing to do with what the
    // test checks. The counter makes collision impossible within this
    // binary, which is where every concurrent caller lives.
    fn tmpdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lbreload-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(dir: &std::path::Path, stem: &str, names: &[&str]) -> CertificateConfig {
        let (cert_file, key_file) = support::write_pair(dir, stem, names);
        CertificateConfig {
            name: stem.to_string(),
            cert_file,
            key_file,
            hostnames: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn resolver_for(cfgs: &[CertificateConfig]) -> SniResolver {
        let loaded = cfgs
            .iter()
            .map(|c| crate::load_certificate(c).unwrap())
            .collect();
        SniResolver::new(std::sync::Arc::new(crate::CertStore::new(loaded)))
    }

    #[test]
    fn an_unchanged_file_is_not_reloaded() {
        let dir = tmpdir();
        let c = vec![cfg(&dir, "a", &["a.example.com"])];
        let resolver = resolver_for(&c);
        let mut stamps = vec![None];

        // First pass records the stamps and applies.
        assert!(reload_once(&c, &resolver, &mut stamps).applied);
        // Second pass sees identical files and does nothing.
        assert!(!reload_once(&c, &resolver, &mut stamps).applied);
    }

    /// `not_after_unix` is a poor signal here: both certificates carry
    /// rcgen's default validity window, so `after >= before` on that field
    /// is nearly always true whether or not a swap actually happened. What
    /// must actually be true is that the store itself was replaced --
    /// captured as an `Arc` before the reload and compared with `ptr_eq`.
    #[test]
    fn a_replaced_certificate_is_picked_up() {
        let dir = tmpdir();
        let c = vec![cfg(&dir, "a", &["a.example.com"])];
        let resolver = resolver_for(&c);
        let mut stamps = vec![None];
        reload_once(&c, &resolver, &mut stamps);
        let before_store = resolver.current();

        // Rewrite with a different certificate. Sleep past filesystem
        // timestamp granularity so the change is detectable.
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        let (cert_pem, key_pem) = support::self_signed(&["a.example.com"]);
        std::fs::write(&c[0].cert_file, cert_pem).unwrap();
        std::fs::write(&c[0].key_file, key_pem).unwrap();

        assert!(reload_once(&c, &resolver, &mut stamps).applied);
        assert!(
            !std::sync::Arc::ptr_eq(&before_store, &resolver.current()),
            "the store was not swapped"
        );
    }

    /// Task 6's rule is that every certificate in the batch is loaded and
    /// validated *before* anything is swapped, so a bad second certificate
    /// cannot leave a good first certificate applied on its own -- a
    /// *partial* swap, which is worse than a fully stale batch because it
    /// puts half-new material into service. This is the direct test for
    /// that: two certificates, a first reload applies both, then only the
    /// second is corrupted, and the whole batch -- including the still-valid
    /// first certificate -- must be rejected together.
    #[test]
    fn a_bad_second_certificate_rejects_the_whole_batch_not_just_itself() {
        let dir = tmpdir();
        let c = vec![
            cfg(&dir, "a", &["a.example.com"]),
            cfg(&dir, "b", &["b.example.com"]),
        ];
        let resolver = resolver_for(&c);
        let mut stamps = vec![None, None];
        reload_once(&c, &resolver, &mut stamps);
        let good = resolver.current();

        // Sleep past filesystem timestamp granularity so the change on the
        // second certificate is detectable.
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        std::fs::write(&c[1].cert_file, b"garbage, not a certificate").unwrap();

        let report = reload_once(&c, &resolver, &mut stamps);
        assert!(report.rejected.is_some());
        // The load-bearing assertion: not just "the bad cert was rejected",
        // but that the store was never swapped at all -- so the still-valid
        // first certificate was not applied either.
        assert!(
            std::sync::Arc::ptr_eq(&good, &resolver.current()),
            "a partial swap occurred: the first certificate was applied \
             even though the second was rejected"
        );
    }

    #[test]
    fn broken_material_is_rejected_and_the_old_certificate_keeps_serving() {
        let dir = tmpdir();
        let c = vec![cfg(&dir, "a", &["a.example.com"])];
        let resolver = resolver_for(&c);
        let mut stamps = vec![None];
        reload_once(&c, &resolver, &mut stamps);
        let good = resolver.current();

        std::thread::sleep(std::time::Duration::from_millis(1_100));
        std::fs::write(&c[0].cert_file, b"garbage, not a certificate").unwrap();

        let report = reload_once(&c, &resolver, &mut stamps);
        assert!(!report.applied);
        assert!(report.rejected.is_some());
        // The load-bearing assertion: a broken reload must not take TLS down.
        // A stale certificate beats no certificate.
        assert!(std::sync::Arc::ptr_eq(&good, &resolver.current()));
    }
}
