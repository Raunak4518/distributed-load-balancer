use crate::{load_certificate, CertStore, SniResolver, TlsError};
use lb_core::{TlsConfig, TlsVersion};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Installs the `ring` provider process-wide. Idempotent and safe to call
/// from every test; `lb-server` calls it once at startup.
///
/// This must agree with the provider every TLS crate in the graph selected,
/// or the mismatch surfaces at runtime rather than at compile time.
pub fn install_crypto_provider() {
    // An Err means one is already installed, which is exactly what we want.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
pub enum HandshakeError {
    TimedOut,
    Failed(std::io::Error),
}

pub struct TlsAcceptor {
    inner: tokio_rustls::TlsAcceptor,
    resolver: Arc<SniResolver>,
    handshake_timeout: Duration,
}

impl TlsAcceptor {
    pub fn new(cfg: &TlsConfig, alpn: &[&[u8]]) -> Result<Self, TlsError> {
        // Not merely belt and braces: this constructor is the first thing in
        // the process to build a rustls type, and it is reachable from any
        // caller, not just `lb_server::run`. Leaving the install as an
        // undocumented obligation on the caller would make a forgotten call
        // a runtime panic in a crate that has no idea rustls is involved.
        // The call is idempotent, so `run` keeps its own -- that stays the
        // documented place, this is the one that cannot be forgotten.
        install_crypto_provider();

        let loaded = cfg
            .certificates
            .iter()
            .map(load_certificate)
            .collect::<Result<Vec<_>, _>>()?;
        let resolver = Arc::new(SniResolver::new(Arc::new(CertStore::new(loaded))));

        let versions: &[&rustls::SupportedProtocolVersion] = match cfg.min_version() {
            TlsVersion::Tls12 => rustls::ALL_VERSIONS,
            TlsVersion::Tls13 => &[&rustls::version::TLS13],
        };

        let mut server_config = rustls::ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_cert_resolver(
                Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>
            );

        server_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

        // rustls defaults to 256 cached sessions, which is negligible at the
        // 50k req/s target -- a full handshake costs milliseconds of CPU,
        // so resumption is the second-biggest lever after key type.
        server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(20_480);
        // TLS 1.3 tickets. Keys are per-process, so a client landing on a
        // different cluster node performs a full handshake; sharing them
        // across nodes is security-sensitive and deliberately deferred.
        if let Ok(ticketer) = rustls::crypto::ring::Ticketer::new() {
            server_config.ticketer = ticketer;
        }

        Ok(TlsAcceptor {
            inner: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
            resolver,
            handshake_timeout: cfg.handshake_timeout(),
        })
    }

    pub fn resolver(&self) -> &Arc<SniResolver> {
        &self.resolver
    }

    /// Completes the handshake, or gives up.
    ///
    /// The caller runs this inside the spawned connection task, never in the
    /// accept loop: a handshake is several network round trips, and doing it
    /// before `spawn` would let one slow client stall every other accept.
    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<tokio_rustls::server::TlsStream<S>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(self.handshake_timeout, self.inner.accept(stream)).await {
            Ok(Ok(tls)) => Ok(tls),
            Ok(Err(err)) => Err(HandshakeError::Failed(err)),
            Err(_) => Err(HandshakeError::TimedOut),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as support;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    fn tls_config(dir: &std::path::Path, names: &[&str]) -> lb_core::TlsConfig {
        let (cert_file, key_file) = support::write_pair(dir, "srv", names);
        lb_core::TlsConfig {
            certificates: vec![lb_core::CertificateConfig {
                name: "srv".into(),
                cert_file,
                key_file,
                hostnames: names.iter().map(|s| s.to_string()).collect(),
            }],
            handshake_timeout_ms: Some(300),
            min_version: None,
            reload_interval_secs: None,
            hsts_max_age_secs: None,
        }
    }

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. The counter makes collision impossible within this binary,
    // which is where every concurrent caller lives.
    fn tmpdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lbacc-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A client that connects and then says nothing must be dropped by the
    /// handshake timeout. Nothing in Phase 5 covers this window: hyper never
    /// sees a connection whose handshake has not completed.
    #[tokio::test]
    async fn a_silent_client_is_timed_out() {
        install_crypto_provider();
        let dir = tmpdir();
        let acceptor =
            TlsAcceptor::new(&tls_config(&dir, &["example.com"]), &[b"http/1.1"]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await.err()
        });

        // Connect, send nothing, hold the socket open.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("acceptor never gave up on a silent client")
            .unwrap();
        assert!(matches!(outcome, Some(HandshakeError::TimedOut)));
    }

    /// Plaintext bytes on a TLS port must produce a clean, prompt failure
    /// rather than a hang.
    #[tokio::test]
    async fn plaintext_on_a_tls_port_fails_promptly() {
        install_crypto_provider();
        let dir = tmpdir();
        let acceptor =
            TlsAcceptor::new(&tls_config(&dir, &["example.com"]), &[b"http/1.1"]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await.err()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("acceptor hung on plaintext")
            .unwrap();
        // Failed, not TimedOut: rustls rejects the bytes as soon as it sees
        // they are not a ClientHello.
        assert!(matches!(outcome, Some(HandshakeError::Failed(_))));
    }

    #[test]
    fn an_unreadable_certificate_fails_construction() {
        install_crypto_provider();
        let cfg = lb_core::TlsConfig {
            certificates: vec![lb_core::CertificateConfig {
                name: "gone".into(),
                cert_file: "/nonexistent/x.crt".into(),
                key_file: "/nonexistent/x.key".into(),
                hostnames: vec![],
            }],
            handshake_timeout_ms: None,
            min_version: None,
            reload_interval_secs: None,
            hsts_max_age_secs: None,
        };
        // Startup must fail loudly rather than binding a port that cannot
        // complete a handshake.
        assert!(TlsAcceptor::new(&cfg, &[b"http/1.1"]).is_err());
    }
}
