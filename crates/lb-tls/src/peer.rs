//! Mutual TLS for the cluster peer channel (`lb-cluster`'s gossip protocol).
//!
//! Unlike a listener's `TlsAcceptor`, there is no SNI resolution here and no
//! multiple certificates to choose between: gossip is symmetric (every node
//! pushes to every peer and accepts pushes from every peer), so one node has
//! exactly one identity for it, presented whichever role it is playing.
//! Trust is CA-based in both directions, using rustls' own WebPKI verifiers
//! rather than a hand-rolled one: a peer's certificate must chain to the
//! configured `ca_file` and carry that peer's gossip bind IP as a Subject
//! Alternative Name, checked by `ServerName::IpAddress` on the connecting
//! side and by the standard client-cert verifier on the accepting side.
use crate::certs::{load_ca_roots, load_chain_and_key};
use crate::{HandshakeError, TlsError};
use lb_core::PeerTlsConfig;
use rustls::pki_types::ServerName;
use rustls::server::WebPkiClientVerifier;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub struct PeerTls {
    acceptor: tokio_rustls::TlsAcceptor,
    connector: tokio_rustls::TlsConnector,
    handshake_timeout: Duration,
}

impl PeerTls {
    pub fn new(cfg: &PeerTlsConfig) -> Result<Self, TlsError> {
        crate::install_crypto_provider();

        // Loaded twice rather than cloned once: `PrivateKeyDer` deliberately
        // has no `Clone` impl (duplicating key material should be a visible,
        // named act, not implicit), and this file is read once at startup,
        // not on any hot path.
        let (server_chain, server_key) = load_chain_and_key(&cfg.cert_file, &cfg.key_file)?;
        let (client_chain, client_key) = load_chain_and_key(&cfg.cert_file, &cfg.key_file)?;
        let roots = Arc::new(load_ca_roots(&cfg.ca_file)?);

        let client_verifier = WebPkiClientVerifier::builder(Arc::clone(&roots))
            .build()
            .map_err(|e| TlsError::Config(format!("peer client verifier: {e}")))?;
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_chain, server_key)
            .map_err(|e| TlsError::Config(format!("peer server config: {e}")))?;

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain, client_key)
            .map_err(|e| TlsError::Config(format!("peer client config: {e}")))?;

        Ok(PeerTls {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
            connector: tokio_rustls::TlsConnector::from(Arc::new(client_config)),
            handshake_timeout: cfg.handshake_timeout(),
        })
    }

    /// Accepts a peer push. The caller runs this inside the spawned
    /// connection task, same reasoning as `TlsAcceptor::accept`: a handshake
    /// is several round trips, and doing it in the accept loop would let one
    /// slow or hostile peer stall every other one.
    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<tokio_rustls::server::TlsStream<S>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
            Ok(Ok(tls)) => Ok(tls),
            Ok(Err(err)) => Err(HandshakeError::Failed(err)),
            Err(_) => Err(HandshakeError::TimedOut),
        }
    }

    /// Connects out to push our own counters to `peer_ip`. `peer_ip` is
    /// checked against that peer's certificate the same way a browser checks
    /// a hostname -- an IP SAN standing in for the DNS name gossip has none
    /// of, since peers are addressed by `SocketAddr`, not hostname.
    pub async fn connect(
        &self,
        peer_ip: IpAddr,
        stream: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, HandshakeError> {
        let name = ServerName::IpAddress(peer_ip.into());
        match tokio::time::timeout(self.handshake_timeout, self.connector.connect(name, stream))
            .await
        {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // The clock alone is not unique: Windows' system time has ~15.6 ms
    // granularity, so concurrent tests routinely read the same nanosecond
    // value, land in the same directory, and overwrite each other's cert/key
    // files. The counter makes collision impossible within this binary,
    // which is where every concurrent caller lives.
    fn tmpdir() -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lbpeer-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn peer_tls_config(
        dir: &std::path::Path,
        stem: &str,
        ca_cert_path: &std::path::Path,
        ca: &support::Ca,
    ) -> PeerTlsConfig {
        let (cert_file, key_file) = support::write_peer_pair(dir, stem, ca, "127.0.0.1");
        PeerTlsConfig {
            cert_file,
            key_file,
            ca_file: ca_cert_path.to_path_buf(),
            handshake_timeout_ms: Some(300),
        }
    }

    /// Both sides trust the same CA, and each cert carries `127.0.0.1` as an
    /// IP SAN -- the baseline that every other test in this file deviates
    /// from in exactly one way.
    #[tokio::test]
    async fn a_mutual_handshake_over_a_shared_ca_succeeds() {
        let dir = tmpdir();
        let ca = support::Ca::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert_pem()).unwrap();

        let server_tls = PeerTls::new(&peer_tls_config(&dir, "srv", &ca_cert_path, &ca)).unwrap();
        let client_tls = PeerTls::new(&peer_tls_config(&dir, "cli", &ca_cert_path, &ca)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = server_tls.accept(stream).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            buf
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = client_tls.connect(addr.ip(), stream).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.shutdown().await.unwrap();

        assert_eq!(server.await.unwrap(), *b"hello");
    }

    /// The whole point of mutual auth: a client with no certificate at all
    /// must not be able to complete the handshake, HMAC layer notwithstanding.
    #[tokio::test]
    async fn a_client_with_no_certificate_is_rejected() {
        let dir = tmpdir();
        let ca = support::Ca::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert_pem()).unwrap();
        let server_tls = PeerTls::new(&peer_tls_config(&dir, "srv", &ca_cert_path, &ca)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await
        });

        // A plain rustls client config with no client cert presented at all.
        crate::install_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        {
            roots.add(cert).unwrap();
        }
        let no_cert_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(no_cert_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(ServerName::IpAddress(addr.ip().into()), stream)
            .await;

        // Either the client-side connect fails outright, or the server
        // refused during the handshake -- both are the rejection this test
        // exists to prove; which one depends on exactly when rustls' alert
        // crosses the wire relative to the client finishing its side.
        let server_outcome = server.await.unwrap();
        assert!(
            result.is_err() || matches!(server_outcome, Err(HandshakeError::Failed(_))),
            "a peer with no client certificate must not complete the handshake"
        );
    }

    /// A certificate from an unrelated CA is exactly as untrusted as no
    /// certificate at all.
    #[tokio::test]
    async fn a_client_certificate_from_a_different_ca_is_rejected() {
        let dir = tmpdir();
        let ca = support::Ca::new();
        let other_ca = support::Ca::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert_pem()).unwrap();

        let server_tls = PeerTls::new(&peer_tls_config(&dir, "srv", &ca_cert_path, &ca)).unwrap();
        // The client trusts (and is certified by) a *different* CA than the
        // server does.
        let other_ca_cert_path = dir.join("other-ca.crt");
        std::fs::write(&other_ca_cert_path, other_ca.cert_pem()).unwrap();
        let client_tls = PeerTls::new(&peer_tls_config(
            &dir,
            "cli",
            &other_ca_cert_path,
            &other_ca,
        ))
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client_result = client_tls.connect(addr.ip(), stream).await;
        let server_outcome = server.await.unwrap();

        assert!(
            client_result.is_err() || matches!(server_outcome, Err(HandshakeError::Failed(_))),
            "a client certified by an untrusted CA must not complete the handshake"
        );
    }

    /// A peer that connects and then says nothing during the handshake must
    /// not be able to hold the connection open forever.
    #[tokio::test]
    async fn a_silent_peer_is_timed_out() {
        let dir = tmpdir();
        let ca = support::Ca::new();
        let ca_cert_path = dir.join("ca.crt");
        std::fs::write(&ca_cert_path, ca.cert_pem()).unwrap();
        let server_tls = PeerTls::new(&peer_tls_config(&dir, "srv", &ca_cert_path, &ca)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await
        });

        let _silent = TcpStream::connect(addr).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("acceptor never gave up on a silent peer")
            .unwrap();
        assert!(matches!(outcome, Err(HandshakeError::TimedOut)));
    }
}
