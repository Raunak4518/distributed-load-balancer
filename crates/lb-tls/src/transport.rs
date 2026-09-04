use crate::BackendConnector;
use lb_core::{OutboundTransport, ProxyStream, WrapFuture};
use std::time::Duration;

/// `lb-core`'s outbound transport seam, backed by `BackendConnector`.
///
/// This is the only place the L4 data plane's re-encryption meets rustls.
/// `lb-tcp` holds an `Arc<dyn OutboundTransport>` and never names a TLS
/// crate; this type turns that request into the handshake the connector's
/// trust roots and verification policy were built for.
pub struct BackendTlsTransport {
    connector: tokio_rustls::TlsConnector,
}

impl BackendTlsTransport {
    /// Takes the already-built connector rather than a `BackendTlsConfig`,
    /// so a listener that both forwards and probes shares one set of trust
    /// roots instead of loading them twice and drifting.
    pub fn new(connector: &BackendConnector) -> Self {
        BackendTlsTransport {
            connector: connector.tls_connector(),
        }
    }
}

impl OutboundTransport for BackendTlsTransport {
    fn wrap(
        &self,
        stream: Box<dyn ProxyStream>,
        server_name: String,
        timeout: Duration,
    ) -> WrapFuture<'_> {
        // Cloning the connector (an `Arc` inside) rather than borrowing self
        // keeps the future independent of the borrow, which is what lets the
        // caller hold it across the retry loop.
        let connector = self.connector.clone();
        Box::pin(async move {
            let name =
                rustls::pki_types::ServerName::try_from(server_name.clone()).map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("'{server_name}' is not a usable server name: {err}"),
                    )
                })?;
            // Bounded by the caller's connect timeout: a backend that
            // accepts the TCP connection and then never finishes the
            // handshake is a backend that did not answer, and must not hold
            // a client connection open indefinitely.
            match tokio::time::timeout(timeout, connector.connect(name, stream)).await {
                Ok(Ok(tls)) => Ok(Box::new(tls) as Box<dyn ProxyStream>),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "backend TLS handshake timed out",
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as support;
    use lb_core::BackendTlsConfig;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "lbtransport-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A TLS server presenting `cert`/`key` that echoes whatever it is sent.
    ///
    /// A real listener completing a real handshake, not a mock: what these
    /// tests exist to prove is that verification actually happens, and a
    /// double would prove only that the plumbing was called.
    async fn spawn_tls_echo(
        cert: &std::path::Path,
        key: &std::path::Path,
        hostname: &str,
    ) -> std::net::SocketAddr {
        let tls_cfg = lb_core::TlsConfig {
            certificates: vec![lb_core::CertificateConfig {
                name: "backend".into(),
                cert_file: cert.to_path_buf(),
                key_file: key.to_path_buf(),
                hostnames: vec![hostname.to_string()],
            }],
            handshake_timeout_ms: Some(5_000),
            min_version: None,
            reload_interval_secs: None,
            hsts_max_age_secs: None,
        };
        let acceptor = Arc::new(crate::TlsAcceptor::new(&tls_cfg, &[]).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = Arc::clone(&acceptor);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = tls.read(&mut buf).await {
                        if n == 0 || tls.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn wrap_against(
        cfg: BackendTlsConfig,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> std::io::Result<Box<dyn ProxyStream>> {
        let transport = BackendTlsTransport::new(&BackendConnector::new(&cfg).unwrap());
        let stream: Box<dyn ProxyStream> = Box::new(TcpStream::connect(addr).await.unwrap());
        transport
            .wrap(stream, server_name.to_string(), Duration::from_secs(5))
            .await
    }

    /// The deferred half of Task 7, now that the connector is wired into a
    /// live connection: a certificate that chains to nothing we trust must
    /// fail the handshake. Everything else about re-encryption is worthless
    /// if this does not hold.
    #[tokio::test]
    async fn an_untrusted_certificate_fails_the_handshake() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);
        let addr = spawn_tls_echo(&cert, &key, "backend.internal").await;

        let result = wrap_against(
            BackendTlsConfig {
                // The system trust store, which has never heard of a
                // certificate generated seconds ago.
                ca_file: None,
                danger_accept_invalid_certs: false,
            },
            addr,
            "backend.internal",
        )
        .await;

        assert!(
            result.is_err(),
            "an untrusted backend certificate was accepted"
        );
    }

    /// The same backend and the same verification, with its certificate
    /// supplied as the trust root — the internal-PKI case `ca_file` exists
    /// for. This is the control: without it, the test above would also pass
    /// if the handshake never happened at all.
    #[tokio::test]
    async fn a_certificate_in_the_trust_store_completes_the_handshake() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);
        let addr = spawn_tls_echo(&cert, &key, "backend.internal").await;

        let mut tls = wrap_against(
            BackendTlsConfig {
                ca_file: Some(cert.clone()),
                danger_accept_invalid_certs: false,
            },
            addr,
            "backend.internal",
        )
        .await
        .expect("a backend whose certificate is the configured trust root");

        // Bytes actually flow over the wrapped stream, so what came back is
        // a working connection and not merely a completed handshake.
        tls.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    /// Verification is by name, not merely by trust: the certificate is the
    /// configured root, but it is not issued for the name we asked for.
    #[tokio::test]
    async fn a_trusted_certificate_for_the_wrong_name_is_refused() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);
        let addr = spawn_tls_echo(&cert, &key, "backend.internal").await;

        let result = wrap_against(
            BackendTlsConfig {
                ca_file: Some(cert.clone()),
                danger_accept_invalid_certs: false,
            },
            addr,
            "someone.else.internal",
        )
        .await;

        assert!(
            result.is_err(),
            "a certificate for another name was accepted"
        );
    }

    /// The other deferred half: `danger_accept_invalid_certs` has to actually
    /// bypass verification, against the very certificate the default mode
    /// refuses above. A flag that is documented as dangerous and quietly does
    /// nothing is worse than no flag.
    #[tokio::test]
    async fn the_danger_flag_accepts_a_certificate_that_would_otherwise_be_refused() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);
        let addr = spawn_tls_echo(&cert, &key, "backend.internal").await;

        let mut tls = wrap_against(
            BackendTlsConfig {
                ca_file: None,
                danger_accept_invalid_certs: true,
            },
            addr,
            "backend.internal",
        )
        .await
        .expect("danger_accept_invalid_certs did not bypass verification");

        tls.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        tls.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    /// A name no certificate could ever carry fails before any byte is sent,
    /// and as an error rather than a panic: it arrives from config, and
    /// config must not be able to kill a connection task.
    #[tokio::test]
    async fn an_unusable_server_name_is_an_error_not_a_panic() {
        let dir = tmpdir();
        let (cert, key) = support::write_pair(&dir, "backend", &["backend.internal"]);
        let addr = spawn_tls_echo(&cert, &key, "backend.internal").await;

        let result = wrap_against(
            BackendTlsConfig {
                ca_file: Some(cert.clone()),
                danger_accept_invalid_certs: false,
            },
            addr,
            "not a hostname",
        )
        .await;

        assert!(matches!(
            result.map(|_| ()),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
}
