use crate::certs::{load_ca_roots, load_chain_and_key};
use crate::{HandshakeError, TlsError};
use rustls::server::WebPkiClientVerifier;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

pub struct AdminTls {
    acceptor: tokio_rustls::TlsAcceptor,
    handshake_timeout: Duration,
}

impl AdminTls {
    pub fn new(
        cert_file: &Path,
        key_file: &Path,
        client_ca_file: Option<&Path>,
        handshake_timeout: Duration,
    ) -> Result<Self, TlsError> {
        crate::install_crypto_provider();
        let (chain, key) = load_chain_and_key(cert_file, key_file)?;
        let builder = rustls::ServerConfig::builder();
        let config = match client_ca_file {
            Some(ca_file) => {
                let roots = Arc::new(load_ca_roots(ca_file)?);
                let verifier = WebPkiClientVerifier::builder(roots)
                    .build()
                    .map_err(|e| TlsError::Config(format!("admin client verifier: {e}")))?;
                builder
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(chain, key)
            }
            None => builder.with_no_client_auth().with_single_cert(chain, key),
        }
        .map_err(|e| TlsError::Config(format!("admin server config: {e}")))?;
        Ok(AdminTls {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            handshake_timeout,
        })
    }

    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>, HandshakeError> {
        match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
            Ok(Ok(tls)) => Ok(tls),
            Ok(Err(err)) => Err(HandshakeError::Failed(err)),
            Err(_) => Err(HandshakeError::TimedOut),
        }
    }
}
