mod support;

use lb_core::Config;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Ca {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    fn issue(&self, names: &[&str]) -> (rcgen::Certificate, rcgen::KeyPair) {
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert, key)
    }
}

fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "\\\\")
}

async fn start_admin_with_mtls(ca: &Ca) -> SocketAddr {
    let dir = std::env::temp_dir().join(format!(
        "lb-admin-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cert, server_key) = ca.issue(&["127.0.0.1"]);
    let cert_file = dir.join("admin.crt");
    let key_file = dir.join("admin.key");
    let ca_file = dir.join("ca.crt");
    std::fs::write(&cert_file, server_cert.pem()).unwrap();
    std::fs::write(&key_file, server_key.serialize_pem()).unwrap();
    std::fs::write(&ca_file, ca.cert.pem()).unwrap();

    let (backend, _) = support::spawn_counting_backend(hyper::StatusCode::OK).await;
    let admin = free_addr().await;
    let traffic = free_addr().await;
    let text = support::admin_config_toml(admin, traffic, backend, 1000.0, 1000).replacen(
        &format!("listen = \"{admin}\"\n"),
        &format!(
            "listen = \"{admin}\"\n\n[admin.tls]\ncert_file = \"{}\"\nkey_file = \"{}\"\nclient_ca_file = \"{}\"\n",
            toml_path(&cert_file),
            toml_path(&key_file),
            toml_path(&ca_file)
        ),
        1,
    );
    tokio::spawn(lb_server::run(Config::parse(&text).unwrap(), None));
    support::wait_until_listening(traffic).await;
    support::wait_until_listening(admin).await;
    admin
}

async fn get_metrics_over_tls(
    admin: SocketAddr,
    trust: &Ca,
    identity: Option<(rcgen::Certificate, rcgen::KeyPair)>,
) -> std::io::Result<String> {
    lb_tls::install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trust.cert.der().clone()).unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(admin).await?;
    let mut tls = connector
        .connect(ServerName::IpAddress(admin.ip().into()), stream)
        .await?;
    tls.write_all(b"GET /metrics HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::other("timed out"))??;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[tokio::test]
async fn a_client_certificate_from_the_trusted_ca_reaches_the_admin_api() {
    let ca = Ca::new();
    let admin = start_admin_with_mtls(&ca).await;
    let response = get_metrics_over_tls(admin, &ca, Some(ca.issue(&["operator"])))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("lb_requests_total"), "{response}");
}

#[tokio::test]
async fn a_client_without_a_trusted_certificate_is_refused() {
    let ca = Ca::new();
    let admin = start_admin_with_mtls(&ca).await;

    let anonymous = get_metrics_over_tls(admin, &ca, None).await;
    assert!(
        anonymous.map_or(true, |r| !r.starts_with("HTTP/1.1 200")),
        "a client with no certificate must not be served"
    );

    let stranger = Ca::new();
    let foreign = get_metrics_over_tls(admin, &ca, Some(stranger.issue(&["intruder"]))).await;
    assert!(
        foreign.map_or(true, |r| !r.starts_with("HTTP/1.1 200")),
        "a certificate from another CA must not be served"
    );

    let mut plain = TcpStream::connect(admin).await.unwrap();
    plain
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut response)).await;
    assert!(
        !String::from_utf8_lossy(&response).contains("lb_requests_total"),
        "plaintext must not reach a TLS admin listener"
    );
}
