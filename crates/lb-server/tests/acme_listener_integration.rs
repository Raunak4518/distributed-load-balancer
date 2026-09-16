mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

fn env_or_skip(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn tls_connect(addr: SocketAddr, sni: &str) -> tokio_rustls::client::TlsStream<TcpStream> {
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    connector
        .connect(name, stream)
        .await
        .expect("tls handshake")
}

#[allow(clippy::too_many_arguments)]
fn acme_listener_config_toml(
    http_listen: SocketAddr,
    tls_listen: SocketAddr,
    backend: SocketAddr,
    directory_url: &str,
    contact_email: &str,
    account_key_file: &std::path::Path,
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
    domain: &str,
    ca_bundle_file: &std::path::Path,
) -> String {
    format!(
        r#"
[[listeners]]
name = "acme-challenge"
protocol = "http"
listen = "{http_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 60000
  timeout_ms = 500
  failure_threshold = 100
  cooldown_ms = 60000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"

[[listeners]]
name = "acme-tls"
protocol = "http"
listen = "{tls_listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 60000
  timeout_ms = 500
  failure_threshold = 100
  cooldown_ms = 60000

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 100000
  burst = 100000

  [listeners.load_balancing]
  strategy = "round_robin"

  [listeners.tls]
  reload_interval_secs = 1

  [[listeners.tls.certificates]]
  name = "acme-cert"
  cert_file = "{cert_file}"
  key_file = "{key_file}"
  hostnames = ["{domain}"]

    [listeners.tls.certificates.acme]
    directory_url = "{directory_url}"
    contact_email = "{contact_email}"
    account_key_file = "{account_key_file}"
    renew_before_days = 30
    check_interval_secs = 43200
    ca_bundle_file = "{ca_bundle_file}"
"#,
        http_listen = http_listen,
        tls_listen = tls_listen,
        backend = backend,
        directory_url = directory_url,
        contact_email = contact_email,
        account_key_file = account_key_file.display().to_string().replace('\\', "\\\\"),
        cert_file = cert_file.display().to_string().replace('\\', "\\\\"),
        key_file = key_file.display().to_string().replace('\\', "\\\\"),
        domain = domain,
        ca_bundle_file = ca_bundle_file.display().to_string().replace('\\', "\\\\"),
    )
}

#[tokio::test]
async fn a_listener_bootstraps_then_serves_an_acme_issued_certificate() {
    let Some(directory_url) = env_or_skip("PEBBLE_DIRECTORY_URL") else {
        eprintln!("PEBBLE_DIRECTORY_URL not set, skipping");
        return;
    };
    let Some(ca_pem) = env_or_skip("PEBBLE_CA_PEM") else {
        eprintln!("PEBBLE_CA_PEM not set, skipping");
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lb_tls=trace,lb_server=trace")
        .try_init();

    let http01_port: u16 = std::env::var("PEBBLE_HTTP01_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5002);

    let (backend_addr, _count) = support::spawn_counting_backend(StatusCode::OK).await;
    let http_listen: SocketAddr = format!("127.0.0.1:{http01_port}").parse().unwrap();
    let tls_listen = free_addr().await;

    let run_id = std::process::id();
    let account_key_file =
        std::env::temp_dir().join(format!("lb-acme-listener-account-{run_id}.json"));
    let cert_file = std::env::temp_dir().join(format!("lb-acme-listener-{run_id}.crt"));
    let key_file = std::env::temp_dir().join(format!("lb-acme-listener-{run_id}.key"));
    let _ = std::fs::remove_file(&account_key_file);
    let _ = std::fs::remove_file(&cert_file);
    let _ = std::fs::remove_file(&key_file);

    let domain = format!("acme-listener-test-{run_id}.example");

    let ca_bundle_file = std::path::PathBuf::from(&ca_pem);
    let config_text = acme_listener_config_toml(
        http_listen,
        tls_listen,
        backend_addr,
        &directory_url,
        "acme-listener-test@example.com",
        &account_key_file,
        &cert_file,
        &key_file,
        &domain,
        &ca_bundle_file,
    );
    let config = Config::parse(&config_text).unwrap();

    tokio::spawn(lb_server::run(config, None));
    support::wait_until_listening(tls_listen).await;

    let bootstrap_tls = tls_connect(tls_listen, &domain).await;
    let bootstrap_der = bootstrap_tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("no peer certificate")[0]
        .to_vec();
    drop(bootstrap_tls);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut issued_der = bootstrap_der.clone();
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let tls = tls_connect(tls_listen, &domain).await;
        let der = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("no peer certificate")[0]
            .to_vec();
        if der != bootstrap_der {
            issued_der = der;
            break;
        }
    }

    assert_ne!(
        issued_der, bootstrap_der,
        "the listener never swapped the bootstrap self-signed certificate for the acme-issued one"
    );

    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&issued_der).unwrap();
    let sans = cert
        .subject_alternative_name()
        .unwrap()
        .expect("certificate has no SAN extension")
        .value
        .general_names
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>();
    assert!(
        sans.iter().any(|s| s.contains(&domain)),
        "issued certificate's SAN {sans:?} does not include {domain}"
    );

    let _ = std::fs::remove_file(&account_key_file);
    let _ = std::fs::remove_file(&cert_file);
    let _ = std::fs::remove_file(&key_file);
}
