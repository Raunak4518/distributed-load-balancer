use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lb_tls::{account_for, obtain_certificate_http01, AcmeChallengeStore, AcmeTrust};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;

fn env_or_skip(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn serve_http01(listener: TcpListener, challenges: Arc<AcmeChallengeStore>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let challenges = Arc::clone(&challenges);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let challenges = Arc::clone(&challenges);
                    async move {
                        let path = req.uri().path();
                        let token = path.strip_prefix("/.well-known/acme-challenge/");
                        let body = token.and_then(|t| challenges.get(t));
                        let (status, text) = match body {
                            Some(key_authorization) => (StatusCode::OK, key_authorization),
                            None => (StatusCode::NOT_FOUND, String::new()),
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(text)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
}

async fn spawn_http01_responder(challenges: Arc<AcmeChallengeStore>, port: u16) {
    let v4 = TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port} for HTTP-01 responder: {e}"));
    serve_http01(v4, Arc::clone(&challenges)).await;
    if let Ok(v6) = TcpListener::bind(("::1", port)).await {
        serve_http01(v6, challenges).await;
    }
}

#[tokio::test]
async fn obtains_a_real_certificate_from_pebble_over_http01() {
    let Some(directory_url) = env_or_skip("PEBBLE_DIRECTORY_URL") else {
        eprintln!("PEBBLE_DIRECTORY_URL not set, skipping");
        return;
    };
    let Some(ca_pem) = env_or_skip("PEBBLE_CA_PEM") else {
        eprintln!("PEBBLE_CA_PEM not set, skipping");
        return;
    };
    let http01_port: u16 = std::env::var("PEBBLE_HTTP01_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5002);

    lb_tls::install_crypto_provider();

    let challenges = Arc::new(AcmeChallengeStore::new());
    spawn_http01_responder(Arc::clone(&challenges), http01_port).await;

    let credentials_path =
        std::env::temp_dir().join(format!("lb-acme-test-account-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&credentials_path);

    let ca_path = std::path::PathBuf::from(&ca_pem);
    let account = account_for(
        AcmeTrust::CustomRootPem(&ca_path),
        &directory_url,
        "acme-test@example.com",
        &credentials_path,
    )
    .await
    .expect("account creation against Pebble failed");

    let domain = format!("acme-test-{}.example", std::process::id());
    let (cert_chain_pem, private_key_pem) =
        obtain_certificate_http01(&account, &domain, &challenges)
            .await
            .expect("certificate issuance failed");

    assert!(cert_chain_pem.contains("BEGIN CERTIFICATE"));
    assert!(private_key_pem.contains("BEGIN PRIVATE KEY"));

    let mut reader = std::io::Cursor::new(cert_chain_pem.as_bytes());
    let leaf_der = rustls_pemfile::certs(&mut reader)
        .next()
        .expect("no certificate in chain")
        .expect("malformed certificate PEM");
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der.as_ref())
        .expect("issued certificate did not parse as valid DER");
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

    let _ = std::fs::remove_file(&credentials_path);
}
