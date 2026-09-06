mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::spawn_counting_backend;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Writes a self-signed pair into a fresh temp dir and returns
/// (dir, cert_path, key_path). Generated per run rather than checked in: no
/// private key, however worthless, belongs in version control.
///
/// The directory name carries a process-wide counter as well as the clock,
/// for the reason documented at the twin of this helper in
/// `tls_integration.rs`: Windows' system time has ~15.6 ms granularity, so
/// two concurrent tests routinely read the same nanosecond value, land in the
/// same directory, overwrite each other's files, and fail with a
/// `KeyMismatch` that has nothing to do with what they were checking.
fn cert_files(names: &[&str]) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lbh2it-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let generated = rcgen::generate_simple_self_signed(owned).unwrap();
    let cert_path = dir.join("s.crt");
    let key_path = dir.join("s.key");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    // rcgen 0.13 names this field `key_pair`, not `signing_key`.
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
    (dir, cert_path, key_path)
}

fn tls_http_config(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    handshake_timeout_ms: u64,
    header_read_timeout_ms: u64,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
header_read_timeout_ms = {header_read_timeout_ms}

  [listeners.tls]
  handshake_timeout_ms = {handshake_timeout_ms}
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "{cert}"
    key_file = "{key}"
    hostnames = ["localhost"]

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#,
        // Windows paths are backslash-separated, and a lone backslash is an
        // escape inside a TOML basic string.
        cert = cert.display().to_string().replace('\\', "\\\\"),
        key = key.display().to_string().replace('\\', "\\\\"),
    )
}

/// The same listener with no `[listeners.tls]` section at all.
fn plaintext_http_config(listen: SocketAddr, backend: SocketAddr) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
  path = "/health"
  interval_ms = 500
  timeout_ms = 200
  failure_threshold = 2
  cooldown_ms = 300

  [listeners.rate_limit]
  key = "source_ip"
  rate_per_sec = 10000
  burst = 10000

  [listeners.load_balancing]
  strategy = "round_robin"
"#
    )
}

#[tokio::test]
async fn a_client_offering_h2_is_served_http2() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config =
        Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // No builder call enables h2: with `native-tls-alpn` on, reqwest offers
    // `h2, http/1.1` by default and the server's ALPN preference decides.
    // The certificate is self-signed, so the harness must trust the cert it
    // just generated — that is the test, not the load balancer, skipping
    // verification.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .expect("https request failed");

    assert_eq!(resp.status(), 200);
    // The assertion that matters: not merely that it worked, but that it
    // worked over HTTP/2.
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_client_offering_only_http11_still_gets_http11() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config =
        Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 5_000)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Phases 1-6 regression guard: adding h2 must not take http/1.1 away.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
}

#[tokio::test]
async fn http2_disabled_means_h2_is_never_negotiated() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let mut toml = tls_http_config(listen, backend, &cert, &key, 5_000, 5_000);
    toml.push_str("\n  [listeners.http2]\n  enabled = false\n");
    let config = Config::parse(&toml).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();
    // The client offered h2; the server did not advertise it.
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
}

#[tokio::test]
async fn a_plaintext_listener_refuses_http2() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&plaintext_http_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Prior-knowledge h2c on an unencrypted edge port is surface nobody asked
    // for. A client that insists on it must fail, not be quietly served.
    let h2c = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    assert!(h2c.get(format!("http://{listen}/")).send().await.is_err());
    // `is_err()` alone would pass on a listener that was simply broken, or
    // never came up. This is the assertion that says *refused*: the request
    // did not reach a backend.
    assert_eq!(count.load(Ordering::SeqCst), 0);

    // And the listener is refusing h2c specifically, not refusing everything:
    // the same port still serves an ordinary HTTP/1.1 client.
    let h1 = reqwest::Client::builder().build().unwrap();
    let resp = h1
        .get(format!("http://{listen}/"))
        .send()
        .await
        .expect("plaintext http/1.1 request failed");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// A client that completes the TLS handshake, negotiates `h2` over ALPN, and
/// then sends nothing at all.
///
/// hyper has no answer for this on its own: its PING keep-alive is armed only
/// once the client's preface and SETTINGS have arrived, so before that there
/// is no timer running anywhere. On HTTP/1.1 the same client is cut by
/// `header_read_timeout`. Without `FirstByteDeadline` this connection is held
/// open indefinitely, occupying a connection permit and a per-IP slot for
/// free -- Phase 5's slowloris, one protocol layer up.
#[tokio::test]
async fn an_h2_client_that_never_sends_its_preface_is_timed_out() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 300)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let mut tls = tls_connect_h2(listen).await;

    // Not a sleep-then-assert: read until the server closes. The deadline is
    // 300ms, so 3s is ten times the budget -- long enough that a pass is not
    // luck, short enough that a regression is not a hang.
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        let mut buf = [0u8; 1024];
        loop {
            match tls.read(&mut buf).await {
                // A clean EOF or a reset. Both are the connection being
                // taken away, which is the whole assertion.
                Ok(0) | Err(_) => return,
                // hyper sends its own SETTINGS frame the moment the
                // connection is handed to it, before anything is due from
                // the client. Reading exactly once would see that and
                // conclude the server was alive, so keep going.
                Ok(_) => continue,
            }
        }
    })
    .await;

    closed.expect(
        "the connection was still open 3s into a 300ms first-byte budget: \
         a silent h2 client is holding its connection permit indefinitely",
    );
}

/// A client-side verifier that accepts whatever certificate it is shown.
///
/// The harness trusting a certificate it generated seconds ago -- the rustls
/// equivalent of `danger_accept_invalid_certs` in the reqwest tests above. It
/// never runs in the load balancer, which does no client-side verification on
/// this path at all.
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

/// Completes a TLS handshake offering only `h2`, and asserts that is what was
/// negotiated.
///
/// Hand-rolled rather than reqwest because the whole point is to stop after
/// the handshake and send nothing -- no HTTP client will do that. The
/// provider is named explicitly rather than taken from the process default:
/// the server installs that from its own task, and this way the test does not
/// depend on having lost that race.
async fn tls_connect_h2(addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
    .with_no_client_auth();
    // Only `h2`: if the server declined it the handshake fails outright,
    // rather than quietly falling back to http/1.1 and leaving this test
    // measuring `header_read_timeout` instead of the h2 deadline.
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = connector
        .connect(name, stream)
        .await
        .expect("tls handshake");

    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "the server did not negotiate h2, so this test would not be exercising the h2 path"
    );
    tls
}
