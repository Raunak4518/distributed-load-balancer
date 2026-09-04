mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use support::spawn_counting_backend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
fn cert_files(names: &[&str]) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "lbtlsit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
    max_connections_per_ip: usize,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
max_connections_per_ip = {max_connections_per_ip}

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

#[tokio::test]
async fn an_https_request_is_proxied_to_a_plaintext_backend() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 100)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // The certificate is self-signed, so the test client must be told to
    // accept it. This is the test harness trusting a cert it just generated,
    // not the load balancer skipping verification.
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
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_client_that_never_starts_the_handshake_is_dropped() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 300, 100)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let mut silent = TcpStream::connect(listen).await.unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 32];
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf)).await;

    assert!(closed.is_ok(), "a silent TLS client was held indefinitely");
    // Tight enough to prove the *configured* 300ms is what is in force: a
    // regression to a hardcoded default, or to the header-read timeout of
    // 5s, would blow this bound. No lower bound — that would only make the
    // test flaky on a loaded machine.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "held for {:?}, far longer than the configured 300ms handshake timeout",
        started.elapsed()
    );
}

#[tokio::test]
async fn plaintext_on_a_tls_port_is_closed_not_hung() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 100)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let outcome = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut buf)).await;
    assert!(
        outcome.is_ok(),
        "server hung on plaintext sent to a TLS port"
    );
    // The other half of the requirement: closed with *no response*. There is
    // no TLS session to answer over and nothing that would be valid HTTP, so
    // an HTTP error page here would be a bug. 0x15 is the TLS record type for
    // an alert, which rustls is entitled to send before closing.
    assert!(
        buf.is_empty() || buf[0] == 0x15,
        "expected no application response (a TLS alert is fine), got: {buf:?}"
    );
}

/// A mistyped `cert_file` is the commonest TLS misconfiguration there is, so
/// it must produce the most useful diagnostic we have: a clean startup error
/// naming the listener. A panic here would be swallowed by the un-awaited
/// `JoinHandle` every other test in this file spawns, and would surface as
/// "nothing listening after 10s" — the least useful message possible.
#[tokio::test]
async fn a_certificate_that_cannot_be_loaded_fails_startup_with_an_error() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (dir, _cert, key) = cert_files(&["localhost"]);
    let missing = dir.join("this-file-was-never-written.crt");
    let config = Config::parse(&tls_http_config(
        listen, backend, &missing, &key, 5_000, 100,
    ))
    .unwrap();

    // Awaited, not spawned: the whole point is that the failure is returned.
    let err = lb_server::run(config)
        .await
        .expect_err("an unreadable certificate must fail startup");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("web"),
        "the error must name the listener that could not start: {err}"
    );
}

/// The whole design argument for holding both Phase 5 guards across the
/// handshake is that the handshake timeout drains the budget again. This
/// proves the draining half: fill the per-IP budget with clients that never
/// start a handshake, wait past the timeout, and the next real client must
/// still be served.
///
/// The other half — that a handshake flood does consume the budget — is
/// already covered by `hardening_integration`'s per-IP test, and asserting it
/// here would mean racing the 300ms timeout with a fourth connection.
#[tokio::test]
async fn a_failed_handshake_releases_the_connection_budget() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    // Three per-IP slots, and a handshake that gives up after 300ms.
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 300, 3)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Held open, saying nothing, for the whole test: if the guards leaked,
    // the budget would still read as full below.
    let mut silent = Vec::new();
    for _ in 0..3 {
        silent.push(TcpStream::connect(listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(900)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .expect("timed-out handshakes did not release the connection budget");
    assert_eq!(resp.status(), 200);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(silent.len(), 3);
}

/// Phase 5 regression guard: a listener with no [listeners.tls] behaves
/// exactly as it did before this phase.
#[tokio::test]
async fn a_plaintext_listener_is_unaffected() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&format!(
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
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let status = reqwest::get(format!("http://{listen}/"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// Same as `tls_http_config`, plus an `[admin]` section (to scrape metrics)
/// and a configurable `reload_interval_secs` (to make the poll fast enough
/// for a test).
fn tls_http_config_with_admin(
    listen: SocketAddr,
    admin: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    reload_interval_secs: u64,
) -> String {
    format!(
        r#"
[admin]
listen = "{admin}"

[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [listeners.tls]
  handshake_timeout_ms = 5000
  reload_interval_secs = {reload_interval_secs}
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
        cert = cert.display().to_string().replace('\\', "\\\\"),
        key = key.display().to_string().replace('\\', "\\\\"),
    )
}

/// The end-to-end proof that the reloader is actually wired into `run`, not
/// just correct in isolation: rewrite the certificate on disk under a
/// running server, and confirm the swap is both recorded in metrics and does
/// not disturb service.
#[tokio::test]
async fn a_certificate_rewritten_on_disk_is_reloaded_without_a_restart() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config_with_admin(
        listen, admin, backend, &cert, &key, 1,
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;
    support::wait_until_listening(admin).await;

    // Sleep past filesystem timestamp granularity, then replace the
    // certificate material with a fresh, distinct pair for the same name.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(&cert, generated.cert.pem()).unwrap();
    std::fs::write(&key, generated.key_pair.serialize_pem()).unwrap();

    // Poll `/metrics` (1s reload interval) for the second "applied" reload:
    // the first happens on the reloader's initial tick against the
    // already-loaded material, the second picks up the rewrite above.
    let body = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let body = reqwest::get(format!("http://{admin}/metrics"))
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            if body
                .contains(r#"lb_tls_certificate_reloads_total{listener="web",outcome="applied"} 2"#)
            {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the on-disk certificate rewrite was never reflected in metrics");

    assert!(
        body.contains(
            r#"lb_tls_certificate_expiry_timestamp_seconds{cert="primary",listener="web"}"#
        ),
        "expected the expiry gauge for the reloaded certificate in:\n{body}"
    );

    // The load-bearing outcome: the listener is still serving HTTPS after
    // the swap, on the new material.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .expect("https request failed after a hot reload");
    assert_eq!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// TLS on a raw TCP (L4) listener
// ---------------------------------------------------------------------------

fn tls_tcp_config(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> String {
    format!(
        r#"
[[listeners]]
name = "tcp-front"
protocol = "tcp"
listen = "{listen}"
connect_timeout_ms = 500
idle_timeout_ms = 5000

  [listeners.tls]
  handshake_timeout_ms = 5000
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "{cert}"
    key_file = "{key}"
    hostnames = ["localhost"]

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"

  [listeners.health_check]
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
        cert = cert.display().to_string().replace('\\', "\\\\"),
        key = key.display().to_string().replace('\\', "\\\\"),
    )
}

/// A client-side verifier that accepts whatever certificate it is shown.
///
/// This is the harness trusting a certificate it generated seconds ago — the
/// rustls equivalent of `danger_accept_invalid_certs` in the HTTP tests
/// above. It never runs in the load balancer, which does no client-side
/// verification at all on this path.
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

/// Opens a TLS connection to `addr`, presenting SNI `localhost`.
///
/// The provider is named explicitly rather than taken from the process
/// default: the server installs that from its own task, and this way the test
/// does not depend on having lost that race.
async fn tls_connect(addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
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
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector
        .connect(name, stream)
        .await
        .expect("tls handshake")
}

/// The commit claims TLS terminates on *any* listener. This is the L4 half:
/// the listener speaks TLS, the backend speaks plaintext, and `lb-tcp` never
/// learns the difference because `handle_connection` is generic over the
/// stream.
#[tokio::test]
async fn a_tls_tcp_listener_proxies_bytes_to_a_plaintext_backend() {
    let (backend, count) = support::spawn_echo_backend().await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_tcp_config(listen, backend, &cert, &key)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let mut tls = tls_connect(listen).await;
    tls.write_all(b"ping over tls").await.unwrap();
    tls.flush().await.unwrap();

    let mut echoed = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut echoed))
        .await
        .expect("no echo came back within 5s")
        .expect("reading the echo failed");

    assert_eq!(&echoed, b"ping over tls");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}
