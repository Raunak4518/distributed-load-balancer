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

// ---------------------------------------------------------------------------
// Re-encrypting to backends
// ---------------------------------------------------------------------------

/// A backend that speaks TLS to real traffic and plaintext to the health
/// probe, counting every non-health request *that arrived over TLS*.
///
/// Counting only the TLS ones is deliberate: it is what makes the
/// trusted-backend test below fail if forwarding ever regresses to
/// plaintext, which would otherwise still answer 200 and look like a pass.
///
/// The dual behaviour is a workaround with a shelf life: until Task 9 the
/// active HTTP probe still speaks plaintext, so a TLS-only backend would be
/// marked unhealthy within milliseconds of startup and every test below
/// would get a 503 for a reason that has nothing to do with what it is
/// testing. Sniffing the first byte (0x16 is a TLS handshake record) keeps
/// the backend eligible so these tests measure the forwarding path.
async fn spawn_tls_backend(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    lb_tls::install_crypto_provider();

    let tls_cfg = lb_core::TlsConfig {
        certificates: vec![lb_core::CertificateConfig {
            name: "backend".into(),
            cert_file: cert.to_path_buf(),
            key_file: key.to_path_buf(),
            hostnames: vec!["localhost".into()],
        }],
        handshake_timeout_ms: Some(5_000),
        min_version: None,
        reload_interval_secs: None,
        hsts_max_age_secs: None,
    };
    let acceptor = std::sync::Arc::new(lb_tls::TlsAcceptor::new(&tls_cfg, &[b"http/1.1"]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let hits = std::sync::Arc::clone(&count);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = std::sync::Arc::clone(&acceptor);
            let hits = std::sync::Arc::clone(&hits);
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                let is_tls = matches!(stream.peek(&mut first).await, Ok(1) if first[0] == 0x16);
                let svc = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let hits = std::sync::Arc::clone(&hits);
                    async move {
                        if is_tls && req.uri().path() != "/health" {
                            hits.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::new()),
                        ))
                    }
                });
                if is_tls {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                        .await;
                }
            });
        }
    });
    (addr, count)
}

/// `tls_http_config` plus a `[listeners.backend_tls]` section, a
/// `server_name` on the backend, and an optional `[admin]` listener.
///
/// `server_name` is a parameter (rather than hardcoded to `localhost`) so
/// `a_backend_whose_server_name_does_not_resolve_via_dns_is_still_proxied_to`
/// below can exercise a name -- `backend.invalid` -- that is guaranteed to
/// never resolve via real DNS. Before the L7 DNS-pinning fix, the forwarding
/// authority (`server_name`) was handed straight to a stock `HttpConnector`,
/// which resolves it via real DNS to find something to dial; the fix pins
/// that dial to the backend's configured `address` instead.
#[allow(clippy::too_many_arguments)]
fn backend_tls_config(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    ca_file: Option<&std::path::Path>,
    danger: bool,
    admin: Option<SocketAddr>,
    server_name: &str,
) -> String {
    let ca_line = match ca_file {
        Some(p) => format!(
            "  ca_file = \"{}\"\n",
            p.display().to_string().replace('\\', "\\\\")
        ),
        None => String::new(),
    };
    let admin_section = match admin {
        Some(a) => format!("[admin]\nlisten = \"{a}\"\n"),
        None => String::new(),
    };
    format!(
        r#"
{admin_section}
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [listeners.tls]
  handshake_timeout_ms = 5000
    [[listeners.tls.certificates]]
    name = "primary"
    cert_file = "{cert}"
    key_file = "{key}"
    hostnames = ["localhost"]

  [listeners.backend_tls]
  danger_accept_invalid_certs = {danger}
{ca_line}
  [[listeners.backends]]
  id = "b1"
  address = "{backend}"
  server_name = "{server_name}"

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

/// A client that trusts the load balancer's own self-signed certificate.
/// This is the harness accepting a certificate it generated seconds ago; it
/// says nothing about what the load balancer accepts from its backends,
/// which is what these tests are about.
fn trusting_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// The certificate is self-signed and in no trust store, so verification
/// must fail. This is the behaviour that makes re-encryption worth anything:
/// encryption without authentication does not address the threat that
/// motivates it.
///
/// It is also the test Task 7's reviewer deferred — until now nothing proved
/// `BackendConnector` rejected anything, because it had never completed a
/// handshake.
#[tokio::test]
async fn an_untrusted_backend_certificate_is_refused() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let (backend, hits) = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend,
        &cert,
        &key,
        /* ca_file */ None,
        /* danger */ false,
        None,
        "localhost",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let resp = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        502,
        "an untrusted backend was proxied to anyway"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the request reached a backend whose certificate we could not verify"
    );
}

/// A plaintext listener with no `[listeners.backend_tls]` still forwards to
/// its backend over plaintext, unchanged by this phase.
#[tokio::test]
async fn a_listener_without_backend_tls_still_forwards_plaintext() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 100)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let resp = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The same backend, with its certificate supplied as the trust root — the
/// internal-PKI case `ca_file` exists for. Without this control, the test
/// above would pass just as well if forwarding were broken outright.
#[tokio::test]
async fn a_backend_trusted_via_ca_file_is_proxied_to() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let (backend, hits) = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend,
        &cert,
        &key,
        Some(&bcert),
        false,
        None,
        "localhost",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let resp = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    // Counted only for TLS connections, so a regression to plaintext
    // forwarding fails here rather than quietly answering 200.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The regression test for the L7 DNS-pinning bug. `backend.invalid` is
/// reserved by RFC 2606 and is guaranteed to never resolve via real DNS,
/// anywhere. Before the fix, the forwarding `HttpConnector` resolved this
/// exact authority (the forwarding URI's authority is `server_name`, so SNI
/// and hostname verification check the certificate's name) via its default,
/// real-DNS resolver, so this request would hang or fail on that lookup
/// without ever reaching `backend.address`. After the fix, the connector
/// dials `address` via a fixed per-listener table and never performs a real
/// DNS lookup at all, so the request succeeds despite the name being
/// unresolvable.
#[tokio::test]
async fn a_backend_whose_server_name_does_not_resolve_via_dns_is_still_proxied_to() {
    let (_bdir, bcert, bkey) = cert_files(&["backend.invalid"]);
    let (backend, hits) = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend,
        &cert,
        &key,
        Some(&bcert),
        false,
        None,
        "backend.invalid",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Bounded explicitly: a real-DNS lookup on a `.invalid` name may hang
    // rather than fail fast, depending on the resolver in front of this
    // machine. Without the fix this future would very plausibly never
    // resolve inside 5s; with the fix, no DNS lookup happens at all, so it
    // returns almost immediately.
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        trusting_client()
            .get(format!("https://localhost:{}/", listen.port()))
            .send(),
    )
    .await
    .expect(
        "the request hung -- forwarding tried to resolve `backend.invalid` \
         via real DNS instead of dialing the pinned backend address",
    )
    .unwrap();

    assert_eq!(resp.status(), 200);
    // Counted only for TLS connections, so a regression to plaintext
    // forwarding fails here rather than quietly answering 200.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// `danger_accept_invalid_certs` must genuinely bypass verification — the
/// same backend the first test refuses is proxied to here — and must say so
/// where an operator will see it. A gauge that is never set is the same as
/// no gauge at all.
#[tokio::test]
async fn the_danger_flag_forwards_to_an_unverifiable_backend_and_is_visible() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let (backend, hits) = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend,
        &cert,
        &key,
        None,
        true,
        Some(admin),
        "localhost",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;
    support::wait_until_listening(admin).await;

    let resp = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    let body = reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains(r#"lb_backend_tls_verification_disabled{listener="web"} 1"#),
        "the danger flag is not visible on /metrics:\n{body}"
    );
}

/// An unreadable `ca_file` is operator input in exactly the same class as an
/// unreadable certificate: it must fail startup, not leave a bound port that
/// rejects every backend at the first request.
#[tokio::test]
async fn an_unreadable_ca_file_fails_startup_with_an_error() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (dir, cert, key) = cert_files(&["localhost"]);
    let missing = dir.join("this-ca-was-never-written.crt");

    let config = Config::parse(&backend_tls_config(
        listen,
        backend,
        &cert,
        &key,
        Some(&missing),
        false,
        None,
        "localhost",
    ))
    .unwrap();

    let err = lb_server::run(config)
        .await
        .expect_err("an unreadable ca_file must fail startup");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("web"),
        "the error must name the listener that could not start: {err}"
    );
}

fn reencrypting_tcp_config(
    listen: SocketAddr,
    backend: SocketAddr,
    ca_file: &std::path::Path,
) -> String {
    format!(
        r#"
[[listeners]]
name = "tcp-front"
protocol = "tcp"
listen = "{listen}"
connect_timeout_ms = 2000
idle_timeout_ms = 5000

  [listeners.backend_tls]
  ca_file = "{ca}"

  [[listeners.backends]]
  id = "b1"
  address = "{backend}"
  server_name = "backend.internal"

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
        ca = ca_file.display().to_string().replace('\\', "\\\\"),
    )
}

/// A TLS echo backend, for the L4 half. Unlike the HTTP fixture above it has
/// no plaintext mode and needs none: `TcpConnectProbe` only opens a socket.
async fn spawn_tls_echo_backend(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    lb_tls::install_crypto_provider();

    let tls_cfg = lb_core::TlsConfig {
        certificates: vec![lb_core::CertificateConfig {
            name: "backend".into(),
            cert_file: cert.to_path_buf(),
            key_file: key.to_path_buf(),
            hostnames: vec!["backend.internal".into()],
        }],
        handshake_timeout_ms: Some(5_000),
        min_version: None,
        reload_interval_secs: None,
        hsts_max_age_secs: None,
    };
    let acceptor = std::sync::Arc::new(lb_tls::TlsAcceptor::new(&tls_cfg, &[]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let hits = std::sync::Arc::clone(&count);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = std::sync::Arc::clone(&acceptor);
            let hits = std::sync::Arc::clone(&hits);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 1024];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, count)
}

/// The L4 half of re-encryption, end to end: a plaintext TCP listener whose
/// outbound leg is TLS. `lb-tcp` has no TLS dependency at all — it is handed
/// an `OutboundTransport` by the wiring and pumps whatever comes back — so
/// this is the test that the seam is actually connected.
///
/// Note the backend's `server_name` is `backend.internal`, a name that does
/// not resolve anywhere: at L4 the connection is already open before the
/// handshake starts, so the name is used for SNI and verification only,
/// never for DNS.
#[tokio::test]
async fn a_tcp_listener_re_encrypts_to_a_tls_backend() {
    let (_bdir, bcert, bkey) = cert_files(&["backend.internal"]);
    let (backend, handshakes) = spawn_tls_echo_backend(&bcert, &bkey).await;
    let listen = free_addr().await;

    let config = Config::parse(&reencrypting_tcp_config(listen, backend, &bcert)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let echoed = tokio::time::timeout(
        Duration::from_secs(10),
        support::tcp_roundtrip(listen, b"ping over re-encrypted tcp"),
    )
    .await
    .expect("no echo came back within 10s")
    .expect("the round trip failed");

    assert_eq!(echoed, b"ping over re-encrypted tcp");
    assert!(
        handshakes.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the backend never completed a TLS handshake"
    );
}

/// The mirror image: the same backend, with nothing trusting its
/// certificate. Plaintext must not be the fallback, so no bytes get through.
#[tokio::test]
async fn a_tcp_listener_refuses_an_untrusted_backend() {
    let (_bdir, bcert, bkey) = cert_files(&["backend.internal"]);
    let (backend, _handshakes) = spawn_tls_echo_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    // A different self-signed certificate as the trust root: a real,
    // non-empty trust store that simply does not vouch for this backend.
    let (_odir, other, _okey) = cert_files(&["someone.else"]);

    let config = Config::parse(&reencrypting_tcp_config(listen, backend, &other)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let echoed = tokio::time::timeout(
        Duration::from_secs(10),
        support::tcp_roundtrip(listen, b"ping"),
    )
    .await
    .expect("the connection was held open instead of being closed");

    // Either the connection was reset or it closed with nothing on it; what
    // must never happen is the echo coming back, which would mean the bytes
    // were proxied to a backend we could not verify.
    let bytes = echoed.unwrap_or_default();
    assert!(
        bytes.is_empty(),
        "bytes were proxied to an unverifiable backend: {bytes:?}"
    );
}
