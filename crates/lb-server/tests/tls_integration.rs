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
///
/// The directory name carries a process-wide counter as well as the clock.
/// The clock alone is not unique: Windows' system time has ~15.6 ms
/// granularity, so two tests running concurrently routinely read the same
/// nanosecond value, land in the same directory, and overwrite each other's
/// `s.crt` and `s.key` — producing a certificate from one pair with the key
/// from another, and a `KeyMismatch` at startup that has nothing to do with
/// what the test was checking. The counter makes collision impossible within
/// the binary, which is where every concurrent caller lives.
fn cert_files(names: &[&str]) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lbtlsit-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

/// Same as `tls_http_config`, plus a configurable `hsts_max_age_secs`.
fn tls_http_config_with_hsts(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    hsts_max_age_secs: u64,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

  [listeners.tls]
  handshake_timeout_ms = 5000
  hsts_max_age_secs = {hsts_max_age_secs}
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

/// The load-bearing positive case, end to end: a TLS listener with
/// `hsts_max_age_secs` set adds `Strict-Transport-Security` to a real HTTPS
/// response, with the configured value.
#[tokio::test]
async fn hsts_header_is_added_when_configured_on_a_tls_listener() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&tls_http_config_with_hsts(
        listen, backend, &cert, &key, 31_536_000,
    ))
    .unwrap();
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
        .expect("https request failed");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("strict-transport-security")
            .expect("Strict-Transport-Security header missing"),
        "max-age=31536000"
    );
}

/// The default-path case, and the one that matters most: `hsts_max_age_secs`
/// defaults to 0 (off), and a TLS listener that never sets it must emit no
/// header at all -- not `max-age=0`, which is a materially different
/// instruction to a browser (an active order to forget the policy), but
/// nothing. A bug here would put an unrequested, hard-to-withdraw policy on
/// every response by default.
#[tokio::test]
async fn hsts_header_is_absent_by_default_on_a_tls_listener() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    // `tls_http_config` never sets hsts_max_age_secs, so this exercises the
    // config default of 0.
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000, 100)).unwrap();
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
        .expect("https request failed");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("strict-transport-security").is_none(),
        "HSTS header must not be sent when hsts_max_age_secs is left at its default of 0"
    );
}

/// The other half of "only on TLS listeners": a plaintext HTTP listener --
/// which has no `[listeners.tls]` for `hsts_max_age_secs` to even live
/// under -- must never emit the header.
#[tokio::test]
async fn hsts_header_is_absent_on_a_plaintext_listener() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
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

    let resp = reqwest::get(format!("http://{listen}/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("strict-transport-security").is_none());
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

/// A TLS-only HTTPS backend, with separate counts of the client requests and
/// the health-probe requests that reached it over TLS.
///
/// TLS-only on purpose: it answers nothing over plaintext, so anything in the
/// load balancer that still spoke `http://` to it -- the health probe very
/// much included -- would be refused. (Until Task 9 this fixture had to
/// answer plaintext as well, because the probe did.)
///
/// The two counters are separate because they answer different questions.
/// `hits` is "did a client's request reach this backend", and excludes
/// `/health` so probe traffic never contaminates it. `health_hits` is the
/// positive, backend-side evidence that the *probe itself* got through over
/// TLS -- the L7 mirror of the handshake count the L4 fixture exposes, and
/// the only thing that distinguishes "the probe succeeded" from "the probe
/// never ran".
struct TlsBackend {
    addr: SocketAddr,
    hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    health_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl TlsBackend {
    fn hits(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn health_hits(&self) -> usize {
        self.health_hits.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn spawn_tls_backend(cert: &std::path::Path, key: &std::path::Path) -> TlsBackend {
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
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let health_hits = std::sync::Arc::new(AtomicUsize::new(0));
    let served = std::sync::Arc::clone(&hits);
    let probed = std::sync::Arc::clone(&health_hits);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = std::sync::Arc::clone(&acceptor);
            let served = std::sync::Arc::clone(&served);
            let probed = std::sync::Arc::clone(&probed);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: hyper::Request<_>| {
                    let served = std::sync::Arc::clone(&served);
                    let probed = std::sync::Arc::clone(&probed);
                    async move {
                        if req.uri().path() == "/health" {
                            probed.fetch_add(1, Ordering::SeqCst);
                        } else {
                            served.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::new()),
                        ))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    TlsBackend {
        addr,
        hits,
        health_hits,
    }
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
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
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

    let status = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();

    // Two ways to be refused, and which one arrives is a race with the health
    // checker: 502 if the forward itself failed verification, 503 if the probe
    // -- which since Task 9 uses this same client and so fails the same way --
    // had already taken the backend out of rotation. Both are the backend
    // being refused; a 200 is the only thing that would mean the load balancer
    // talked to a backend it could not verify. The `hits` assertion below is
    // what makes that airtight either way.
    assert!(
        status == 502 || status == 503,
        "an untrusted backend answered {status}"
    );
    assert_eq!(
        backend.hits(),
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
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
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
    assert_eq!(backend.hits(), 1);
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
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
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
    assert_eq!(backend.hits(), 1);
}

/// `danger_accept_invalid_certs` must genuinely bypass verification — the
/// same backend the first test refuses is proxied to here — and must say so
/// where an operator will see it. A gauge that is never set is the same as
/// no gauge at all.
#[tokio::test]
async fn the_danger_flag_forwards_to_an_unverifiable_backend_and_is_visible() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
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
    assert_eq!(backend.hits(), 1);

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
    admin: Option<SocketAddr>,
) -> String {
    let admin_section = match admin {
        Some(a) => format!("[admin]\nlisten = \"{a}\"\n"),
        None => String::new(),
    };
    format!(
        r#"
{admin_section}
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

    let config = Config::parse(&reencrypting_tcp_config(listen, backend, &bcert, None)).unwrap();
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

    let config = Config::parse(&reencrypting_tcp_config(listen, backend, &other, None)).unwrap();
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

// ---------------------------------------------------------------------------
// Probe/traffic transport agreement (spec section 5)
//
// The invariant these four tests exist for: **a probe validates what traffic
// validates.** If the health checker and the data plane disagree about
// whether a backend is reachable, the load balancer keeps routing to a
// backend it cannot talk to while the dashboard shows green -- every request
// fails, and nothing says why.
//
// Before Task 9 the probes had their own transport: at L7 `HttpProbe`
// hardcoded `http://` and used its own `reqwest` client (its own TLS stack,
// its own trust roots, its own verification policy); at L4
// `TcpConnectProbe` completed the TCP handshake and dropped the stream, which
// says nothing at all about whether the backend's TLS works. Both would call
// an unverifiable backend healthy. Each failing test below is paired with a
// control on a *trusted* backend, so neither can pass by simply reporting
// everything unhealthy.
// ---------------------------------------------------------------------------

/// Long enough for several 500ms probe intervals to have run and published
/// their result into the pool the readiness check reads.
const PROBE_SETTLE: Duration = Duration::from_millis(2_500);

async fn ready_status(admin: SocketAddr) -> u16 {
    reqwest::get(format!("http://{admin}/ready"))
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// **The most important test in this phase.** A backend whose certificate we
/// cannot verify must fail forwarding *and* probe unhealthy.
///
/// If these two ever disagree, the load balancer keeps a backend in rotation
/// that it cannot actually talk to: every request fails while `/ready` says
/// 200 and the dashboard shows green. Before Task 9 that was exactly the
/// behaviour, because the probe went over its own `reqwest` client with its
/// own trust configuration and never had an opinion about this backend's
/// certificate at all.
///
/// **What this test proves on its own, precisely.** It fails for any probe
/// that reaches a verdict of "healthy" on a backend the data plane refuses --
/// a probe on a second client with different (or no) trust roots, a probe
/// with the danger flag wired to it, a probe that never runs. It does *not*
/// by itself discriminate the specific plaintext-`http://` regression named
/// above any more, because this fixture is now TLS-only (that is deliberate,
/// and is itself a guard): a plaintext probe would be refused by the
/// backend's acceptor rather than getting a cheerful 200, and would land on
/// the same 503. The other half of that proof is
/// `a_backend_we_can_verify_probes_healthy` below, which asserts the probe
/// reached this same TLS-only backend at `/health` -- so between the two,
/// "the probe speaks the traffic transport, and agrees with it about trust"
/// is pinned from both sides.
#[tokio::test]
async fn a_backend_we_cannot_verify_also_probes_unhealthy() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    // No ca_file, danger off: the backend's self-signed certificate is in no
    // trust store this listener has.
    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
        &cert,
        &key,
        /* ca_file */ None,
        /* danger */ false,
        Some(admin),
        "localhost",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;
    support::wait_until_listening(admin).await;

    tokio::time::sleep(PROBE_SETTLE).await;

    assert_eq!(
        ready_status(admin).await,
        503,
        "the probe called an unverifiable backend healthy -- probe and traffic \
         are using different trust configuration"
    );

    // The other half of the same invariant: traffic is refused too. 502 (the
    // forward itself failed verification) and 503 (the probe already took the
    // backend out of rotation, so there was nothing to forward to) both mean
    // refused; which one arrives depends only on whether a probe has landed
    // yet, and after PROBE_SETTLE it is 503. What must never happen is a 200,
    // or the request reaching the backend.
    let status = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert!(
        status == 502 || status == 503,
        "an unverifiable backend answered {status}"
    );
    assert_eq!(
        backend.hits(),
        0,
        "the request reached a backend whose certificate we could not verify"
    );
    // Backend-side evidence for the probe half, not just the pool's verdict:
    // in 2.5s the checker ran several times and not one of those probes ever
    // completed a request against this backend. A probe that had verified it
    // (or skipped verification) would show up here.
    assert_eq!(
        backend.health_hits(),
        0,
        "a probe completed a request against a backend we cannot verify"
    );
}

/// The control for the test above, and the other half of its proof: the
/// *same* backend, with its certificate as the trust root, must probe healthy
/// and serve traffic.
///
/// Two things rest on this. Without it, the test above would pass just as
/// well if probing were broken outright and every backend were reported
/// unhealthy. And its `health_hits` assertion is the positive, backend-side
/// evidence that the probe really does speak the traffic transport -- the
/// backend is TLS-only, so a request from the probe arriving at `/health`
/// could not have been made over plaintext. It is the L7 mirror of
/// `a_tcp_backend_we_can_verify_probes_healthy`'s handshake count.
#[tokio::test]
async fn a_backend_we_can_verify_probes_healthy() {
    let (_bdir, bcert, bkey) = cert_files(&["localhost"]);
    let backend = spawn_tls_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config = Config::parse(&backend_tls_config(
        listen,
        backend.addr,
        &cert,
        &key,
        Some(&bcert),
        false,
        Some(admin),
        "localhost",
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;
    support::wait_until_listening(admin).await;

    tokio::time::sleep(PROBE_SETTLE).await;

    assert_eq!(
        ready_status(admin).await,
        200,
        "a backend we can verify was probed unhealthy"
    );

    // Asserted before any client request, so it can only be the probe's
    // doing. Over TLS by construction: this backend answers nothing else.
    assert!(
        backend.health_hits() >= 1,
        "the probe never reached the backend over TLS -- /ready said 200 for \
         some other reason"
    );

    let resp = trusting_client()
        .get(format!("https://localhost:{}/", listen.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(backend.hits(), 1);
}

/// The L4 half of the same invariant. A completed TCP handshake says nothing
/// about whether the backend's TLS works -- an expired or untrusted
/// certificate accepts the connection just the same -- so before Task 9 this
/// backend probed healthy while every byte sent to it was refused.
#[tokio::test]
async fn a_tcp_backend_we_cannot_verify_also_probes_unhealthy() {
    let (_bdir, bcert, bkey) = cert_files(&["backend.internal"]);
    let (backend, _handshakes) = spawn_tls_echo_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    // A real, non-empty trust store that simply does not vouch for this
    // backend.
    let (_odir, other, _okey) = cert_files(&["someone.else"]);

    let config = Config::parse(&reencrypting_tcp_config(
        listen,
        backend,
        &other,
        Some(admin),
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    // Deliberately *not* waiting on the traffic listener: connecting to it is
    // a client connection, and at L4 that would drive the data plane's own
    // outbound attempt and trip the circuit breaker -- which would take the
    // backend out of rotation for a reason that has nothing to do with the
    // health probe this test is about. The admin listener binds after every
    // traffic listener, so waiting on it alone is enough to know the server
    // is up.
    support::wait_until_listening(admin).await;

    tokio::time::sleep(PROBE_SETTLE).await;

    assert_eq!(
        ready_status(admin).await,
        503,
        "the TCP probe called an unverifiable backend healthy -- a completed \
         TCP handshake is not the transport real traffic uses"
    );

    let echoed = tokio::time::timeout(
        Duration::from_secs(10),
        support::tcp_roundtrip(listen, b"ping"),
    )
    .await
    .expect("the connection was held open instead of being closed")
    .unwrap_or_default();
    assert!(
        echoed.is_empty(),
        "bytes were proxied to an unverifiable backend: {echoed:?}"
    );
}

/// The L4 control: the same backend, trusted, probes healthy and echoes.
#[tokio::test]
async fn a_tcp_backend_we_can_verify_probes_healthy() {
    let (_bdir, bcert, bkey) = cert_files(&["backend.internal"]);
    let (backend, handshakes) = spawn_tls_echo_backend(&bcert, &bkey).await;
    let listen = free_addr().await;
    let admin = free_addr().await;

    let config = Config::parse(&reencrypting_tcp_config(
        listen,
        backend,
        &bcert,
        Some(admin),
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    // Not waiting on the traffic listener, for the same reason as the test
    // above: a client connection would complete a handshake of its own, and
    // the handshake count below has to be the *probe*'s work alone.
    support::wait_until_listening(admin).await;

    tokio::time::sleep(PROBE_SETTLE).await;

    assert_eq!(
        ready_status(admin).await,
        200,
        "a TCP backend we can verify was probed unhealthy"
    );
    // The probe itself must have completed real handshakes against the
    // backend -- if it were still only opening a socket, none of these would
    // have been counted before any client connected.
    assert!(
        handshakes.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the probe never completed a TLS handshake with the backend"
    );

    let echoed = tokio::time::timeout(
        Duration::from_secs(10),
        support::tcp_roundtrip(listen, b"ping over re-encrypted tcp"),
    )
    .await
    .expect("no echo came back within 10s")
    .expect("the round trip failed");
    assert_eq!(echoed, b"ping over re-encrypted tcp");
}
