mod support;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::StatusCode;
use lb_core::Config;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

/// Every knob the TLS listener configs below vary, in one builder.
///
/// The wrappers underneath are one-liners over this rather than four more
/// copies of the same TOML: three of these tests differ from the default in
/// exactly one field, and a copy per test is how the copies drift.
#[allow(clippy::too_many_arguments)]
fn tls_http_config_with(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    handshake_timeout_ms: u64,
    header_read_timeout_ms: u64,
    forward_timeout_ms: u64,
    rate_per_sec: f64,
    burst: u32,
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"
header_read_timeout_ms = {header_read_timeout_ms}
forward_timeout_ms = {forward_timeout_ms}

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
  rate_per_sec = {rate_per_sec}
  burst = {burst}

  [listeners.load_balancing]
  strategy = "round_robin"
"#,
        // Windows paths are backslash-separated, and a lone backslash is an
        // escape inside a TOML basic string.
        cert = cert.display().to_string().replace('\\', "\\\\"),
        key = key.display().to_string().replace('\\', "\\\\"),
    )
}

/// The default TLS listener: rate limiting effectively off, backends fast.
fn tls_http_config(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    handshake_timeout_ms: u64,
    header_read_timeout_ms: u64,
) -> String {
    tls_http_config_with(
        listen,
        backend,
        cert,
        key,
        handshake_timeout_ms,
        header_read_timeout_ms,
        5_000,
        10_000.0,
        10_000,
    )
}

/// The same listener with the rate limiter turned down to `burst`.
///
/// `rate_per_sec` is set to `burst` as well, so the bucket refills one token
/// every `1/burst` of a second — orders of magnitude slower than a loop of
/// in-process requests issues them. The burst is therefore the entire budget
/// for the duration of a test, and no request is refused for a reason other
/// than the one under examination.
fn tls_config_with_rate_limit(
    listen: SocketAddr,
    backend: SocketAddr,
    cert: &std::path::Path,
    key: &std::path::Path,
    burst: u32,
) -> String {
    tls_http_config_with(
        listen,
        backend,
        cert,
        key,
        5_000,
        5_000,
        5_000,
        f64::from(burst),
        burst,
    )
}

/// Prefixes an `[admin]` section onto a listener config, so a test can scrape
/// `/metrics` off a second port.
///
/// A prefix rather than a parameter of the builder above: `[admin]` is a
/// top-level table and `[[listeners]]` is an array of tables, so the only
/// place it can legally go is before the listener it accompanies.
fn with_admin(admin: SocketAddr, listener_toml: &str) -> String {
    format!("[admin]\nlisten = \"{admin}\"\n{listener_toml}")
}

async fn scrape(admin: SocketAddr) -> String {
    reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
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

/// `lb_requests_total` carries the HTTP version a request actually arrived
/// on, not a constant.
///
/// The counters were split by version when they were introduced, but the
/// request path fed them a hardcoded `false`, so every h2 request landed
/// under `protocol="http1"` and the split answered nothing. Asserting on the
/// `http2` series with a non-zero value is what distinguishes a wired-up
/// selector from a placeholder: the `http1` series exists either way, and it
/// is flat zero only when the selector is real.
#[tokio::test]
async fn requests_are_counted_under_the_version_they_arrived_on() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let config = Config::parse(&with_admin(
        admin,
        &tls_http_config(listen, backend, &cert, &key, 5_000, 5_000),
    ))
    .unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;
    support::wait_until_listening(admin).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", listen.port());
    for _ in 0..3 {
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.version(), reqwest::Version::HTTP_2);
        assert_eq!(resp.status(), 200);
    }

    let body = scrape(admin).await;
    assert!(
        body.contains(r#"lb_requests_total{listener="web",protocol="http2",status="2xx"} 3"#),
        "three h2 requests were not counted as http2:\n{body}"
    );
    // The other half of the claim. Without this, a version selector stuck at
    // `true` would pass the assertion above just as happily as a correct one.
    assert!(
        body.contains(r#"lb_requests_total{listener="web",protocol="http1",status="2xx"} 0"#),
        "h2 requests leaked into the http1 series:\n{body}"
    );
}

/// Multiplexing does not buy a client a way around the rate limiter.
///
/// The obvious worry about HTTP/2 is that limits keyed on a connection stop
/// meaning anything once one connection carries many requests. Rate limiting
/// is not one of those limits — it runs per request inside `lb_proxy::handle`
/// — but that is a claim about where a call sits in the code, and this is the
/// test that turns it into a fact. It would fail if a future change moved the
/// check to connection scope.
#[tokio::test]
async fn http2_requests_are_rate_limited_per_request_not_per_connection() {
    let (backend, count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    // burst = 3: the fourth request on the SAME connection must be refused.
    let config =
        Config::parse(&tls_config_with_rate_limit(listen, backend, &cert, &key, 3)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", listen.port());

    let mut statuses = Vec::new();
    for _ in 0..5 {
        let resp = client.get(&url).send().await.unwrap();
        // Asserted per response, not once: a client that silently downgraded
        // to HTTP/1.1 partway through would leave this test proving nothing
        // about multiplexing at all.
        assert_eq!(resp.version(), reqwest::Version::HTTP_2);
        statuses.push(resp.status().as_u16());
    }

    assert!(
        statuses.contains(&429),
        "multiplexed requests bypassed the rate limiter: {statuses:?}"
    );
    assert!(
        count.load(Ordering::SeqCst) < 5,
        "every request reached the backend despite the limit"
    );
}

/// h2's own default `max_pending_accept_reset_streams`
/// (`h2::proto::DEFAULT_REMOTE_RESET_STREAM_MAX`). Private there, so it is
/// restated here along with why it matters: hyper's builder field defaults to
/// `None`, and `None` means h2 applies this instead of nothing at all.
const H2_BUILTIN_RESET_LIMIT: usize = 20;

/// How many streams the reset flood below opens and cancels.
///
/// The number is load-bearing, not arbitrary. It has to sit strictly between
/// the two bounds in play:
///
/// * above the configured bound's trip point — with
///   `max_pending_accept_reset_streams = 2` the third reset is refused, so
///   twelve is four times the margin needed;
/// * *below* `H2_BUILTIN_RESET_LIMIT` — because deleting the load balancer's
///   `.max_pending_accept_reset_streams(...)` call does not leave the server
///   unbounded, it leaves it on h2's default of 20. A flood of 50 would be
///   refused either way and the test could never fail, which is precisely
///   the failure mode this test exists to avoid.
///
/// Raising this past 20 silently turns the test into a tautology, so the
/// invariant is enforced below at compile time rather than trusted to whoever
/// edits the number next.
const RESET_FLOOD_STREAMS: usize = 12;

const _: () = assert!(
    RESET_FLOOD_STREAMS < H2_BUILTIN_RESET_LIMIT,
    "a flood this large trips h2's own default reset bound, so the rapid-reset \
     test would pass with the load balancer's configured bound removed"
);

/// Opens `n` streams and cancels each one immediately, then reports what
/// became of the connection.
///
/// `Ok(())` means the server absorbed the whole flood and the connection was
/// still up afterwards. `Err` is the connection being torn down.
///
/// One ordinary request is completed first, and its 200 asserted. That is not
/// setup: without it, "the connection ended in an error" is satisfied just as
/// well by a listener that never worked -- a bad certificate, a port serving
/// nothing -- and this test would report a CVE bounded when it had only
/// observed a broken server. The prime establishes that this connection
/// carried real traffic, so anything that kills it afterwards is the flood.
///
/// Raw `h2` rather than reqwest because no HTTP client will cancel a request
/// the instant it makes it — that is the attack, not a usage pattern. The
/// loop deliberately awaits nothing that yields: `SendRequest::poll_ready`
/// resolves immediately while stream capacity is available, so all `n`
/// HEADERS+RST_STREAM pairs are queued before the connection task writes a
/// byte and they reach the server in a single burst.
///
/// That burst is the point. h2 counts a reset only while the stream is still
/// *pending accept* (`recv_reset` in `proto/streams/recv.rs`), and decrements
/// again the moment the application accepts it. A flood paced slowly enough
/// for hyper to accept each stream before its reset arrives is therefore
/// counted at zero — correctly, because it costs the server nothing. Only the
/// burst is an attack, so only the burst is the test.
async fn flood_with_cancelled_streams(addr: SocketAddr, n: usize) -> Result<(), h2::Error> {
    let tls = tls_connect_h2(addr).await;
    let (mut send, connection) = h2::client::handshake(tls).await?;
    let driver = tokio::spawn(connection);

    let url = format!("https://localhost:{}/", addr.port());
    let (primed, _) = send.send_request(
        hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(())
            .unwrap(),
        true,
    )?;
    assert_eq!(
        primed.await?.status(),
        200,
        "the listener was not serving before the flood started"
    );

    for _ in 0..n {
        send = send.ready().await?;
        let req = hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(())
            .unwrap();
        // `end_of_stream = true`: a complete, entirely well-formed request, so
        // the server has every reason to start work on it — and then the
        // cancel lands. Half a request would be a different attack.
        let (response, body) = send.send_request(req, true)?;
        // Dropping both handles of a stream that has not completed is what
        // puts RST_STREAM(CANCEL) on the wire.
        drop(response);
        drop(body);
    }

    // The outcome surfaces here rather than on any `send_request` above: the
    // whole flood was queued before the server could answer, so every call
    // returned `Ok` and the GOAWAY arrives afterwards. `send` is deliberately
    // still alive across this await — dropping it would close the connection
    // from this side and yield an `Ok` that says nothing about the server.
    let outcome = driver.await.expect("h2 client connection task panicked");
    drop(send);
    outcome
}

/// Open streams and immediately cancel them, past the configured bound.
///
/// This is CVE-2023-44487. Cancellation is nearly free for a client and
/// expensive for the server, and cancelled streams evade
/// `max_concurrent_streams` precisely by not being concurrent -- so the
/// concurrency limit alone does not cover it.
#[tokio::test]
async fn a_rapid_reset_flood_terminates_the_connection() {
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    let mut toml = tls_http_config(listen, backend, &cert, &key, 5_000, 5_000);
    toml.push_str("\n  [listeners.http2]\n  max_pending_accept_reset_streams = 2\n");
    let config = Config::parse(&toml).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Drive raw h2 so streams can be cancelled immediately after opening --
    // a normal HTTP client will not do this.
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        flood_with_cancelled_streams(listen, RESET_FLOOD_STREAMS),
    )
    .await
    .expect("server never terminated a reset-flooding connection");

    let err =
        outcome.expect_err("the connection survived a reset flood well past the configured bound");

    // The server writes GOAWAY(ENHANCE_YOUR_CALM) and then drops the socket
    // while a dozen unread frames are still sitting in its receive buffer,
    // which makes the OS send RST and discard the GOAWAY the client had not
    // read yet. So the reason is genuinely not always observable, and
    // demanding it would be a flaky test rather than a strict one. What is
    // asserted instead: if a reason did survive the race it is the right one,
    // and never a protocol error of this client's own making.
    if let Some(reason) = err.reason() {
        assert_eq!(
            reason,
            h2::Reason::ENHANCE_YOUR_CALM,
            "the connection ended, but not because the reset bound refused it: {err}"
        );
    }
}

/// A backend that answers `/health` at once and holds every other request open
/// until released, recording the most it ever had in flight together.
///
/// Blocking is what makes concurrency observable at all: against the ordinary
/// counting backend every request finishes in microseconds, so "two at once"
/// and "eight one after another" look identical from here.
#[allow(clippy::type_complexity)]
async fn spawn_blocking_backend() -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::sync::watch::Sender<bool>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (release, _) = tokio::sync::watch::channel(false);

    let (task_in_flight, task_peak, task_release) =
        (in_flight.clone(), peak.clone(), release.clone());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (in_flight, peak, release) = (
                task_in_flight.clone(),
                task_peak.clone(),
                task_release.clone(),
            );
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let (in_flight, peak, release) =
                        (in_flight.clone(), peak.clone(), release.clone());
                    async move {
                        // The load balancer's own probe, and the request this
                        // test uses to prove the server's SETTINGS have
                        // landed. Neither is a client request under test, so
                        // neither is blocked and neither is counted.
                        if req.uri().path() == "/health" {
                            return Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        }
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        let mut rx = release.subscribe();
                        while !*rx.borrow_and_update() {
                            if rx.changed().await.is_err() {
                                break;
                            }
                        }
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    (addr, in_flight, peak, release)
}

/// Polls `counter` until it reaches `target`, or panics with what it saw.
///
/// A fixed sleep would be the same race `wait_until_listening` exists to
/// avoid: long enough on an idle machine, short enough to flake under load.
async fn wait_for_count(counter: &AtomicUsize, target: usize, within: Duration) {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if counter.load(Ordering::SeqCst) >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "backend never reached {target} concurrent requests (reached {})",
        counter.load(Ordering::SeqCst)
    );
}

/// `max_concurrent_streams` is enforced on the wire, not merely configured.
///
/// This is the load-bearing replacement for Phase 5's `max_connections_per_ip`
/// under multiplexing: one HTTP/2 connection carries many requests, so a
/// per-IP *connection* cap stopped bounding per-IP *work* the moment h2 was
/// advertised. Everything else about that hardening has a test; until now
/// nothing proved this limit reaches a client at all.
#[tokio::test]
async fn max_concurrent_streams_is_enforced_on_the_wire() {
    const LIMIT: u32 = 2;
    const ATTEMPTED: usize = 8;

    let (backend, in_flight, peak, release) = spawn_blocking_backend().await;
    let listen = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);
    // A 30s forward timeout: the backend deliberately never answers, and a
    // 504 from the load balancer would close the stream and free a slot,
    // hiding the very limit under test.
    let mut toml = tls_http_config_with(
        listen, backend, &cert, &key, 5_000, 5_000, 30_000, 10_000.0, 10_000,
    );
    toml.push_str(&format!(
        "\n  [listeners.http2]\n  max_concurrent_streams = {LIMIT}\n"
    ));
    let config = Config::parse(&toml).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    let tls = tls_connect_h2(listen).await;
    let (mut send, mut connection) = h2::client::handshake(tls).await.unwrap();
    let url = format!("https://localhost:{}/", listen.port());

    // Queue all eight streams before the connection is polled even once.
    //
    // This is the only way to test the server rather than the client's
    // manners. h2's client-side check against the peer's advertised limit is
    // explicitly a guess -- its own comment says "send_request has to guess if
    // it should wait" -- and here the guess cannot be anything else: nothing
    // has been read from the socket yet, so the server's SETTINGS have not
    // arrived and this client still believes it may open as many streams as
    // it likes. All eight therefore go on the wire in one burst.
    //
    // A conforming client cannot exceed the limit, which is why a polite
    // version of this test proves only that h2 is polite. An attacker is
    // under no obligation to be, and `max_concurrent_streams` exists for the
    // attacker.
    let mut streams = Vec::new();
    for _ in 0..ATTEMPTED {
        let req = hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(())
            .unwrap();
        let (response, _body) = send.send_request(req, true).unwrap();
        // Held, not dropped: dropping a handle resets its stream and frees the
        // slot, which would turn this into the reset test above.
        streams.push(response);
    }

    // Only now let the connection run. It flushes everything queued above
    // before it reads the server's first byte, so the burst is already gone
    // by the time the SETTINGS that would have prevented it arrive.
    let _ = tokio::time::timeout(Duration::from_millis(500), &mut connection).await;
    let advertised = connection.max_concurrent_send_streams();
    let driver = tokio::spawn(connection);

    // The limit on the wire, before any behaviour depends on it. If the
    // server never advertised it, everything below would be measuring
    // something else.
    assert_eq!(
        advertised, LIMIT as usize,
        "the server advertised SETTINGS_MAX_CONCURRENT_STREAMS = {advertised}, \
         not the configured {LIMIT}"
    );

    wait_for_count(&in_flight, LIMIT as usize, Duration::from_secs(5)).await;
    // Long enough for an unenforced excess to show up: the streams that were
    // allowed through reached the backend in milliseconds.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let peak_in_flight = peak.load(Ordering::SeqCst);

    // What became of each stream. Read before anything is dropped: dropping a
    // held `ResponseFuture` resets its stream, which frees a slot and lets a
    // queued one through -- so a careless teardown here rewrites the very
    // number being asserted.
    let (mut refused, mut still_open, mut answered) = (0usize, 0usize, 0usize);
    for response in streams {
        match tokio::time::timeout(Duration::from_millis(300), response).await {
            // Accepted, forwarded, and now waiting on a backend that will
            // never answer.
            Err(_) => still_open += 1,
            Ok(Ok(_)) => answered += 1,
            Ok(Err(err)) => {
                assert_eq!(
                    err.reason(),
                    Some(h2::Reason::REFUSED_STREAM),
                    "a stream failed for a reason other than the concurrency \
                     limit: {err}"
                );
                refused += 1;
            }
        }
    }

    assert_eq!(
        peak_in_flight, LIMIT as usize,
        "the backend saw {peak_in_flight} requests at once out of {ATTEMPTED} \
         streams put on the wire; max_concurrent_streams = {LIMIT} was not enforced"
    );
    assert_eq!(
        still_open, LIMIT as usize,
        "expected exactly {LIMIT} streams to be carrying a request"
    );
    // The assertion the whole test exists for: the excess was refused, one
    // RST_STREAM(REFUSED_STREAM) per stream, rather than queued up to be
    // served later. Queueing would mean the limit bounded nothing -- the work
    // would still arrive, just less punctually.
    assert_eq!(
        refused,
        ATTEMPTED - LIMIT as usize,
        "{refused} of the {} excess streams were refused; the rest were \
         accepted or left queued",
        ATTEMPTED - LIMIT as usize
    );
    assert_eq!(
        answered, 0,
        "the backend answered a request it was supposed to be holding open"
    );

    release.send(true).unwrap();
    driver.abort();
}
