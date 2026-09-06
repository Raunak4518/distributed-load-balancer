mod support;

use hyper::StatusCode;
use lb_core::Config;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use support::spawn_counting_backend;
use tokio::net::TcpListener;

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
) -> String {
    format!(
        r#"
[[listeners]]
name = "web"
protocol = "http"
listen = "{listen}"

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
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000)).unwrap();
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
    let config = Config::parse(&tls_http_config(listen, backend, &cert, &key, 5_000)).unwrap();
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
    let mut toml = tls_http_config(listen, backend, &cert, &key, 5_000);
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
    let (backend, _count) = spawn_counting_backend(StatusCode::OK).await;
    let listen = free_addr().await;
    let config = Config::parse(&plaintext_http_config(listen, backend)).unwrap();
    tokio::spawn(lb_server::run(config));
    support::wait_until_listening(listen).await;

    // Prior-knowledge h2c on an unencrypted edge port is surface nobody asked
    // for. A client that insists on it must fail, not be quietly served.
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    assert!(client
        .get(format!("http://{listen}/"))
        .send()
        .await
        .is_err());
}
