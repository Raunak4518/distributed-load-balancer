use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

mod results;

use std::sync::OnceLock;

static RESULTS: OnceLock<results::ResultsWriter> = OnceLock::new();

fn results() -> &'static results::ResultsWriter {
    RESULTS.get_or_init(results::ResultsWriter::new)
}

const DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS: usize = 20;

fn cert_files(names: &[&str]) -> (PathBuf, PathBuf, PathBuf) {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "lbh2stress-{}-{}",
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
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
    (dir, cert_path, key_path)
}

async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_fast_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
                });
                let _ = server_http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

fn lb_server_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    let name = if cfg!(windows) {
        "lb-server.exe"
    } else {
        "lb-server"
    };
    path.push(name);
    if !path.exists() {
        eprintln!(
            "{} not found -- build it first: cargo build -p lb-server (or --release, matching how lb-bench-h2-stress itself was built)",
            path.display()
        );
        std::process::exit(1);
    }
    path
}

fn write_config(
    path: &Path,
    listen: SocketAddr,
    backend: SocketAddr,
    admin: SocketAddr,
    cert: &Path,
    key: &Path,
    max_pending_accept_reset_streams: usize,
) {
    let toml = format!(
        r#"
[admin]
listen = "{admin}"

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
  rate_per_sec = 1000000
  burst = 1000000

  [listeners.load_balancing]
  strategy = "round_robin"

  [listeners.http2]
  max_pending_accept_reset_streams = {max_pending_accept_reset_streams}
"#,
        cert = cert.display().to_string().replace('\\', "\\\\"),
        key = key.display().to_string().replace('\\', "\\\\"),
    );
    std::fs::write(path, toml).expect("write config");
}

async fn spawn_lb_server(config_path: &Path) -> Child {
    Command::new(lb_server_path())
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn lb-server")
}

async fn wait_until_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing listening on {addr} after 10s");
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

async fn tls_connect_h2(addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector
        .connect(name, stream)
        .await
        .expect("tls handshake")
}

async fn connect_and_flood(
    addr: SocketAddr,
    resets: usize,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
) {
    let tls = tls_connect_h2(addr).await;
    let (mut send, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    let driver = tokio::spawn(connection);

    let url = format!("https://localhost:{}/", addr.port());
    let (primed, _) = send
        .send_request(
            Request::builder().method("GET").uri(&url).body(()).unwrap(),
            true,
        )
        .expect("primer send_request");
    primed.await.expect("primer response");

    for _ in 0..resets {
        send = send.ready().await.expect("send_request ready");
        let req = Request::builder().method("GET").uri(&url).body(()).unwrap();
        let (response, body) = send.send_request(req, true).expect("send_request");
        drop(response);
        drop(body);
    }

    (send, driver)
}

async fn flood_survives(addr: SocketAddr, resets: usize) -> bool {
    let (send, driver) = connect_and_flood(addr, resets).await;
    let abort = driver.abort_handle();
    let survived = tokio::time::timeout(Duration::from_secs(2), driver)
        .await
        .is_err();
    if survived {
        abort.abort();
    }
    drop(send);
    survived
}

async fn find_activation_point(addr: SocketAddr) -> Option<usize> {
    let sweep: &[usize] = &[1, 5, 10, 15, 18, 19, 20, 21, 22, 25, 30];
    println!("=== Locating the max_pending_accept_reset_streams activation point ===");
    println!("{:>10} | {:>10}", "resets", "connection");
    let mut activation = None;
    for &n in sweep {
        let survived = flood_survives(addr, n).await;
        println!(
            "{:>10} | {:>10}",
            n,
            if survived { "survived" } else { "terminated" }
        );
        results().record(
            "rapid_reset/activation_sweep",
            &format!("n={n}"),
            if survived { "survived" } else { "terminated" },
        );
        if !survived && activation.is_none() {
            activation = Some(n);
        }
    }
    println!();
    activation
}

#[cfg(windows)]
fn sample_process(pid: u32) -> Option<(f64, f64)> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ Write-Output \"$($p.CPU),$($p.WorkingSet64)\" }}"
            ),
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    let mut parts = line.trim().split(',');
    let cpu_secs: f64 = parts.next()?.trim().parse().ok()?;
    let mem_bytes: f64 = parts.next()?.trim().parse().ok()?;
    Some((cpu_secs, mem_bytes / (1024.0 * 1024.0)))
}

#[cfg(not(windows))]
fn sample_process(pid: u32) -> Option<(f64, f64)> {
    const CLK_TCK_HZ: f64 = 100.0;

    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: f64 = fields.get(11)?.parse().ok()?;
    let stime: f64 = fields.get(12)?.parse().ok()?;
    let cpu_secs = (utime + stime) / CLK_TCK_HZ;

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut mem_mb: Option<f64> = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            mem_mb = rest
                .split_whitespace()
                .next()
                .and_then(|kb| kb.parse::<f64>().ok())
                .map(|kb| kb / 1024.0);
        }
    }
    Some((cpu_secs, mem_mb?))
}

type ProxyClient = Client<HttpConnector, Full<Bytes>>;

fn build_client() -> ProxyClient {
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new())
}

async fn scrape_metrics(client: &ProxyClient, admin: SocketAddr) -> String {
    let uri: hyper::Uri = format!("http://{admin}/metrics").parse().unwrap();
    let req = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.expect("metrics scrape");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&body).to_string()
}

fn metric_value(body: &str, prefix: &str) -> Option<f64> {
    body.lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

async fn sustained_attack(
    addr: SocketAddr,
    pid: u32,
    connections: usize,
    resets_per_connection: usize,
) {
    println!("=== Sustained Rapid Reset attack: {connections} connections x {resets_per_connection} resets each ===");

    let idle_before = sample_process(pid).expect("idle baseline sample");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let idle_after = sample_process(pid).expect("idle baseline sample");
    let idle_cpu_cores = (idle_after.0 - idle_before.0) / 2.0;
    println!(
        "  idle baseline: {:.3} cores, {:.1} MB RSS",
        idle_cpu_cores, idle_after.1
    );

    let before = sample_process(pid).expect("pre-attack sample");
    let start = Instant::now();
    let mut terminated = 0usize;
    for _ in 0..connections {
        if !flood_survives(addr, resets_per_connection).await {
            terminated += 1;
        }
    }
    let wall = start.elapsed();
    let after = sample_process(pid).expect("post-attack sample");

    let attack_cpu_cores = (after.0 - before.0) / wall.as_secs_f64();
    let total_streams = connections * (resets_per_connection + 1);

    println!(
        "  wall: {:.2}s, {} connections opened, {terminated} terminated by the server \
         (max_pending_accept_reset_streams tripped), {total_streams} total streams opened \
         (incl. one primer request per connection)",
        wall.as_secs_f64(),
        connections
    );
    println!(
        "  during attack: {:.3} cores, {:.1} MB RSS (delta {:+.1} MB from pre-attack)",
        attack_cpu_cores,
        after.1,
        after.1 - before.1
    );

    results().record("rapid_reset/sustained", "wall_secs", wall.as_secs_f64());
    results().record("rapid_reset/sustained", "connections", connections);
    results().record(
        "rapid_reset/sustained",
        "connections_terminated",
        terminated,
    );
    results().record("rapid_reset/sustained", "total_streams", total_streams);
    results().record("rapid_reset/sustained", "idle_cpu_cores", idle_cpu_cores);
    results().record(
        "rapid_reset/sustained",
        "attack_cpu_cores",
        attack_cpu_cores,
    );
    results().record("rapid_reset/sustained", "mem_before_mb", before.1);
    results().record("rapid_reset/sustained", "mem_after_mb", after.1);
    println!();
}

#[tokio::main]
async fn main() {
    let backend = spawn_fast_backend().await;
    let listen = free_addr().await;
    let admin = free_addr().await;
    let (_dir, cert, key) = cert_files(&["localhost"]);

    let config_dir = std::env::temp_dir().join(format!(
        "lbh2stress-cfg-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    write_config(
        &config_path,
        listen,
        backend,
        admin,
        &cert,
        &key,
        DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS,
    );

    let mut child = spawn_lb_server(&config_path).await;
    let pid = child.id().expect("child pid");
    wait_until_listening(listen).await;
    wait_until_listening(admin).await;

    println!("lb-server pid={pid}, listening on {listen} (admin {admin})");
    println!(
        "configured max_pending_accept_reset_streams = {DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS} (h2's own default, per the README)"
    );
    println!();

    let client = build_client();
    let before_metrics = scrape_metrics(&client, admin).await;

    let activation = find_activation_point(listen).await;
    match activation {
        Some(n) => println!(
            "activation point: the server terminated the connection at {n} resets \
             (configured bound is {DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS}, so the \
             ({DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS} + 1)-th pending reset is expected \
             to trip it)"
        ),
        None => println!(
            "activation point: not found within the sweep up to 30 resets -- \
             the connection survived every tested flood size"
        ),
    }
    println!();

    let resets_per_connection = DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS + 5;
    sustained_attack(listen, pid, 200, resets_per_connection).await;

    let after_metrics = scrape_metrics(&client, admin).await;
    let before_h2 = metric_value(
        &before_metrics,
        r#"lb_requests_total{listener="web",protocol="http2",status="2xx"}"#,
    )
    .unwrap_or(0.0);
    let after_h2 = metric_value(
        &after_metrics,
        r#"lb_requests_total{listener="web",protocol="http2",status="2xx"}"#,
    )
    .unwrap_or(0.0);
    println!(
        "lb_requests_total{{protocol=\"http2\",status=\"2xx\"}} moved from {before_h2:.0} to \
         {after_h2:.0} across the whole run -- every count is a primer request that ran to \
         completion; the many thousands of opened-and-reset streams never reached that counter, \
         which is the efficiency asymmetry Rapid Reset exploits"
    );
    results().record(
        "rapid_reset/sustained",
        "lb_requests_total_http2_2xx_delta",
        after_h2 - before_h2,
    );

    if let Some(n) = activation {
        results().record("rapid_reset/activation_point", "resets", n);
    }

    let _ = child.kill().await;

    match results().finish(
        "rapid-reset-stress",
        &[(
            "max_pending_accept_reset_streams",
            DEFAULT_MAX_PENDING_ACCEPT_RESET_STREAMS.to_string(),
        )],
    ) {
        Ok(dir) => println!("results persisted to {}", dir.display()),
        Err(err) => eprintln!("failed to persist results: {err}"),
    }
}
