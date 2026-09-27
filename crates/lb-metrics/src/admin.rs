use crate::Metrics;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

pub trait AdminIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AdminIo for T {}

pub type AdminAcceptor = Arc<
    dyn Fn(tokio::net::TcpStream) -> Pin<Box<dyn Future<Output = Option<Box<dyn AdminIo>>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct AdminOptions {
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub read_only_token: Option<Arc<[u8]>>,
    pub acceptor: Option<AdminAcceptor>,
}

impl Default for AdminOptions {
    fn default() -> Self {
        AdminOptions {
            max_connections: 64,
            header_read_timeout: Duration::from_secs(5),
            read_only_token: None,
            acceptor: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdminRole {
    Unauthenticated,
    ReadOnly,
    Admin,
}

impl AdminRole {
    fn as_str(self) -> &'static str {
        match self {
            AdminRole::Unauthenticated => "unauthenticated",
            AdminRole::ReadOnly => "read_only",
            AdminRole::Admin => "admin",
        }
    }
}

/// Returns true when this instance should receive traffic.
pub type ReadinessCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Extends this admin server with routes this crate has no way to serve
/// itself: `lb-metrics` knows nothing of `BackendPool` or live listener
/// state (both live in `lb-core`/`lb-server`), and `lb-server` already
/// depends on `lb-metrics`, so a reverse dependency to reach them from here
/// would cycle. The caller that *does* have that data supplies this closure
/// instead -- the same "the crate that needs the extension point defines
/// it, the crate with the concrete data implements it" shape already used
/// for `ClusterCoordinator`.
///
/// Only ever invoked for a path this server's own routes don't own (see
/// `route`'s dispatch), so it can assume ownership of the request and
/// always produce a real response -- there is no "not mine, try something
/// else" case once it's been called.
pub type AdminExtension = Arc<
    dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Response<Full<Bytes>>> + Send>>
        + Send
        + Sync,
>;

/// Serves `/metrics`, `/healthz` and `/ready` on a private listener, plus
/// whatever `extension` adds.
///
/// Deliberately separate from the traffic listeners: this surface exposes
/// internal topology (backend names, health, traffic volumes) and must not
/// face the public internet.
///
/// `admin_token`, when `Some`, gates every route below (including
/// `extension`'s) on a matching `Authorization: Bearer <token>` header,
/// checked in `route` before any of them run. `None` (the default) leaves
/// this server exactly as unauthenticated as it always was.
pub fn spawn_admin_server(
    metrics: Arc<Metrics>,
    listener: TcpListener,
    readiness: ReadinessCheck,
    extension: Option<AdminExtension>,
    admin_token: Option<Arc<[u8]>>,
) -> tokio::task::JoinHandle<()> {
    spawn_admin_server_with_options(
        metrics,
        listener,
        readiness,
        extension,
        admin_token,
        AdminOptions::default(),
    )
}

pub fn spawn_admin_server_with_options(
    metrics: Arc<Metrics>,
    listener: TcpListener,
    readiness: ReadinessCheck,
    extension: Option<AdminExtension>,
    admin_token: Option<Arc<[u8]>>,
    options: AdminOptions,
) -> tokio::task::JoinHandle<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(options.max_connections));
    let header_read_timeout = options.header_read_timeout;
    let read_only_token = options.read_only_token;
    let acceptor = options.acceptor;
    tokio::spawn(async move {
        loop {
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let metrics = Arc::clone(&metrics);
            let readiness = Arc::clone(&readiness);
            let extension = extension.clone();
            let admin_token = admin_token.clone();
            let read_only_token = read_only_token.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let io: Box<dyn AdminIo> = match &acceptor {
                    Some(accept) => match accept(stream).await {
                        Some(io) => io,
                        None => return,
                    },
                    None => Box::new(stream),
                };
                let io = TokioIo::new(io);
                let svc = service_fn(move |req| {
                    let metrics = Arc::clone(&metrics);
                    let readiness = Arc::clone(&readiness);
                    let extension = extension.clone();
                    let admin_token = admin_token.clone();
                    let read_only_token = read_only_token.clone();
                    async move {
                        route(
                            req,
                            metrics,
                            readiness,
                            extension,
                            admin_token,
                            read_only_token,
                            peer,
                        )
                        .await
                    }
                });
                if let Err(err) = http1::Builder::new()
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(header_read_timeout)
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!(error = %err, "admin connection error");
                }
            });
        }
    })
}

async fn route(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
    readiness: ReadinessCheck,
    extension: Option<AdminExtension>,
    admin_token: Option<Arc<[u8]>>,
    read_only_token: Option<Arc<[u8]>>,
    peer: std::net::SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Checked before anything else, so every route below except `/healthz`
    // and `/ready` (including `extension`'s, which owns everything under
    // /backends and /cache) is covered by one check instead of needing its own. A
    // byte-wise `==` here would leak how much of the presented token matched
    // through timing -- the same concern `lb-cluster`'s gossip HMAC check
    // already guards against -- hence `ConstantTimeEq` rather than a plain
    // comparison.
    let (role, allowed) = authorize(&req, admin_token.as_deref(), read_only_token.as_deref());
    let response = match (allowed, role) {
        (true, _) => dispatch(req, &metrics, readiness, extension).await,
        (false, Some(_)) => {
            metrics.admin_auth_failures.inc();
            text(
                StatusCode::FORBIDDEN,
                "this token may only read".to_string(),
            )
        }
        (false, None) => {
            metrics.admin_auth_failures.inc();
            unauthorized()
        }
    };
    if !matches!(method, Method::GET | Method::HEAD) {
        tracing::info!(
            target: "lb_admin_audit",
            method = %method,
            path = %path,
            peer = %peer,
            role = role.map_or("none", AdminRole::as_str),
            allowed,
            status = response.status().as_u16(),
            "admin write request"
        );
    }
    Ok(response)
}

fn authorize(
    req: &Request<Incoming>,
    admin_token: Option<&[u8]>,
    read_only_token: Option<&[u8]>,
) -> (Option<AdminRole>, bool) {
    let Some(admin_token) = admin_token else {
        return (Some(AdminRole::Unauthenticated), true);
    };
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::as_bytes);
    let matches = |token: &[u8]| presented.is_some_and(|p| bool::from(p.ct_eq(token)));
    if matches(admin_token) {
        return (Some(AdminRole::Admin), true);
    }
    if read_only_token.is_some_and(matches) {
        let reading = matches!(*req.method(), Method::GET | Method::HEAD);
        return (Some(AdminRole::ReadOnly), reading);
    }
    if matches!(req.uri().path(), "/healthz" | "/ready") {
        return (Some(AdminRole::Unauthenticated), true);
    }
    (None, false)
}

async fn dispatch(
    req: Request<Incoming>,
    metrics: &Metrics,
    readiness: ReadinessCheck,
    extension: Option<AdminExtension>,
) -> Response<Full<Bytes>> {
    // Checked by prefix, before matching on the exact built-in paths below,
    // so the request can be handed to the extension by value (it may need
    // the body, e.g. for a future write endpoint) without first needing it
    // back to fall through -- there is nothing to fall through to once a
    // path is recognized as the extension's own.
    if req.uri().path().starts_with("/backends") || req.uri().path().starts_with("/cache") {
        return match extension {
            Some(ext) => ext(req).await,
            None => text(StatusCode::NOT_FOUND, "not found".to_string()),
        };
    }

    let response = match req.uri().path() {
        "/metrics" => text(StatusCode::OK, metrics.gather_text()),

        // Liveness: is the process functioning? Deliberately independent of
        // backend health — a failing liveness probe restarts the process, and
        // restarting cannot fix an unhealthy backend. Coupling them turns a
        // partial outage into a crash loop.
        "/healthz" => text(StatusCode::OK, "ok".to_string()),

        // Readiness: should this instance receive traffic? False when a
        // listener has nowhere to forward or is serving an expired
        // certificate, which removes it from rotation without killing it.
        "/ready" => {
            if readiness() {
                text(StatusCode::OK, "ready".to_string())
            } else {
                text(StatusCode::SERVICE_UNAVAILABLE, "not ready".to_string())
            }
        }

        _ => text(StatusCode::NOT_FOUND, "not found".to_string()),
    };
    response
}

fn text(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::from_static(b"")));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}

fn unauthorized() -> Response<Full<Bytes>> {
    let mut response = text(StatusCode::UNAUTHORIZED, "unauthorized".to_string());
    response
        .headers_mut()
        .insert("www-authenticate", "Bearer".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusClass;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn start(ready: bool) -> (String, Arc<AtomicBool>) {
        let metrics = Arc::new(Metrics::new().unwrap());
        metrics
            .listener("web")
            .record_status(false, StatusClass::Success);

        let flag = Arc::new(AtomicBool::new(ready));
        let flag_clone = Arc::clone(&flag);
        let readiness: ReadinessCheck = Arc::new(move || flag_clone.load(Ordering::SeqCst));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server(metrics, listener, readiness, None, None);
        (format!("http://{addr}"), flag)
    }

    /// Like `start`, but with an admin bearer token configured -- returns
    /// the `Metrics` handle too, so a test can assert on `admin_auth_failures`.
    async fn start_with_token(token: &str) -> (String, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new().unwrap());
        let readiness: ReadinessCheck = Arc::new(|| true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server(
            Arc::clone(&metrics),
            listener,
            readiness,
            None,
            Some(Arc::from(token.as_bytes())),
        );
        (format!("http://{addr}"), metrics)
    }

    /// No token configured: every existing route stays exactly as
    /// unauthenticated as it always was -- this is the "no behavior change
    /// on the golden path" bar this session's other features have all had
    /// to clear too.
    #[tokio::test]
    async fn with_no_token_configured_every_route_stays_open() {
        let (base, _) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/healthz"))
                .await
                .unwrap()
                .status(),
            200
        );
    }

    #[tokio::test]
    async fn a_request_with_no_authorization_header_is_rejected() {
        let (base, metrics) = start_with_token("s3cret").await;
        let resp = reqwest::get(format!("{base}/metrics")).await.unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
        assert!(metrics
            .gather_text()
            .contains("lb_admin_auth_failures_total 1"));
    }

    #[tokio::test]
    async fn the_probes_answer_without_a_token_while_everything_else_requires_it() {
        let (base, _) = start_with_token("s3cret").await;
        for path in ["/healthz", "/ready"] {
            let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
            assert_eq!(resp.status(), 200, "{path} must not require the token");
        }
        for path in ["/metrics", "/backends", "/ready/../metrics"] {
            let resp = reqwest::get(format!("{base}{path}")).await.unwrap();
            assert_eq!(resp.status(), 401, "{path} must require the token");
        }
    }

    #[tokio::test]
    async fn a_request_with_the_wrong_token_is_rejected() {
        let (base, _) = start_with_token("s3cret").await;
        let resp = reqwest::Client::new()
            .get(format!("{base}/metrics"))
            .header("Authorization", "Bearer wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    /// A different length than the real token is still a plain rejection,
    /// not a panic -- `ConstantTimeEq` must be safe to call with mismatched
    /// lengths.
    #[tokio::test]
    async fn a_shorter_or_longer_token_is_rejected_not_a_panic() {
        let (base, _) = start_with_token("s3cret").await;
        for wrong in ["short", "a-much-longer-token-than-the-real-one"] {
            let resp = reqwest::Client::new()
                .get(format!("{base}/metrics"))
                .header("Authorization", format!("Bearer {wrong}"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 401);
        }
    }

    /// The correct token reaches every route, including the extension's --
    /// proving the check composes with `/backends` dispatch, not just the
    /// three built-in paths.
    #[tokio::test]
    async fn the_correct_token_reaches_every_route() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let readiness: ReadinessCheck = Arc::new(|| true);
        let extension: AdminExtension = Arc::new(|req: Request<Incoming>| {
            Box::pin(async move { text(StatusCode::OK, format!("saw {}", req.uri().path())) })
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server(
            metrics,
            listener,
            readiness,
            Some(extension),
            Some(Arc::from(b"s3cret".as_slice())),
        );

        let client = reqwest::Client::new();
        for path in ["/metrics", "/healthz", "/ready", "/backends"] {
            let resp = client
                .get(format!("http://{addr}{path}"))
                .header("Authorization", "Bearer s3cret")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "path {path} should be reachable");
        }
    }

    async fn start_limited(options: AdminOptions) -> std::net::SocketAddr {
        let metrics = Arc::new(Metrics::new().unwrap());
        let readiness: ReadinessCheck = Arc::new(|| true);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server_with_options(metrics, listener, readiness, None, None, options);
        addr
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_its_request_head_is_disconnected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = start_limited(AdminOptions {
            max_connections: 8,
            header_read_timeout: Duration::from_millis(200),
            read_only_token: None,
            acceptor: None,
        })
        .await;
        let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
        stalled
            .write_all(b"GET /metrics HTTP/1.1\r\nHo")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_secs(3), stalled.read_to_end(&mut buf)).await;
        assert!(
            closed.is_ok(),
            "a stalled request head must not hold an admin connection open"
        );
    }

    #[tokio::test]
    async fn connections_past_the_cap_wait_for_a_free_slot() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = start_limited(AdminOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_secs(30),
            read_only_token: None,
            acceptor: None,
        })
        .await;
        let holder = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut waiting = tokio::net::TcpStream::connect(addr).await.unwrap();
        waiting
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), waiting.read(&mut buf))
                .await
                .is_err(),
            "a connection past the cap must not be served while the cap is held"
        );

        drop(holder);
        let n = tokio::time::timeout(Duration::from_secs(3), waiting.read(&mut buf))
            .await
            .expect("the waiting connection must be served once a slot frees")
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    }

    async fn start_with_roles() -> std::net::SocketAddr {
        let metrics = Arc::new(Metrics::new().unwrap());
        let readiness: ReadinessCheck = Arc::new(|| true);
        let extension: AdminExtension = Arc::new(|req: Request<Incoming>| {
            Box::pin(async move { text(StatusCode::OK, format!("saw {}", req.uri().path())) })
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server_with_options(
            metrics,
            listener,
            readiness,
            Some(extension),
            Some(Arc::from(b"admin-secret".as_slice())),
            AdminOptions {
                read_only_token: Some(Arc::from(b"viewer-secret".as_slice())),
                ..AdminOptions::default()
            },
        );
        addr
    }

    #[tokio::test]
    async fn a_read_only_token_can_read_but_not_write() {
        let addr = start_with_roles().await;
        let client = reqwest::Client::new();
        let send = |method: reqwest::Method, path: &str, token: &str| {
            client
                .request(method, format!("http://{addr}{path}"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
        };
        assert_eq!(
            send(reqwest::Method::GET, "/metrics", "viewer-secret")
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            send(reqwest::Method::GET, "/backends", "viewer-secret")
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            send(
                reqwest::Method::POST,
                "/backends/web/b1/drain",
                "viewer-secret"
            )
            .await
            .unwrap()
            .status(),
            403
        );
        assert_eq!(
            send(
                reqwest::Method::POST,
                "/backends/web/b1/drain",
                "admin-secret"
            )
            .await
            .unwrap()
            .status(),
            200
        );
        assert_eq!(
            send(reqwest::Method::POST, "/backends/web/b1/drain", "wrong")
                .await
                .unwrap()
                .status(),
            401
        );
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_write_attempt_is_audited_with_who_what_and_outcome() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let addr = start_with_roles().await;
        let client = reqwest::Client::new();
        for token in ["viewer-secret", "admin-secret"] {
            client
                .post(format!("http://{addr}/backends/web/b1/drain"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
        }
        client
            .get(format!("http://{addr}/metrics"))
            .header("Authorization", "Bearer admin-secret")
            .send()
            .await
            .unwrap();

        let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let audit: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("lb_admin_audit"))
            .collect();
        assert_eq!(audit.len(), 2, "exactly the two writes are audited:\n{log}");
        assert!(
            audit[0].contains("role=\"read_only\"") || audit[0].contains("role=read_only"),
            "{}",
            audit[0]
        );
        assert!(audit[0].contains("status=403"), "{}", audit[0]);
        assert!(audit[1].contains("admin"), "{}", audit[1]);
        assert!(audit[1].contains("status=200"), "{}", audit[1]);
        assert!(audit[1].contains("/backends/web/b1/drain"), "{}", audit[1]);
        assert!(audit[1].contains("127.0.0.1"), "{}", audit[1]);
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_exposition() {
        let (base, _) = start(true).await;
        let body = reqwest::get(format!("{base}/metrics"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("lb_requests_total"));
        assert!(body.contains("# TYPE"));
    }

    #[tokio::test]
    async fn healthz_is_ok_even_when_not_ready() {
        // The core distinction: liveness must not follow backend health, or a
        // backend outage would restart the load balancer in a loop.
        let (base, _) = start(false).await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn ready_reflects_the_readiness_check() {
        let (base, flag) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/ready"))
                .await
                .unwrap()
                .status(),
            200
        );

        flag.store(false, Ordering::SeqCst);
        assert_eq!(
            reqwest::get(format!("{base}/ready"))
                .await
                .unwrap()
                .status(),
            503
        );
    }

    #[tokio::test]
    async fn unknown_paths_are_404() {
        let (base, _) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/admin"))
                .await
                .unwrap()
                .status(),
            404
        );
    }

    /// A `/backends...` path with no extension configured still 404s like
    /// any other unrecognized path -- the prefix check alone must not
    /// change behavior when there is nothing to hand the request to.
    #[tokio::test]
    async fn backends_path_without_an_extension_is_404() {
        let (base, _) = start(true).await;
        assert_eq!(
            reqwest::get(format!("{base}/backends"))
                .await
                .unwrap()
                .status(),
            404
        );
    }

    /// The extension is tried for anything under `/backends`, and its
    /// response is returned verbatim -- proving the dispatch actually wires
    /// the closure in, not just that the built-in routes still work.
    #[tokio::test]
    async fn backends_path_is_handed_to_the_extension() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let readiness: ReadinessCheck = Arc::new(|| true);
        let extension: AdminExtension = Arc::new(|req: Request<Incoming>| {
            Box::pin(async move {
                text(
                    StatusCode::OK,
                    format!("extension saw {}", req.uri().path()),
                )
            })
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_admin_server(metrics, listener, readiness, Some(extension), None);

        let body = reqwest::get(format!("http://{addr}/backends/web/b1/drain"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "extension saw /backends/web/b1/drain");

        // Built-in routes are unaffected by an extension being present.
        assert_eq!(
            reqwest::get(format!("http://{addr}/healthz"))
                .await
                .unwrap()
                .status(),
            200
        );
    }
}
