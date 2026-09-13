use crate::Metrics;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;

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
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            let metrics = Arc::clone(&metrics);
            let readiness = Arc::clone(&readiness);
            let extension = extension.clone();
            let admin_token = admin_token.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let metrics = Arc::clone(&metrics);
                    let readiness = Arc::clone(&readiness);
                    let extension = extension.clone();
                    let admin_token = admin_token.clone();
                    async move { route(req, metrics, readiness, extension, admin_token).await }
                });
                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
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
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Checked before anything else, so every route below (including
    // `extension`'s, which owns everything under /backends) is covered by
    // one check instead of needing its own. A byte-wise `==` here would leak
    // how much of the presented token matched through timing -- the same
    // concern `lb-cluster`'s gossip HMAC check already guards against --
    // hence `ConstantTimeEq` rather than a plain comparison.
    if let Some(token) = &admin_token {
        let presented = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let authorized = presented.is_some_and(|p| bool::from(p.as_bytes().ct_eq(token)));
        if !authorized {
            metrics.admin_auth_failures.inc();
            return Ok(unauthorized());
        }
    }

    // Checked by prefix, before matching on the exact built-in paths below,
    // so the request can be handed to the extension by value (it may need
    // the body, e.g. for a future write endpoint) without first needing it
    // back to fall through -- there is nothing to fall through to once a
    // path is recognized as the extension's own.
    if req.uri().path().starts_with("/backends") {
        return Ok(match extension {
            Some(ext) => ext(req).await,
            None => text(StatusCode::NOT_FOUND, "not found".to_string()),
        });
    }

    let response = match req.uri().path() {
        "/metrics" => text(StatusCode::OK, metrics.gather_text()),

        // Liveness: is the process functioning? Deliberately independent of
        // backend health — a failing liveness probe restarts the process, and
        // restarting cannot fix an unhealthy backend. Coupling them turns a
        // partial outage into a crash loop.
        "/healthz" => text(StatusCode::OK, "ok".to_string()),

        // Readiness: should this instance receive traffic? False when there is
        // nowhere to forward, which removes it from rotation without killing it.
        "/ready" => {
            if readiness() {
                text(StatusCode::OK, "ready".to_string())
            } else {
                text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no eligible backend".to_string(),
                )
            }
        }

        _ => text(StatusCode::NOT_FOUND, "not found".to_string()),
    };
    Ok(response)
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
