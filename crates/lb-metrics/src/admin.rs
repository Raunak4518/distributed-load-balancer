use crate::Metrics;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Returns true when this instance should receive traffic.
pub type ReadinessCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Serves `/metrics`, `/healthz` and `/ready` on a private listener.
///
/// Deliberately separate from the traffic listeners: this surface exposes
/// internal topology (backend names, health, traffic volumes) and must not
/// face the public internet.
pub fn spawn_admin_server(
    metrics: Arc<Metrics>,
    listener: TcpListener,
    readiness: ReadinessCheck,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            let metrics = Arc::clone(&metrics);
            let readiness = Arc::clone(&readiness);
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let metrics = Arc::clone(&metrics);
                    let readiness = Arc::clone(&readiness);
                    async move { route(req, metrics, readiness).await }
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
) -> Result<Response<Full<Bytes>>, Infallible> {
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
        spawn_admin_server(metrics, listener, readiness);
        (format!("http://{addr}"), flag)
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
}
