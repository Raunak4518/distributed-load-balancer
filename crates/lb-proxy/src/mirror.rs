use crate::forward::{full_body, ProxyClient};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Request, Uri};
use lb_metrics::ListenerMetrics;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct Mirror {
    address: SocketAddr,
    percent: u8,
    timeout: Duration,
    in_flight: Arc<Semaphore>,
    cursor: AtomicU64,
}

impl Mirror {
    pub fn new(address: SocketAddr, percent: u8, max_in_flight: usize, timeout: Duration) -> Self {
        Mirror {
            address,
            percent,
            timeout,
            in_flight: Arc::new(Semaphore::new(max_in_flight)),
            cursor: AtomicU64::new(0),
        }
    }

    fn sampled(&self) -> bool {
        self.cursor.fetch_add(1, Ordering::Relaxed) % 100 < u64::from(self.percent)
    }

    pub fn send(
        &self,
        client: &ProxyClient,
        parts: &Parts,
        body: Option<&Bytes>,
        metrics: &Arc<ListenerMetrics>,
    ) {
        if !self.sampled() {
            return;
        }
        let Some(body) = body else {
            metrics.mirror_skipped.inc();
            return;
        };
        let Ok(permit) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            metrics.mirror_dropped.inc();
            return;
        };
        let Some(req) = self.shadow_request(parts, body.clone()) else {
            metrics.mirror_failed.inc();
            return;
        };
        let client = client.clone();
        let metrics = Arc::clone(metrics);
        let timeout = self.timeout;
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = tokio::time::timeout(timeout, async {
                let resp = client.request(req).await.map_err(|_| ())?;
                resp.into_body().collect().await.map_err(|_| ())
            })
            .await;
            match outcome {
                Ok(Ok(_)) => metrics.mirror_sent.inc(),
                _ => metrics.mirror_failed.inc(),
            }
        });
    }

    fn shadow_request(
        &self,
        parts: &Parts,
        body: Bytes,
    ) -> Option<Request<crate::forward::ProxyRequestBody>> {
        let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let uri = Uri::builder()
            .scheme("http")
            .authority(self.address.to_string())
            .path_and_query(path_and_query)
            .build()
            .ok()?;
        let mut headers = parts.headers.clone();
        crate::service::strip_hop_by_hop(&mut headers);
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| format!("{h}-shadow"))
            .unwrap_or_else(|| format!("{}-shadow", self.address));
        headers.insert(header::HOST, HeaderValue::from_str(&host).ok()?);
        let mut req = Request::builder()
            .method(parts.method.clone())
            .uri(uri)
            .body(full_body(body))
            .ok()?;
        *req.headers_mut() = headers;
        Some(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_percentage_mirrors_exactly_that_share_of_requests() {
        let mirror = Mirror::new(
            "127.0.0.1:1".parse().unwrap(),
            25,
            1,
            Duration::from_secs(1),
        );
        let sampled = (0..400).filter(|_| mirror.sampled()).count();
        assert_eq!(sampled, 100);
    }

    #[test]
    fn the_shadow_request_is_marked_and_keeps_method_path_and_headers() {
        let mirror = Mirror::new(
            "127.0.0.1:9000".parse().unwrap(),
            100,
            1,
            Duration::from_secs(1),
        );
        let (parts, ()) = Request::builder()
            .method("POST")
            .uri("/orders?id=7")
            .header("host", "shop.example")
            .header("x-trace", "abc")
            .header("connection", "keep-alive")
            .body(())
            .unwrap()
            .into_parts();
        let req = mirror
            .shadow_request(&parts, Bytes::from_static(b"{}"))
            .unwrap();
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "http://127.0.0.1:9000/orders?id=7");
        assert_eq!(req.headers()["host"], "shop.example-shadow");
        assert_eq!(req.headers()["x-trace"], "abc");
        assert!(!req.headers().contains_key("connection"));
    }
}
