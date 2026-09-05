use lb_core::{Backend, HealthProbe, OutboundTransport, ProbeClient};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// Health probe for HTTP backends: GET `<path>`, 2xx means healthy.
///
/// Deliberately built on the *same* client `lb-proxy` forwards real traffic
/// with, sharing its connection pool, trust roots, verification policy and
/// pinned resolver. It used to own a `reqwest::Client`, which carried its own
/// TLS stack and its own trust configuration -- so a backend whose
/// certificate could not be verified probed healthy while every real request
/// to it failed, and the load balancer kept routing to a backend it could not
/// talk to with the dashboard showing green.
///
/// The client arrives as `Arc<dyn ProbeClient>` rather than as a concrete
/// type because `lb-proxy` depends on this crate; taking the concrete client
/// would be a dependency cycle. What makes the guarantee real is not the
/// trait but the wiring: `lb-server` builds one client per listener and hands
/// that same value to both the proxy context and this probe.
pub struct HttpProbe {
    client: Arc<dyn ProbeClient>,
    path: String,
    timeout: Duration,
    /// Whether this listener re-encrypts to its backends. A listener-level
    /// fact, passed straight through to the client, which owns the
    /// scheme/authority decision. The probe does not need to know *why* the
    /// scheme is what it is -- only that the same rule applies to it as to
    /// traffic.
    backend_tls: bool,
}

impl HttpProbe {
    pub fn new(
        client: Arc<dyn ProbeClient>,
        path: impl Into<String>,
        timeout: Duration,
        backend_tls: bool,
    ) -> Self {
        HttpProbe {
            client,
            path: path.into(),
            timeout,
            backend_tls,
        }
    }
}

impl HealthProbe for HttpProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let status = self
            .client
            .get(backend, &self.path, self.backend_tls, self.timeout);
        // What counts as healthy lives here rather than in the client: the
        // client reports what happened, the probe decides what it means.
        async move { matches!(status.await, Some(code) if (200..300).contains(&code)) }
    }
}

/// Health probe for arbitrary TCP backends: the connection has to be
/// establishable the way real traffic establishes it.
///
/// For a plaintext listener that is the TCP handshake, which is all you can
/// portably assert about a service that may speak Postgres, Redis, SMTP or
/// anything else. For a listener that re-encrypts, it is the TCP handshake
/// *and* the TLS handshake on top of it -- a completed TCP handshake says
/// nothing about whether the backend's TLS works, since a backend with an
/// expired or untrusted certificate accepts the connection just the same. The
/// L4 shape of exactly the failure `HttpProbe` exists to prevent.
pub struct TcpConnectProbe {
    timeout: Duration,
    /// The *same* `Arc` the L4 data plane wraps its outbound connections
    /// with, not a second transport built from the same config. `None` means
    /// this listener's outbound leg is plaintext.
    backend_tls: Option<Arc<dyn OutboundTransport>>,
}

impl TcpConnectProbe {
    pub fn new(timeout: Duration, backend_tls: Option<Arc<dyn OutboundTransport>>) -> Self {
        TcpConnectProbe {
            timeout,
            backend_tls,
        }
    }
}

impl HealthProbe for TcpConnectProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let addr = backend.address;
        let timeout = self.timeout;
        let transport = self.backend_tls.clone();
        let server_name = backend.server_name.clone();
        async move {
            let Ok(Ok(stream)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await
            else {
                return false;
            };
            match (transport, server_name) {
                // Both connections are dropped immediately — establishing one
                // is the entire test.
                (Some(transport), Some(name)) => transport
                    .wrap(Box::new(stream), name, timeout)
                    .await
                    .is_ok(),
                // A re-encrypting listener whose backend has no `server_name`
                // is unreachable through config validation. Unhealthy rather
                // than "the TCP connect was enough": the data plane refuses to
                // proxy to it for the same reason, and a probe that disagreed
                // would keep an unusable backend in rotation.
                (Some(_), None) => false,
                (None, _) => true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{StubProbeClient, StubTransport};
    use std::sync::atomic::Ordering;
    use tokio::net::TcpListener;

    /// A listener that accepts and then does nothing — enough for a TCP
    /// connect to succeed, which is the point: at L4 that is all a plaintext
    /// probe ever gets to observe.
    async fn accepting_port() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });
        addr
    }

    fn backend(name: Option<&str>) -> Backend {
        Backend::new(
            "b1",
            "127.0.0.1:9000".parse().unwrap(),
            1,
            name.map(str::to_string),
        )
    }

    #[tokio::test]
    async fn http_probe_is_healthy_on_2xx() {
        let probe = HttpProbe::new(
            Arc::new(StubProbeClient::new(Some(204))),
            "/health",
            Duration::from_millis(200),
            false,
        );
        assert!(probe.probe(&backend(None)).await);
    }

    #[tokio::test]
    async fn http_probe_is_unhealthy_on_non_2xx() {
        let probe = HttpProbe::new(
            Arc::new(StubProbeClient::new(Some(500))),
            "/health",
            Duration::from_millis(200),
            false,
        );
        assert!(!probe.probe(&backend(None)).await);
    }

    /// The case this whole task exists for: a backend the client could not
    /// reach at all — a refused certificate reaches the probe exactly like a
    /// connect failure does — is unhealthy, never "no answer, assume fine".
    #[tokio::test]
    async fn http_probe_is_unhealthy_when_the_request_could_not_be_completed() {
        let probe = HttpProbe::new(
            Arc::new(StubProbeClient::new(None)),
            "/health",
            Duration::from_millis(200),
            false,
        );
        assert!(!probe.probe(&backend(None)).await);
    }

    /// The probe hands the client the backend and the decision inputs and
    /// lets it build the URL. If it ever started composing a URL itself, that
    /// second decision could drift from the one real traffic makes.
    #[tokio::test]
    async fn http_probe_passes_the_decision_inputs_to_the_client() {
        let client = Arc::new(StubProbeClient::new(Some(200)));
        let probe = HttpProbe::new(client.clone(), "/healthz", Duration::from_millis(250), true);
        assert!(probe.probe(&backend(Some("web1.internal"))).await);

        let calls = client.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].backend_id, "b1");
        assert_eq!(calls[0].path, "/healthz");
        assert!(calls[0].backend_tls);
        assert_eq!(calls[0].timeout, Duration::from_millis(250));
    }

    #[tokio::test]
    async fn tcp_probe_reports_healthy_when_port_accepts() {
        let addr = accepting_port().await;
        let probe = TcpConnectProbe::new(Duration::from_millis(500), None);
        let b = Backend::new("b1", addr, 1, None);
        assert!(probe.probe(&b).await);
    }

    #[tokio::test]
    async fn tcp_probe_reports_unhealthy_when_nothing_listens() {
        // Bind then immediately drop, so the port is almost certainly closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let probe = TcpConnectProbe::new(Duration::from_millis(300), None);
        let b = Backend::new("b1", addr, 1, None);
        assert!(!probe.probe(&b).await);
    }

    /// The L4 regression: the port accepts, so the old probe called this
    /// backend healthy. Real traffic to it would be refused at the handshake,
    /// so the probe must be too.
    #[tokio::test]
    async fn tcp_probe_is_unhealthy_when_the_outbound_wrap_fails() {
        let addr = accepting_port().await;
        let transport = Arc::new(StubTransport::new(false));
        let probe = TcpConnectProbe::new(Duration::from_millis(500), Some(transport.clone()));
        let b = Backend::new("b1", addr, 1, Some("backend.internal".into()));

        assert!(!probe.probe(&b).await);
        assert_eq!(
            transport.wraps.load(Ordering::SeqCst),
            1,
            "the probe never asked the transport to wrap the connection"
        );
        // The name on the certificate, not the address dialed — the same
        // distinction the data plane makes.
        assert_eq!(
            transport.names.lock().unwrap().as_slice(),
            ["backend.internal"]
        );
    }

    /// The matched control, so the test above cannot pass by refusing
    /// everything.
    #[tokio::test]
    async fn tcp_probe_is_healthy_when_the_outbound_wrap_succeeds() {
        let addr = accepting_port().await;
        let transport = Arc::new(StubTransport::new(true));
        let probe = TcpConnectProbe::new(Duration::from_millis(500), Some(transport.clone()));
        let b = Backend::new("b1", addr, 1, Some("backend.internal".into()));

        assert!(probe.probe(&b).await);
        assert_eq!(transport.wraps.load(Ordering::SeqCst), 1);
    }

    /// Config validation makes this unreachable, but if it were ever bypassed
    /// the answer must not be "the TCP connect succeeded, call it healthy" —
    /// the data plane refuses to proxy to such a backend, and the probe has
    /// to agree.
    #[tokio::test]
    async fn tcp_probe_is_unhealthy_for_a_nameless_backend_on_a_re_encrypting_listener() {
        let addr = accepting_port().await;
        let transport = Arc::new(StubTransport::new(true));
        let probe = TcpConnectProbe::new(Duration::from_millis(500), Some(transport.clone()));
        let b = Backend::new("b1", addr, 1, None);

        assert!(!probe.probe(&b).await);
        assert_eq!(
            transport.wraps.load(Ordering::SeqCst),
            0,
            "there is no name to verify against, so nothing should be wrapped"
        );
    }
}
