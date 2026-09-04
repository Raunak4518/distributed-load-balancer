use lb_core::{Backend, HealthProbe};
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;

/// Health probe for HTTP backends: GET `<path>`, 2xx means healthy.
pub struct HttpProbe {
    client: reqwest::Client,
    path: String,
    timeout: Duration,
}

impl HttpProbe {
    pub fn new(path: impl Into<String>, timeout: Duration) -> Self {
        HttpProbe {
            client: reqwest::Client::new(),
            path: path.into(),
            timeout,
        }
    }
}

impl HealthProbe for HttpProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let url = format!("http://{}{}", backend.address, self.path);
        let client = self.client.clone();
        let timeout = self.timeout;
        async move {
            match tokio::time::timeout(timeout, client.get(&url).send()).await {
                Ok(Ok(resp)) => resp.status().is_success(),
                _ => false,
            }
        }
    }
}

/// Health probe for arbitrary TCP backends: if the TCP handshake completes,
/// the backend is alive. This is all you can portably assert about a service
/// that may speak Postgres, Redis, SMTP, or anything else.
pub struct TcpConnectProbe {
    timeout: Duration,
}

impl TcpConnectProbe {
    pub fn new(timeout: Duration) -> Self {
        TcpConnectProbe { timeout }
    }
}

impl HealthProbe for TcpConnectProbe {
    fn probe(&self, backend: &Backend) -> impl Future<Output = bool> + Send {
        let addr = backend.address;
        let timeout = self.timeout;
        async move {
            // The connection is dropped immediately — establishing it is the
            // entire test.
            matches!(
                tokio::time::timeout(timeout, TcpStream::connect(addr)).await,
                Ok(Ok(_))
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_probe_reports_healthy_when_port_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    return;
                }
            }
        });

        let probe = TcpConnectProbe::new(Duration::from_millis(500));
        let backend = Backend::new("b1", addr, 1, None);
        assert!(probe.probe(&backend).await);
    }

    #[tokio::test]
    async fn tcp_probe_reports_unhealthy_when_nothing_listens() {
        // Bind then immediately drop, so the port is almost certainly closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let probe = TcpConnectProbe::new(Duration::from_millis(300));
        let backend = Backend::new("b1", addr, 1, None);
        assert!(!probe.probe(&backend).await);
    }
}
