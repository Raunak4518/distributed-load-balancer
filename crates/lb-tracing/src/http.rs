//! A minimal blocking HTTP/1.1 client, used only to POST span batches to the
//! configured OTLP collector.
//!
//! Not `reqwest`: the batch span processor drives its exporter from its own
//! dedicated OS thread, not a Tokio task -- confirmed by actually running
//! this against a real collector, not assumed -- so an async client there
//! has no reactor to run on ("there is no reactor running, must be called
//! from the context of a Tokio 1.x runtime"). A blocking client needs no
//! ambient runtime at all, which is why this exists instead of using one of
//! `opentelemetry-otlp`'s own HTTP client features (see this crate's
//! `Cargo.toml` for why `reqwest` specifically is also worth avoiding here).
//!
//! Deliberately plain HTTP, no TLS: `TracingConfig::otlp_endpoint` already
//! scopes this to a same-trust-domain collector, so there is nothing to add
//! a second TLS stack for.
use bytes::Bytes;
use http::{Request, Response};
use opentelemetry_http::{HttpClient, HttpError};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct BlockingHttpClient {
    timeout: Duration,
}

impl BlockingHttpClient {
    pub fn new(timeout: Duration) -> Self {
        BlockingHttpClient { timeout }
    }
}

#[async_trait::async_trait]
impl HttpClient for BlockingHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let uri = request.uri();
        let host = uri.host().ok_or("OTLP request URI has no host")?;
        let port = uri.port_u16().unwrap_or(80);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let body = request.body();

        // A numeric IP parses directly, skipping `getaddrinfo` entirely --
        // observed empirically to matter: resolving a bare "127.0.0.1" as a
        // hostname string went through a multi-second dual-stack resolution
        // path on Windows before ever attempting the connect.
        let mut stream = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), self.timeout)?
        } else {
            TcpStream::connect((host, port))?
        };

        let mut head = format!(
            "{} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n",
            request.method(),
            body.len(),
        );
        for (name, value) in request.headers() {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            if let Ok(v) = value.to_str() {
                head.push_str(&format!("{name}: {v}\r\n"));
            }
        }
        head.push_str("\r\n");

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;

        // A collector we told to close the connection (above) makes
        // read-to-end a safe way to read the whole response -- there is no
        // keep-alive framing to get wrong.
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;

        let text = String::from_utf8_lossy(&raw);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or("could not parse the collector's HTTP status line")?;

        Ok(Response::builder().status(status).body(Bytes::new())?)
    }
}
