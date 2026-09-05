//! Test doubles for the two seams the probes are built on.
//!
//! They live here rather than inside one module's `mod tests` because both
//! `probe.rs` (does the probe read the seam's answer correctly?) and
//! `active.rs` (does the checker publish that answer into the pool?) need
//! them, and a second copy of a fake is a second thing to keep in sync.
//!
//! This crate deliberately depends on `lb-core` alone -- no HTTP client, no
//! TLS -- which is exactly why doubles are the right tool here: the real
//! implementations of both seams live in `lb-proxy` and `lb-tls`, and the
//! proof that the *real* ones agree with the data plane is `lb-server`'s
//! integration suite, where a genuine certificate is genuinely refused.

use lb_core::{Backend, OutboundTransport, ProbeClient, ProbeFuture, ProxyStream, WrapFuture};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// A `ProbeClient` that answers with a fixed status and records exactly what
/// it was asked for, so a test can assert the probe passed the decision
/// inputs through rather than inventing its own.
pub struct StubProbeClient {
    answer: Option<u16>,
    pub calls: Mutex<Vec<StubCall>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubCall {
    pub backend_id: String,
    pub path: String,
    pub backend_tls: bool,
    pub timeout: Duration,
}

impl StubProbeClient {
    /// `answer` is what `get` returns: `Some(status)` for a backend that
    /// answered, `None` for one that could not be reached at all (a connect
    /// failure, a refused certificate, a timeout).
    pub fn new(answer: Option<u16>) -> Self {
        StubProbeClient {
            answer,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl ProbeClient for StubProbeClient {
    fn get(
        &self,
        backend: &Backend,
        path: &str,
        backend_tls: bool,
        timeout: Duration,
    ) -> ProbeFuture<'_> {
        self.calls.lock().unwrap().push(StubCall {
            backend_id: backend.id.0.clone(),
            path: path.to_string(),
            backend_tls,
            timeout,
        });
        let answer = self.answer;
        Box::pin(async move { answer })
    }
}

/// An `OutboundTransport` that either completes or refuses the wrap, and
/// counts how often it was asked.
pub struct StubTransport {
    succeeds: bool,
    pub wraps: AtomicUsize,
    pub names: Mutex<Vec<String>>,
}

impl StubTransport {
    pub fn new(succeeds: bool) -> Self {
        StubTransport {
            succeeds,
            wraps: AtomicUsize::new(0),
            names: Mutex::new(Vec::new()),
        }
    }
}

impl OutboundTransport for StubTransport {
    fn wrap(
        &self,
        stream: Box<dyn ProxyStream>,
        server_name: String,
        _timeout: Duration,
    ) -> WrapFuture<'_> {
        self.wraps.fetch_add(1, Ordering::SeqCst);
        self.names.lock().unwrap().push(server_name);
        let succeeds = self.succeeds;
        Box::pin(async move {
            if succeeds {
                Ok(stream)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stub transport refused the handshake",
                ))
            }
        })
    }
}
