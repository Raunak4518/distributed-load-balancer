use serde::Deserialize;
use std::time::Duration;

/// Per-listener HTTP/2 settings.
///
/// Every field is optional and every default is chosen to be safe
/// unconfigured: an operator who never writes this section still gets the
/// full set of protections. The defaults are not tuning knobs left at zero —
/// they are the bounds that keep HTTP/2 survivable on a public port.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct Http2Config {
    pub enabled: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub max_pending_accept_reset_streams: Option<usize>,
    pub max_local_error_reset_streams: Option<usize>,
    pub max_header_list_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub keep_alive_interval_secs: Option<u64>,
    pub keep_alive_timeout_secs: Option<u64>,
    /// Plaintext backends only. TLS backends negotiate HTTP/2 over ALPN per
    /// connection and need nothing here, which is why a mixed TLS fleet works
    /// with no configuration.
    pub backend_h2c: Option<bool>,
}

impl Http2Config {
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Concurrent requests per connection.
    ///
    /// This is the HTTP/2 analogue of `max_connections_per_ip`. Under HTTP/2
    /// one connection carries many concurrent requests, so a per-IP
    /// *connection* cap no longer bounds per-IP *work*; without this, Phase 5's
    /// hardening silently regresses.
    pub fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams.unwrap_or(128)
    }

    /// Bounds Rapid Reset (CVE-2023-44487): a client opens streams and
    /// immediately cancels them. Cancellation is nearly free for the client
    /// and expensive for us, and cancelled streams evade
    /// `max_concurrent_streams` precisely by not being concurrent.
    ///
    /// Twenty is deliberately h2's own built-in default
    /// (`DEFAULT_REMOTE_RESET_STREAM_MAX`), and the number is pinned from
    /// both directions:
    ///
    /// * Not higher. A looser default would be inert — h2 applies its own
    ///   bound when hyper is given none, so anything above 20 is a number we
    ///   claim to enforce while the library enforces something stricter. The
    ///   previous default of 32 was exactly that, and it made "safe
    ///   unconfigured" the library's promise rather than ours.
    /// * Not lower. Cancelling a stream is legitimate: a browser navigating
    ///   away, an abandoned image load, a user hitting stop. Tightening this
    ///   below what h2 itself considers ordinary starts cutting real clients
    ///   off mid-session, and a mitigation that produces its own outage is
    ///   not a mitigation.
    ///
    /// Operators who want a stricter bound can set one; the point is that the
    /// unconfigured value is the one number that is defensible without
    /// knowing the traffic.
    pub fn max_pending_accept_reset_streams(&self) -> usize {
        self.max_pending_accept_reset_streams.unwrap_or(20)
    }

    pub fn max_local_error_reset_streams(&self) -> usize {
        self.max_local_error_reset_streams.unwrap_or(128)
    }

    /// Bounds HPACK and `CONTINUATION` expansion, where few frames can become
    /// a lot of server-side state.
    pub fn max_header_list_size(&self) -> u32 {
        self.max_header_list_size.unwrap_or(16384)
    }

    pub fn max_frame_size(&self) -> u32 {
        self.max_frame_size.unwrap_or(16384)
    }

    /// HTTP/2's liveness check. There is deliberately no header-read timeout
    /// here: `header_read_timeout_ms` is an HTTP/1.1 concept, and an idle
    /// HTTP/2 connection is normal where a dead one is not. PING tells them
    /// apart — the same distinction the L4 idle timeout draws in Phase 2.
    pub fn keep_alive_interval(&self) -> Duration {
        Duration::from_secs(self.keep_alive_interval_secs.unwrap_or(20))
    }

    pub fn keep_alive_timeout(&self) -> Duration {
        Duration::from_secs(self.keep_alive_timeout_secs.unwrap_or(10))
    }

    pub fn backend_h2c(&self) -> bool {
        self.backend_h2c.unwrap_or(false)
    }
}
