use prometheus::{Histogram, IntCounter, IntGauge, IntGaugeVec};

/// Status codes are recorded by *class*, not exact code.
///
/// Two reasons. Alerting cares about error rate (5xx) rather than the
/// difference between 502 and 504, and — more importantly — a bounded set of
/// classes means the counter handles can be resolved once at wiring time
/// instead of doing a string-keyed lookup on every request at 50k req/s.
/// Rate-limit rejections, the one 4xx worth isolating, get their own metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    Success,
    Redirect,
    ClientError,
    ServerError,
}

impl StatusClass {
    pub fn from_code(code: u16) -> Self {
        match code {
            200..=299 => StatusClass::Success,
            300..=399 => StatusClass::Redirect,
            400..=499 => StatusClass::ClientError,
            _ => StatusClass::ServerError,
        }
    }

    pub fn as_label(self) -> &'static str {
        match self {
            StatusClass::Success => "2xx",
            StatusClass::Redirect => "3xx",
            StatusClass::ClientError => "4xx",
            StatusClass::ServerError => "5xx",
        }
    }
}

/// Metric handles for one listener, resolved once at wiring time.
///
/// Every field is a concrete handle wrapping an atomic. Recording a request
/// costs a couple of atomic increments and one histogram observation — no
/// map lookup, no string hashing, no lock.
pub struct ListenerMetrics {
    pub requests_2xx: IntCounter,
    pub requests_3xx: IntCounter,
    pub requests_4xx: IntCounter,
    pub requests_5xx: IntCounter,
    pub request_duration: Histogram,
    pub active_connections: IntGauge,
    pub connections_total: IntCounter,
    pub ratelimit_rejected_local: IntCounter,
    pub ratelimit_rejected_cluster: IntCounter,

    // Edge hardening (Phase 5). A limit you cannot see being approached is a
    // limit you only learn about during an incident.
    pub connections_rejected_max: IntCounter,
    pub connections_rejected_per_ip: IntCounter,
    pub timeouts_header: IntCounter,
    pub timeouts_body: IntCounter,
    /// Early warning that the rate-limit overflow bucket is about to engage.
    pub tracked_keys: IntGauge,

    // TLS (Phase 6). Pre-resolved per outcome for the same reason as every
    // handle above: the outcome set is fixed in code, so there is no reason
    // to hash a label string once per handshake.
    pub tls_handshakes_success: IntCounter,
    pub tls_handshakes_failed: IntCounter,
    pub tls_handshakes_timeout: IntCounter,
    pub tls_handshake_duration: Histogram,

    // TLS certificate hot reload (Phase 6). The outcome set is fixed in
    // code (applied/unchanged/rejected), so these are pre-resolved handles
    // like every other counter above -- never `with_label_values` on a
    // reload tick.
    pub tls_certificate_reloads_applied: IntCounter,
    pub tls_certificate_reloads_unchanged: IntCounter,
    pub tls_certificate_reloads_rejected: IntCounter,
    /// Unlike every other field here, this is the family itself rather than
    /// a pre-resolved handle: `cert` genuinely varies per configured
    /// certificate, and the set of certificates is not known when this
    /// struct is built. Reload ticks are infrequent (60s by default), so
    /// resolving a label pair here is not a hot-path cost the way it would
    /// be per-request or per-handshake.
    pub tls_certificate_expiry_timestamp_seconds: IntGaugeVec,
}

impl ListenerMetrics {
    pub fn record_status(&self, class: StatusClass) {
        match class {
            StatusClass::Success => self.requests_2xx.inc(),
            StatusClass::Redirect => self.requests_3xx.inc(),
            StatusClass::ClientError => self.requests_4xx.inc(),
            StatusClass::ServerError => self.requests_5xx.inc(),
        }
    }
}

/// Metric handles for one backend of one listener.
pub struct BackendMetrics {
    pub healthy: IntGauge,
    pub circuit_state: IntGauge,
    pub requests_success: IntCounter,
    pub requests_failure: IntCounter,
    pub requests_timeout: IntCounter,
    pub upstream_duration: Histogram,
}
