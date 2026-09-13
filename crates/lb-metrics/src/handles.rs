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

/// The four status-class counters for one HTTP version.
///
/// Split out so `ListenerMetrics` can hold one resolved set per HTTP
/// version (see `ListenerMetrics::requests_for`) without doubling up on the
/// four-field boilerplate above.
pub struct RequestCounters {
    pub c2xx: IntCounter,
    pub c3xx: IntCounter,
    pub c4xx: IntCounter,
    pub c5xx: IntCounter,
}

impl RequestCounters {
    fn record(&self, class: StatusClass) {
        match class {
            StatusClass::Success => self.c2xx.inc(),
            StatusClass::Redirect => self.c3xx.inc(),
            StatusClass::ClientError => self.c4xx.inc(),
            StatusClass::ServerError => self.c5xx.inc(),
        }
    }
}

/// Metric handles for one listener, resolved once at wiring time.
///
/// Every field is a concrete handle wrapping an atomic. Recording a request
/// costs a couple of atomic increments and one histogram observation — no
/// map lookup, no string hashing, no lock.
pub struct ListenerMetrics {
    /// Pre-resolved per HTTP version, so selecting between them on the
    /// request path is a branch (`requests_for`) rather than a label lookup.
    /// A TCP listener holds these like every other listener but never
    /// increments them — it counts connections, not requests.
    pub requests_h1: RequestCounters,
    pub requests_h2: RequestCounters,
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

    /// Response caching. Absent from a listener with no `[listeners.cache]`
    /// -- these are simply never incremented there, same as every other
    /// feature-gated counter above.
    pub cache_hit: IntCounter,
    pub cache_miss: IntCounter,

    /// WAF first-slice. One fixed handle per built-in rule -- the rule set
    /// is closed and known at compile time, so this is pre-resolved like
    /// every other fixed-outcome-set counter above rather than a
    /// per-request `with_label_values` lookup.
    pub waf_blocked_sql_injection: IntCounter,
    pub waf_blocked_xss: IntCounter,
    pub waf_blocked_path_traversal: IntCounter,

    /// WebSocket/Upgrade proxying. Same fixed-outcome-set shape as the WAF
    /// counters above.
    pub websocket_upgrade_success: IntCounter,
    pub websocket_upgrade_backend_declined: IntCounter,
    pub websocket_upgrade_backend_unreachable: IntCounter,
}

/// The built-in WAF rule that matched a request -- see `lb_proxy::waf`.
/// Lives here, not in `lb-proxy`, for the same reason `StatusClass` does:
/// `lb-proxy` depends on `lb-metrics`, not the other way around, and every
/// metric label value in this codebase must come from a fixed, code-known
/// set (`Metrics::no_unbounded_label_names_are_exposed` enforces this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafRule {
    SqlInjection,
    Xss,
    PathTraversal,
}

impl WafRule {
    pub fn as_label(self) -> &'static str {
        match self {
            WafRule::SqlInjection => "sql_injection",
            WafRule::Xss => "xss",
            WafRule::PathTraversal => "path_traversal",
        }
    }
}

impl ListenerMetrics {
    /// Increments this listener's counter for whichever built-in rule
    /// matched. A plain dispatch, not a label lookup -- every handle is
    /// already resolved at listener-build time.
    pub fn record_waf_block(&self, rule: WafRule) {
        match rule {
            WafRule::SqlInjection => self.waf_blocked_sql_injection.inc(),
            WafRule::Xss => self.waf_blocked_xss.inc(),
            WafRule::PathTraversal => self.waf_blocked_path_traversal.inc(),
        }
    }
}

/// The terminal outcome of one WebSocket/`Upgrade` proxy attempt -- see
/// `lb_proxy::upgrade`. Lives here for the same reason `WafRule` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebsocketUpgradeResult {
    Success,
    BackendDeclined,
    BackendUnreachable,
}

impl WebsocketUpgradeResult {
    pub fn as_label(self) -> &'static str {
        match self {
            WebsocketUpgradeResult::Success => "success",
            WebsocketUpgradeResult::BackendDeclined => "backend_declined",
            WebsocketUpgradeResult::BackendUnreachable => "backend_unreachable",
        }
    }
}

impl ListenerMetrics {
    pub fn record_websocket_upgrade(&self, result: WebsocketUpgradeResult) {
        match result {
            WebsocketUpgradeResult::Success => self.websocket_upgrade_success.inc(),
            WebsocketUpgradeResult::BackendDeclined => {
                self.websocket_upgrade_backend_declined.inc()
            }
            WebsocketUpgradeResult::BackendUnreachable => {
                self.websocket_upgrade_backend_unreachable.inc()
            }
        }
    }
}

impl ListenerMetrics {
    /// Selects the counters for the version this request arrived on.
    ///
    /// A lookup into two already-resolved sets, not a label lookup — the
    /// `with_label_values` calls all happened once at startup.
    pub fn requests_for(&self, is_h2: bool) -> &RequestCounters {
        if is_h2 {
            &self.requests_h2
        } else {
            &self.requests_h1
        }
    }

    /// Records one completed request's status class under the counters for
    /// the HTTP version it arrived on.
    pub fn record_status(&self, is_h2: bool, class: StatusClass) {
        self.requests_for(is_h2).record(class);
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
