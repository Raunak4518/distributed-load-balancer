mod admin;
mod handles;

pub use admin::{spawn_admin_server, AdminExtension, ReadinessCheck};
pub use handles::{
    BackendMetrics, ListenerMetrics, RequestCounters, StatusClass, WafRule, WebsocketUpgradeResult,
};

/// Re-exported so consumer crates can hold metric handles without taking a
/// direct dependency on the metrics backend.
pub use prometheus::IntGauge;

use prometheus::{
    exponential_buckets, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

/// Process-wide metric families. Per-listener and per-backend handles are
/// resolved from these once, at wiring time.
pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration: HistogramVec,
    active_connections: IntGaugeVec,
    connections_total: IntCounterVec,
    ratelimit_rejected: IntCounterVec,
    backend_healthy: IntGaugeVec,
    backend_circuit_state: IntGaugeVec,
    backend_requests: IntCounterVec,
    upstream_duration: HistogramVec,
    pub cluster_peer_sync: IntCounterVec,
    pub cluster_tracked_keys: IntGauge,

    // Edge hardening (Phase 5)
    connections_rejected: IntCounterVec,
    request_timeouts: IntCounterVec,
    ratelimit_tracked_keys: IntGaugeVec,
    pub cluster_auth_failures: IntCounterVec,

    // TLS (Phase 6)
    tls_handshakes: IntCounterVec,
    tls_handshake_duration: HistogramVec,
    tls_certificate_reloads: IntCounterVec,
    tls_certificate_expiry_timestamp_seconds: IntGaugeVec,
    /// Public, and resolved at the call site rather than in `listener()`,
    /// because it must exist only for listeners that actually re-encrypt: a
    /// zero here on a plaintext-backend listener would read as "backend TLS
    /// is on and verifying", which is a lie a dashboard would repeat.
    pub backend_tls_verification_disabled: IntGaugeVec,

    // Response caching.
    cache_result: IntCounterVec,

    // WAF first slice.
    waf_blocked: IntCounterVec,

    // WebSocket / Upgrade proxying.
    websocket_upgrades: IntCounterVec,
}

/// Latency buckets from 1ms to ~16s. An edge load balancer cares about the
/// tail, so the buckets are dense where p99 lives rather than uniformly
/// spaced.
fn latency_buckets() -> Vec<f64> {
    exponential_buckets(0.001, 2.0, 15).expect("valid bucket parameters")
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("lb_requests_total", "Requests handled, by status class"),
            &["listener", "protocol", "status"],
        )?;
        let request_duration = HistogramVec::new(
            HistogramOpts::new("lb_request_duration_seconds", "End-to-end request duration")
                .buckets(latency_buckets()),
            &["listener"],
        )?;
        let active_connections = IntGaugeVec::new(
            Opts::new("lb_active_connections", "Currently open client connections"),
            &["listener"],
        )?;
        let connections_total = IntCounterVec::new(
            Opts::new("lb_connections_total", "Client connections accepted"),
            &["listener"],
        )?;
        let ratelimit_rejected = IntCounterVec::new(
            Opts::new(
                "lb_ratelimit_rejected_total",
                "Requests rejected by rate limiting, by layer",
            ),
            &["listener", "layer"],
        )?;
        let backend_healthy = IntGaugeVec::new(
            Opts::new(
                "lb_backend_healthy",
                "Backend health (1 healthy, 0 unhealthy)",
            ),
            &["listener", "backend"],
        )?;
        let backend_circuit_state = IntGaugeVec::new(
            Opts::new(
                "lb_backend_circuit_state",
                "Circuit breaker state (0 closed, 1 open, 2 half-open)",
            ),
            &["listener", "backend"],
        )?;
        let backend_requests = IntCounterVec::new(
            Opts::new(
                "lb_backend_requests_total",
                "Requests forwarded, by outcome",
            ),
            &["listener", "backend", "outcome"],
        )?;
        let upstream_duration = HistogramVec::new(
            HistogramOpts::new("lb_upstream_duration_seconds", "Backend response duration")
                .buckets(latency_buckets()),
            &["listener", "backend"],
        )?;
        let cluster_peer_sync = IntCounterVec::new(
            Opts::new(
                "lb_cluster_peer_sync_total",
                "Peer sync attempts, by outcome",
            ),
            &["peer", "outcome"],
        )?;
        let cluster_tracked_keys = IntGauge::new(
            "lb_cluster_tracked_keys",
            "Distinct rate-limit keys currently tracked",
        )?;
        let connections_rejected = IntCounterVec::new(
            Opts::new(
                "lb_connections_rejected_total",
                "Connections refused by a limit, by reason",
            ),
            &["listener", "reason"],
        )?;
        let request_timeouts = IntCounterVec::new(
            Opts::new(
                "lb_request_timeouts_total",
                "Requests aborted on a read timeout, by phase",
            ),
            &["listener", "phase"],
        )?;
        let ratelimit_tracked_keys = IntGaugeVec::new(
            Opts::new(
                "lb_ratelimit_tracked_keys",
                "Distinct rate-limit keys tracked by this listener",
            ),
            &["listener"],
        )?;
        let cluster_auth_failures = IntCounterVec::new(
            Opts::new(
                "lb_cluster_auth_failures_total",
                "Peer sync messages rejected for a bad authentication tag",
            ),
            &["peer"],
        )?;
        // `outcome` separates "we are being probed" (failed) from "clients
        // cannot finish" (timeout) from "our configuration is wrong" (no
        // successes at all) -- three incidents with three different fixes.
        // The set is fixed in code; the SNI hostname a client asked for is
        // deliberately absent, being entirely client-controlled.
        let tls_handshakes = IntCounterVec::new(
            Opts::new("lb_tls_handshakes_total", "TLS handshakes, by outcome"),
            &["listener", "outcome"],
        )?;
        // Handshake latency never shows up in request latency, because a
        // failed handshake never becomes a request. Shares the request
        // buckets so operators only have one bucket vocabulary to learn.
        let tls_handshake_duration = HistogramVec::new(
            HistogramOpts::new(
                "lb_tls_handshake_duration_seconds",
                "TLS handshake duration",
            )
            .buckets(latency_buckets()),
            &["listener"],
        )?;
        // outcome: applied | unchanged | rejected. A rising `rejected` means
        // renewal is broken while the certificate on disk quietly ages
        // toward expiry -- this is what turns that into a ticket instead of
        // a Sunday outage.
        let tls_certificate_reloads = IntCounterVec::new(
            Opts::new(
                "lb_tls_certificate_reloads_total",
                "Certificate reload attempts, by outcome",
            ),
            &["listener", "outcome"],
        )?;
        // Unix seconds of the leaf's notAfter. Alert on "< 14 days" and an
        // expiry becomes a ticket instead of an outage. `cert` is carried
        // alongside `listener` because two listeners could otherwise reuse
        // the same certificate name and clobber each other's gauge value.
        let tls_certificate_expiry_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "lb_tls_certificate_expiry_timestamp_seconds",
                "Unix timestamp of each certificate's notAfter",
            ),
            &["listener", "cert"],
        )?;

        // 1 when this listener forwards to backends without verifying their
        // certificates. Alert on it: traffic is encrypted but not
        // authenticated, which does not address the threat encryption is
        // there for.
        let backend_tls_verification_disabled = IntGaugeVec::new(
            Opts::new(
                "lb_backend_tls_verification_disabled",
                "1 when backend certificate verification is disabled for this listener",
            ),
            &["listener"],
        )?;
        let cache_result = IntCounterVec::new(
            Opts::new(
                "lb_cache_result_total",
                "Response cache outcomes, by result",
            ),
            &["listener", "result"],
        )?;
        let waf_blocked = IntCounterVec::new(
            Opts::new(
                "lb_waf_blocked_total",
                "Requests blocked or flagged by the built-in WAF rules, by rule",
            ),
            &["listener", "rule"],
        )?;
        let websocket_upgrades = IntCounterVec::new(
            Opts::new(
                "lb_websocket_upgrades_total",
                "WebSocket/Upgrade proxy attempts, by result",
            ),
            &["listener", "result"],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(connections_total.clone()))?;
        registry.register(Box::new(ratelimit_rejected.clone()))?;
        registry.register(Box::new(backend_healthy.clone()))?;
        registry.register(Box::new(backend_circuit_state.clone()))?;
        registry.register(Box::new(backend_requests.clone()))?;
        registry.register(Box::new(upstream_duration.clone()))?;
        registry.register(Box::new(cluster_peer_sync.clone()))?;
        registry.register(Box::new(cluster_tracked_keys.clone()))?;
        registry.register(Box::new(connections_rejected.clone()))?;
        registry.register(Box::new(request_timeouts.clone()))?;
        registry.register(Box::new(ratelimit_tracked_keys.clone()))?;
        registry.register(Box::new(cluster_auth_failures.clone()))?;
        registry.register(Box::new(tls_handshakes.clone()))?;
        registry.register(Box::new(tls_handshake_duration.clone()))?;
        registry.register(Box::new(tls_certificate_reloads.clone()))?;
        registry.register(Box::new(tls_certificate_expiry_timestamp_seconds.clone()))?;
        registry.register(Box::new(backend_tls_verification_disabled.clone()))?;
        registry.register(Box::new(cache_result.clone()))?;
        registry.register(Box::new(waf_blocked.clone()))?;
        registry.register(Box::new(websocket_upgrades.clone()))?;

        Ok(Metrics {
            registry,
            requests_total,
            request_duration,
            active_connections,
            connections_total,
            ratelimit_rejected,
            backend_healthy,
            backend_circuit_state,
            backend_requests,
            upstream_duration,
            cluster_peer_sync,
            cluster_tracked_keys,
            connections_rejected,
            request_timeouts,
            ratelimit_tracked_keys,
            cluster_auth_failures,
            tls_handshakes,
            tls_handshake_duration,
            tls_certificate_reloads,
            tls_certificate_expiry_timestamp_seconds,
            backend_tls_verification_disabled,
            cache_result,
            waf_blocked,
            websocket_upgrades,
        })
    }

    /// Resolves the four status-class counters for one listener and HTTP
    /// version. Called only from `listener()`, at startup.
    fn request_counters(&self, listener: &str, version: &str) -> RequestCounters {
        RequestCounters {
            c2xx: self
                .requests_total
                .with_label_values(&[listener, version, "2xx"]),
            c3xx: self
                .requests_total
                .with_label_values(&[listener, version, "3xx"]),
            c4xx: self
                .requests_total
                .with_label_values(&[listener, version, "4xx"]),
            c5xx: self
                .requests_total
                .with_label_values(&[listener, version, "5xx"]),
        }
    }

    /// Resolve one listener's handles. Called once per listener at startup —
    /// never on the request path.
    ///
    /// Both HTTP versions are always resolved, for every listener, using the
    /// literal version strings `"http1"`/`"http2"` — a TCP listener holds
    /// these like any other but simply never increments them, exactly as it
    /// never incremented the old undifferentiated counter: it counts
    /// connections, not requests. This keeps the request path a branch
    /// (`ListenerMetrics::requests_for`) instead of a protocol-conditional
    /// field set.
    pub fn listener(&self, name: &str) -> ListenerMetrics {
        ListenerMetrics {
            requests_h1: self.request_counters(name, "http1"),
            requests_h2: self.request_counters(name, "http2"),
            request_duration: self.request_duration.with_label_values(&[name]),
            active_connections: self.active_connections.with_label_values(&[name]),
            connections_total: self.connections_total.with_label_values(&[name]),
            ratelimit_rejected_local: self.ratelimit_rejected.with_label_values(&[name, "local"]),
            ratelimit_rejected_cluster: self
                .ratelimit_rejected
                .with_label_values(&[name, "cluster"]),
            connections_rejected_max: self
                .connections_rejected
                .with_label_values(&[name, "max_connections"]),
            connections_rejected_per_ip: self
                .connections_rejected
                .with_label_values(&[name, "max_per_ip"]),
            timeouts_header: self.request_timeouts.with_label_values(&[name, "header"]),
            timeouts_body: self.request_timeouts.with_label_values(&[name, "body"]),
            tracked_keys: self.ratelimit_tracked_keys.with_label_values(&[name]),
            tls_handshakes_success: self.tls_handshakes.with_label_values(&[name, "success"]),
            tls_handshakes_failed: self.tls_handshakes.with_label_values(&[name, "failed"]),
            tls_handshakes_timeout: self.tls_handshakes.with_label_values(&[name, "timeout"]),
            tls_handshake_duration: self.tls_handshake_duration.with_label_values(&[name]),
            tls_certificate_reloads_applied: self
                .tls_certificate_reloads
                .with_label_values(&[name, "applied"]),
            tls_certificate_reloads_unchanged: self
                .tls_certificate_reloads
                .with_label_values(&[name, "unchanged"]),
            tls_certificate_reloads_rejected: self
                .tls_certificate_reloads
                .with_label_values(&[name, "rejected"]),
            // A clone, not a resolved handle: `IntGaugeVec::clone()` shares
            // the same underlying series storage, so this is cheap, and the
            // set of certificate names is not known until the reloader
            // reads its config.
            tls_certificate_expiry_timestamp_seconds: self
                .tls_certificate_expiry_timestamp_seconds
                .clone(),
            cache_hit: self.cache_result.with_label_values(&[name, "hit"]),
            cache_miss: self.cache_result.with_label_values(&[name, "miss"]),
            waf_blocked_sql_injection: self
                .waf_blocked
                .with_label_values(&[name, WafRule::SqlInjection.as_label()]),
            waf_blocked_xss: self
                .waf_blocked
                .with_label_values(&[name, WafRule::Xss.as_label()]),
            waf_blocked_path_traversal: self
                .waf_blocked
                .with_label_values(&[name, WafRule::PathTraversal.as_label()]),
            websocket_upgrade_success: self
                .websocket_upgrades
                .with_label_values(&[name, WebsocketUpgradeResult::Success.as_label()]),
            websocket_upgrade_backend_declined: self
                .websocket_upgrades
                .with_label_values(&[name, WebsocketUpgradeResult::BackendDeclined.as_label()]),
            websocket_upgrade_backend_unreachable: self
                .websocket_upgrades
                .with_label_values(&[name, WebsocketUpgradeResult::BackendUnreachable.as_label()]),
        }
    }

    /// Resolve one backend's handles. Called once per backend at startup.
    pub fn backend(&self, listener: &str, backend: &str) -> BackendMetrics {
        BackendMetrics {
            healthy: self.backend_healthy.with_label_values(&[listener, backend]),
            circuit_state: self
                .backend_circuit_state
                .with_label_values(&[listener, backend]),
            requests_success: self
                .backend_requests
                .with_label_values(&[listener, backend, "success"]),
            requests_failure: self
                .backend_requests
                .with_label_values(&[listener, backend, "failure"]),
            requests_timeout: self
                .backend_requests
                .with_label_values(&[listener, backend, "timeout"]),
            upstream_duration: self
                .upstream_duration
                .with_label_values(&[listener, backend]),
        }
    }

    /// Prometheus text exposition format.
    pub fn gather_text(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        if encoder.encode(&self.registry.gather(), &mut buf).is_err() {
            return String::new();
        }
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classes_map_correctly() {
        assert_eq!(StatusClass::from_code(200).as_label(), "2xx");
        assert_eq!(StatusClass::from_code(301).as_label(), "3xx");
        assert_eq!(StatusClass::from_code(429).as_label(), "4xx");
        assert_eq!(StatusClass::from_code(502).as_label(), "5xx");
    }

    #[test]
    fn recording_a_request_shows_up_in_exposition() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web");
        listener.record_status(false, StatusClass::Success);
        listener.record_status(false, StatusClass::ServerError);

        let text = metrics.gather_text();
        assert!(
            text.contains(r#"status="2xx"} 1"#),
            "expected a 2xx count of 1 in:\n{text}"
        );
        assert!(
            text.contains(r#"status="5xx"} 1"#),
            "expected a 5xx count of 1 in:\n{text}"
        );
    }

    #[test]
    fn rate_limit_layers_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web");
        listener.ratelimit_rejected_local.inc();
        listener.ratelimit_rejected_cluster.inc();
        listener.ratelimit_rejected_cluster.inc();

        let text = metrics.gather_text();
        assert!(
            text.contains(r#"lb_ratelimit_rejected_total{layer="local",listener="web"} 1"#),
            "expected local=1 in:\n{text}"
        );
        assert!(
            text.contains(r#"lb_ratelimit_rejected_total{layer="cluster",listener="web"} 2"#),
            "expected cluster=2 in:\n{text}"
        );
    }

    #[test]
    fn waf_rules_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web");
        listener.record_waf_block(WafRule::SqlInjection);
        listener.record_waf_block(WafRule::Xss);
        listener.record_waf_block(WafRule::Xss);
        listener.record_waf_block(WafRule::PathTraversal);

        let text = metrics.gather_text();
        assert!(
            text.contains(r#"lb_waf_blocked_total{listener="web",rule="sql_injection"} 1"#),
            "expected sql_injection=1 in:\n{text}"
        );
        assert!(
            text.contains(r#"lb_waf_blocked_total{listener="web",rule="xss"} 2"#),
            "expected xss=2 in:\n{text}"
        );
        assert!(
            text.contains(r#"lb_waf_blocked_total{listener="web",rule="path_traversal"} 1"#),
            "expected path_traversal=1 in:\n{text}"
        );
    }

    #[test]
    fn websocket_upgrade_outcomes_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let listener = metrics.listener("web");
        listener.record_websocket_upgrade(WebsocketUpgradeResult::Success);
        listener.record_websocket_upgrade(WebsocketUpgradeResult::Success);
        listener.record_websocket_upgrade(WebsocketUpgradeResult::BackendDeclined);
        listener.record_websocket_upgrade(WebsocketUpgradeResult::BackendUnreachable);

        let text = metrics.gather_text();
        assert!(
            text.contains(r#"lb_websocket_upgrades_total{listener="web",result="success"} 2"#),
            "expected success=2 in:\n{text}"
        );
        assert!(
            text.contains(
                r#"lb_websocket_upgrades_total{listener="web",result="backend_declined"} 1"#
            ),
            "expected backend_declined=1 in:\n{text}"
        );
        assert!(
            text.contains(
                r#"lb_websocket_upgrades_total{listener="web",result="backend_unreachable"} 1"#
            ),
            "expected backend_unreachable=1 in:\n{text}"
        );
    }

    #[test]
    fn backend_handles_record_health_and_outcomes() {
        let metrics = Metrics::new().unwrap();
        let backend = metrics.backend("web", "b1");
        backend.healthy.set(1);
        backend.requests_success.inc();
        backend.requests_timeout.inc();

        let text = metrics.gather_text();
        assert!(text.contains(r#"lb_backend_healthy{backend="b1",listener="web"} 1"#));
        assert!(text.contains(r#"outcome="success""#));
        assert!(text.contains(r#"outcome="timeout""#));
    }

    #[test]
    fn exposition_is_valid_prometheus_text_format() {
        let metrics = Metrics::new().unwrap();
        metrics
            .listener("web")
            .record_status(false, StatusClass::Success);
        let text = metrics.gather_text();

        // Every metric family carries HELP and TYPE lines, and no line is
        // malformed (a bare label brace would break scraping).
        assert!(text.contains("# HELP lb_requests_total"));
        assert!(text.contains("# TYPE lb_requests_total counter"));
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            assert!(
                line.split_whitespace().count() >= 2,
                "malformed exposition line: {line}"
            );
        }
    }

    #[test]
    fn edge_hardening_metrics_are_exposed() {
        let metrics = Metrics::new().unwrap();
        let l = metrics.listener("web");
        l.connections_rejected_max.inc();
        l.connections_rejected_per_ip.inc();
        l.connections_rejected_per_ip.inc();
        l.timeouts_header.inc();
        l.timeouts_body.inc();
        l.tracked_keys.set(7);
        metrics
            .cluster_auth_failures
            .with_label_values(&["10.0.0.9:7946"])
            .inc();

        let text = metrics.gather_text();
        assert!(text.contains(r#"reason="max_connections""#));
        assert!(text.contains(r#"reason="max_per_ip""#));
        assert!(text.contains(r#"phase="header""#));
        assert!(text.contains(r#"phase="body""#));
        assert!(text.contains(r#"lb_ratelimit_tracked_keys{listener="web"} 7"#));
        assert!(text.contains("lb_cluster_auth_failures_total"));
    }

    /// A rising `rejected` count means renewal is broken while the
    /// certificate on disk quietly ages toward expiry -- this is the signal
    /// that turns that into a ticket instead of a Sunday outage. The expiry
    /// gauge is the other half: `cert` genuinely varies per certificate, so
    /// it carries both `listener` and `cert` labels (two listeners could
    /// otherwise reuse the same certificate name and clobber each other's
    /// gauge value).
    #[test]
    fn tls_certificate_reload_and_expiry_metrics_are_exposed() {
        let metrics = Metrics::new().unwrap();
        let l = metrics.listener("web");
        l.tls_certificate_reloads_applied.inc();
        l.tls_certificate_reloads_unchanged.inc();
        l.tls_certificate_reloads_unchanged.inc();
        l.tls_certificate_reloads_rejected.inc();
        l.tls_certificate_expiry_timestamp_seconds
            .with_label_values(&["web", "primary"])
            .set(1_893_456_000);

        let text = metrics.gather_text();
        assert!(
            text.contains(
                r#"lb_tls_certificate_reloads_total{listener="web",outcome="applied"} 1"#
            ),
            "expected applied=1 in:\n{text}"
        );
        assert!(
            text.contains(
                r#"lb_tls_certificate_reloads_total{listener="web",outcome="unchanged"} 2"#
            ),
            "expected unchanged=2 in:\n{text}"
        );
        assert!(
            text.contains(
                r#"lb_tls_certificate_reloads_total{listener="web",outcome="rejected"} 1"#
            ),
            "expected rejected=1 in:\n{text}"
        );
        assert!(
            text.contains(
                r#"lb_tls_certificate_expiry_timestamp_seconds{cert="primary",listener="web"} 1893456000"#
            ),
            "expected the expiry gauge in:\n{text}"
        );
    }

    /// Separating the three outcomes is the whole point of the metric: a
    /// spike in `failed` means we are being probed, a spike in `timeout`
    /// means clients cannot finish, and a flatline in `success` while the
    /// port is busy means the configuration is wrong. Three incidents, three
    /// different fixes.
    #[test]
    fn tls_handshake_outcomes_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let l = metrics.listener("web");
        l.tls_handshakes_success.inc();
        l.tls_handshakes_failed.inc();
        l.tls_handshakes_failed.inc();
        l.tls_handshakes_timeout.inc();
        l.tls_handshake_duration.observe(0.012);

        let text = metrics.gather_text();
        assert!(
            text.contains(r#"lb_tls_handshakes_total{listener="web",outcome="success"} 1"#),
            "expected success=1 in:
{text}"
        );
        assert!(
            text.contains(r#"lb_tls_handshakes_total{listener="web",outcome="failed"} 2"#),
            "expected failed=2 in:
{text}"
        );
        assert!(
            text.contains(r#"lb_tls_handshakes_total{listener="web",outcome="timeout"} 1"#),
            "expected timeout=1 in:
{text}"
        );
        assert!(
            text.contains(r#"lb_tls_handshake_duration_seconds_count{listener="web"} 1"#),
            "expected one handshake duration observation in:
{text}"
        );
    }

    /// `danger_accept_invalid_certs` must be visible on a dashboard rather
    /// than living undiscovered in a config file, which means the series has
    /// to exist and read zero on a listener that does verify -- a gap and a
    /// zero look identical to an alert otherwise.
    #[test]
    fn the_backend_verification_gauge_reports_both_states() {
        let metrics = Metrics::new().unwrap();
        metrics
            .backend_tls_verification_disabled
            .with_label_values(&["dangerous"])
            .set(1);
        metrics
            .backend_tls_verification_disabled
            .with_label_values(&["strict"])
            .set(0);
        let text = metrics.gather_text();
        assert!(
            text.contains(r#"lb_backend_tls_verification_disabled{listener="dangerous"} 1"#),
            "missing the disabled series in:\n{text}"
        );
        assert!(
            text.contains(r#"lb_backend_tls_verification_disabled{listener="strict"} 0"#),
            "missing the flat-zero series in:\n{text}"
        );
    }

    /// The `protocol` label on `lb_requests_total` used to carry the
    /// listener's kind (always "http" for this metric, since TCP listeners
    /// never increment it). It now carries the HTTP version instead, so
    /// "is anyone actually using h2" is answerable from an existing counter
    /// rather than a new one.
    #[test]
    fn request_counters_are_separated_by_http_version() {
        let metrics = Metrics::new().unwrap();
        let m = metrics.listener("web");

        m.requests_for(false).c2xx.inc();
        m.requests_for(true).c2xx.inc();
        m.requests_for(true).c5xx.inc();

        let body = metrics.gather_text();
        assert!(
            body.contains(r#"lb_requests_total{listener="web",protocol="http1",status="2xx"} 1"#),
            "missing http1 2xx series:\n{body}"
        );
        assert!(
            body.contains(r#"lb_requests_total{listener="web",protocol="http2",status="2xx"} 1"#),
            "missing http2 2xx series:\n{body}"
        );
        assert!(
            body.contains(r#"lb_requests_total{listener="web",protocol="http2",status="5xx"} 1"#),
            "missing http2 5xx series:\n{body}"
        );
    }

    /// Encodes spec section 2.3 as an executable rule: every label name in the
    /// exposition must come from a known, config-derived set. A client IP or
    /// path label would explode Prometheus's series count.
    #[test]
    fn no_unbounded_label_names_are_exposed() {
        let metrics = Metrics::new().unwrap();
        metrics
            .listener("web")
            .record_status(false, StatusClass::Success);
        metrics.backend("web", "b1").healthy.set(1);
        metrics
            .cluster_peer_sync
            .with_label_values(&["10.0.0.2:7946", "ok"])
            .inc();
        metrics
            .cluster_auth_failures
            .with_label_values(&["10.0.0.2:7946"])
            .inc();
        let hardening = metrics.listener("web");
        hardening.connections_rejected_max.inc();
        hardening.connections_rejected_per_ip.inc();
        hardening.timeouts_header.inc();
        hardening.timeouts_body.inc();
        hardening.tracked_keys.set(42);
        let tls = metrics.listener("web");
        tls.tls_handshakes_success.inc();
        tls.tls_handshakes_failed.inc();
        tls.tls_handshakes_timeout.inc();
        tls.tls_handshake_duration.observe(0.01);
        tls.tls_certificate_reloads_applied.inc();
        tls.tls_certificate_reloads_unchanged.inc();
        tls.tls_certificate_reloads_rejected.inc();
        tls.tls_certificate_expiry_timestamp_seconds
            .with_label_values(&["web", "primary"])
            .set(1_893_456_000);
        metrics
            .backend_tls_verification_disabled
            .with_label_values(&["web"])
            .set(1);
        let text = metrics.gather_text();

        const ALLOWED: [&str; 13] = [
            "listener", "protocol", "status", "backend", "outcome", "layer", "peer",
            // Phase 5: both drawn from fixed sets in the code, never input.
            "reason", "phase",
            // `le` is Prometheus's own histogram bucket-boundary label. It is
            // bounded by our bucket count (15), not client-derived.
            "le",
            // Phase 6: an operator-chosen name from `[[listeners.tls.certificates]]`,
            // never client-controlled -- unlike the SNI hostname, which is
            // deliberately not a label anywhere.
            "cert",
            // Response caching: always exactly "hit" or "miss", drawn from
            // the code, never from a cached key or client-supplied header.
            "result",
            // WAF first slice: always one of a fixed, built-in rule set
            // (`WafRule::as_label`), never the matched text or client input.
            "rule",
        ];
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(start) = line.find('{') else {
                continue;
            };
            let Some(end) = line.find('}') else { continue };
            for pair in line[start + 1..end].split(',') {
                let Some(name) = pair.split('=').next() else {
                    continue;
                };
                assert!(
                    ALLOWED.contains(&name.trim()),
                    "unexpected metric label '{name}' — client-derived labels are forbidden"
                );
            }
        }
    }
}
