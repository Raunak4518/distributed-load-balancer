mod admin;
mod handles;

pub use admin::{spawn_admin_server, ReadinessCheck};
pub use handles::{BackendMetrics, ListenerMetrics, StatusClass};

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
        })
    }

    /// Resolve one listener's handles. Called once per listener at startup —
    /// never on the request path.
    pub fn listener(&self, name: &str, protocol: &str) -> ListenerMetrics {
        ListenerMetrics {
            requests_2xx: self
                .requests_total
                .with_label_values(&[name, protocol, "2xx"]),
            requests_3xx: self
                .requests_total
                .with_label_values(&[name, protocol, "3xx"]),
            requests_4xx: self
                .requests_total
                .with_label_values(&[name, protocol, "4xx"]),
            requests_5xx: self
                .requests_total
                .with_label_values(&[name, protocol, "5xx"]),
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
        let listener = metrics.listener("web", "http");
        listener.record_status(StatusClass::Success);
        listener.record_status(StatusClass::ServerError);

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
        let listener = metrics.listener("web", "http");
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
            .listener("web", "http")
            .record_status(StatusClass::Success);
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
        let l = metrics.listener("web", "http");
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

    /// Separating the three outcomes is the whole point of the metric: a
    /// spike in `failed` means we are being probed, a spike in `timeout`
    /// means clients cannot finish, and a flatline in `success` while the
    /// port is busy means the configuration is wrong. Three incidents, three
    /// different fixes.
    #[test]
    fn tls_handshake_outcomes_are_counted_separately() {
        let metrics = Metrics::new().unwrap();
        let l = metrics.listener("web", "http");
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

    /// Encodes spec section 2.3 as an executable rule: every label name in the
    /// exposition must come from a known, config-derived set. A client IP or
    /// path label would explode Prometheus's series count.
    #[test]
    fn no_unbounded_label_names_are_exposed() {
        let metrics = Metrics::new().unwrap();
        metrics
            .listener("web", "http")
            .record_status(StatusClass::Success);
        metrics.backend("web", "b1").healthy.set(1);
        metrics
            .cluster_peer_sync
            .with_label_values(&["10.0.0.2:7946", "ok"])
            .inc();
        metrics
            .cluster_auth_failures
            .with_label_values(&["10.0.0.2:7946"])
            .inc();
        let hardening = metrics.listener("web", "http");
        hardening.connections_rejected_max.inc();
        hardening.connections_rejected_per_ip.inc();
        hardening.timeouts_header.inc();
        hardening.timeouts_body.inc();
        hardening.tracked_keys.set(42);
        let tls = metrics.listener("web", "http");
        tls.tls_handshakes_success.inc();
        tls.tls_handshakes_failed.inc();
        tls.tls_handshakes_timeout.inc();
        tls.tls_handshake_duration.observe(0.01);
        let text = metrics.gather_text();

        const ALLOWED: [&str; 10] = [
            "listener", "protocol", "status", "backend", "outcome", "layer", "peer",
            // Phase 5: both drawn from fixed sets in the code, never input.
            "reason", "phase",
            // `le` is Prometheus's own histogram bucket-boundary label. It is
            // bounded by our bucket count (15), not client-derived.
            "le",
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
