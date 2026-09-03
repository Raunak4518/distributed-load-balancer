mod handles;

pub use handles::{BackendMetrics, ListenerMetrics, StatusClass};

use prometheus::{
    exponential_buckets, Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
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
            Opts::new(
                "lb_active_connections",
                "Currently open client connections",
            ),
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
            HistogramOpts::new(
                "lb_upstream_duration_seconds",
                "Backend response duration",
            )
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
            ratelimit_rejected_local: self
                .ratelimit_rejected
                .with_label_values(&[name, "local"]),
            ratelimit_rejected_cluster: self
                .ratelimit_rejected
                .with_label_values(&[name, "cluster"]),
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
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            assert!(
                line.split_whitespace().count() >= 2,
                "malformed exposition line: {line}"
            );
        }
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
        let text = metrics.gather_text();

        const ALLOWED: [&str; 8] = [
            "listener", "protocol", "status", "backend", "outcome", "layer", "peer",
            // `le` is Prometheus's own histogram bucket-boundary label. It is
            // bounded by our bucket count (15), not client-derived.
            "le",
        ];
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(start) = line.find('{') else { continue };
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
