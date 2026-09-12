//! Subscriber setup for `lb-server`: structured logs (always) plus
//! OpenTelemetry trace export (only when `[tracing]` is configured).
//!
//! Spans are created unconditionally by the data-plane crates -- that cost
//! is what `tracing` is built to make cheap when nothing is listening. This
//! crate is the one place that knows whether anything actually is.
mod http;

use lb_core::{LogFormat, LoggingConfig, TracingConfig};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Bounds the OTLP export POST -- the same role `forward_timeout_ms` plays
/// for proxied requests, just for the telemetry side channel instead.
const EXPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Held for the process lifetime; `shutdown` flushes whatever span batch is
/// still buffered. OTel's exporters do not flush on `Drop` -- an unflushed
/// batch at process exit is just lost, silently.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl TracingGuard {
    pub fn shutdown(self) {
        if let Some(provider) = self.provider {
            if let Err(err) = provider.shutdown() {
                eprintln!("failed to flush trace export on shutdown: {err}");
            }
        }
    }
}

pub fn init(
    logging: &LoggingConfig,
    tracing_cfg: Option<&TracingConfig>,
) -> Result<TracingGuard, String> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = match logging.format {
        LogFormat::Json => tracing_subscriber::fmt::layer().json().boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer().pretty().boxed(),
    };

    let (otel_layer, provider) = match tracing_cfg {
        Some(cfg) => {
            let (layer, provider) = build_otel_layer(cfg)?;
            (Some(layer), Some(provider))
        }
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    Ok(TracingGuard { provider })
}

fn build_otel_layer<S>(
    cfg: &TracingConfig,
) -> Result<
    (
        tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>,
        SdkTracerProvider,
    ),
    String,
>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&cfg.otlp_endpoint)
        .with_http_client(http::BlockingHttpClient::new(EXPORT_TIMEOUT))
        .build()
        .map_err(|err| format!("failed to build the OTLP exporter: {err}"))?;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(cfg.service_name.clone().unwrap_or_else(|| "lb-server".into()))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(cfg.sample_ratio))
        .build();

    let tracer = provider.tracer("lb-server");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok((layer, provider))
}
