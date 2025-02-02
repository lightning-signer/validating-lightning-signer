use super::{deployment_environment, otlp_endpoint, otlp_timeout};
use crate::GIT_DESC;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{ExportConfig, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{runtime, trace::TracerProvider as SdkTracerProvider, Resource};
use opentelemetry_semantic_conventions::{
    attribute::DEPLOYMENT_NAME,
    resource::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use std::time::Duration;

/**
 * Create a Resource that captures information about the entity for which telemetry is recorded.
 */
pub fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, GIT_DESC),
            KeyValue::new(DEPLOYMENT_NAME, deployment_environment()),
        ],
        SCHEMA_URL,
    )
}

/**
 * Create a ExportConfig that contains information about the exporter endpoint, timeout to collector and protocol
*/
pub fn otlp_exporter_config() -> ExportConfig {
    ExportConfig {
        endpoint: otlp_endpoint(),
        timeout: Duration::from_secs(otlp_timeout()),
        protocol: Protocol::Grpc,
    }
}

/** Initialize a tracer provider for OTLP with a batch span exporter.*/
pub fn new_tracer_provider() -> Result<SdkTracerProvider, opentelemetry::trace::TraceError> {
    let span_exporter =
        SpanExporter::builder().with_tonic().with_export_config(otlp_exporter_config()).build()?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter, runtime::Tokio)
        .with_resource(resource())
        .build())
}

#[cfg(test)]
mod tests {
    use opentelemetry::{
        global::ObjectSafeSpan,
        trace::{SpanBuilder, Tracer, TracerProvider as _},
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn test_new_tracer() {
        let tracer_provider = super::new_tracer_provider().unwrap();
        let mut _span = tracer_provider.tracer("test-tracer").build(SpanBuilder::default());
        tracing::info!("tracer test");
        _span.end();
    }
}
