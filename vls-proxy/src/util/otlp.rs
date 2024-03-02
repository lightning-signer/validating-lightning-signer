#![cfg(feature = "opentelemetry_protocol")]

use std::time::Duration;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::{runtime, trace::{self, BatchConfig, Tracer}, Resource};
use opentelemetry_semantic_conventions::{resource::{
    DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION,
}, SCHEMA_URL};
use crate::GIT_DESC;
use super::{deployment_environment, otlp_timeout, otlp_endpoint};

/**
 * Create a Resource that captures information about the entity for which telemetry is recorded.
 */
pub fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, GIT_DESC),
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, deployment_environment()),
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

/** Initialize a tracer provider with the OTLP exporter and a batch span processor.*/
pub fn new_tracer() -> Result<Tracer, opentelemetry::trace::TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter().tonic().with_export_config(otlp_exporter_config()),
        )
        .with_trace_config(trace::config().with_resource(resource()))
        .with_batch_config(BatchConfig::default())
        .install_batch(runtime::Tokio)
}

#[cfg(test)]
mod tests {
    use opentelemetry::{global::ObjectSafeSpan, trace::{SpanBuilder, Tracer}, Value};
    use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};

    #[test]
    fn test_oltp_export_config() {
        let config = super::otlp_exporter_config();
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.timeout, std::time::Duration::from_secs(3));
        assert_eq!(config.protocol, opentelemetry_otlp::Protocol::Grpc);
    }

    #[test]
    fn test_resource() {
        let resource = super::resource();
        assert_eq!(resource.get(SERVICE_NAME), Some(Value::String(env!("CARGO_PKG_NAME").into())));
        assert_eq!(resource.get(SERVICE_VERSION), Some(Value::String(super::GIT_DESC.into())));
        assert_eq!(resource.get(super::DEPLOYMENT_ENVIRONMENT), Some(Value::String(super::deployment_environment().into())));
    }

    #[tokio::test]
    async fn test_new_tracer() {
        let tracer= super::new_tracer();
        match tracer {
            Ok(tracer) => {
                let mut _span = tracer.build(SpanBuilder::default());
                tracing::info!("tracer test");
                _span.end();
            },
            Err(err) => panic!("Failed to create tracer: {}", err)
        }
    }
}