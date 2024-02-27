use std::error::Error;
use std::path::Path;

use tracing::Level;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;

use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "opentelemetry_protocol")]
use std::time::Duration;
#[cfg(feature = "opentelemetry_protocol")]
use opentelemetry::{KeyValue, global};
#[cfg(feature = "opentelemetry_protocol")]
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
#[cfg(feature = "opentelemetry_protocol")]
use opentelemetry_sdk::{runtime, trace::{self, BatchConfig, Tracer}, Resource};
#[cfg(feature = "opentelemetry_protocol")]
use opentelemetry_semantic_conventions::{resource::{
    DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION,
}, SCHEMA_URL};
#[cfg(feature = "opentelemetry_protocol")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(feature = "opentelemetry_protocol")]
use crate::GIT_DESC;
#[cfg(feature = "opentelemetry_protocol")]
use super::{deployment_environment, otlp_timeout, otlp_endpoint};

/**
 * Create a Resource that captures information about the entity for which telemetry is recorded.
 */
#[cfg(feature = "opentelemetry_protocol")]
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
#[cfg(feature = "opentelemetry_protocol")]
pub fn otlp_exporter_config() -> ExportConfig {
    ExportConfig {
        endpoint: otlp_endpoint(),
        timeout: Duration::from_secs(otlp_timeout()),
        protocol: Protocol::Grpc,
    }
}

/** Initialize a tracer provider with the OTLP exporter and a batch span processor.*/
#[cfg(feature = "opentelemetry_protocol")]
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

/** create a non blocking tracing file appender with daily rolling */
pub fn setup_file_appender<P: AsRef<Path>>(datadir: P, who: &str) -> (NonBlocking, WorkerGuard) {
    let file_appender = rolling::never(
        datadir.as_ref(),
        format!("{}.log", who),
    );

    tracing_appender::non_blocking(file_appender)
}

/** create a RUST_LOG env based log filter with default level set to info */
pub fn env_filter() -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy()
}

/**
 * Initialize tracing-subscriber with env filter based on RUST_LOG env variable.
 * fmt layer is used to print logs to stdout.
 * OpenTelemetryLayer is used to export logs to the configured OTLP endpoint.
 * fmt layer with custom writer is used to write logs to log file in datadir.
*/
pub fn init_tracing_subscriber<P: AsRef<Path>>(datadir: P, who: &str) -> Result<OtelGuard, Box<dyn Error>> {
    #[cfg(feature = "opentelemetry_protocol")]
    let tracer = new_tracer()?;
    let (file_writer, file_guard) = setup_file_appender(datadir, who);

    let stdout_layer = fmt::layer().with_writer(std::io::stdout);
    let file_layer = fmt::layer().with_writer(file_writer);
    let env_filter = env_filter();

    #[cfg(feature = "opentelemetry_protocol")]
    let otlp_layer = Some(OpenTelemetryLayer::new(tracer));

    #[cfg(not(feature = "opentelemetry_protocol"))]
    let default_subscriber = tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .with(env_filter);

    #[cfg(feature = "opentelemetry_protocol")]
    let default_subscriber = tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .with(env_filter)
        .with(otlp_layer);

    match default_subscriber
        .try_init() {
            Ok(_) => Ok(OtelGuard::new(file_guard)),
            Err(err) => Err(Box::new(err))
        }
}

pub struct OtelGuard {
    _file_appender_guard: WorkerGuard
}

impl OtelGuard {
    pub fn new(file_appender_guard: WorkerGuard) -> Self {
        Self { _file_appender_guard: file_appender_guard }
    }
}

impl Drop for OtelGuard {
    /** Shut down the current tracer provider. This will invoke the shutdown method on all span processors. Span processors should export remaining spans before return. */
    fn drop(&mut self) {
        #[cfg(feature = "opentelemetry_protocol")]
        global::shutdown_tracer_provider();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "opentelemetry_protocol")]
    use opentelemetry::{global::ObjectSafeSpan, trace::{SpanBuilder, Tracer}, Value};
    #[cfg(feature = "opentelemetry_protocol")]
    use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};

    use std::time::Duration;
    use tokio::time::sleep;
    use tracing_subscriber::{fmt, layer::SubscriberExt};
    use crate::util::observability::env_filter;

    #[test]
    #[cfg(feature = "opentelemetry_protocol")]
    fn test_oltp_export_config() {
        let config = super::otlp_exporter_config();
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.timeout, std::time::Duration::from_secs(3));
        assert_eq!(config.protocol, opentelemetry_otlp::Protocol::Grpc);
    }

    #[test]
    #[cfg(feature = "opentelemetry_protocol")]
    fn test_resource() {
        let resource = super::resource();
        assert_eq!(resource.get(SERVICE_NAME), Some(Value::String(env!("CARGO_PKG_NAME").into())));
        assert_eq!(resource.get(SERVICE_VERSION), Some(Value::String(super::GIT_DESC.into())));
        assert_eq!(resource.get(super::DEPLOYMENT_ENVIRONMENT), Some(Value::String(super::deployment_environment().into())));
    }

    #[cfg(feature = "opentelemetry_protocol")]
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

    #[tokio::test]
    async fn test_setup_file_appender() {
        std::env::set_var("RUST_LOG", "info");

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test.log"));

        let handle = tokio::spawn(async move {
            let (file_writer, _file_guard) = super::setup_file_appender(temp_dir, "test");

            let subscriber = tracing_subscriber::registry()
                .with(fmt::layer().with_writer(file_writer))
                .with(env_filter());

            tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

            tracing::info!("test random date: 11/08/2001");

            sleep(Duration::from_millis(10000)).await;
        });

        let _ = handle.await;

        assert_eq!(file_path.exists(), true);
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        assert_eq!(contents.contains("test random date: 11/08/2001"), true);
    }
}
