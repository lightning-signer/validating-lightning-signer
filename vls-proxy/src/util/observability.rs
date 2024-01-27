use std::error::Error;
use std::path::Path;
use std::time::Duration;

use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use opentelemetry_sdk::trace::{self, Tracer};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::{runtime, trace::BatchConfig};
use opentelemetry_semantic_conventions::resource::{
    DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION,
};
use opentelemetry_semantic_conventions::SCHEMA_URL;
use tracing::Level;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
 * Create a ExportConfig that contains information about the exporter endpoint, timeout to collector and protocol.*/
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

/** create a non blocking tracing file appender with daily rolling */
pub fn setup_file_appender<P: AsRef<Path>>(datadir: P, who: &str) -> (NonBlocking, WorkerGuard) {
    let file_appender = rolling::daily(
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
 * */
pub fn init_tracing_subscriber<P: AsRef<Path>>(datadir: P, who: &str) -> Result<OtelGuard, Box<dyn Error>> {
    let tracer = new_tracer()?;
    let (file_writer, file_guard) = setup_file_appender(datadir, who);

    let stdout_layer = fmt::layer().with_writer(std::io::stdout);
    let file_layer = fmt::layer().with_writer(file_writer);
    let env_filter = env_filter();
    let otlp_layer = OpenTelemetryLayer::new(tracer);

    match tracing_subscriber::registry()
        .with(stdout_layer)
        .with(file_layer)
        .with(otlp_layer)
        .with(env_filter)
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
        global::shutdown_tracer_provider();
    }
}
