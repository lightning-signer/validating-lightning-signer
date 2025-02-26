use std::error::Error;
use std::path::Path;

use tracing::Level;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;

use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "otlp")]
use crate::util::otlp::new_tracer_provider;
#[cfg(feature = "otlp")]
use opentelemetry::{global, trace::TracerProvider as _};
#[cfg(feature = "otlp")]
use tracing_opentelemetry::OpenTelemetryLayer;

/** create a non blocking tracing file appender with daily rolling */
pub fn setup_file_appender<P: AsRef<Path>>(datadir: P, who: &str) -> (NonBlocking, WorkerGuard) {
    let file_appender = rolling::never(datadir.as_ref(), format!("{}.log", who));

    tracing_appender::non_blocking(file_appender)
}

/** create a RUST_LOG env based log filter with default level set to info */
pub fn env_filter() -> EnvFilter {
    EnvFilter::builder().with_default_directive(Level::INFO.into()).from_env_lossy()
}

/**
 * Initialize tracing-subscriber with env filter based on RUST_LOG env variable.
 * fmt layer is used to print logs to stdout.
 * OpenTelemetryLayer is used to export logs to the configured OTLP endpoint.
 * fmt layer with custom writer is used to write logs to log file in datadir.
*/
pub fn init_tracing_subscriber<P: AsRef<Path>>(
    datadir: P,
    who: &str,
) -> Result<OtelGuard, Box<dyn Error>> {
    let (file_writer, file_guard) = setup_file_appender(datadir, who);

    let format = fmt::format()
        .with_level(true)
        .with_ansi(true)
        .with_target(false)
        .with_source_location(true)
        .compact();

    let stdout_layer = fmt::layer().event_format(format.clone()).with_writer(std::io::stdout);
    let file_layer = fmt::layer().event_format(format).with_writer(file_writer);
    let env_filter = env_filter();

    let default_subscriber =
        tracing_subscriber::registry().with(stdout_layer).with(file_layer).with(env_filter);

    #[cfg(feature = "otlp")]
    let default_subscriber = {
        let tracer = new_tracer_provider()?.tracer(who.to_string());
        let otlp_trace_layer = OpenTelemetryLayer::new(tracer);
        default_subscriber.with(otlp_trace_layer)
    };

    match default_subscriber.try_init() {
        Ok(_) => Ok(OtelGuard::new(file_guard)),
        Err(err) => Err(Box::new(err)),
    }
}

pub struct OtelGuard {
    _file_appender_guard: WorkerGuard,
}

impl OtelGuard {
    pub fn new(file_appender_guard: WorkerGuard) -> Self {
        Self { _file_appender_guard: file_appender_guard }
    }
}

impl Drop for OtelGuard {
    /** Shut down the current tracer provider. This will invoke the shutdown method on all span processors. Span processors should export remaining spans before return. */
    fn drop(&mut self) {
        #[cfg(feature = "otlp")]
        global::shutdown_tracer_provider();
    }
}

#[cfg(test)]
mod tests {
    use crate::util::observability::env_filter;
    use std::time::Duration;
    use tokio::time::sleep;
    use tracing_subscriber::{fmt, layer::SubscriberExt};

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

            tracing::subscriber::set_global_default(subscriber)
                .expect("setting default subscriber failed");

            tracing::info!("test random date: 11/08/2001");

            sleep(Duration::from_millis(10000)).await;
        });

        let _ = handle.await;

        assert_eq!(file_path.exists(), true);
        let contents = std::fs::read_to_string(&file_path).expect("failed to read file");
        assert_eq!(contents.contains("test random date: 11/08/2001"), true);
    }
}
