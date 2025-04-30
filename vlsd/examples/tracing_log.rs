use std::{thread::sleep, time::Duration};

use tracing::{error, info};
use vls_util::observability::{init_tracing_subscriber, OtelGuard};

#[tokio::main]
async fn main() {
    let datadir = "/tmp".to_string();
    let bin_name = "otlp_sample".to_string();

    let tracing_result = init_tracing_subscriber(&datadir, &bin_name);
    let _guard: Option<OtelGuard>;
    match tracing_result {
        Ok(otel_guard) => _guard = Some(otel_guard),
        Err(e) => error!("error during tracing init {}", e),
    }

    tracing::event!(tracing::Level::INFO, "Hello");

    foo().await;
}

#[tracing::instrument]
async fn foo() {
    info!(monotonic_counter.foo = 1_u64, key_1 = "bar", key_2 = 10, "handle foo",);

    info!(histogram.baz = 10, "histogram example");

    sleep(Duration::from_millis(500));

    log::info!("info log");
}
