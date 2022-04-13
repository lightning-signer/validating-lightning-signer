use log::{LevelFilter, Metadata, Record};
#[cfg(target_arch = "wasm32")]
use web_sys;

struct SimpleLogger;

static LOGGER: SimpleLogger = SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("{} - {}", record.level(), record.args()).into());
            #[cfg(not(target_arch = "wasm32"))]
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub(crate) fn setup_log() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Info))
        .expect("create logger");
    debug!("Logging started");
}
