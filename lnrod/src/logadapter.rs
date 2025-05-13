use log;

use lightning::util::logger;
use lightning_signer::{lightning, SendSync};

use lightning_signer::node::SyncLogger;

// Convert an LDK log level to log::Level.
pub fn convert_to_log_level(lvl: logger::Level) -> log::Level {
    match lvl {
        logger::Level::Error => log::Level::Error,
        logger::Level::Warn => log::Level::Warn,
        logger::Level::Info => log::Level::Info,
        logger::Level::Debug => log::Level::Debug,
        logger::Level::Trace => log::Level::Trace,
        logger::Level::Gossip => log::Level::Trace,
    }
}

pub struct LoggerAdapter {}

impl logger::Logger for LoggerAdapter {
    fn log(&self, rec: logger::Record) {
        let record = log::Record::builder()
            .args(rec.args)
            .level(convert_to_log_level(rec.level))
            .file(Some(rec.file))
            .line(Some(rec.line))
            .module_path(Some(rec.module_path))
            .build();
        log::logger().log(&record);
    }
}

impl SendSync for LoggerAdapter {}
impl SyncLogger for LoggerAdapter {}

impl LoggerAdapter {
    pub fn new() -> LoggerAdapter {
        LoggerAdapter {}
    }
}
