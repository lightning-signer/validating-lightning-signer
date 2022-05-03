use log::{info, trace, Level, Metadata, Record};
use rtt_target::{rprintln, rtt_init_print};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        #[cfg(feature = "trace")]
        let res = metadata.level() <= Level::Trace;
        #[cfg(not(feature = "trace"))]
        let res = metadata.level() <= Level::Debug;
        res
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            rprintln!("{} {} - {}", record.target(), record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

use log::{LevelFilter, SetLoggerError};

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init() -> Result<(), SetLoggerError> {
    rtt_init_print!(BlockIfFull);
    rprintln!("demo_signer starting");
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))?;
    trace!("logger started");
    info!("logger started");
    Ok(())
}
