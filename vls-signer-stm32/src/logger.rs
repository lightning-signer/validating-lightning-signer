use core::cell::RefCell;
use log::{info, trace, Level, Metadata, Record};
use rtt_target::{rprint, rprintln, rtt_init_print};

struct SimpleLogger {
    timer: RefCell<Option<FreeTimer>>,
}

unsafe impl Sync for SimpleLogger {}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        #[cfg(feature = "trace")]
        let res = metadata.level() <= Level::Trace;
        #[cfg(feature = "debug")]
        let res = metadata.level() <= Level::Debug;
        #[cfg(all(not(feature = "debug"), not(feature = "trace")))]
        let res = metadata.level() <= Level::Info;
        res
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timer_ref = self.timer.borrow();
            if let Some(timer) = timer_ref.as_ref() {
                rprint!("{} ", timer.now().duration_since_epoch().to_millis());
            }
            rprintln!("{} {} - {}", record.target(), record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

use crate::device::FreeTimer;
use log::{LevelFilter, SetLoggerError};

static LOGGER: SimpleLogger = SimpleLogger { timer: RefCell::new(None) };

pub fn init() -> Result<(), SetLoggerError> {
    rtt_init_print!(BlockIfFull);
    rprintln!("demo_signer starting");
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))?;
    trace!("logger started");
    info!("logger started");
    Ok(())
}

pub fn set_timer(timer: FreeTimer) {
    *LOGGER.timer.borrow_mut() = Some(timer);
}
