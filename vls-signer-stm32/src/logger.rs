use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use log::{info, trace, Level, Metadata, Record};
use rtt_target::{rprint, rprintln, rtt_init_print};

struct SimpleLogger {
    timer: RefCell<Option<FreeTimer>>,
    also: RefCell<Vec<Box<dyn log::Log>>>,
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

        for lgr in &*self.also.borrow() {
            lgr.log(record);
        }
    }

    fn flush(&self) {}
}

use crate::device::FreeTimer;
use log::{LevelFilter, SetLoggerError};

static LOGGER: SimpleLogger =
    SimpleLogger { timer: RefCell::new(None), also: RefCell::new(vec![]) };

pub fn init(progname: &str) -> Result<(), SetLoggerError> {
    rtt_init_print!(NoBlockTrim, 4096);
    rprintln!("{} starting", progname);
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))?;
    trace!("logger started");
    info!("logger started");
    Ok(())
}

#[allow(dead_code)]
pub fn set_timer(timer: FreeTimer) {
    *LOGGER.timer.borrow_mut() = Some(timer);
}

#[allow(dead_code)]
pub fn add_also(also: Box<dyn log::Log>) {
    LOGGER.also.borrow_mut().push(also);
}
