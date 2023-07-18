use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::cell::RefCell;

use crate::setup::SetupFS;

use fatfs::{Seek, SeekFrom, Write};

use log::*;

pub struct FatLogger {
    logpath: String,
    setupfs: Arc<RefCell<SetupFS>>,
}

impl FatLogger {
    pub fn new(logpath: String, setupfs: Arc<RefCell<SetupFS>>) -> Self {
        Self { logpath, setupfs }
    }
}

unsafe impl Send for FatLogger {}
unsafe impl Sync for FatLogger {}

impl log::Log for FatLogger {
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
            let buffer = format!("{} {} - {}\n", record.target(), record.level(), record.args());
            let setupfs = self.setupfs.borrow();
            let mut log_file = setupfs.rundir().create_file(&self.logpath).expect("log file");
            log_file.seek(SeekFrom::End(0)).expect("seek end");
            log_file.write_all(buffer.as_bytes()).expect("write bytes");
            log_file.flush().expect("flush");
        }
    }

    fn flush(&self) {}
}
