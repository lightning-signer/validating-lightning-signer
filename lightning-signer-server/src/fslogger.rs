use std::fs;
use std::io::Write;
use std::sync::Mutex;

use time::OffsetDateTime;

use log::{LevelFilter, Log, Metadata, Record};

/// A filesystem logger
#[derive(Debug)]
pub struct FilesystemLogger {
    disk_log_level: LevelFilter,
    console_log_level: LevelFilter,
    logs_file_path: String,
    file: Mutex<fs::File>,
}

impl FilesystemLogger {
    /// Create a new logger
    pub fn new(
        data_dir: String,
        disk_log_level: LevelFilter,
        console_log_level: LevelFilter,
    ) -> Self {
        let logs_path = format!("{}/logs", data_dir);
        fs::create_dir_all(logs_path.clone()).expect("Cannot create logs directory");
        let logs_file_path = format!("{}/logs.txt", logs_path.clone());
        let file = Mutex::new(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&logs_file_path)
                .expect(&format!("Failed to open file: {}", &logs_file_path)),
        );
        Self { disk_log_level, console_log_level, logs_file_path, file }
    }
}

impl Log for FilesystemLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.console_log_level || metadata.level() <= self.disk_log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let tstamp = OffsetDateTime::now_utc().format("%F %H:%M:%S.%N");
            let tstamp = tstamp.get(0..tstamp.len() - 6).expect("bad timestamp"); // strip to mSec
            let raw_log = record.args().to_string();
            let log = format!(
                "{} {:<5} [{}:{}] {}\n",
                tstamp,
                record.level().to_string(),
                record.module_path().unwrap_or_else(|| "<unknown-module-path>"),
                record.line().unwrap_or_else(|| 0),
                raw_log
            );
            if record.level() <= self.disk_log_level {
                self.file
                    .lock()
                    .unwrap()
                    .write_all(log.as_bytes())
                    .expect(&format!("Failed to write to file: {}", &self.logs_file_path));
            }
            if record.level() <= self.console_log_level {
                print!("{}", &log);
            }
        }
    }

    fn flush(&self) {
        self.file.lock().unwrap().flush().expect("flush");
    }
}
