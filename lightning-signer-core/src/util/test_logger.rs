use crate::node::SyncLogger;
use crate::prelude::*;
use lightning::util::logger::{Level, Logger, Record};

pub struct TestLogger {
    level: Level,
    #[allow(unused)]
    id: String,
    pub lines: Mutex<Map<(String, String), usize>>,
}

impl SendSync for TestLogger {}

impl SyncLogger for TestLogger {}

impl TestLogger {
    pub fn new() -> TestLogger {
        Self::new_with_id("".to_owned())
    }

    pub fn new_with_id(id: String) -> TestLogger {
        TestLogger { level: Level::Trace, id, lines: Mutex::new(Map::new()) }
    }

    pub fn enable(&mut self, level: Level) {
        self.level = level;
    }

    pub fn assert_log(&self, module: String, line: String, count: usize) {
        let log_entries = self.lines.lock().unwrap();
        assert_eq!(log_entries.get(&(module, line)), Some(&count));
    }
}

impl Logger for TestLogger {
    fn log(&self, record: &Record) {
        *self
            .lines
            .lock()
            .unwrap()
            .entry((record.module_path.to_string(), format!("{}", record.args)))
            .or_insert(0) += 1;
        if self.level >= record.level {
            #[cfg(feature = "std")]
            println!(
                "{:<5} {} [{} : {}, {}] {}",
                record.level.to_string(),
                self.id,
                record.module_path,
                record.file,
                record.line,
                record.args
            );
        }
    }
}
