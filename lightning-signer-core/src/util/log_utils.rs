use anyhow::{anyhow, Result};
use log;

pub const LOG_LEVEL_FILTERS: [log::LevelFilter; 6] = [
	log::LevelFilter::Off,
	log::LevelFilter::Error,
	log::LevelFilter::Warn,
	log::LevelFilter::Info,
	log::LevelFilter::Debug,
	log::LevelFilter::Trace,
];

pub const LOG_LEVEL_FILTER_NAMES: [&'static str; 6] =
	["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

pub fn parse_log_level_filter(lvlstr: String) -> Result<log::LevelFilter> {
	Ok(*LOG_LEVEL_FILTERS
		.iter()
		.find(|ll| lvlstr == ll.as_str())
		.ok_or_else(|| anyhow!("invalid log level: {}", lvlstr))?)
}

pub struct ConsoleLogger;

impl log::Log for ConsoleLogger {
	fn enabled(&self, _metadata: &log::Metadata) -> bool {
		true
	}
	fn log(&self, record: &log::Record) {
		println!(
			"{:<5} [{} : {}, {}] {}",
			record.level().to_string(),
			record.module_path().unwrap_or_else(|| ""),
			record.file().unwrap_or_else(|| ""),
			record.line().unwrap_or_else(|| 0),
			record.args()
		);
	}
	fn flush(&self) {}
}
