use crate::prelude::*;
use anyhow::{anyhow, Result};
use log;

const LOG_LEVEL_FILTERS: [log::LevelFilter; 6] = [
    log::LevelFilter::Off,
    log::LevelFilter::Error,
    log::LevelFilter::Warn,
    log::LevelFilter::Info,
    log::LevelFilter::Debug,
    log::LevelFilter::Trace,
];

/// Name for each log level
pub const LOG_LEVEL_FILTER_NAMES: [&'static str; 6] =
    ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];

/// Parse a log level name to a Level filter
pub fn parse_log_level_filter(lvlstr: String) -> Result<log::LevelFilter> {
    Ok(*LOG_LEVEL_FILTERS
        .iter()
        .find(|ll| lvlstr == ll.as_str())
        .ok_or_else(|| anyhow!("invalid log level: {}", lvlstr))?)
}
