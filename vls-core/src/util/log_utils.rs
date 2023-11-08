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

/// Macro to catch panics for an expression evaluation and convert them to
/// Status::internal errors with the given format string and additional args.
/// The format string must have a {} placeholder for the panic message.
/// The surrounding function must return a Result<_, Status>.
#[macro_export]
macro_rules! catch_panic {
    ($e:expr, $fmt:expr) => {{
        catch_panic!($fmt,)
    }};
    ($e:expr, $fmt:expr, $($arg:tt)*) => {{
        #[cfg(feature = "std")]
        match std::panic::catch_unwind(|| $e) {
            Ok(res) => res,
            Err(err) => {
                let details = if let Some(s) = err.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = err.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "Unknown panic message".to_string()
                };
                log::error!($fmt, details, $($arg)*);
                return Err(crate::util::status::Status::internal(format!($fmt, details, $($arg)*)))
            }
        }
        #[cfg(not(feature = "std"))]
        $e
    }};
}

#[cfg(test)]
mod tests {
    use crate::util::status::{Code, Status};

    #[test]
    fn catch_test() {
        fn fut_panic() -> Result<u8, Status> {
            catch_panic!(panic!("test"), "panic: {} {}", "arg1")
        }
        fn fut_success() -> Result<u8, Status> {
            catch_panic!(Ok(42), "panic: {} {}", "arg1")
        }
        let res = fut_panic();
        assert!(res.is_err());
        let status = res.unwrap_err();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "panic: test arg1");

        let res = fut_success();
        assert_eq!(res.unwrap(), 42);
    }
}
