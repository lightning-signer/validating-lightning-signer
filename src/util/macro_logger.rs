#[cfg(feature = "grpc")]
use serde::Serializer;

// BEGIN NOT TESTED
#[cfg(feature = "grpc")]
pub fn as_hex<S>(buf: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&buf))
}
// END NOT TESTED

macro_rules! function {
    () => {{
        fn _f() {}
        fn _type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = _type_name_of(_f);
        &name[..name.len() - 3]
    }};
}

macro_rules! log_internal {
	($self: ident, $lvl:expr, $($arg:tt)+) => (
		&$self.logger.log(&lightning::util::logger::Record::new($lvl, format_args!($($arg)+), module_path!(), file!(), line!()));
	);
}

macro_rules! log_error {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off")))]
		log_internal!($self, lightning::util::logger::Level::Error, $($arg)*);
	)
}

macro_rules! log_warn {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error")))]
		log_internal!($self, lightning::util::logger::Level::Warn, $($arg)*);
	)
}

macro_rules! log_info {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn")))]
		log_internal!($self, lightning::util::logger::Level::Info, $($arg)*);
	)
}

macro_rules! log_debug {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info")))]
		log_internal!($self, lightning::util::logger::Level::Debug, $($arg)*);
	)
}

macro_rules! log_trace {
	($self: ident, $($arg:tt)*) => (
		#[cfg(not(any(feature = "max_level_off", feature = "max_level_error", feature = "max_level_warn", feature = "max_level_info", feature = "max_level_debug")))]
		log_internal!($self, lightning::util::logger::Level::Trace, $($arg)*);
	)
}

pub struct DebugBytes<'a>(pub &'a [u8]);
impl<'a> std::fmt::Display for DebugBytes<'a> {
    // BEGIN NOT TESTED
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for i in self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
    // END NOT TESTED
}

macro_rules! log_bytes {
    ($obj: expr) => {
        crate::util::macro_logger::DebugBytes(&$obj)
    };
}
