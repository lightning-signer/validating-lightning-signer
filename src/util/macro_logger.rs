use std;

use secp256k1::key::PublicKey;

pub(crate) struct DebugPubKey<'a>(pub &'a PublicKey);

impl<'a> std::fmt::Display for DebugPubKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for i in self.0.serialize().iter() {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}
macro_rules! log_pubkey {
    ($obj: expr) => {
        ::util::macro_logger::DebugPubKey(&$obj)
    };
}

pub(crate) struct DebugBytes<'a>(pub &'a [u8]);

impl<'a> std::fmt::Display for DebugBytes<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for i in self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}
macro_rules! log_bytes {
    ($obj: expr) => {
        ::util::macro_logger::DebugBytes(&$obj)
    };
}

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
