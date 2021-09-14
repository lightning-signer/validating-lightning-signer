/// Byte to integer conversion
pub mod byte_utils;
/// Cryptographic utilities
pub mod crypto_utils;
/// Logging macros
#[macro_use]
#[allow(unused_macros)]
pub mod macro_logger;
#[macro_use]
/// Debugging
pub mod debug_utils;
/// Invoices
pub mod invoice_utils;
/// Logging
pub mod log_utils;
/// An implementation of the LDK Sign trait for integration with LDK based nodes
#[cfg(feature = "test_utils")]
pub mod loopback;
#[allow(missing_docs)]
pub mod test_logger;
#[allow(missing_docs)]
#[cfg(feature = "test_utils")]
#[macro_use]
pub mod test_utils;
#[allow(missing_docs)]
#[cfg(feature = "test_utils")]
#[rustfmt::skip]
#[macro_use]
pub mod functional_test_utils;
/// Status error results
pub mod status;
/// Transaction utilities
pub mod transaction_utils;
/// Key utilities
pub mod key_utils;

/// The initial commitment number when counting backwards
pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;
