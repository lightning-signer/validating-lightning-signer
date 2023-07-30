use alloc::string::String;
use alloc::string::ToString;
use bitcoin::consensus::encode::Error as BitcoinError;
use core::fmt::{Debug, Display, Formatter};
use serde_bolt::bitcoin;

/// Error
#[derive(Debug, Clone)]
pub enum Error {
    UnexpectedType(u16),
    BadFraming,
    /// Bitcoin consensus decoding error
    Bitcoin,
    /// Includes the message type for trailing bytes
    TrailingBytes(usize, u16),
    ShortRead,
    MessageTooLarge,
    Eof,
    Io(String),
}

// convert bitcoin consensus decode error to our error
impl From<BitcoinError> for Error {
    fn from(_: BitcoinError) -> Self {
        Error::Bitcoin
    }
}

impl From<serde_bolt::io::Error> for Error {
    fn from(e: serde_bolt::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// Result
pub type Result<T> = core::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
