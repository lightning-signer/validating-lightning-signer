use core::fmt::{Debug, Display, Formatter};
use serde_bolt::Error as BoltError;

/// Error
#[derive(Debug, Clone)]
pub enum Error {
    UnexpectedType(u16),
    BadFraming,
    BoltError(BoltError),
    /// Includes the message type for trailing bytes
    TrailingBytes(usize, u16),
    ShortRead,
    MessageTooLarge,
    Eof,
}

impl From<BoltError> for Error {
    fn from(e: BoltError) -> Self {
        Error::BoltError(e)
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
