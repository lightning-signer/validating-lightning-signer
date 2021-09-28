use serde_bolt::{Error as BoltError};

/// Error
#[derive(Debug)]
pub enum Error {
    BoltError(BoltError),
    // Include the message type for trailing bytes
    TrailingBytes(u16),
    ShortRead,
    Eof,
}

impl From<BoltError> for Error {
    fn from(e: BoltError) -> Self {
        Error::BoltError(e)
    }
}

/// Result
pub type Result<T> = core::result::Result<T, Error>;
