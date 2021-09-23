use serde_bolt::{Error as BoltError};

/// Error
#[derive(Debug)]
pub enum Error {
    BoltError(BoltError),
    TrailingBytes,
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
