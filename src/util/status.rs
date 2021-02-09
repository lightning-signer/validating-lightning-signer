use std::error::Error;
use std::fmt;

// BEGIN NOT TESTED
#[derive(Clone)]
pub struct Status {
    /// The gRPC status code, found in the `grpc-status` header.
    code: Code,
    /// A relevant error message, found in the `grpc-message` header.
    message: String,
}
// END NOT TESTED

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The operation completed successfully.
    Ok = 0,

    /// Client specified an invalid argument.
    InvalidArgument = 3,

    /// Internal error.
    Internal = 13,
}

impl Status {
    /// Create a new `Status` with the associated code and message.
    pub fn new(code: Code, message: impl Into<String>) -> Status {
        Status {
            code,
            message: message.into(),
        }
    }

    /// Get the gRPC `Code` of this `Status`.
    pub fn code(&self) -> Code {
        self.code
    }

    /// Get the text error message of this `Status`.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn invalid_argument(message: impl Into<String>) -> Status {
        Status::new(Code::InvalidArgument, message)
    }

    pub fn internal(message: impl Into<String>) -> Status {
        Status::new(Code::Internal, message)
    }
}

// BEGIN NOT TESTED

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A manual impl to reduce the noise of frequently empty fields.
        let mut builder = f.debug_struct("Status");

        builder.field("code", &self.code);

        if !self.message.is_empty() {
            builder.field("message", &self.message);
        }

        builder.finish()
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "status: {:?}, message: {:?}",
            self.code(),
            self.message()
        )
    }
}

// END NOT TESTED

impl Error for Status {}
