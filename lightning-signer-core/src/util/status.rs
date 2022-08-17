use crate::prelude::*;
use core::fmt;

#[cfg(feature = "use_backtrace")]
use backtrace::Backtrace;
use log::error;

use crate::policy::error::ValidationError;

/// gRPC compatible error status
#[derive(Clone)]
pub struct Status {
    /// The gRPC status code, found in the `grpc-status` header.
    code: Code,
    /// A relevant error message, found in the `grpc-message` header.
    message: String,
}

/// gRPC compatible error status code
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The operation completed successfully.
    Ok = 0,

    /// Client specified an invalid argument.
    InvalidArgument = 3,

    /// The system is not in a state required for the operation’s execution.
    FailedPrecondition = 9,

    /// Internal error.
    Internal = 13,
}

impl Status {
    /// Create a new `Status` with the associated code and message.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Status { code, message: message.into() }
    }

    /// Get the gRPC `Code` of this `Status`.
    pub fn code(&self) -> Code {
        self.code
    }

    /// Get the text error message of this `Status`.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Construct an invalid argument status
    pub fn invalid_argument(message: impl Into<String>) -> Status {
        Self::new(Code::InvalidArgument, message)
    }

    /// Construct a failed precondition status, used for policy violation
    pub fn failed_precondition(message: impl Into<String>) -> Status {
        Self::new(Code::FailedPrecondition, message)
    }

    /// Construct an internal error status
    pub fn internal(message: impl Into<String>) -> Status {
        Self::new(Code::Internal, message)
    }
}

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
        write!(f, "status: {:?}, message: {:?}", self.code(), self.message())
    }
}

#[cfg(feature = "grpc")]
impl std::error::Error for Status {}

#[cfg(feature = "grpc")]
use core::convert::TryInto;

#[cfg(feature = "grpc")]
impl From<Status> for tonic::Status {
    fn from(s: Status) -> Self {
        let code = s.code() as i32;
        tonic::Status::new(code.try_into().unwrap(), s.message())
    }
}

/// An invalid argument was detected
pub fn invalid_argument(msg: impl Into<String>) -> Status {
    let s = msg.into();
    error!("INVALID ARGUMENT: {}", &s);
    #[cfg(feature = "use_backtrace")]
    error!("BACKTRACE:\n{:?}", Backtrace::new());
    Status::invalid_argument(s)
}

pub(crate) fn internal_error(msg: impl Into<String>) -> Status {
    let s = msg.into();
    error!("INTERNAL ERROR: {}", &s);
    #[cfg(feature = "use_backtrace")]
    error!("BACKTRACE:\n{:?}", Backtrace::new());
    Status::internal(s)
}

#[allow(unused)]
pub(crate) fn failed_precondition(msg: impl Into<String>) -> Status {
    let s = msg.into();
    error!("FAILED PRECONDITION: {}", &s);
    // Skip backtrace since ValidationError handled already ...
    Status::failed_precondition(s)
}

impl From<ValidationError> for Status {
    fn from(ve: ValidationError) -> Self {
        let s: String = ve.clone().into();
        error!("FAILED PRECONDITION: {}", &s);
        #[cfg(feature = "use_backtrace")]
        error!("BACKTRACE:\n{:?}", &ve.resolved_backtrace());
        Status::failed_precondition(s)
    }
}
