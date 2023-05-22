#[cfg(feature = "use_backtrace")]
use backtrace::Backtrace;

use ValidationErrorKind::*;

use crate::prelude::*;

/// Kind of validation error
#[derive(Clone, Debug, PartialEq)]
pub enum ValidationErrorKind {
    /// The transaction could not be parsed or had non-standard elements
    TransactionFormat(String),
    /// A scriptPubkey could not be parsed or was non-standard for Lightning
    ScriptFormat(String),
    /// A script element didn't match the channel setup
    Mismatch(String),
    /// A policy was violated
    Policy(String),
    /// A policy was temporarily violated, but a retry is possible
    /// (e.g. the funding is not yet considered confirmed because
    /// the oracle is behind)
    TemporaryPolicy(String),
    /// A layer-1 transaction outputs to unknown destinations.
    /// Includes the list of tx output indices that are unknown.
    UnknownDestinations(String, Vec<usize>),
}

// Explicit PartialEq which ignores backtrace.
impl PartialEq for ValidationError {
    fn eq(&self, other: &ValidationError) -> bool {
        self.kind == other.kind
    }
}

/// Validation error
#[derive(Clone)]
pub struct ValidationError {
    /// The kind of error
    pub kind: ValidationErrorKind,
    /// A non-resolved backtrace
    #[cfg(feature = "use_backtrace")]
    pub bt: Backtrace,
}

impl ValidationError {
    /// Resolve the backtrace for display to the user
    #[cfg(feature = "use_backtrace")]
    pub fn resolved_backtrace(&self) -> Backtrace {
        let mut mve = self.clone();
        mve.bt.resolve();
        mve.bt
    }

    /// Return a new ValidationError with the message prepended
    pub fn prepend_msg(&self, premsg: String) -> ValidationError {
        let modkind = match &self.kind {
            TransactionFormat(s0) => TransactionFormat(premsg + &s0),
            ScriptFormat(s0) => ScriptFormat(premsg + &s0),
            Mismatch(s0) => Mismatch(premsg + &s0),
            Policy(s0) => Policy(premsg + &s0),
            TemporaryPolicy(s0) => TemporaryPolicy(premsg + &s0),
            UnknownDestinations(s0, indices) => UnknownDestinations(premsg + &s0, indices.clone()),
        };
        ValidationError {
            kind: modkind,
            #[cfg(feature = "use_backtrace")]
            bt: self.bt.clone(),
        }
    }
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.kind)
    }
}

impl core::fmt::Debug for ValidationError {
    #[cfg(not(feature = "use_backtrace"))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("ValidationError").field("kind", &self.kind).finish()
    }
    #[cfg(feature = "use_backtrace")]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("ValidationError")
            .field("kind", &self.kind)
            .field("bt", &self.resolved_backtrace())
            .finish()
    }
}

impl Into<String> for ValidationError {
    fn into(self) -> String {
        match self.kind {
            TransactionFormat(s) => "transaction format: ".to_string() + &s,
            ScriptFormat(s) => "script format: ".to_string() + &s,
            Mismatch(s) => "script template mismatch: ".to_string() + &s,
            Policy(s) => "policy failure: ".to_string() + &s,
            TemporaryPolicy(s) => "temporary policy failure: ".to_string() + &s,
            UnknownDestinations(s, indices) => {
                format!("unknown destinations: {} {:?}", s, indices)
            }
        }
    }
}

pub(crate) fn transaction_format_error(msg: impl Into<String>) -> ValidationError {
    ValidationError {
        kind: TransactionFormat(msg.into()),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

pub(crate) fn script_format_error(msg: impl Into<String>) -> ValidationError {
    ValidationError {
        kind: ScriptFormat(msg.into()),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

pub(crate) fn mismatch_error(msg: impl Into<String>) -> ValidationError {
    ValidationError {
        kind: Mismatch(msg.into()),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

pub(crate) fn policy_error(msg: impl Into<String>) -> ValidationError {
    ValidationError {
        kind: Policy(msg.into()),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

pub(crate) fn temporary_policy_error(msg: impl Into<String>) -> ValidationError {
    ValidationError {
        kind: TemporaryPolicy(msg.into()),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

pub(crate) fn unknown_destinations_error(unknowns: Vec<usize>) -> ValidationError {
    ValidationError {
        kind: UnknownDestinations("".to_string(), unknowns),
        #[cfg(feature = "use_backtrace")]
        bt: Backtrace::new_unresolved(),
    }
}

// Ignore obj and tag for now, no filtering allowed
#[allow(unused)]
macro_rules! transaction_format_err {
	($obj:expr, $tag:tt, $($arg:tt)*) => (
            return Err(transaction_format_error(format!(
                "{}: {}",
                short_function!(),
                format!($($arg)*)
            )))
        )
}

/// Return a policy error from the current function, by invoking
/// policy_error on the policy object.
#[doc(hidden)]
#[macro_export]
#[allow(unused)]
macro_rules! policy_err {
	($obj:expr, $tag:tt, $($arg:tt)*) => (
        $obj.policy().policy_error($tag.into(), format!(
            "{}: {}",
            short_function!(),
            format!($($arg)*)
        ))?
    )
}

/// Return a policy error from the current function, by invoking
/// temporary_policy_error on the policy object.
#[doc(hidden)]
#[macro_export]
#[allow(unused)]
macro_rules! temporary_policy_err {
	($obj:expr, $tag:tt, $($arg:tt)*) => (
        $obj.policy().temporary_policy_error($tag.into(), format!(
            "{}: {}",
            short_function!(),
            format!($($arg)*)
        ))?
    )
}

#[allow(unused)]
#[macro_export]
/// Log at the matching policy error level (ERROR or WARN).
macro_rules! policy_log {
	($obj:expr, $tag:tt, $($arg:tt)*) => (
        $obj.policy().policy_log($tag.into(), format!(
            "{}: {}",
            short_function!(),
            format!($($arg)*)
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_test() {
        assert_eq!(
            format!("{}", transaction_format_error("testing".to_string())),
            "TransactionFormat(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(transaction_format_error("testing".to_string())),
            "transaction format: testing"
        );
        assert_eq!(
            format!("{}", script_format_error("testing".to_string())),
            "ScriptFormat(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(script_format_error("testing".to_string())),
            "script format: testing"
        );
        assert_eq!(format!("{}", mismatch_error("testing".to_string())), "Mismatch(\"testing\")");
        assert_eq!(
            Into::<String>::into(mismatch_error("testing".to_string())),
            "script template mismatch: testing"
        );
        assert_eq!(format!("{}", policy_error("testing".to_string())), "Policy(\"testing\")");
        assert_eq!(
            Into::<String>::into(policy_error("testing".to_string())),
            "policy failure: testing"
        );
    }
}
