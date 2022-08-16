#[cfg(feature = "use_backtrace")]
use backtrace::Backtrace;
use bitcoin::hashes::hex::ToHex;
use lightning::ln::PaymentHash;

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
    /// A payment is not balanced
    Unbalanced(String, Vec<PaymentHash>),
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
            Unbalanced(s0, hashes) => Unbalanced(premsg + &s0, hashes.clone()),
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
            Unbalanced(s, hashes) => {
                let hashes: Vec<_> = hashes.iter().map(|h| h.0.to_hex()).collect();
                format!("unbalanced payments: {} {}", s, hashes.join(", "))
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

pub(crate) fn unbalanced_error(hashes: Vec<PaymentHash>) -> ValidationError {
    ValidationError {
        kind: Unbalanced("".to_string(), hashes),
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
