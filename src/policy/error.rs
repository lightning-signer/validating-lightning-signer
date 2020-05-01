use ValidationError::{Mismatch, Policy, ScriptFormat, TransactionFormat};

#[derive(PartialEq, Debug)]
pub enum ValidationError {
    TransactionFormat(String),
    ScriptFormat(String),
    Mismatch(String),
    Policy(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Into<String> for ValidationError {
    fn into(self) -> String {
        match self {
            TransactionFormat(s) => "transaction format ".to_string() + &s,
            ScriptFormat(s) => "script format ".to_string() + &s,
            Mismatch(s) => "script template mismatch ".to_string() + &s,
            Policy(s) => "policy failure ".to_string() + &s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_test() {
        assert_eq!(
            format!("{}", TransactionFormat("testing".to_string())),
            "TransactionFormat(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(TransactionFormat("testing".to_string())),
            "transaction format testing"
        );
        assert_eq!(
            format!("{}", ScriptFormat("testing".to_string())),
            "ScriptFormat(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(ScriptFormat("testing".to_string())),
            "script format testing"
        );
        assert_eq!(
            format!("{}", Mismatch("testing".to_string())),
            "Mismatch(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(Mismatch("testing".to_string())),
            "script template mismatch testing"
        );
        assert_eq!(
            format!("{}", Policy("testing".to_string())),
            "Policy(\"testing\")"
        );
        assert_eq!(
            Into::<String>::into(Policy("testing".to_string())),
            "policy failure testing"
        );
    }
}
