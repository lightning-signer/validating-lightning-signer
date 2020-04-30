use ValidationError::{Mismatch, Policy, ScriptFormat, TransactionFormat};

#[derive(PartialEq, Debug)]
pub enum ValidationError {
    TransactionFormat(String),
    ScriptFormat(String),
    Mismatch(String),
    Policy(String),
}

// BEGIN NOT TESTED
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
// END NOT TESTED

impl Into<String> for ValidationError {
    fn into(self) -> String {
        match self {
            TransactionFormat(s) => "transaction format ".to_string() + &s,
            ScriptFormat(s) => "script format ".to_string() + &s,
            Mismatch(s) => "script template mismatch".to_string() + &s,
            Policy(s) => "policy failure ".to_string() + &s,
        }
    }
}
