use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

#[derive(Serialize, Deserialize)]
pub struct Value {
    /// The version of the value.  These must be strictly increasing with no gaps.
    /// This is used to detect concurrent updates.
    /// Normally, we would used an unsigned integer, but databases don't map those well.
    pub version: i64,
    /// Client provided opaque value.
    /// NOTE: the client should internally append an HMAC, but this is out of scope for the server
    /// data model.
    pub value: Vec<u8>,
}

// kcov-ignore-start
impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("version", &self.version)
            // try to emit the value as a string, but if that fails, print the hex bytes
            .field(
                "value",
                &String::from_utf8(self.value.clone()).unwrap_or_else(|_| hex::encode(&self.value)),
            )
            .finish()
    }
}
// kcov-ignore-end
