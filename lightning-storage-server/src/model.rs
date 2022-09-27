use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
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
