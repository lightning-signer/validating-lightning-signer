use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Value {
    /// The version of the value.  These must be strictly increasing with no gaps.
    /// This is used to detect concurrent updates.
    pub version: u64,
    /// Client provided opaque value.
    /// NOTE: the client should internally append an HMAC, but this is out of scope for the server
    /// data model.
    pub value: Vec<u8>,
}
