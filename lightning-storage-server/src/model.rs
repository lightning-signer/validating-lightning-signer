use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Value {
    /// Signature by client of the value.
    /// Covers the version (8 bytes little endian) and the value.
    pub signature: Vec<u8>,
    /// The version of the value.  These must be strictly increasing with no gaps.
    /// This is used to detect concurrent updates.
    pub version: u64,
    /// Client provided opaque value.
    pub value: Vec<u8>,
}
