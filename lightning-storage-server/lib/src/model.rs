use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

use crate::proto;

#[derive(Serialize, Deserialize, Clone)]
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

impl Into<(String, Value)> for proto::KeyValue {
    fn into(self) -> (String, Value) {
        (self.key, Value { version: self.version, value: self.value })
    }
}

// convert a conflict to proto
impl Into<proto::KeyValue> for (String, Option<Value>) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        let version = v.as_ref().map(|v| v.version).unwrap_or(-1);
        let value = v.as_ref().map(|v| v.value.clone()).unwrap_or_default();
        proto::KeyValue { key, version, value }
    }
}

// convert get result to proto
impl Into<proto::KeyValue> for (String, Value) {
    fn into(self) -> proto::KeyValue {
        let (key, v) = self;
        proto::KeyValue { key, version: v.version, value: v.value }
    }
}
