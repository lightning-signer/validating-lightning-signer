pub mod sled;

use crate::model::Value;

/// Database errors
#[derive(Debug)]
pub enum Error {
    /// underlying database error
    Sled(::sled::Error),
    /// version conflicts detected - existing values are returned
    Conflict(Vec<(String, Option<Value>)>),
}

pub trait Database: Send + Sync {
    /// Atomically put a vector of key-values into the database.
    ///
    /// If any of the value versions are not the next version, the entire
    /// transaction is aborted and the error includes the existing values.
    fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error>;

    /// Get all keys matching a prefix from the database
    fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error>;
}
