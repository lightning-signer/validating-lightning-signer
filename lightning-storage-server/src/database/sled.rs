use super::Error;
use crate::model::Value;
use async_trait::async_trait;
use sled::transaction::{abort, TransactionError};
use std::path::Path;

impl From<TransactionError<Error>> for Error {
    fn from(e: TransactionError<Error>) -> Self {
        match e {
            TransactionError::Abort(e) => e,
            TransactionError::Storage(e) => Error::Sled(e),
        }
    }
}

/// A versioned key-value store
pub struct SledDatabase {
    db: sled::Db,
}

impl SledDatabase {
    /// Open a database at the given path.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path.as_ref())?;
        Ok(Self { db })
    }
}

#[async_trait]
impl super::Database for SledDatabase {
    async fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error> {
        let client_id_prefix = hex::encode(client_id);
        self.db.transaction(|tx| {
            let mut conflicts = Vec::new();
            for (key_suffix, value) in kvs.iter() {
                let key = format!("{}/{}", client_id_prefix, key_suffix);
                let res_o = tx.get(key).unwrap();
                let (next_version, existing) = if let Some(res) = res_o {
                    let existing: Value = serde_cbor::from_reader(&res[..]).unwrap();
                    (existing.version + 1, Some(existing))
                } else {
                    (0, None)
                };
                if value.version != next_version {
                    conflicts.push((key_suffix.clone(), existing))
                }
            }
            if !conflicts.is_empty() {
                abort(Error::Conflict(conflicts))?;
            }
            for (key_suffix, value) in kvs.iter() {
                let key = format!("{}/{}", client_id_prefix, key_suffix);
                let mut value_vec = Vec::new();
                serde_cbor::to_writer(&mut value_vec, value).unwrap();
                tx.insert(key.as_str(), value_vec).unwrap();
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Get all keys matching a prefix from the database
    async fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error> {
        let prefix = format!("{}/{}", hex::encode(client_id), key_prefix);
        let mut res = Vec::new();
        let prefix_bytes = prefix.as_bytes();
        for item in self.db.scan_prefix(prefix_bytes) {
            let (key, value) = item?;
            let value: Value = serde_cbor::from_reader(&value[..]).unwrap();
            let key_s = String::from_utf8(key.to_vec())
                .expect("keys must be utf-8")
                .split_off(client_id.len() * 2 + 1);
            res.push((key_s, value));
        }
        Ok(res)
    }
}
