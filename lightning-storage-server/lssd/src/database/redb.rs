use super::Error;
use async_trait::async_trait;
use lightning_storage_server::model::Value;
use log::*;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");

/// Database errors
#[derive(Debug, Error)]
pub enum RedbError {
    /// underlying database error
    #[error("transaction error: {0}")]
    RedbTransaction(#[from] ::redb::TransactionError),
    #[error("storage error: {0}")]
    RedbStorage(#[from] ::redb::StorageError),
    #[error("database error: {0}")]
    RedbDatabase(#[from] ::redb::DatabaseError),
    #[error("database error: {0}")]
    RedbTable(#[from] ::redb::TableError),
    #[error("database error: {0}")]
    RedbCommit(#[from] ::redb::CommitError),
}

/// A versioned key-value store backed by redb
pub struct RedbDatabase {
    db: Database,
}

impl RedbDatabase {
    /// Open a database at the given path.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db = Database::create(path.as_ref().join("redb")).map_err(RedbError::from)?;
        Self::maybe_create_table(&mut db, false)?;
        Ok(Self { db })
    }

    /// Open a database at the given path and clear it.
    pub async fn new_and_clear<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db = Database::create(path.as_ref().join("redb")).map_err(RedbError::from)?;
        Self::maybe_create_table(&mut db, true)?;
        Ok(Self { db })
    }

    fn maybe_create_table(db: &mut Database, clear: bool) -> Result<(), RedbError> {
        if !db.check_integrity().map_err(RedbError::from)? {
            warn!("database was repaired");
        }

        // create the table if it doesn't exist
        let tx = db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            if clear {
                // clear the table
                table.retain(|_, _| false)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn do_put(
        &self,
        client_id: &[u8],
        kvs: &Vec<(String, Value)>,
    ) -> Result<Vec<(String, Option<Value>)>, RedbError> {
        let client_id_prefix = hex::encode(client_id);
        let tx = self.db.begin_write()?;
        let mut table = tx.open_table(TABLE)?;
        let mut conflicts = Vec::new();
        for (key_suffix, value) in kvs.iter() {
            let key = format!("{}/{}", client_id_prefix, key_suffix);
            let res_o = table.get(&*key)?;
            let (next_version, existing) = if let Some(res) = res_o {
                let existing: Value = ciborium::from_reader(&res.value()[..]).unwrap();
                (existing.version + 1, Some(existing))
            } else {
                (0, None)
            };
            if value.version != next_version {
                conflicts.push((key_suffix.clone(), existing))
            }
        }
        if !conflicts.is_empty() {
            drop(table);
            tx.abort()?;
            return Ok(conflicts);
        } else {
            for (key_suffix, value) in kvs.iter() {
                let key = format!("{}/{}", client_id_prefix, key_suffix);
                let mut value_vec = Vec::new();
                ciborium::into_writer(value, &mut value_vec).unwrap();
                table.insert(key.as_str(), &value_vec.as_slice()).unwrap();
            }
            drop(table);
            tx.commit()?;
        }
        // conflicts are empty
        return Ok(conflicts);
    }

    fn do_get(&self, client_id: &[u8], prefix: &str) -> Result<Vec<(String, Value)>, RedbError> {
        let mut res = Vec::new();

        let tx = self.db.begin_read()?;
        let table = tx.open_table(TABLE)?;

        for item in table.range(prefix..)? {
            let (key, value) = item?;
            if key.value().starts_with(&prefix) {
                let value: Value = ciborium::from_reader(&value.value()[..]).unwrap();
                let key_s = key.value().to_owned().split_off(client_id.len() * 2 + 1);
                res.push((key_s, value));
            } else {
                break;
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl super::Database for RedbDatabase {
    async fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error> {
        let conflicts = self.do_put(client_id, kvs)?;
        if !conflicts.is_empty() {
            return Err(Error::Conflict(conflicts));
        }
        Ok(())
    }

    /// Get all keys matching a prefix from the database
    async fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error> {
        let prefix = format!("{}/{}", hex::encode(client_id), key_prefix);

        let res = self.do_get(client_id, &prefix)?;
        Ok(res)
    }
}
