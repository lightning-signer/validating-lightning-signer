use super::Error;
use async_trait::async_trait;
use lightning_storage_server::model::Value;
use log::*;
use redb::{Database, ReadableTable, TableDefinition, TableHandle};
use redb1::ReadableTable as ReadableTable1;
use std::path::Path;

const REDB_DIR_NAME: &str = "redb";
const DB2_EXTENSION: &str = "db2";

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
    #[error("migration error: {0}")]
    MigrationError(String),
}

/// A versioned key-value store backed by redb
pub struct RedbDatabase {
    db: Database,
}

impl RedbDatabase {
    /// Open a database at the given path.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let db_path = path.as_ref().join(REDB_DIR_NAME);

        // Attempt to open the database in the db2 format (redb 2.x)
        let mut db = match Database::create(&db_path) {
            Ok(db) => db,
            Err(redb::DatabaseError::UpgradeRequired(_)) => Self::migrate_v1_to_v2(&db_path)?,
            Err(e) => return Err(RedbError::RedbDatabase(e).into()),
        };
        Self::maybe_create_table(&mut db, false)?;
        Ok(Self { db })
    }

    /// Migrate data from redb 1.x to redb 2.x
    fn migrate_v1_to_v2(db1_path: &Path) -> Result<Database, RedbError> {
        info!("Starting database migration to redb 2 for path: {}", db1_path.display());

        let db1 = Self::open_db1_database(db1_path)?;
        let db2_path = db1_path.with_extension(DB2_EXTENSION);

        if db2_path.exists() {
            std::fs::remove_file(&db2_path).map_err(|e| {
                RedbError::MigrationError(format!(
                    "Failed to remove existing temporary database file: {}",
                    e
                ))
            })?;
        }

        let db2 = Self::create_db2_database(&db2_path)?;
        Self::migrate_data(&db1, &db2)?;

        drop(db1);
        drop(db2);

        std::fs::rename(db2_path, db1_path).map_err(|e| {
            RedbError::MigrationError(format!("Failed to replace db1 with db2: {}", e))
        })?;

        let migrated_db = Database::open(db1_path).map_err(|e| {
            RedbError::MigrationError(format!("Failed to open db2 database after migration: {}", e))
        })?;

        info!(
            "Database migration to redb 2 completed successfully for path: {}",
            db1_path.display()
        );

        Ok(migrated_db)
    }

    fn open_db1_database(db1_path: &Path) -> Result<redb1::Database, RedbError> {
        redb1::Database::open(db1_path)
            .map_err(|e| RedbError::MigrationError(format!("Failed to open redb1 database: {}", e)))
    }

    fn create_db2_database(db2_path: &Path) -> Result<Database, RedbError> {
        Database::create(&db2_path)
            .map_err(|e| RedbError::MigrationError(format!("Failed to create db2 database: {}", e)))
    }

    /// Migrate data from the db1 database to the db2 one
    fn migrate_data(db1: &redb1::Database, db2: &Database) -> Result<(), RedbError> {
        let read_txn = db1.begin_read().map_err(|e| {
            RedbError::MigrationError(format!("Failed to begin read transaction: {}", e))
        })?;

        let write_txn = db2.begin_write().map_err(|e| {
            RedbError::MigrationError(format!("Failed to begin write transaction: {}", e))
        })?;

        Self::migrate_table(&read_txn, &write_txn, TABLE.name())?;

        write_txn.commit().map_err(|e| {
            RedbError::MigrationError(format!("Failed to commit db2 transaction: {}", e))
        })?;

        Ok(())
    }

    /// Migrate a specific table from the db1 database to the db2 one
    fn migrate_table(
        read_txn: &redb1::ReadTransaction,
        write_txn: &redb::WriteTransaction,
        table_name: &str,
    ) -> Result<(), RedbError> {
        let table_def1: redb1::TableDefinition<&str, &[u8]> =
            redb1::TableDefinition::new(table_name);

        let table1 = match read_txn.open_table(table_def1) {
            Ok(table) => table,
            Err(e) => {
                error!("Table '{}' not found or error opening it: {}", table_name, e);
                return Ok(());
            }
        };

        let table_def2: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new(table_name);

        let mut table2 = write_txn.open_table(table_def2).map_err(|e| {
            RedbError::MigrationError(format!(
                "Failed to open target '{}' table: {}",
                table_name, e
            ))
        })?;

        for result in table1.iter().map_err(|e| {
            RedbError::MigrationError(format!(
                "Failed to iterate source '{}' table: {}",
                table_name, e
            ))
        })? {
            let (key, value) = result.map_err(|e| {
                RedbError::MigrationError(format!(
                    "Failed to read source '{}' table entry: {}",
                    table_name, e
                ))
            })?;

            table2.insert(key.value(), value.value()).map_err(|e| {
                RedbError::MigrationError(format!(
                    "Failed to insert into target '{}' table: {}",
                    table_name, e
                ))
            })?;
        }

        Ok(())
    }

    /// Open a database at the given path and clear it.
    pub async fn new_and_clear<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db =
            Database::create(path.as_ref().join(REDB_DIR_NAME)).map_err(RedbError::from)?;
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
