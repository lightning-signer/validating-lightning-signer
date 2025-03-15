use super::{KVVStore, KVV};
use lightning_signer::persist::{Error, SignerId};
use lightning_signer::SendSync;
use redb::{Database, ReadableTable, TableDefinition, TableHandle, WriteTransaction};
use redb1::ReadableTable as ReadableTable1;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::*;

const REDB_DIR_NAME: &str = "redb";
const DB2_EXTENSION: &str = "db2";

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("kv");
const META_TABLE: TableDefinition<&str, &SignerId> = TableDefinition::new("meta");

// this is stored in the meta table, so there's no opportunity for a collision
const SIGNER_ID_KEY: &'static str = "signer_id";

/// An iterator over a KVVStore range
pub struct Iter(alloc::vec::IntoIter<KVV>);

impl Iterator for Iter {
    type Item = KVV;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// A key-version-value store backed by redb
pub struct RedbKVVStore {
    db: Database,
    // keep track of current versions for each key, so we can efficiently enforce versioning.
    // we don't expect many keys, so this is OK for low-resource environments.
    versions: Mutex<BTreeMap<String, u64>>,
    signer_id: SignerId,
}

impl SendSync for RedbKVVStore {}

impl RedbKVVStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self::new_store(path)
    }

    pub fn new_store<P: AsRef<Path>>(path: P) -> RedbKVVStore {
        let path = path.as_ref();
        if !path.exists() {
            fs::create_dir(path).expect("failed to create directory");
        }
        assert!(path.is_dir(), "{} is not a directory", path.display());

        let db_path = path.join(REDB_DIR_NAME);

        // Attempt to open the database in the db2 format (redb 2.x)
        let mut db = match Database::create(&db_path) {
            Ok(db) => db,
            Err(redb::DatabaseError::UpgradeRequired(_)) =>
                Self::migrate_v1_to_v2(&db_path).expect("Failed to migrate database"),
            Err(e) => panic!("Failed to open database: {}", e),
        };

        db.check_integrity().expect("database integrity check failed");
        let mut versions = BTreeMap::new();
        let signer_id = {
            // create the main table if it doesn't exist
            let tx = db.begin_write().unwrap();
            tx.open_table(TABLE).unwrap();

            // create the id table and signer ID if they don't exist
            let mut id_table = tx.open_table(META_TABLE).unwrap();
            let signer_id_bytes = id_table.get(SIGNER_ID_KEY).unwrap().map(|id| id.value().clone());
            let signer_id = signer_id_bytes.unwrap_or_else(|| {
                let signer_id = uuid::Uuid::new_v4();
                id_table.insert(SIGNER_ID_KEY, signer_id.as_bytes()).unwrap();
                signer_id.into_bytes()
            });
            drop(id_table);
            tx.commit().unwrap();
            signer_id
        };

        {
            // load the current versions
            let tx = db.begin_read().unwrap();
            let table = tx.open_table(TABLE).unwrap();
            for item in table.iter().unwrap() {
                let (key, vv) = item.expect("failed to iterate");
                let (version, _) = Self::decode_vv(vv.value());
                versions.insert(key.value().to_string(), version);
            }
        }

        let store = Self { db, versions: Mutex::new(versions), signer_id };
        store
    }

    fn migrate_v1_to_v2(db1_path: &Path) -> Result<Database, Error> {
        info!("Starting database migration to redb 2 for path: {}", db1_path.display());

        let db1 = Self::open_db1_database(db1_path)?;
        let db2_path = db1_path.with_extension(DB2_EXTENSION);

        if db2_path.exists() {
            std::fs::remove_file(&db2_path).map_err(|e| {
                Error::Internal(format!("Failed to remove existing temporary database file: {}", e))
            })?;
        }

        let db2 = Self::create_db2_database(&db2_path)?;
        Self::migrate_data(&db1, &db2)?;

        drop(db1);
        drop(db2);

        std::fs::rename(&db2_path, db1_path)
            .map_err(|e| Error::Internal(format!("Failed to replace db1 with db2: {}", e)))?;

        let migrated_db = Database::open(db1_path).map_err(|e| {
            Error::Internal(format!("Failed to open db2 database after migration: {}", e))
        })?;

        info!(
            "Database migration to redb 2 completed successfully for path: {}",
            db1_path.display()
        );

        Ok(migrated_db)
    }

    fn open_db1_database(db1_path: &Path) -> Result<redb1::Database, Error> {
        redb1::Database::open(db1_path)
            .map_err(|e| Error::Internal(format!("Failed to open db1 database: {}", e)))
    }

    fn create_db2_database(db2_path: &Path) -> Result<Database, Error> {
        Database::create(db2_path)
            .map_err(|e| Error::Internal(format!("Failed to create db2 database: {}", e)))
    }

    fn migrate_data(db1: &redb1::Database, db2: &Database) -> Result<(), Error> {
        let read_txn = db1
            .begin_read()
            .map_err(|e| Error::Internal(format!("Failed to begin read transaction: {}", e)))?;

        let write_txn = db2
            .begin_write()
            .map_err(|e| Error::Internal(format!("Failed to begin write transaction: {}", e)))?;

        Self::migrate_kv_table(&read_txn, &write_txn)?;
        Self::migrate_meta_table(&read_txn, &write_txn)?;

        write_txn
            .commit()
            .map_err(|e| Error::Internal(format!("Failed to commit db2 transaction: {}", e)))?;

        Ok(())
    }

    fn migrate_kv_table(
        read_txn: &redb1::ReadTransaction,
        write_txn: &WriteTransaction,
    ) -> Result<(), Error> {
        let table_def1: redb1::TableDefinition<&str, &[u8]> =
            redb1::TableDefinition::new(TABLE.name());

        let table1 = match read_txn.open_table(table_def1) {
            Ok(table) => table,
            Err(e) => {
                error!("Table 'kv' not found or error opening it: {}", e);
                return Ok(());
            }
        };

        let table_def2: redb::TableDefinition<&str, &[u8]> = TABLE;
        let mut table2 = write_txn
            .open_table(table_def2)
            .map_err(|e| Error::Internal(format!("Failed to open target 'kv' table: {}", e)))?;

        for result in table1
            .iter()
            .map_err(|e| Error::Internal(format!("Failed to iterate source 'kv' table: {}", e)))?
        {
            let (key, value) = result.map_err(|e| {
                Error::Internal(format!("Failed to read source 'kv' table entry: {}", e))
            })?;

            table2.insert(key.value(), value.value()).map_err(|e| {
                Error::Internal(format!("Failed to insert into target 'kv' table: {}", e))
            })?;
        }

        Ok(())
    }

    fn migrate_meta_table(
        read_txn: &redb1::ReadTransaction,
        write_txn: &WriteTransaction,
    ) -> Result<(), Error> {
        let table_def1: redb1::TableDefinition<&str, &[u8]> =
            redb1::TableDefinition::new(META_TABLE.name());

        let table1 = match read_txn.open_table(table_def1) {
            Ok(table) => table,
            Err(e) => {
                info!("Table 'meta' not found or error opening it: {}", e);
                return Ok(());
            }
        };

        let table_def2 = META_TABLE;
        let mut table2 = write_txn
            .open_table(table_def2)
            .map_err(|e| Error::Internal(format!("Failed to open target 'meta' table: {}", e)))?;

        if let Some(value_result) = table1.get(SIGNER_ID_KEY).map_err(|e| {
            Error::Internal(format!("Failed to get signer_id from source table: {}", e))
        })? {
            let bytes = value_result.value();

            if bytes.len() == 16 {
                let mut signer_id = [0u8; 16];
                signer_id.copy_from_slice(bytes);

                table2.insert(SIGNER_ID_KEY, &signer_id).map_err(|e| {
                    Error::Internal(format!("Failed to insert signer_id into target table: {}", e))
                })?;
            } else {
                return Err(Error::Internal(format!(
                    "Invalid signer_id length: expected 16 bytes, got {}",
                    bytes.len()
                )));
            }
        }

        Ok(())
    }

    fn decode_vv(vv: &[u8]) -> (u64, Vec<u8>) {
        let version = u64::from_be_bytes(vv[..8].try_into().unwrap());
        let value = vv[8..].to_vec();
        (version, value)
    }

    fn encode_vv(version: u64, value: Vec<u8>) -> Vec<u8> {
        let mut vv = Vec::with_capacity(value.len() + 8);
        vv.extend_from_slice(&version.to_be_bytes());
        vv.extend_from_slice(&value);
        vv
    }
}

impl KVVStore for RedbKVVStore {
    type Iter = Iter;

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let version = self.versions.lock().unwrap().get(key).map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    #[instrument(skip(self, value))]
    fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error> {
        let vv = Self::encode_vv(version, value);
        let mut versions = self.versions.lock().unwrap();

        if let Some(v) = versions.get(key) {
            if version < *v {
                error!("version mismatch for {}: {} < {}", key, version, v);
                // version cannot go backwards
                return Err(Error::VersionMismatch);
            } else if version == *v {
                // if same version, value must not have changed
                let tx = self.db.begin_read().unwrap();
                {
                    let table = tx.open_table(TABLE).unwrap();
                    let existing = table.get(key).expect("failed to get").unwrap();
                    if existing.value() != &vv {
                        error!("value mismatch for {}: {}", key, version);
                        return Err(Error::VersionMismatch);
                    }
                }
                return Ok(());
            }
        }
        let tx = self.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(TABLE).unwrap();
            table.insert(key, vv.as_slice()).expect("failed to insert");
        }
        versions.insert(key.to_string(), version);
        tx.commit().unwrap();
        Ok(())
    }

    fn put_batch(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        let tx = self.db.begin_write().unwrap();
        let mut table = tx.open_table(TABLE).unwrap();
        let mut found_version_mismatch = false;
        let mut staged_versions: BTreeMap<String, u64> = BTreeMap::new();
        let mut versions = self.versions.lock().unwrap();

        for kvv in kvvs.into_iter() {
            let (key, (version, value)) = (kvv.0.as_str(), (kvv.1 .0, kvv.1 .1));
            let vv = Self::encode_vv(version, value);
            if let Some(v) = versions.get(key) {
                if version < *v {
                    // version cannot go backwards
                    error!("version mismatch for {}: {} < {}", key, version, v);
                    found_version_mismatch = true;
                } else if version == *v {
                    // if same version, value must not have changed
                    let existing = table.get(key).expect("failed to get").unwrap();
                    if existing.value() != &vv {
                        error!("value mismatch for {}: {}", key, version);
                        found_version_mismatch = true;
                    }
                    continue;
                }
            }
            table.insert(key, vv.as_slice()).expect("failed to insert");
            staged_versions.insert(key.to_string(), version);
        }
        drop(table);
        if found_version_mismatch {
            // be explicit about aborting the transaction
            tx.abort().unwrap();
            return Err(Error::VersionMismatch);
        }
        tx.commit().unwrap();
        for (key, value) in staged_versions.into_iter() {
            versions.insert(key, value);
        }
        Ok(())
    }

    #[instrument(
        skip(self),
        fields(
            key = key,
        )
    )]
    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let tx = self.db.begin_read().unwrap();
        let table = tx.open_table(TABLE).unwrap();
        let result = table.get(key).expect("failed to get");
        if let Some(vv) = result {
            let (version, value) = Self::decode_vv(vv.value());
            Ok(Some((version, value)))
        } else {
            Ok(None)
        }
    }

    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        Ok(self.versions.lock().unwrap().get(key).copied())
    }

    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        let tx = self.db.begin_read().unwrap();
        let table = tx.open_table(TABLE).unwrap();
        let mut result = Vec::new();
        for item in table.range(prefix..).unwrap() {
            let (key, vv) = item.expect("failed to iterate");
            if key.value().starts_with(prefix) {
                let (version, value) = Self::decode_vv(vv.value());
                result.push(KVV(key.value().to_string(), (version, value)));
            } else {
                break;
            }
        }
        Ok(Iter(result.into_iter()))
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.put(key, Vec::new())
    }

    fn clear_database(&self) -> Result<(), Error> {
        let tx = self.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(TABLE).unwrap();
            table.retain(|_, _| false).unwrap();
        }
        tx.commit().unwrap();
        Ok(())
    }

    fn reset_versions(&self) -> Result<(), Error> {
        let mut versions = self.versions.lock().unwrap();
        let tx = self.db.begin_write().unwrap();
        {
            let mut table = tx.open_table(TABLE).unwrap();
            for key in versions.keys() {
                let vv = table.get(key.as_str()).expect("failed to get").unwrap();
                let (_version, value) = Self::decode_vv(vv.value());
                drop(vv);
                let vv = Self::encode_vv(0, value);
                table.insert(key.as_str(), vv.as_slice()).expect("failed to insert");
            }
            for version in versions.values_mut() {
                *version = 0;
            }
        }
        tx.commit().unwrap();
        Ok(())
    }

    fn signer_id(&self) -> SignerId {
        self.signer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvv::{JsonFormat, KVVPersister};
    use alloc::sync::Arc;
    use hex::FromHex;
    use lightning_signer::channel::ChannelId;
    use lightning_signer::node::{Node, NodeServices};
    use lightning_signer::persist::Error;
    use lightning_signer::persist::{MemorySeedPersister, Mutations, Persist};
    use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
    use lightning_signer::util::clock::StandardClock;
    use lightning_signer::util::test_utils::*;
    use std::path::Path;
    use std::{env, fs};

    #[test]
    fn basic_test() -> Result<(), Error> {
        let tempdir = tempfile::tempdir().unwrap();
        let store = RedbKVVStore::new(tempdir.path());
        store.put("foo1", b"bar".to_vec())?;
        store.put("foo2", b"boo".to_vec())?;
        assert_eq!(store.get_version("foo1")?.unwrap(), 0);
        assert_eq!(store.get("foo1")?.unwrap().1, b"bar");
        store.put_with_version("foo1", 1, b"bar2".to_vec())?;
        assert_eq!(store.get_version("foo1")?.unwrap(), 1);
        store.put_with_version("foo1", 1, b"bar2".to_vec())?;
        assert_eq!(store.get_version("foo1")?.unwrap(), 1);
        assert_eq!(store.get("foo1")?.unwrap().1, b"bar2");

        // wrong version
        assert!(store.put_with_version("foo1", 0, b"bar2".to_vec()).is_err());

        // check that the ID is persistent
        let id = store.signer_id();
        drop(store);
        let store = RedbKVVStore::new(tempdir.path());
        assert_eq!(store.signer_id(), id);

        Ok(())
    }

    #[test]
    fn begin_replicate_test() -> Result<(), Error> {
        let tempdir = tempfile::tempdir().unwrap();
        let store = RedbKVVStore::new(tempdir.path());
        store.put("foo1", b"bar".to_vec())?;
        store.put("foo2", b"boo".to_vec())?;
        let persist = KVVPersister(store, JsonFormat);
        let muts = persist.begin_replication().unwrap();
        let mut iter = muts.iter();
        assert_eq!(iter.next().unwrap().clone(), ("foo1".to_owned(), (0, b"bar".to_vec())));
        assert_eq!(iter.next().unwrap().clone(), ("foo2".to_owned(), (0, b"boo".to_vec())));
        assert!(iter.next().is_none());
        Ok(())
    }

    #[test]
    fn put_batch_test() -> Result<(), Error> {
        let tempdir = tempfile::tempdir().unwrap();
        let store = RedbKVVStore::new(tempdir.path());
        let kvvs = vec![
            KVV("foo1".to_string(), (0, b"bar".to_vec())),
            KVV("foo1".to_string(), (0, b"bar".to_vec())),
            KVV("foo2".to_string(), (0, b"bar".to_vec())),
        ];
        assert!(store.put_batch(kvvs).is_ok());
        let kvvs = vec![
            KVV("foo1".to_string(), (1, b"bar2".to_vec())),
            KVV("foo2".to_string(), (0, b"bar3".to_vec())),
        ];
        assert!(store.put_batch(kvvs).is_err());
        store.put_with_version("foo1", 1, b"bar3".to_vec())?;
        assert_eq!(store.get_version("foo1")?.unwrap(), 1);
        assert_eq!(store.get("foo1")?.unwrap().1, b"bar3");
        Ok(())
    }

    #[test]
    fn non_transactional_test() {
        // cover some trait methods for the non-transactional case
        let tempdir = tempfile::tempdir().unwrap();
        let persister = KVVPersister(RedbKVVStore::new(tempdir.path()), JsonFormat);
        persister.commit().unwrap();
        assert!(persister.prepare().is_empty());
        assert!(persister.commit().is_ok());
        persister.put_batch_unlogged(Mutations::new()).unwrap();
    }

    #[test]
    fn restore_0_9_test() {
        // this data wasn't actually created with redb on 0.9
        // it was created with sled/kvv-json and then migrated to redb
        do_restore_test(
            "0_9_persist_redb",
            "0202020202020202020202020202020202020202020202020202020202020202",
        )
    }

    #[test]
    fn restore_0_10_test() {
        // non-symmetric txid tests for endianness issues
        do_restore_test(
            "0_10_persist_redb",
            "0101010101010101010101010101010101010101010101010101010101010102",
        )
    }

    fn do_restore_test(name: &str, expected_outpoint: &str) {
        // running inside coverage doesn't set CARGO_MANIFEST_DIR, so we have a fallback
        let fixture_path = if let Ok(module_path) = env::var("CARGO_MANIFEST_DIR") {
            println!("module_path: {}", module_path);
            format!("{}/../data/samples/{}", module_path, name)
        } else if let Ok(fixtures_path) = env::var("FIXTURES_DIR") {
            println!("fixtures_path: {}", fixtures_path);
            format!("{}/samples/{}", fixtures_path, name)
        } else {
            panic!("Missing CARGO_MANIFEST_DIR / FIXTURES_DIR");
        };
        if !Path::new(&fixture_path).exists() {
            panic!("Fixture path does not exist: {}", fixture_path);
        }

        // copy to a temporary directory, because redb modifies the files and we don't want to
        // clutter the development tree with these changes
        let tempdir = tempfile::tempdir().unwrap();

        // copy all files from fixture_path to tempdir
        for entry in fs::read_dir(fixture_path).unwrap() {
            let path = entry.unwrap().path();
            let filename = path.file_name().unwrap();
            let dest = tempdir.path().join(filename);
            fs::copy(path, dest).unwrap();
        }

        let persister = KVVPersister(RedbKVVStore::new(&tempdir), JsonFormat);
        let mut seed = [0; 32];
        seed.copy_from_slice(Vec::from_hex(TEST_SEED[0]).unwrap().as_slice());

        let seed_persister = Arc::new(MemorySeedPersister::new(seed.to_vec()));
        let node_services = NodeServices {
            validator_factory: Arc::new(SimpleValidatorFactory::new()),
            starting_time_factory: make_genesis_starting_time_factory(TEST_NODE_CONFIG.network),
            persister: Arc::new(persister),
            clock: Arc::new(StandardClock()),
            trusted_oracle_pubkeys: vec![],
        };
        let nodes = Node::restore_nodes(node_services, seed_persister).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = nodes.values().next().unwrap();
        let channels = node.get_channels();
        assert_eq!(channels.len(), 1);
        drop(channels);
        let expected_channel_id = ChannelId::new(&hex::decode(TEST_CHANNEL_ID[0]).unwrap());
        node.with_channel(&expected_channel_id, |channel| {
            assert_eq!(channel.setup.funding_outpoint.txid.to_string(), expected_outpoint);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_migrate_v1_to_v2_success() {
        let tempdir = tempfile::tempdir().unwrap();
        let db1_path = tempdir.path().join(REDB_DIR_NAME);
        let test_signer_id = uuid::Uuid::new_v4();
        let signer_id_bytes = test_signer_id.as_bytes().to_vec();

        create_v1_database(&db1_path, &signer_id_bytes);
        let store = RedbKVVStore::new(tempdir.path());
        verify_migrated_data(&store, &signer_id_bytes);

        drop(store);
        verify_persistence(tempdir.path(), &signer_id_bytes);
    }

    #[test]
    fn test_migrate_v1_to_v2_with_existing_db2_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let db1_path = tempdir.path().join(REDB_DIR_NAME);
        let db2_path = db1_path.with_extension(DB2_EXTENSION);

        fs::File::create(&db2_path).unwrap();

        let test_signer_id = uuid::Uuid::new_v4();
        let signer_id_bytes = test_signer_id.as_bytes().to_vec();
        create_v1_database(&db1_path, &signer_id_bytes);

        let store = RedbKVVStore::new(tempdir.path());
        verify_migrated_data(&store, &signer_id_bytes);
    }

    #[test]
    fn test_migrate_v1_to_v2_with_missing_kv_table() {
        let tempdir = tempfile::tempdir().unwrap();
        let db1_path = tempdir.path().join(REDB_DIR_NAME);
        let test_signer_id = uuid::Uuid::new_v4();
        let signer_id_bytes = test_signer_id.as_bytes().to_vec();

        {
            let db1 = redb1::Database::create(&db1_path).unwrap();
            let write_txn = db1.begin_write().unwrap();
            {
                let meta_table_def: redb1::TableDefinition<&str, &[u8]> =
                    redb1::TableDefinition::new(META_TABLE.name());
                let mut meta_table = write_txn.open_table(meta_table_def).unwrap();
                meta_table.insert(SIGNER_ID_KEY, &*signer_id_bytes).unwrap();
            }
            write_txn.commit().unwrap();
        }

        let store = RedbKVVStore::new(tempdir.path());
        assert_eq!(store.signer_id().to_vec(), signer_id_bytes);
    }

    #[test]
    #[should_panic(expected = "Invalid signer_id length")]
    fn test_migrate_v1_to_v2_with_invalid_signer_id_length() {
        let tempdir = tempfile::tempdir().unwrap();
        let db1_path = tempdir.path().join(REDB_DIR_NAME);

        {
            let db1 = redb1::Database::create(&db1_path).unwrap();
            let write_txn = db1.begin_write().unwrap();
            {
                let meta_table_def: redb1::TableDefinition<&str, &[u8]> =
                    redb1::TableDefinition::new(META_TABLE.name());
                let mut meta_table = write_txn.open_table(meta_table_def).unwrap();
                meta_table.insert(SIGNER_ID_KEY, b"invalid-length".as_slice()).unwrap();
            }
            write_txn.commit().unwrap();
        }

        RedbKVVStore::new(tempdir.path());
    }

    fn create_v1_database(db1_path: &Path, signer_id_bytes: &[u8]) {
        let db1 = redb1::Database::create(db1_path)
            .or_else(|_| redb1::Database::open(db1_path))
            .map_err(|e| format!("Failed to open or create db1 database: {}", e))
            .unwrap();
        let write_txn = db1.begin_write().unwrap();

        {
            let table_def: redb1::TableDefinition<&str, &[u8]> =
                redb1::TableDefinition::new(TABLE.name());
            let mut table = write_txn.open_table(table_def).unwrap();

            let value1 = RedbKVVStore::encode_vv(1, b"value1".to_vec());
            let value2 = RedbKVVStore::encode_vv(2, b"value2".to_vec());

            table.insert("key1", value1.as_slice()).unwrap();
            table.insert("key2", value2.as_slice()).unwrap();
        }

        {
            let meta_table_def: redb1::TableDefinition<&str, &[u8]> =
                redb1::TableDefinition::new(META_TABLE.name());
            let mut meta_table = write_txn.open_table(meta_table_def).unwrap();

            meta_table.insert(SIGNER_ID_KEY, signer_id_bytes).unwrap();
        }

        write_txn.commit().unwrap();
    }

    fn verify_migrated_data(store: &RedbKVVStore, signer_id_bytes: &[u8]) {
        {
            let tx = store.db.begin_read().unwrap();
            let kv_table = tx.open_table(TABLE).unwrap();

            let value1_guard = kv_table.get("key1").unwrap().unwrap();
            let value1 = value1_guard.value();
            let (version1, data1) = RedbKVVStore::decode_vv(value1);
            assert_eq!(version1, 1, "Version for key1 should be 1");
            assert_eq!(data1, b"value1".to_vec(), "Data for key1 should be 'value1'");

            let value2_guard = kv_table.get("key2").unwrap().unwrap();
            let value2 = value2_guard.value();
            let (version2, data2) = RedbKVVStore::decode_vv(value2);
            assert_eq!(version2, 2, "Version for key2 should be 2");
            assert_eq!(data2, b"value2".to_vec(), "Data for key2 should be 'value2'");

            let meta_table = tx.open_table(META_TABLE).unwrap();
            let signer_id_guard = meta_table.get(SIGNER_ID_KEY).unwrap().unwrap();
            let migrated_signer_id = signer_id_guard.value();

            assert_eq!(
                migrated_signer_id, signer_id_bytes,
                "Signer ID should be preserved after migration"
            );
        }

        {
            let versions = store.versions.lock().unwrap();
            assert_eq!(versions.get("key1"), Some(&1), "Version for key1 should be stored as 1");
            assert_eq!(versions.get("key2"), Some(&2), "Version for key2 should be stored as 2");
        }

        assert_eq!(
            store.signer_id().to_vec(),
            signer_id_bytes,
            "Signer ID should be accessible through the store"
        );
    }

    fn verify_persistence(temp_path: &Path, signer_id_bytes: &[u8]) {
        let reopened_store = RedbKVVStore::new(temp_path);

        let tx = reopened_store.db.begin_read().unwrap();
        let kv_table = tx.open_table(TABLE).unwrap();

        let value1_guard = kv_table.get("key1").unwrap().unwrap();
        let value1 = value1_guard.value();
        let (version1, data1) = RedbKVVStore::decode_vv(value1);
        assert_eq!(version1, 1);
        assert_eq!(data1, b"value1".to_vec());

        assert_eq!(
            reopened_store.signer_id().to_vec(),
            signer_id_bytes,
            "Signer ID should persist after reopening"
        );
    }
}
