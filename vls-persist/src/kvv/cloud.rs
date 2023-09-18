use crate::kvv::{Error, KVVPersister, KVVStore, KVV};
use alloc::collections::BTreeMap;
use lightning_signer::persist::SignerId;
use lightning_signer::prelude::*;
use lightning_signer::{persist::Mutations, SendSync};
use log::*;

/// The key used to store the last-writer record.
pub const LAST_WRITER_KEY: &str = "_WRITER";

/// A cloud key-version-value store backed by a local KVVStore.
/// The local store maintains an up to date copy of the cloud store.
/// Updating the stores is transactional:
/// - enter() starts a transaction
/// - put() and delete() log the change in the commit log
/// - prepare() returns the commit log as a Mutations object
/// - the caller stores the Mutations object in the cloud
/// - commit() commits the changes to the local store
///
/// If the cloud store has updates, you can use `self.put_batch_unlogged`
/// to apply them directly to the local store.
///
/// We add a last-writer record to each Mutations object returned by
/// prepare(). This record is used to detect if the cloud store is in
/// sync with the local store.  We will get a put conflict if they are not.
///
/// You can also use `self.is_in_sync` to check for sync.
pub struct CloudKVVStore<L: KVVStore> {
    local: L,
    commit_log: Mutex<Option<BTreeMap<String, (u64, Vec<u8>)>>>,
}

impl<L: KVVStore> CloudKVVStore<L> {
    pub fn get_local(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        self.local.get(key)
    }
}

impl<L: KVVStore> CloudKVVStore<L> {
    /// Create a new CloudKVVStore backed by the given local KVVStore.
    pub fn new(local: L) -> KVVPersister<Self> {
        let s = Self { local, commit_log: Mutex::new(None) };
        KVVPersister(s)
    }

    /// Check if the cloud store is in sync with the local store,
    /// given version-value of the last-writer record.
    ///
    /// Note that this takes an Option so you can check even if the
    /// cloud storage does not have a last-writer record yet (e.g. a new
    /// store, or an upgrade).
    ///
    /// See also `self.prepare` and `LAST_WRITER_KEY`.
    pub fn is_in_sync(&self, version_value: Option<(u64, Vec<u8>)>) -> bool {
        match self.local.get(LAST_WRITER_KEY) {
            Ok(vv) => version_value == vv,
            _ => {
                error!("failed to get last-writer record");
                false
            }
        }
    }
}

impl<L: KVVStore> SendSync for CloudKVVStore<L> {}

impl<L: KVVStore> KVVStore for CloudKVVStore<L> {
    type Iter = L::Iter;

    fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let version = self.get_version(key)?.map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: &[u8]) -> Result<(), Error> {
        let mut commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_mut().expect("not in transaction");
        let local = self.local.get(key)?;
        let existing = commit_log.get(key).or_else(|| local.as_ref());
        if let Some((v, _)) = existing {
            if version < *v {
                error!("version mismatch for {}: {} < {}", key, version, v);
                // version cannot go backwards
                return Err(Error::VersionMismatch);
            } else if version == *v {
                // if same version, value must not have changed
                let existing = self.local.get(key).expect("failed to get").unwrap();
                if existing.1 != value {
                    error!("value mismatch for {}: {}", key, version);
                    return Err(Error::VersionMismatch);
                }
                return Ok(());
            }
        }
        commit_log.insert(key.to_string(), (version, value.to_vec()));
        Ok(())
    }

    fn put_batch(&self, kvvs: &[&KVV]) -> Result<(), Error> {
        // we are already transactional, because of commit logging, so just call put_with_version
        for kvv in kvvs.into_iter() {
            self.put_with_version(kvv.0.as_str(), kvv.1 .0, &kvv.1 .1)?;
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_ref().expect("not in transaction");
        if let Some((v, vv)) = commit_log.get(key) {
            return Ok(Some((*v, vv.clone())));
        }
        self.local.get(key)
    }

    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_ref().expect("not in transaction");
        if let Some((v, _)) = commit_log.get(key) {
            return Ok(Some(*v));
        }
        self.local.get_version(key)
    }

    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        // TODO merge with commit log
        self.local.get_prefix(prefix)
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.put(key, &[])
    }

    fn clear_database(&self) -> Result<(), Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_ref().expect("not in transaction");
        assert!(commit_log.is_empty(), "cannot clear database with pending commits");
        self.local.clear_database()
    }

    fn enter(&self) -> Result<(), Error> {
        let last_writer = self.local.get(LAST_WRITER_KEY)?;
        let next_writer_version = last_writer.map(|(ver, _)| ver + 1).unwrap_or(0);

        let mut commit_log = self.commit_log.lock().unwrap();
        assert!(commit_log.is_none(), "cannot enter transaction twice");
        let mut log = BTreeMap::new();
        log.insert(LAST_WRITER_KEY.to_owned(), (next_writer_version, self.signer_id().to_vec()));
        *commit_log = Some(log);
        Ok(())
    }

    fn prepare(&self) -> Mutations {
        let mut commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_mut().expect("not in transaction");
        let mutations: Vec<_> =
            commit_log.iter().map(|(k, (v, vv))| (k.clone(), (*v, vv.clone()))).collect();

        // optimize out effectively empty mutations
        if mutations.len() == 1 {
            assert_eq!(mutations[0].0, LAST_WRITER_KEY);
            commit_log.clear();
            return Mutations::new();
        }

        Mutations::from_vec(mutations)
    }

    fn commit(&self) -> Result<(), Error> {
        let mut commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.take().expect("not in transaction");
        let mut kvvs = Vec::new();
        for (key, (version, vv)) in commit_log.into_iter() {
            kvvs.push(KVV(key, (version, vv)));
        }
        let kvv_refs: Vec<&KVV> = kvvs.iter().collect();
        self.local.put_batch(&kvv_refs)?;
        Ok(())
    }

    fn put_batch_unlogged(&self, kvvs: &[&KVV]) -> Result<(), Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        if commit_log_opt.is_some() {
            panic!("cannot put_batch_unlogged while in transaction");
        }
        self.local.put_batch(kvvs)
    }

    fn signer_id(&self) -> SignerId {
        self.local.signer_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvv::redb::RedbKVVStore;

    #[test]
    fn cloud_test() -> Result<(), Error> {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        let signer_id = local.signer_id();
        local.put("foo1", b"bar")?;

        let cloud = CloudKVVStore::new(local);

        cloud.enter()?;
        cloud.put("foo2", b"boo")?;

        // wrong version
        assert!(cloud.put_with_version("foo1", 0, b"bar2").is_err());

        assert_eq!(cloud.get("foo1")?.unwrap().1, b"bar");
        cloud.put_with_version("foo1", 1, b"bar2")?;
        assert_eq!(cloud.get("foo1")?.unwrap().1, b"bar2");

        let mutations = cloud.prepare();
        // 2 changes and 1 last writer record
        assert_eq!(mutations.len(), 3);
        assert_eq!(mutations[0], ("_WRITER".to_owned(), (0, signer_id.to_vec())));
        assert_eq!(mutations[1], ("foo1".to_owned(), (1, b"bar2".to_vec())));
        assert_eq!(mutations[2], ("foo2".to_owned(), (0, b"boo".to_vec())));

        assert_eq!(cloud.local.get("foo1")?.unwrap(), (0, b"bar".to_vec()));
        cloud.commit()?;

        assert_eq!(cloud.local.get("foo1")?.unwrap(), (1, b"bar2".to_vec()));

        assert!(cloud.is_in_sync(Some((0, signer_id.to_vec()))));

        Ok(())
    }

    #[test]
    #[should_panic(expected = "not in transaction")]
    fn no_transaction_test() {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        let cloud = CloudKVVStore::new(local);
        cloud.put("foo", b"bar").unwrap();
    }

    #[test]
    fn put_batch_unlogged_test() {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        let cloud = CloudKVVStore::new(local);
        cloud.put_batch_unlogged(&[&KVV("foo".to_string(), (0, b"bar".to_vec()))]).unwrap();
        cloud.enter().unwrap();
        assert_eq!(cloud.get("foo").unwrap().unwrap().1, b"bar");
    }

    #[test]
    #[should_panic(expected = "cannot put_batch_unlogged while in transaction")]
    fn put_batch_unlogged_in_transaction_test() {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        let cloud = CloudKVVStore::new(local);
        cloud.enter().unwrap();
        cloud.put_batch_unlogged(&[]).unwrap();
    }
}