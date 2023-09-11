use crate::kvv::{Error, KVVPersister, KVVStore, KVV};
use alloc::collections::BTreeMap;
use lightning_signer::prelude::*;
use lightning_signer::{persist::Mutations, SendSync};
use log::*;

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
pub struct CloudKVVStore<L: KVVStore> {
    local: L,
    commit_log: Mutex<Option<BTreeMap<String, (u64, Vec<u8>)>>>,
}

impl<L: KVVStore> CloudKVVStore<L> {
    /// Create a new CloudKVVStore backed by the given local KVVStore.
    pub fn new(local: L) -> KVVPersister<Self> {
        let s = Self { local, commit_log: Mutex::new(None) };
        KVVPersister(s)
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

    fn enter(&self) {
        let mut commit_log = self.commit_log.lock().unwrap();
        assert!(commit_log.is_none(), "cannot enter transaction twice");
        *commit_log = Some(BTreeMap::new());
    }

    fn prepare(&self) -> Mutations {
        let commit_log_opt = self.commit_log.lock().unwrap();
        let commit_log = commit_log_opt.as_ref().expect("not in transaction");
        let mutations =
            commit_log.iter().map(|(k, (v, vv))| (k.clone(), (*v, vv.clone()))).collect();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvv::redb::RedbKVVStore;

    #[test]
    fn cloud_test() -> Result<(), Error> {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        local.put("foo1", b"bar")?;

        let cloud = CloudKVVStore::new(local);

        cloud.enter();
        cloud.put("foo2", b"boo")?;

        // wrong version
        assert!(cloud.put_with_version("foo1", 0, b"bar2").is_err());

        assert_eq!(cloud.get("foo1")?.unwrap().1, b"bar");
        cloud.put_with_version("foo1", 1, b"bar2")?;
        assert_eq!(cloud.get("foo1")?.unwrap().1, b"bar2");

        let mutations = cloud.prepare();
        assert_eq!(mutations.len(), 2);
        assert_eq!(mutations[0], ("foo1".to_owned(), (1, b"bar2".to_vec())));
        assert_eq!(mutations[1], ("foo2".to_owned(), (0, b"boo".to_vec())));

        assert_eq!(cloud.local.get("foo1")?.unwrap(), (0, b"bar".to_vec()));
        cloud.commit()?;

        assert_eq!(cloud.local.get("foo1")?.unwrap(), (1, b"bar2".to_vec()));

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
        cloud.enter();
        assert_eq!(cloud.get("foo").unwrap().unwrap().1, b"bar");
    }

    #[test]
    #[should_panic(expected = "cannot put_batch_unlogged while in transaction")]
    fn put_batch_unlogged_in_transaction_test() {
        let tempdir = tempfile::tempdir().unwrap();
        let local = RedbKVVStore::new(tempdir.path()).0;
        let cloud = CloudKVVStore::new(local);
        cloud.enter();
        cloud.put_batch_unlogged(&[]).unwrap();
    }
}
