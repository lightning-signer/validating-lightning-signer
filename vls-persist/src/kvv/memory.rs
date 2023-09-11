use crate::kvv::{Error, KVVPersister, KVVStore, KVV};
use alloc::collections::BTreeMap;
use lightning_signer::prelude::*;
use lightning_signer::SendSync;
use log::*;

/// A key-version-value in-memory store.
pub struct MemoryKVVStore {
    data: Mutex<BTreeMap<String, (u64, Vec<u8>)>>,
}

/// An iterator over a KVVStore range
pub struct Iter(alloc::vec::IntoIter<KVV>);

impl Iterator for Iter {
    type Item = KVV;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl MemoryKVVStore {
    /// Create a new MemoryKVVStore
    pub fn new() -> KVVPersister<Self> {
        let store = Self { data: Mutex::new(BTreeMap::new()) };
        KVVPersister(store)
    }
}

impl SendSync for MemoryKVVStore {}

impl KVVStore for MemoryKVVStore {
    type Iter = Iter;

    fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let version = self.get_version(key)?.map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: &[u8]) -> Result<(), Error> {
        let mut data = self.data.lock().unwrap();
        let existing = data.get(key);
        if let Some((v, vv)) = existing {
            if version < *v {
                error!("version mismatch for {}: {} < {}", key, version, v);
                // version cannot go backwards
                return Err(Error::VersionMismatch);
            } else if version == *v {
                // if same version, value must not have changed
                if vv != value {
                    error!("value mismatch for {}: {}", key, version);
                    return Err(Error::VersionMismatch);
                }
                return Ok(());
            }
        }
        data.insert(key.to_string(), (version, value.to_vec()));
        Ok(())
    }

    fn put_batch(&self, kvvs: &[&KVV]) -> Result<(), Error> {
        let mut data = self.data.lock().unwrap();
        for kvv in kvvs.into_iter() {
            let key = &kvv.0;
            let (version, value) = &kvv.1;
            let existing = data.get(key);
            if let Some((v, vv)) = existing {
                if version < v {
                    error!("version mismatch for {}: {} < {}", key, version, v);
                    // version cannot go backwards
                    return Err(Error::VersionMismatch);
                } else if version == v {
                    // if same version, value must not have changed
                    if vv != value {
                        error!("value mismatch for {}: {}", key, version);
                        return Err(Error::VersionMismatch);
                    }
                }
            }
        }
        for kvv in kvvs.into_iter() {
            let key = kvv.0.clone();
            let (version, value) = &kvv.1;
            data.insert(key.to_string(), (*version, value.clone()));
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let data = self.data.lock().unwrap();
        Ok(data.get(key).cloned())
    }

    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        let data = self.data.lock().unwrap();
        Ok(data.get(key).map(|(v, _)| *v))
    }

    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        let data = self.data.lock().unwrap();
        let mut result = Vec::new();
        for (k, (v, vv)) in data.range(prefix.to_string()..) {
            if k.starts_with(prefix) {
                result.push(KVV(k.clone(), (*v, vv.clone())));
            } else {
                break;
            }
        }
        Ok(Iter(result.into_iter()))
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.put(key, &[])
    }

    fn clear_database(&self) -> Result<(), Error> {
        self.data.lock().unwrap().clear();
        Ok(())
    }
}
