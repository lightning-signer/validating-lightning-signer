use crate::kvv::{Error, KVVPersister, KVVStore, KVV};
use alloc::collections::BTreeMap;
use lightning_signer::persist::SignerId;
use lightning_signer::prelude::*;
use lightning_signer::SendSync;
use log::*;

/// A key-version-value in-memory store.
pub struct MemoryKVVStore {
    data: Mutex<BTreeMap<String, (u64, Vec<u8>)>>,
    signer_id: SignerId,
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
    pub fn new(signer_id: SignerId) -> KVVPersister<Self> {
        let store = Self { data: Mutex::new(BTreeMap::new()), signer_id };
        KVVPersister(store)
    }
}

impl SendSync for MemoryKVVStore {}

impl KVVStore for MemoryKVVStore {
    type Iter = Iter;

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let version = self.get_version(key)?.map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error> {
        let mut data = self.data.lock().unwrap();
        let existing = data.get(key);
        if let Some((ver, val)) = existing {
            if version < *ver {
                error!("version mismatch for {}: {} < {}", key, version, ver);
                // version cannot go backwards
                return Err(Error::VersionMismatch);
            } else if version == *ver {
                // if same version, value must not have changed
                if *val != value {
                    error!("value mismatch for {}: {}", key, version);
                    return Err(Error::VersionMismatch);
                }
                return Ok(());
            }
        }
        data.insert(key.to_string(), (version, value));
        Ok(())
    }

    fn put_batch(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        let mut data = self.data.lock().unwrap();
        for kvv in kvvs.iter() {
            let key = &kvv.0;
            let (version, value) = &kvv.1;
            let existing = data.get(key);
            if let Some((ver, val)) = existing {
                if version < ver {
                    error!("version mismatch for {}: {} < {}", key, version, ver);
                    // version cannot go backwards
                    return Err(Error::VersionMismatch);
                } else if version == ver {
                    // if same version, value must not have changed
                    if val != value {
                        error!("value mismatch for {}: {}", key, version);
                        return Err(Error::VersionMismatch);
                    }
                }
            }
        }
        for kvv in kvvs.into_iter() {
            let key = kvv.0;
            data.insert(key.to_string(), kvv.1);
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
        for (k, (ver, value)) in data.range(prefix.to_string()..) {
            if k.starts_with(prefix) {
                result.push(KVV(k.clone(), (*ver, value.clone())));
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
        self.data.lock().unwrap().clear();
        Ok(())
    }

    fn signer_id(&self) -> SignerId {
        self.signer_id
    }
}
