use crate::kvv::{Error, KVVStore, KVV};
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
    pub fn new(signer_id: SignerId) -> Self {
        Self { data: Mutex::new(BTreeMap::new()), signer_id }
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

    fn reset_versions(&self) -> Result<(), Error> {
        let mut data = self.data.lock().unwrap();
        for (_, (ver, _)) in data.iter_mut() {
            *ver = 0;
        }
        Ok(())
    }

    fn signer_id(&self) -> SignerId {
        self.signer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    fn make_kvv(key: &str, version: u64, value: Vec<u8>) -> KVV {
        KVV(key.to_string(), (version, value))
    }

    #[test]
    fn test_new() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        assert_eq!(store.signer_id(), signer_id);
        assert!(store.data.lock().unwrap().is_empty());
    }

    #[test]
    fn test_put() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);

        let key = "key1";
        let value = vec![1, 2, 3];
        assert!(store.put(key, value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (0, value.clone()));

        let new_value = vec![4, 5, 6];
        assert!(store.put(key, new_value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (1, new_value));
    }

    #[test]
    fn test_put_with_version() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        let key = "key1";
        let value = vec![1, 2, 3];

        assert!(store.put_with_version(key, 0, value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (0, value.clone()));

        assert!(store.put_with_version(key, 0, value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (0, value.clone()));

        let different_value = vec![4, 5, 6];
        assert!(matches!(
            store.put_with_version(key, 0, different_value),
            Err(Error::VersionMismatch)
        ));

        let new_value = vec![7, 8, 9];
        assert!(store.put_with_version(key, 1, new_value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (1, new_value));
    }

    #[test]
    fn test_put_batch() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        let kvvs = vec![make_kvv("key1", 0, vec![1, 2, 3]), make_kvv("key2", 0, vec![4, 5, 6])];

        assert!(store.put_batch(kvvs).is_ok());
        assert_eq!(store.get("key1").unwrap().unwrap(), (0, vec![1, 2, 3]));
        assert_eq!(store.get("key2").unwrap().unwrap(), (0, vec![4, 5, 6]));

        let valid_kvvs = vec![make_kvv("key1", 0, vec![1, 2, 3])];
        assert!(store.put_batch(valid_kvvs).is_ok());

        let new_kvvs = vec![make_kvv("key1", 1, vec![7, 8, 9])];
        assert!(store.put_batch(new_kvvs).is_ok());
        assert_eq!(store.get("key1").unwrap().unwrap(), (1, vec![7, 8, 9]));
    }

    #[test]
    fn test_get() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        let key = "key1";
        let value = vec![1, 2, 3];

        assert!(store.get(key).unwrap().is_none());

        assert!(store.put(key, value.clone()).is_ok());
        let result = store.get(key).unwrap().unwrap();
        assert_eq!(result, (0, value));
    }

    #[test]
    fn test_get_version() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        let key = "key1";
        let value = vec![1, 2, 3];

        assert!(store.get_version(key).unwrap().is_none());

        assert!(store.put(key, value).is_ok());
        assert_eq!(store.get_version(key).unwrap(), Some(0));

        assert!(store.put(key, vec![4, 5, 6]).is_ok());
        assert_eq!(store.get_version(key).unwrap(), Some(1));
    }

    #[test]
    fn test_get_prefix() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);

        assert!(store.put("prefix/key1", vec![1, 2, 3]).is_ok());
        assert!(store.put("prefix/key2", vec![4, 5, 6]).is_ok());
        assert!(store.put("other/key", vec![7, 8, 9]).is_ok());

        let iter = store.get_prefix("nonexistent/").unwrap();
        let results: Vec<KVV> = iter.collect();
        assert!(results.is_empty());

        let mut iter = store.get_prefix("prefix/").unwrap();
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_delete() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        let key = "key1";
        let value = vec![1, 2, 3];

        assert!(store.delete(key).is_ok());
        assert_eq!(store.get(key).unwrap().unwrap(), (0, vec![]));

        assert!(store.put(key, value).is_ok());
        assert!(store.delete(key).is_ok());
        assert_eq!(store.get(key).unwrap().unwrap(), (2, vec![]));
    }

    #[test]
    fn test_clear_database() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);

        assert!(store.put("key1", vec![1, 2, 3]).is_ok());
        assert!(store.put("key2", vec![4, 5, 6]).is_ok());

        assert!(store.clear_database().is_ok());
        assert!(store.get("key1").unwrap().is_none());
        assert!(store.get("key2").unwrap().is_none());
        assert!(store.data.lock().unwrap().is_empty());
    }

    #[test]
    fn test_reset_versions() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);

        assert!(store.put("key1", vec![1, 2, 3]).is_ok());
        assert!(store.put("key1", vec![4, 5, 6]).is_ok());
        assert!(store.put("key2", vec![7, 8, 9]).is_ok());

        assert!(store.reset_versions().is_ok());
        assert_eq!(store.get_version("key1").unwrap(), Some(0));
        assert_eq!(store.get_version("key2").unwrap(), Some(0));

        assert_eq!(store.get("key1").unwrap().unwrap().1, vec![4, 5, 6]);
        assert_eq!(store.get("key2").unwrap().unwrap().1, vec![7, 8, 9]);
    }

    #[test]
    fn test_signer_id() {
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let store = MemoryKVVStore::new(signer_id);
        assert_eq!(store.signer_id(), signer_id);
    }
}
