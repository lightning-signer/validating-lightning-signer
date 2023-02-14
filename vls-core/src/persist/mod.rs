use crate::chain::tracker::ChainTracker;
use alloc::sync::Arc;
use bitcoin::secp256k1::PublicKey;

use crate::channel::{Channel, ChannelId, ChannelStub};
use crate::monitor::ChainMonitor;
use crate::node::{NodeConfig, NodeState};
use crate::policy::validator::ValidatorFactory;
use crate::prelude::*;

/// Models for persistence
pub mod model;

/// A list of mutations memorized by a memorizing persister
pub type Mutations = Vec<(String, (u64, Vec<u8>))>;

/// Storage context, for memorizing implementations
pub trait Context: Send {
    /// Exit the context, returning values that were modified
    fn exit(&self) -> Mutations;
}

struct DummyContext;

impl Context for DummyContext {
    fn exit(&self) -> Mutations {
        vec![]
    }
}

#[derive(Clone, Debug)]
/// Error returned by persister
pub enum Error {
    /// Persister is temporarily unavailable, might work later
    Unavailable(String),
    /// Inconsistent state, needed resource is missing
    NotFound(String),
    /// Inconsistent state, resource already present
    AlreadyExists(String),
    /// Non-recoverable internal error
    Internal(String),
}

/// Persister of nodes and channels
///
/// A Node will call the relevant methods here as needed.
///
/// There are two types of persisters:
///
/// - Memorizing persisters, which only store the mutations in memory, for later
/// retrieval and storage by the caller.  This is used in embedded environments
/// to return the mutations to the host system.
///
/// - Real persisters, which store the mutations directly, for example to disk.
/// This is used in non-embedded environments. This kind of persister should
/// persist durably before returning, for safety.
///
pub trait Persist: SendSync {
    /// Enter a persistence context
    ///
    /// Entering while the thread is already in a context will panic
    ///
    /// Returns a [`Context`] object, which can be used to retrieve the
    /// modified entries and exit the context.
    ///
    /// If this is not a memorizing context, the returned object will always
    /// have an empty list of modified entries.
    fn enter(&self, _state: Arc<Mutex<OrderedMap<String, (u64, Vec<u8>)>>>) -> Box<dyn Context> {
        Box::new(DummyContext)
    }

    /// Create a new node
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error>;

    /// Update node enforcement state
    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error>;

    /// Delete a node and all of its channels.  Used in test mode.
    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error>;

    /// Will error if exists
    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error>;

    /// Create a new tracker
    fn new_chain_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error>;

    /// Update the tracker
    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error>;

    /// Get the tracker
    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<ChainTracker<ChainMonitor>, Error>;

    /// Will error if doesn't exist.
    ///
    /// * `id0` original channel ID supplied to [`Persist::new_channel()`]
    /// * `id` an optional additional permanent channel ID
    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error>;

    /// Get a channel from store
    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<model::ChannelEntry, Error>;

    /// Get all channels for a node from store
    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, model::ChannelEntry)>, Error>;

    /// Persist the allowlist to the store.
    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error>;

    /// Get the allowlist from the store.
    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error>;

    /// Get all nodes from store
    fn get_nodes(&self) -> Result<Vec<(PublicKey, model::NodeEntry)>, Error>;

    /// Clears the database.  Not for production use.
    fn clear_database(&self) -> Result<(), Error>;
}

/// A null persister for testing
pub struct DummyPersister;

impl SendSync for DummyPersister {}

#[allow(unused_variables)]
impl Persist for DummyPersister {
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        Ok(())
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        Ok(())
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        Ok(())
    }

    fn new_chain_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<ChainTracker<ChainMonitor>, Error> {
        Err(Error::Internal(format!("get_tracker unimplemented")))
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        Ok(())
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<model::ChannelEntry, Error> {
        Err(Error::Internal(format!("get_channel unimplemented")))
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, model::ChannelEntry)>, Error> {
        Ok(Vec::new())
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        Ok(Vec::new())
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, model::NodeEntry)>, Error> {
        Ok(Vec::new())
    }

    fn clear_database(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Seed persister
///
/// By convention, the `key` is the hex-encoded public key, but this may change
/// in the future.
pub trait SeedPersist: Sync + Send {
    /// Persist the seed
    fn put(&self, key: &str, seed: &[u8]);
    /// Get the seed, if exists
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// List the seeds
    fn list(&self) -> Vec<String>;
}

/// A null seed persister for testing
pub struct DummySeedPersister;

impl SeedPersist for DummySeedPersister {
    fn put(&self, _key: &str, _seed: &[u8]) {}

    fn get(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }

    fn list(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A single in-memory seed persister - for testing
pub struct MemorySeedPersister {
    seed: Vec<u8>,
}

impl MemorySeedPersister {
    /// Create a new in-memory seed persister
    pub fn new(seed: Vec<u8>) -> Self {
        Self { seed }
    }
}

impl SeedPersist for MemorySeedPersister {
    fn put(&self, _key: &str, _seed: &[u8]) {
        unimplemented!()
    }

    fn get(&self, _key: &str) -> Option<Vec<u8>> {
        Some(self.seed.clone())
    }

    fn list(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(feature = "std")]
/// File system persisters
pub mod fs {
    use crate::persist::SeedPersist;
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use std::fs;
    use std::path::PathBuf;

    /// A file system directory seed persister
    ///
    /// Stores seed in a file named `<node_id_hex>.seed` in the directory
    pub struct FileSeedPersister {
        path: PathBuf,
    }

    impl FileSeedPersister {
        /// Create
        pub fn new<P: Into<PathBuf>>(path: P) -> Self {
            Self { path: path.into() }
        }

        fn seed_path_for_key(&self, node_id: &str) -> PathBuf {
            let mut path = self.path.clone();
            path.push(format!("{}.seed", node_id));
            path
        }
    }

    impl SeedPersist for FileSeedPersister {
        fn put(&self, key: &str, seed: &[u8]) {
            write_seed(self.seed_path_for_key(key), seed);
        }

        fn get(&self, key: &str) -> Option<Vec<u8>> {
            read_seed(self.seed_path_for_key(key))
        }

        fn list(&self) -> Vec<String> {
            let mut keys = Vec::new();
            for entry in fs::read_dir(&self.path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if let Some(fileext) = path.extension() {
                    if fileext == "seed" {
                        let key = path.file_stem().unwrap().to_str().unwrap();
                        keys.push(key.to_string());
                    }
                }
            }
            keys
        }
    }

    fn write_seed(path: PathBuf, seed: &[u8]) {
        fs::write(path, seed.to_hex()).unwrap();
    }

    fn read_seed(path: PathBuf) -> Option<Vec<u8>> {
        fs::read_to_string(path).ok().map(|s| Vec::from_hex(&s).expect("bad hex seed"))
    }
}
