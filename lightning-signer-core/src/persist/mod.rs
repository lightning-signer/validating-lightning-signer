use crate::chain::tracker::ChainTracker;
use alloc::sync::Arc;
use bitcoin::secp256k1::PublicKey;

use crate::channel::{Channel, ChannelId, ChannelStub};
use crate::monitor::ChainMonitor;
use crate::node::{NodeConfig, NodeState};
use crate::prelude::*;

/// Models for persistence
pub mod model;

/// Storage context, for memorizing implementations
pub trait Context: Send {
    /// Exit the context, returning values that were modified
    fn exit(&self) -> Vec<(String, (u64, Vec<u8>))>;
}

struct DummyContext;

impl Context for DummyContext {
    fn exit(&self) -> Vec<(String, (u64, Vec<u8>))> {
        vec![]
    }
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
pub trait Persist: Sync + Send {
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
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, state: &NodeState, seed: &[u8]);
    /// Update node enforcement state
    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), ()>;
    /// Delete a node and all of its channels.  Used in test mode.
    fn delete_node(&self, node_id: &PublicKey);

    /// Will error if exists
    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()>;

    /// Create a new tracker
    fn new_chain_tracker(&self, node_id: &PublicKey, tracker: &ChainTracker<ChainMonitor>);
    /// Update the tracker
    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), ()>;
    /// Get the tracker
    fn get_tracker(&self, node_id: &PublicKey) -> Result<ChainTracker<ChainMonitor>, ()>;

    /// Will error if doesn't exist.
    ///
    /// * `id0` original channel ID supplied to [`Persist::new_channel()`]
    /// * `id` an optional additional permanent channel ID
    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()>;
    /// Get a channel from store
    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<model::ChannelEntry, ()>;
    /// Get all channels for a node from store
    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, model::ChannelEntry)>;
    /// Persist the allowlist to the store.
    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<String>) -> Result<(), ()>;
    /// Get the allowlist from the store.
    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<String>;
    /// Get all nodes from store
    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)>;
    /// Clears the database.  Not for production use.
    fn clear_database(&self);
}

/// A null persister for testing
pub struct DummyPersister;

#[allow(unused_variables)]
impl Persist for DummyPersister {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, state: &NodeState, seed: &[u8]) {}

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), ()> {
        Ok(())
    }

    fn delete_node(&self, node_id: &PublicKey) {}

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        Ok(())
    }

    fn new_chain_tracker(&self, node_id: &PublicKey, tracker: &ChainTracker<ChainMonitor>) {}

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn get_tracker(&self, node_id: &PublicKey) -> Result<ChainTracker<ChainMonitor>, ()> {
        Err(())
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()> {
        Ok(())
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<model::ChannelEntry, ()> {
        Err(())
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, model::ChannelEntry)> {
        Vec::new()
    }

    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<String>) -> Result<(), ()> {
        Ok(())
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<String> {
        Vec::new()
    }

    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)> {
        Vec::new()
    }

    fn clear_database(&self) {}
}
