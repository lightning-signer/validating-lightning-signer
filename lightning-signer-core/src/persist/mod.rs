use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, Script};

use crate::channel::{Channel, ChannelId, ChannelStub};
use crate::node::NodeConfig;
use crate::prelude::*;

/// Models for persistence
pub mod model;

/// Persister of nodes and channels
///
/// A Node will call the relevant methods here as needed.
/// The persister should durably persist before returning, for safety.
pub trait Persist: Sync + Send {
    /// Create a new node
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, seed: &[u8], network: Network);
    /// Delete a node and all of its channels.  Used in test mode.
    fn delete_node(&self, node_id: &PublicKey);
    /// Will error if exists
    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()>;
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
    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<Script>) -> Result<(), ()>;
    /// Get the allowlist from the store.
    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<Script>;
    /// Get all nodes from store
    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)>;
    /// Clears the database.  Not for production use.
    fn clear_database(&self);
}

/// A null persister for testing
pub struct DummyPersister;

#[allow(unused_variables)]
impl Persist for DummyPersister {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, seed: &[u8], network: Network) {}

    fn delete_node(&self, node_id: &PublicKey) {}

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        Ok(())
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

    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<Script>) -> Result<(), ()> {
        Ok(())
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<Script> {
        Vec::new()
    }

    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)> {
        Vec::new()
    }

    fn clear_database(&self) {}
}
