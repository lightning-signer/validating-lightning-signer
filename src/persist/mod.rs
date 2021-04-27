use crate::node::node::{Channel, ChannelId, ChannelStub, NodeConfig};

pub mod model;
pub mod ser_util;

use crate::persist::model::{ChannelEntry, NodeEntry};
use bitcoin::Network;
use bitcoin::secp256k1::PublicKey;

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
    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<model::ChannelEntry, ()>;
    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, model::ChannelEntry)>;
    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)>;
    /// Clears the database.  Not for production use.
    fn clear_database(&self);
}

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

    // BEGIN NOT TESTED

    fn get_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<ChannelEntry, ()> {
        Err(())
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, ChannelEntry)> {
        Vec::new()
    }

    // END NOT TESTED

    fn get_nodes(&self) -> Vec<(PublicKey, NodeEntry)> {
        Vec::new()
    }

    fn clear_database(&self) {} // NOT TESTED
}

pub mod util;

#[cfg(feature = "persist_kv_json")]
pub mod persist_json;
