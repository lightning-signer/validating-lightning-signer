use crate::node::node::{Channel, ChannelId, ChannelStub, NodeConfig};

pub mod ser_util;
pub mod model;

use bitcoin::Network;
use secp256k1::PublicKey;
use crate::persist::model::{ChannelEntry, NodeEntry};

pub trait Persist: Sync+Send {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, seed: &[u8], network: Network);
    /// Will error if exists
    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()>;
    /// Will error if doesn't exist.
    ///
    /// * `id0` original channel ID supplied to [`Persist::new_channel()`]
    /// * `id` an optional additional permanent channel ID
    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()>;
    fn get_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<model::ChannelEntry, ()>;
    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, model::ChannelEntry)>;
    fn get_nodes(&self) -> Vec<(PublicKey, model::NodeEntry)>;
    /// Clears the database.  Not for production use.
    fn clear_database(&self);
}

pub struct DummyPersister;

#[allow(unused_variables)]
impl Persist for DummyPersister {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, seed: &[u8], network: Network) {
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        Ok(())
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()> {
        Ok(())
    }

    fn get_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<ChannelEntry, ()> {
        Err(())
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, ChannelEntry)> {
        Vec::new()
    }

    fn get_nodes(&self) -> Vec<(PublicKey, NodeEntry)> {
        Vec::new()
    }

    fn clear_database(&self) {
    }
}

pub mod util;

#[cfg(feature="persist_kv_json")]
pub mod persist_json;
