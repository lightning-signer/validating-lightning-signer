use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;

use log::*;

use vls_protocol_signer::lightning_signer;

use lightning_signer::node::{NodeConfig, NodeState as CoreNodeState};
use lightning_signer::persist::Persist;
use lightning_signer::{
    bitcoin::secp256k1::PublicKey,
    chain::tracker::ChainTracker,
    channel::{Channel, ChannelId, ChannelStub},
    monitor::ChainMonitor,
    persist::model::{ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry},
    prelude::*,
};

use crate::setup::SetupFS;

#[allow(unused)] // FIXME - remove when used
pub struct FatJsonPersister {
    setupfs: Arc<RefCell<SetupFS>>,
}

impl SendSync for FatJsonPersister {}

impl FatJsonPersister {
    pub fn new(setupfs: Arc<RefCell<SetupFS>>) -> Self {
        Self { setupfs }
    }
}

#[allow(unused)] // FIXME - remove this when mostly done
impl Persist for FatJsonPersister {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, state: &CoreNodeState) {
        unimplemented!();
    }

    fn update_node(&self, node_id: &PublicKey, state: &CoreNodeState) -> Result<(), ()> {
        unimplemented!();
    }

    fn delete_node(&self, node_id: &PublicKey) {
        unimplemented!();
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        unimplemented!();
    }

    fn new_chain_tracker(&self, node_id: &PublicKey, tracker: &ChainTracker<ChainMonitor>) {
        unimplemented!();
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), ()> {
        unimplemented!();
    }

    fn get_tracker(&self, node_id: &PublicKey) -> Result<ChainTracker<ChainMonitor>, ()> {
        unimplemented!();
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()> {
        unimplemented!();
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, ()> {
        unimplemented!();
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, CoreChannelEntry)> {
        unimplemented!();
    }

    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<String>) -> Result<(), ()> {
        unimplemented!();
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<String> {
        unimplemented!();
    }

    fn get_nodes(&self) -> Vec<(PublicKey, CoreNodeEntry)> {
        info!("FatJsonPersister::get_nodes unimplemented, looping until it is ...");
        loop {}
    }

    fn clear_database(&self) {
        unimplemented!();
    }
}
