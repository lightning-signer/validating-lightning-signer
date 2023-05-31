use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{NodeConfig, NodeState};
use lightning_signer::persist::model::{ChannelEntry, NodeEntry};
use lightning_signer::persist::{Context, Error, Persist};
use lightning_signer::policy::validator::ValidatorFactory;
use lightning_signer::prelude::*;
use lightning_signer::SendSync;
use std::sync::{Arc, Mutex};

/// A composite persister that writes to two underlying persisters.
///
/// NOTE: only the backup persister is assumed to (optionally) use context (see `[Persist::enter]`).
///
/// The main persister is written to first.
///
/// On startup, the node should write the entire node state (including channels)
/// to this persister, to ensure that the backup is up to date.  This is because
/// the backup persister is only written to after the main persister, so if the
/// signer crashes, the backup persister may be missing the latest state.
pub struct BackupPersister<M: Persist, B: Persist> {
    main: M,
    backup: B,
}

impl<M: Persist, B: Persist> BackupPersister<M, B> {
    // Create a new backup persister
    pub fn new(main: M, backup: B) -> Self {
        Self { main, backup }
    }
}

impl<M: Persist, B: Persist> SendSync for BackupPersister<M, B> {}

impl<M: Persist, B: Persist> Persist for BackupPersister<M, B> {
    fn enter(&self, state: Arc<Mutex<OrderedMap<String, (u64, Vec<u8>)>>>) -> Box<dyn Context> {
        self.backup.enter(state)
    }

    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        self.main.new_node(node_id, config, state)?;
        self.backup.new_node(node_id, config, state)
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        self.main.update_node(node_id, state)?;
        self.backup.update_node(node_id, state)
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        self.main.delete_node(node_id)?;
        self.backup.delete_node(node_id)
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        self.main.new_channel(node_id, stub)?;
        self.backup.new_channel(node_id, stub)
    }

    fn new_chain_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        self.main.new_chain_tracker(node_id, tracker)?;
        self.backup.new_chain_tracker(node_id, tracker)
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        self.main.update_tracker(node_id, tracker)?;
        self.backup.update_tracker(node_id, tracker)
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<ChainTracker<ChainMonitor>, Error> {
        self.main.get_tracker(node_id, validator_factory.clone())
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        self.main.update_channel(node_id, channel)?;
        self.backup.update_channel(node_id, channel)
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<ChannelEntry, Error> {
        self.main.get_channel(node_id, channel_id)
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, ChannelEntry)>, Error> {
        self.main.get_node_channels(node_id)
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        self.main.update_node_allowlist(node_id, allowlist.clone())?;
        self.backup.update_node_allowlist(node_id, allowlist)
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        self.main.get_node_allowlist(node_id)
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, NodeEntry)>, Error> {
        self.main.get_nodes()
    }

    fn clear_database(&self) -> Result<(), Error> {
        self.main.clear_database()?;
        self.backup.clear_database()
    }
}
