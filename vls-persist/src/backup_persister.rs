use core::sync::atomic::{AtomicBool, Ordering};
use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{NodeConfig, NodeState};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::persist::{ChainTrackerListenerEntry, Error, Persist};
use lightning_signer::policy::validator::ValidatorFactory;
use lightning_signer::prelude::*;
use lightning_signer::SendSync;

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
    // this flag prevents reads/writes to the main persister if it requires recovery
    // until the initial restore from persistence is complete
    initial_restore_complete: AtomicBool,
}

impl<M: Persist, B: Persist> BackupPersister<M, B> {
    // Create a new backup persister
    pub fn new(main: M, backup: B) -> Self {
        Self { main, backup, initial_restore_complete: AtomicBool::new(false) }
    }

    // the main persister is ready if it doesn't require recovery, or if the initial restore
    // from the backup persister is complete.
    fn main_is_ready(&self) -> bool {
        !self.main.recovery_required() || self.initial_restore_complete.load(Ordering::Relaxed)
    }
}

impl<M: Persist, B: Persist> SendSync for BackupPersister<M, B> {}

impl<M: Persist, B: Persist> Persist for BackupPersister<M, B> {
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.new_node(node_id, config, state)?;
        }
        self.backup.new_node(node_id, config, state)
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.update_node(node_id, state)?;
        }
        self.backup.update_node(node_id, state)
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.delete_node(node_id)?;
        }
        self.backup.delete_node(node_id)
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.new_channel(node_id, stub)?;
        }
        self.backup.new_channel(node_id, stub)
    }

    fn delete_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.delete_channel(node_id, channel_id)?;
        }
        self.backup.delete_channel(node_id, channel_id)
    }

    fn new_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.new_tracker(node_id, tracker)?;
        }
        self.backup.new_tracker(node_id, tracker)
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.update_tracker(node_id, tracker)?;
        }
        self.backup.update_tracker(node_id, tracker)
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<(ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>), Error> {
        if self.main_is_ready() {
            self.main.get_tracker(node_id, validator_factory)
        } else {
            self.backup.get_tracker(node_id, validator_factory)
        }
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.update_channel(node_id, channel)?;
        }
        self.backup.update_channel(node_id, channel)
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, Error> {
        if self.main_is_ready() {
            self.main.get_channel(node_id, channel_id)
        } else {
            self.backup.get_channel(node_id, channel_id)
        }
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, CoreChannelEntry)>, Error> {
        if self.main_is_ready() {
            self.main.get_node_channels(node_id)
        } else {
            self.backup.get_node_channels(node_id)
        }
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        if self.main_is_ready() {
            self.main.update_node_allowlist(node_id, allowlist.clone())?;
        }
        self.backup.update_node_allowlist(node_id, allowlist)
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        if self.main_is_ready() {
            self.main.get_node_allowlist(node_id)
        } else {
            self.backup.get_node_allowlist(node_id)
        }
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, CoreNodeEntry)>, Error> {
        if self.main_is_ready() {
            self.main.get_nodes()
        } else {
            self.backup.get_nodes()
        }
    }

    fn clear_database(&self) -> Result<(), Error> {
        self.main.clear_database()?;
        self.backup.clear_database()
    }

    fn on_initial_restore(&self) -> bool {
        self.initial_restore_complete.store(true, Ordering::Relaxed);
        // we always want a sync on startup, either main -> backup in normal
        // operation or backup -> main when recovering from main persister failure
        true
    }

    fn signer_id(&self) -> [u8; 16] {
        self.main.signer_id()
    }
}

#[cfg(test)]
#[allow(unused_variables)]
mod tests {
    use super::*;
    use crate::model::{ChainTrackerEntry, NodeEntry, NodeStateEntry};
    use lightning_signer::node::Node;
    use lightning_signer::persist::SignerId;
    use lightning_signer::util::test_utils::{
        hex_decode, make_services, TEST_CHANNEL_ID, TEST_NODE_CONFIG, TEST_SEED,
    };
    use serde_json::{from_slice, to_vec};
    use std::collections::BTreeMap;

    // A persister that "persists" to a BTreeMap
    #[derive(Clone)]
    struct TestPersister {
        state: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    impl TestPersister {
        fn new() -> Self {
            Self { state: Arc::new(Mutex::new(BTreeMap::new())) }
        }
    }

    impl SendSync for TestPersister {}

    impl Persist for TestPersister {
        fn new_node(
            &self,
            node_id: &PublicKey,
            config: &NodeConfig,
            node_state: &NodeState,
        ) -> Result<(), Error> {
            self.update_node(node_id, node_state)?;
            let mut state = self.state.lock().unwrap();
            let key = format!("node/entry/{}", &node_id.to_string());
            let entry = NodeEntry {
                key_derivation_style: config.key_derivation_style as u8,
                network: config.network.to_string(),
            };
            let value = to_vec(&entry).unwrap();
            state.insert(key, value);
            Ok(())
        }

        fn update_node(&self, node_id: &PublicKey, node_state: &NodeState) -> Result<(), Error> {
            let mut state = self.state.lock().unwrap();
            let key = format!("node/state/{}", &node_id.to_string());
            let state_entry: NodeStateEntry = node_state.into();
            let state_value = to_vec(&state_entry).unwrap();
            state.insert(key, state_value);
            Ok(())
        }

        fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
            todo!()
        }

        fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
            todo!()
        }

        fn delete_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<(), Error> {
            todo!()
        }

        fn new_tracker(
            &self,
            node_id: &PublicKey,
            tracker: &ChainTracker<ChainMonitor>,
        ) -> Result<(), Error> {
            let mut state = self.state.lock().unwrap();
            let key = format!("node/tracker/{}", &node_id.to_string());
            let model: ChainTrackerEntry = tracker.into();
            let value = to_vec(&model).unwrap();
            state.insert(key, value);
            Ok(())
        }

        fn update_tracker(
            &self,
            node_id: &PublicKey,
            tracker: &ChainTracker<ChainMonitor>,
        ) -> Result<(), Error> {
            self.new_tracker(node_id, tracker)
        }

        fn get_tracker(
            &self,
            node_id: PublicKey,
            validator_factory: Arc<dyn ValidatorFactory>,
        ) -> Result<(ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>), Error> {
            let state = self.state.lock().unwrap();
            let key = format!("node/tracker/{}", &node_id.to_string());
            let value = state.get(&key).unwrap();
            let model: ChainTrackerEntry = from_slice(&value).unwrap();
            Ok(model.into_tracker(node_id.clone(), validator_factory))
        }

        fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
            todo!()
        }

        fn get_channel(
            &self,
            node_id: &PublicKey,
            channel_id: &ChannelId,
        ) -> Result<CoreChannelEntry, Error> {
            todo!()
        }

        fn get_node_channels(
            &self,
            node_id: &PublicKey,
        ) -> Result<Vec<(ChannelId, CoreChannelEntry)>, Error> {
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

        fn get_nodes(&self) -> Result<Vec<(PublicKey, CoreNodeEntry)>, Error> {
            let state = self.state.lock().unwrap();
            let keys: Vec<_> = state
                .iter()
                .filter_map(
                    |(k, _)| {
                        if k.starts_with("node/entry/") {
                            Some(k.clone())
                        } else {
                            None
                        }
                    },
                )
                .collect();
            let mut res = Vec::new();
            for key in keys {
                let id = hex::decode(key.replacen("node/entry/", "", 1)).unwrap();
                let node_id = PublicKey::from_slice(&id).unwrap();
                let value = state.get(&format!("node/entry/{}", hex::encode(&id))).unwrap();
                let entry: NodeEntry = from_slice(&value).unwrap();
                let state_value = state.get(&format!("node/state/{}", hex::encode(&id))).unwrap();
                let state_entry: NodeStateEntry = from_slice(&state_value).unwrap();
                let node_state = NodeState {
                    invoices: Default::default(),
                    issued_invoices: Default::default(),
                    payments: Default::default(),
                    excess_amount: 0,
                    log_prefix: "".to_string(),
                    velocity_control: state_entry.velocity_control.into(),
                    fee_velocity_control: state_entry.fee_velocity_control.into(),
                    last_summary: String::new(),
                    dbid_high_water_mark: state_entry.dbid_high_water_mark,
                };
                let node_entry = CoreNodeEntry {
                    key_derivation_style: entry.key_derivation_style as u8,
                    network: entry.network,
                    state: node_state,
                };
                res.push((node_id, node_entry));
            }
            Ok(res)
        }

        fn clear_database(&self) -> Result<(), Error> {
            todo!()
        }

        fn recovery_required(&self) -> bool {
            self.state.lock().unwrap().is_empty()
        }

        fn signer_id(&self) -> SignerId {
            todo!()
        }
    }

    #[test]
    fn backup_persister_test() {
        let persister = TestPersister::new();
        let channel_id0 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let seed = hex_decode(TEST_SEED[1]).unwrap();
        let mut services = make_services();
        services.persister = Arc::new(persister.clone());
        let node = Arc::new(Node::new(TEST_NODE_CONFIG, &seed, vec![], services));
        let node_id = node.get_id();

        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();
        persister.new_tracker(&node_id, &node.get_tracker()).unwrap();

        let nodes1 = persister.get_nodes().unwrap();
        assert_eq!(nodes1.len(), 1);
        let (node_id1, node_entry1) = nodes1.into_iter().next().unwrap();
        assert_eq!(node_id, node_id1);

        let backup = TestPersister::new();
        let backup_persister = Arc::new(BackupPersister::new(persister, backup.clone()));
        let nodes2 = backup_persister.get_nodes().unwrap();
        let (node_id2, node_entry2) = nodes2.into_iter().next().unwrap();
        assert_eq!(node_id, node_id2);

        let mut services = make_services();
        services.persister = backup_persister.clone();
        let node = Node::restore_node(&node_id, node_entry1, &seed, services.clone()).unwrap();

        // test recovery by starting with a wiped main persister
        let persister = TestPersister::new();
        let backup_persister = Arc::new(BackupPersister::new(persister.clone(), backup));
        let mut services = make_services();
        services.persister = backup_persister.clone();
        let nodes1 = backup_persister.get_nodes().unwrap();
        assert_eq!(nodes1.len(), 1);
        let (node_id1, node_entry1) = nodes1.into_iter().next().unwrap();
        let node = Node::restore_node(&node_id, node_entry1, &seed, services).unwrap();
        assert_eq!(node.get_id(), node_id);

        // check restoring from main persister after it's been recovered
        let nodes1 = persister.get_nodes().unwrap();
        assert_eq!(nodes1.len(), 1);
        let (node_id1, node_entry1) = nodes1.into_iter().next().unwrap();
        let mut services = make_services();
        services.persister = Arc::new(persister.clone());
        let node = Node::restore_node(&node_id, node_entry1, &seed, services).unwrap();
        assert_eq!(node.get_id(), node_id);
    }
}
