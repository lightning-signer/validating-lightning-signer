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
    use crate::model::{ChainTrackerEntry, ChannelEntry, NodeEntry, NodeStateEntry};
    use lightning_signer::bitcoin::secp256k1::PublicKey;
    use lightning_signer::bitcoin::Network;
    use lightning_signer::chain::tracker::ChainTracker;
    use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
    use lightning_signer::monitor::ChainMonitor;
    use lightning_signer::node::{Node, NodeConfig, NodeState};
    use lightning_signer::persist::SignerId;
    use lightning_signer::signer::derive::KeyDerivationStyle;
    use lightning_signer::util::test_utils::TEST_CHANNEL_ID;
    use lightning_signer::util::test_utils::{
        hex_decode, make_services, TEST_NODE_CONFIG, TEST_SEED,
    };
    use lightning_signer::util::velocity::{
        VelocityControl, VelocityControlIntervalType, VelocityControlSpec,
    };
    use serde_json::{from_slice, to_vec};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    fn setup_test_environment() -> (
        TestPersister,
        TestPersister,
        BackupPersister<TestPersister, TestPersister>,
        PublicKey,
        NodeConfig,
        NodeState,
        Arc<Node>,
        ChannelId,
        ChannelStub,
    ) {
        let main = TestPersister::new();
        let backup = TestPersister::new();
        let persister = BackupPersister::new(main.clone(), backup.clone());
        let node_id = PublicKey::from_slice(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap();
        let config = NodeConfig {
            key_derivation_style: KeyDerivationStyle::Native,
            network: Network::Regtest,
            allow_deep_reorgs: false,
            use_checkpoints: false,
        };
        let state = NodeState::new(
            VelocityControl::new(VelocityControlSpec {
                limit_msat: 0,
                interval_type: VelocityControlIntervalType::Hourly,
            }),
            VelocityControl::new(VelocityControlSpec {
                limit_msat: 0,
                interval_type: VelocityControlIntervalType::Hourly,
            }),
            Vec::new(),
        );
        let seed = hex_decode(TEST_SEED[1]).unwrap();
        let mut services = make_services();
        services.persister = Arc::new(main.clone());
        let node = Arc::new(Node::new(TEST_NODE_CONFIG, &seed, vec![], services));
        let pk = PublicKey::from_slice(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
        .unwrap();
        let peer_id = pk.serialize();
        let (channel_id, stub_option) =
            node.new_channel(100, &peer_id, &Arc::clone(&node)).unwrap();
        let stub = match stub_option.unwrap() {
            lightning_signer::channel::ChannelSlot::Stub(stub) => stub,
            _ => panic!("Expected ChannelSlot::Stub"),
        };
        (main, backup, persister, node_id, config, state, node, channel_id, stub)
    }

    #[derive(Clone)]
    struct TestPersister {
        state: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        signer_id: SignerId,
    }

    impl TestPersister {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(BTreeMap::new())),
                signer_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            }
        }

        fn new_with_signer_id(signer_id: SignerId) -> Self {
            Self { state: Arc::new(Mutex::new(BTreeMap::new())), signer_id }
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
            let mut state = self.state.lock().unwrap();
            let node_key = format!("node/entry/{}", hex::encode(node_id.serialize()));
            let state_key = format!("node/state/{}", hex::encode(node_id.serialize()));
            state.insert(node_key, Vec::new());
            state.insert(state_key, Vec::new());
            Ok(())
        }

        fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
            let mut state = self.state.lock().unwrap();
            let key = format!(
                "channel/{}/{}",
                hex::encode(node_id.serialize()),
                hex::encode(stub.id0.as_slice())
            );
            let entry = ChannelEntry {
                channel_value_satoshis: 0,
                channel_setup: None,
                id: None,
                enforcement_state: lightning_signer::policy::validator::EnforcementState::new(0),
                blockheight: Some(stub.blockheight),
            };
            let value = to_vec(&entry).map_err(|e| Error::SerdeError(e.to_string()))?;
            state.insert(key, value);
            Ok(())
        }

        fn delete_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<(), Error> {
            let mut state = self.state.lock().unwrap();
            let key = format!(
                "channel/{}/{}",
                hex::encode(node_id.serialize()),
                hex::encode(channel_id.as_slice())
            );
            state.insert(key, Vec::new());
            Ok(())
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
            let state = self.state.lock().unwrap();
            let key = format!(
                "channel/{}/{}",
                hex::encode(node_id.serialize()),
                hex::encode(channel_id.as_slice())
            );
            let value =
                state.get(&key).ok_or_else(|| Error::NotFound("channel not found".to_string()))?;
            if value.is_empty() {
                return Err(Error::NotFound("channel deleted".to_string()));
            }
            let entry: ChannelEntry =
                from_slice(value).map_err(|e| Error::SerdeError(e.to_string()))?;
            Ok(entry.into())
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
                    allowlist: OrderedSet::new(),
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
            let mut state = self.state.lock().unwrap();
            state.clear();
            Ok(())
        }

        fn recovery_required(&self) -> bool {
            self.state.lock().unwrap().is_empty()
        }

        fn signer_id(&self) -> SignerId {
            self.signer_id
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

    #[test]
    fn test_update_node() {
        let (main, backup, persister, node_id, _config, state, _node, _channel_id, _stub) =
            setup_test_environment();

        assert!(persister.update_node(&node_id, &state).is_ok());
        let main_state = main.state.lock().unwrap();
        let backup_state = backup.state.lock().unwrap();
        let key = format!("node/state/{}", hex::encode(node_id.serialize()));
        assert_eq!(
            backup_state.get(&key),
            Some(&vec![
                123, 34, 105, 110, 118, 111, 105, 99, 101, 115, 34, 58, 91, 93, 44, 34, 105, 115,
                115, 117, 101, 100, 95, 105, 110, 118, 111, 105, 99, 101, 115, 34, 58, 91, 93, 44,
                34, 118, 101, 108, 111, 99, 105, 116, 121, 95, 99, 111, 110, 116, 114, 111, 108,
                34, 58, 123, 34, 115, 116, 97, 114, 116, 95, 115, 101, 99, 34, 58, 48, 44, 34, 98,
                117, 99, 107, 101, 116, 95, 105, 110, 116, 101, 114, 118, 97, 108, 34, 58, 51, 48,
                48, 44, 34, 98, 117, 99, 107, 101, 116, 115, 34, 58, 91, 48, 44, 48, 44, 48, 44,
                48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 93, 44, 34,
                108, 105, 109, 105, 116, 34, 58, 48, 125, 44, 34, 102, 101, 101, 95, 118, 101, 108,
                111, 99, 105, 116, 121, 95, 99, 111, 110, 116, 114, 111, 108, 34, 58, 123, 34, 115,
                116, 97, 114, 116, 95, 115, 101, 99, 34, 58, 48, 44, 34, 98, 117, 99, 107, 101,
                116, 95, 105, 110, 116, 101, 114, 118, 97, 108, 34, 58, 51, 48, 48, 44, 34, 98,
                117, 99, 107, 101, 116, 115, 34, 58, 91, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44,
                48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 93, 44, 34, 108, 105, 109, 105,
                116, 34, 58, 48, 125, 44, 34, 112, 114, 101, 105, 109, 97, 103, 101, 115, 34, 58,
                91, 93, 44, 34, 100, 98, 105, 100, 95, 104, 105, 103, 104, 95, 119, 97, 116, 101,
                114, 95, 109, 97, 114, 107, 34, 58, 48, 125
            ])
        );
    }

    #[test]
    fn test_delete_node() {
        let (main, backup, persister, node_id, config, state, _node, _channel_id, _stub) =
            setup_test_environment();

        main.new_node(&node_id, &config, &state).unwrap();
        backup.new_node(&node_id, &config, &state).unwrap();
        assert!(persister.delete_node(&node_id).is_ok());
        let main_state = main.state.lock().unwrap();
        let backup_state = backup.state.lock().unwrap();
        let node_key = format!("node/entry/{}", hex::encode(node_id.serialize()));
        let state_key = format!("node/state/{}", hex::encode(node_id.serialize()));
        assert_eq!(main_state.get(&node_key).unwrap(), &Vec::<u8>::new());
        assert_eq!(main_state.get(&state_key).unwrap(), &Vec::<u8>::new());
        assert_eq!(backup_state.get(&node_key).unwrap(), &Vec::<u8>::new());
        assert_eq!(backup_state.get(&state_key).unwrap(), &Vec::<u8>::new());
    }

    #[test]
    fn test_new_channel() {
        let (main, backup, persister, node_id, _config, _state, node, channel_id, stub) =
            setup_test_environment();

        assert!(persister.new_channel(&node_id, &stub).is_ok());
        let main_state = main.state.lock().unwrap();
        let backup_state = backup.state.lock().unwrap();
        let key = format!(
            "channel/{}/{}",
            hex::encode(node_id.serialize()),
            hex::encode(channel_id.as_slice())
        );
        let main_entry: ChannelEntry = from_slice(&main_state.get(&key).unwrap()).unwrap();
        let backup_entry: ChannelEntry = from_slice(&backup_state.get(&key).unwrap()).unwrap();
        assert_eq!(main_entry.blockheight, Some(0));
        assert_eq!(backup_entry.blockheight, Some(0));
    }

    #[test]
    fn test_delete_channel() {
        let (main, backup, persister, node_id, _config, _state, node, channel_id, stub) =
            setup_test_environment();

        // Test when main is ready
        main.new_channel(&node_id, &stub).unwrap();
        backup.new_channel(&node_id, &stub).unwrap();
        assert!(persister.delete_channel(&node_id, &channel_id).is_ok());
        let main_state = main.state.lock().unwrap();
        let backup_state = backup.state.lock().unwrap();
        let key = format!(
            "channel/{}/{}",
            hex::encode(node_id.serialize()),
            hex::encode(channel_id.as_slice())
        );
        assert_eq!(main_state.get(&key).unwrap(), &Vec::<u8>::new());
        assert_eq!(backup_state.get(&key).unwrap(), &Vec::<u8>::new());
    }

    #[test]
    fn test_get_channel() {
        let (main, backup, persister, node_id, _config, _state, node, channel_id, stub) =
            setup_test_environment();

        backup.new_channel(&node_id, &stub).unwrap();

        main.new_channel(&node_id, &stub).unwrap();
        let entry = persister.get_channel(&node_id, &channel_id).unwrap();
        assert_eq!(entry.blockheight, Some(0));

        let main = TestPersister::new();
        let persister = BackupPersister::new(main, backup);
        let entry = persister.get_channel(&node_id, &channel_id).unwrap();
        assert_eq!(entry.blockheight, Some(0));

        let invalid_channel_id = ChannelId::new(&[2; 32]);
        assert!(matches!(
            persister.get_channel(&node_id, &invalid_channel_id),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn test_clear_database() {
        let (main, backup, persister, node_id, config, state, _node, _channel_id, _stub) =
            setup_test_environment();

        main.new_node(&node_id, &config, &state).unwrap();
        backup.new_node(&node_id, &config, &state).unwrap();

        assert!(persister.clear_database().is_ok());
        assert!(main.state.lock().unwrap().is_empty());
        assert!(backup.state.lock().unwrap().is_empty());
    }

    #[test]
    fn test_signer_id() {
        let main_signer_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let backup_signer_id = [2; 16];
        let main = TestPersister::new_with_signer_id(main_signer_id);
        let backup = TestPersister::new_with_signer_id(backup_signer_id);
        let persister = BackupPersister::new(main, backup);
        assert_eq!(persister.signer_id(), main_signer_id);
    }
}
