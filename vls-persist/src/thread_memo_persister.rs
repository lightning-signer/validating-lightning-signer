use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use std::sync::{Arc, Mutex};

use serde_json::{from_slice, to_vec};

use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{NodeConfig, NodeState};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::persist::{Context, Error, Mutations, Persist};
use lightning_signer::policy::validator::{EnforcementState, ValidatorFactory};
use lightning_signer::prelude::*;

use crate::model::*;

struct State {
    // value is (revision, value)
    store: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    dirty: BTreeSet<String>,
}

impl State {
    fn new(store: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>) -> Self {
        Self { store, dirty: Default::default() }
    }

    fn insert(&mut self, prefix: impl Into<String>, key: &[u8], value: Vec<u8>) {
        let full_key = Self::make_key(prefix, key);
        self.do_insert(value, full_key);
    }

    // use for nested items (e.g. node -> channel)
    fn insert2(&mut self, prefix: impl Into<String>, key1: &[u8], key2: &[u8], value: Vec<u8>) {
        let full_key = Self::make_key2(prefix, key1, key2);
        self.do_insert(value, full_key);
    }

    fn do_insert(&mut self, value: Vec<u8>, full_key: String) {
        let mut store = self.store.lock().unwrap();
        let revision = if self.dirty.contains(&full_key) {
            // if already dirty, do not increment revision
            store.get(&full_key).expect("dirty key must exist").0
        } else {
            // if not dirty, increment revision
            store.get(&full_key).map(|(r, _)| r + 1).unwrap_or(0)
        };
        store.insert(full_key.clone(), (revision, value));
        self.dirty.insert(full_key);
    }

    fn get(&self, prefix: impl Into<String>, key: &[u8]) -> Option<Vec<u8>> {
        let full_key = Self::make_key(prefix, key);
        let store = self.store.lock().unwrap();
        store.get(&full_key).map(|(_, v)| v.clone())
    }

    fn get2(&self, prefix: impl Into<String>, key1: &[u8], key2: &[u8]) -> Option<Vec<u8>> {
        let full_key = Self::make_key2(prefix, key1, key2);
        let store = self.store.lock().unwrap();
        store.get(&full_key).map(|(_, v)| v.clone())
    }

    fn get_prefix(&self, prefix: impl Into<String>) -> Vec<(Vec<u8>, (u64, Vec<u8>))> {
        let prefix2 = Self::make_key(prefix, &[]);
        let store = self.store.lock().unwrap();
        store
            .range(prefix2.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix2))
            .map(|(k, (r, v))| {
                let key = hex::decode(&k[prefix2.len()..]).expect("key must be hex");
                (key, (*r, v.clone()))
            })
            .collect()
    }

    fn get_prefix2(
        &self,
        prefix: impl Into<String>,
        key1: &[u8],
    ) -> Vec<(Vec<u8>, (u64, Vec<u8>))> {
        let prefix2 = Self::make_key2(prefix, key1, &[]);
        let store = self.store.lock().unwrap();
        store
            .range(prefix2.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix2))
            .map(|(k, (r, v))| {
                let key = hex::decode(&k[prefix2.len()..]).expect("key must be hex");
                (key, (*r, v.clone()))
            })
            .collect()
    }

    fn remove(&mut self, prefix: impl Into<String>, key: &[u8]) {
        let full_key = Self::make_key(prefix, key);
        let mut store = self.store.lock().unwrap();
        let revision = store.get(&full_key).map(|(r, _)| r + 1).unwrap_or(0);
        store.insert(full_key.clone(), (revision, Vec::new()));
        self.dirty.insert(full_key);
    }

    fn make_key(prefix: impl Into<String>, key: &[u8]) -> String {
        format!("{}/{}", prefix.into(), hex::encode(key))
    }

    fn make_key2(prefix: impl Into<String>, key1: &[u8], key2: &[u8]) -> String {
        format!("{}/{}/{}", prefix.into(), hex::encode(key1), hex::encode(key2))
    }

    fn get_dirty(&self) -> Mutations {
        let store = self.store.lock().unwrap();
        let mut res = Vec::new();
        for key in self.dirty.iter() {
            res.push((key.clone(), store.get(key).cloned().unwrap()));
        }
        res
    }
}

thread_local!(static MEMOS: RefCell<Option<State>>  = RefCell::new(None));

/// A thread-local in-memory persister
///
/// Use [`enter()`] to enter a new context with an initial state.
/// Use [`Context.exit()`] to exit the context and return modified entries.
///
/// State is not shared between contexts. It is the responsibility of the caller
/// to handle concurrency in storage updates.
///
/// It is the responsibility of the caller to actually persist the returned
/// entries in some external storage, such as a cloud service.
pub struct ThreadMemoPersister {}

impl SendSync for ThreadMemoPersister {}

const NODE_ENTRY_PREFIX: &str = "node/entry";
const NODE_STATE_PREFIX: &str = "node/state";
const NODE_TRACKER_PREFIX: &str = "node/tracker";
const ALLOWLIST_PREFIX: &str = "node/allowlist";
const CHANNEL_PREFIX: &str = "channel";

impl ThreadMemoPersister {
    fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        MEMOS.with(|memos| {
            let mut memo = memos.borrow_mut();
            let state = memo.as_mut().expect("not in persist context");
            f(state)
        })
    }
}

/// A persistence context
///
/// The context is exited when dropped or [`exit()`] is called.
pub struct StdContext {}

impl Context for StdContext {
    fn exit(&self) -> Mutations {
        MEMOS.with(|m| {
            let mut m = m.borrow_mut();
            let dirty = m.as_ref().expect("persist context was already cleared").get_dirty();
            *m = None;
            dirty
        })
    }
}

impl Drop for StdContext {
    fn drop(&mut self) {
        MEMOS.with(|m| {
            let mut m = m.borrow_mut();
            if m.is_some() {
                *m = None;
                if !std::thread::panicking() {
                    // only panic if not already panicking
                    panic!("must call exit() and handle the returned entries");
                }
            }
        })
    }
}

#[allow(unused_variables)]
impl Persist for ThreadMemoPersister {
    fn enter(&self, state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>) -> Box<dyn Context> {
        MEMOS.with(|m| {
            if m.borrow().is_some() {
                panic!("already entered a persist context");
            }
            *m.borrow_mut() = Some(State::new(state));
        });
        Box::new(StdContext {})
    }

    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        self.update_node(node_id, state).unwrap();
        let key = &node_id.serialize();
        let entry = NodeEntry {
            key_derivation_style: config.key_derivation_style as u8,
            network: config.network.to_string(),
        };
        let value = to_vec(&entry).unwrap();
        self.with_state(|state| state.insert(NODE_ENTRY_PREFIX, key, value));
        Ok(())
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        let key = &node_id.serialize();
        let state_entry: NodeStateEntry = state.into();
        let state_value = to_vec(&state_entry).unwrap();
        self.with_state(|state| state.insert(NODE_STATE_PREFIX, key, state_value));
        Ok(())
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        let key = &node_id.serialize();
        self.with_state(|state| {
            state.remove(NODE_ENTRY_PREFIX, key);
            state.remove(NODE_STATE_PREFIX, key);
        });
        Ok(())
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        let channel_value_satoshis = 0; // TODO not known yet

        let node_key = &node_id.serialize();
        let channel_key = stub.id0.as_slice();
        let entry = ChannelEntry {
            channel_value_satoshis,
            channel_setup: None,
            id: None,
            enforcement_state: EnforcementState::new(0),
        };
        let value = to_vec(&entry).unwrap();
        self.with_state(|state| state.insert2(CHANNEL_PREFIX, node_key, channel_key, value));
        Ok(())
    }

    fn new_chain_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        let key = &node_id.serialize();
        let model: ChainTrackerEntry = tracker.into();
        let value = to_vec(&model).unwrap();
        self.with_state(|state| state.insert(NODE_TRACKER_PREFIX, key, value));
        Ok(())
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        let key = &node_id.serialize();
        let model: ChainTrackerEntry = tracker.into();
        let value = to_vec(&model).unwrap();
        self.with_state(|state| state.insert(NODE_TRACKER_PREFIX, key, value));
        Ok(())
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<ChainTracker<ChainMonitor>, Error> {
        let key = &node_id.serialize();
        let value = self.with_state(|state| state.get(NODE_TRACKER_PREFIX, key)).unwrap();
        let model: ChainTrackerEntry = from_slice(&value).unwrap();
        Ok(model.into_tracker(node_id.clone(), validator_factory))
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        let channel_value_satoshis = channel.setup.channel_value_sat;
        let node_key = &node_id.serialize();
        let channel_key = channel.id0.as_slice();
        let entry = ChannelEntry {
            channel_value_satoshis,
            channel_setup: Some(channel.setup.clone()),
            id: channel.id.clone(),
            enforcement_state: channel.enforcement_state.clone(),
        };
        let value = to_vec(&entry).unwrap();
        self.with_state(|state| state.insert2(CHANNEL_PREFIX, node_key, channel_key, value));
        Ok(())
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, Error> {
        let node_id = &node_id.serialize();
        let channel_key = channel_id.as_slice();
        let entry = self.with_state(|state| {
            let value = state.get2(NODE_ENTRY_PREFIX, node_id, channel_key).unwrap();
            let entry: ChannelEntry = from_slice(&value).unwrap();
            entry
        });
        Ok(entry.into())
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, CoreChannelEntry)>, Error> {
        let node_id = &node_id.serialize();
        let mut res = Vec::new();
        self.with_state(|state| {
            for (key, (_version, value)) in state.get_prefix2(CHANNEL_PREFIX, node_id) {
                let entry: ChannelEntry = from_slice(&value).unwrap();
                let channel_id = ChannelId::new(&key);
                res.push((channel_id, entry.into()));
            }
        });
        Ok(res)
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        let key = &node_id.serialize();
        let entry = AllowlistItemEntry { allowlist };
        let value = to_vec(&entry).unwrap();
        self.with_state(|state| state.insert(ALLOWLIST_PREFIX, key, value));
        Ok(())
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        let key = &node_id.serialize();
        let entry = self.with_state(|state| {
            let value = state.get(ALLOWLIST_PREFIX, key).unwrap();
            let entry: AllowlistItemEntry = from_slice(&value).unwrap();
            entry
        });
        Ok(entry.allowlist)
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, CoreNodeEntry)>, Error> {
        let mut res = Vec::new();
        self.with_state(|state| {
            state
                .get_prefix(NODE_ENTRY_PREFIX)
                .into_iter()
                .filter(|(_k, (_r, value))| !value.is_empty())
                .for_each(|(key, (_r, value))| {
                    let node_id = PublicKey::from_slice(&key).unwrap();
                    let entry: NodeEntry = from_slice(&value).unwrap();
                    let state_value = state.get(NODE_STATE_PREFIX, &key).unwrap();
                    let state_entry: NodeStateEntry = from_slice(&state_value).unwrap();
                    let node_state = NodeState {
                        invoices: Default::default(),
                        issued_invoices: Default::default(),
                        payments: Default::default(),
                        excess_amount: 0,
                        log_prefix: "".to_string(),
                        velocity_control: state_entry.velocity_control.into(),
                    };
                    let node_entry = CoreNodeEntry {
                        key_derivation_style: entry.key_derivation_style as u8,
                        network: entry.network,
                        state: node_state,
                    };
                    res.push((node_id, node_entry));
                });
        });
        Ok(res)
    }

    fn clear_database(&self) -> Result<(), Error> {
        unimplemented!("clear_database is not implemented")
    }
}

#[cfg(test)]
mod tests {
    use lightning_signer::util::test_utils::{
        hex_decode, make_node_and_channel, TEST_CHANNEL_ID, TEST_NODE_CONFIG,
    };
    use std::iter::FromIterator;
    use std::panic::catch_unwind;

    use super::*;

    #[test]
    fn test_node() {
        let persister = ThreadMemoPersister {};
        let channel_id0 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let (node_id, node_arc, _stub, _seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let state = Arc::new(Mutex::new(BTreeMap::new()));
        let persist_ctx = persister.enter(state);
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();
        let nodes = persister.get_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        let dirty = persist_ctx.exit();
        assert_eq!(dirty.len(), 2);
        assert_eq!(
            dirty[0].0,
            "node/entry/022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
        );
        assert_eq!(
            dirty[1].0,
            "node/state/022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
        );
        assert_eq!(dirty[0].1 .0, 0);

        persister.enter(Default::default()).exit();
    }

    #[test]
    fn test_update_node() {
        let persister = ThreadMemoPersister {};
        let channel_id0 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let (node_id, node_arc, _stub, _seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let state = Arc::new(Mutex::new(BTreeMap::new()));
        let persist_ctx = persister.enter(state);
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();
        persister.update_node(&node_id, &*node.get_state()).unwrap();
        let dirty = persist_ctx.exit();
        // updating the same record twice in one transaction should not increment the revision
        assert_eq!(dirty.len(), 2);
        assert_eq!(dirty[0].1 .0, 0);
        assert_eq!(dirty[1].1 .0, 0);
        let store = Arc::new(Mutex::new(BTreeMap::from_iter(dirty.into_iter())));
        let persist_ctx = persister.enter(store);
        persister.update_node(&node_id, &*node.get_state()).unwrap();
        let dirty = persist_ctx.exit();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].1 .0, 1);
    }

    #[test]
    fn test_delete_node() {
        let persister = ThreadMemoPersister {};
        let channel_id0 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        let (node_id, node_arc, _stub, _seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let state = Arc::new(Mutex::new(BTreeMap::new()));
        let ctx = persister.enter(state);
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();
        let nodes = persister.get_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        persister.delete_node(&node_id).unwrap();
        let nodes = persister.get_nodes().unwrap();
        assert_eq!(nodes.len(), 0);
        ctx.exit();
    }

    #[test]
    fn test_panic_before_drop() {
        // this tests that the drop impl does not panic if already panicking
        let persister = ThreadMemoPersister {};

        let err = catch_unwind(|| {
            let _ctx = persister.enter(Default::default());
            panic!("test");
        })
        .expect_err("should have panicked")
        .downcast::<&str>()
        .expect("should have panicked with an &str");
        assert_eq!(*err, "test");

        // entering another context should not panic because context was dropped
        persister.enter(Default::default()).exit();
    }

    #[test]
    fn test_no_exit() {
        // this tests that the drop impl panics if exit was not called
        let persister = ThreadMemoPersister {};

        let err = catch_unwind(|| {
            let _ctx = persister.enter(Default::default());
        })
        .expect_err("should have panicked")
        .downcast::<&str>()
        .expect("should have panicked with an &str");
        assert_eq!(*err, "must call exit() and handle the returned entries");

        // entering another context should not panic because context was dropped
        persister.enter(Default::default()).exit();
    }

    #[test]
    #[should_panic]
    fn test_bad_get() {
        let persister = ThreadMemoPersister {};
        persister.get_nodes().unwrap();
    }

    #[test]
    fn test_bad_enter() {
        let persister = ThreadMemoPersister {};
        // keep context on stack
        let ctx = persister.enter(Default::default());
        catch_unwind(|| {
            // try to enter another context
            persister.enter(Default::default());
        })
        .expect_err("should have panicked");
        ctx.exit();
    }
}
