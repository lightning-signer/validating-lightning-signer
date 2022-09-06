use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use serde_json::to_vec;

use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{NodeConfig, NodeState};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::persist::Persist;

use crate::model::{NodeEntry, NodeStateEntry};

struct State {
    // value is (revision, value)
    store: BTreeMap<String, (u64, Vec<u8>)>,
    dirty: BTreeSet<String>,
}

impl State {
    fn new(store: BTreeMap<String, (u64, Vec<u8>)>) -> Self {
        Self { store, dirty: Default::default() }
    }

    fn insert(&mut self, prefix: impl Into<String>, key: Vec<u8>, value: Vec<u8>) {
        let full_key = Self::make_key(prefix, key);
        let revision = if self.dirty.contains(&full_key) {
            // if already dirty, do not increment revision
            self.store.get(&full_key).expect("dirty key must exist").0
        } else {
            // if not dirty, increment revision
            self.store.get(&full_key).map(|(r, _)| r + 1).unwrap_or(0)
        };
        self.store.insert(full_key.clone(), (revision, value));
        self.dirty.insert(full_key);
    }

    fn get(&self, prefix: impl Into<String>, key: Vec<u8>) -> Option<&Vec<u8>> {
        let full_key = Self::make_key(prefix, key);
        self.store.get(&full_key).map(|(_, v)| v)
    }

    fn remove(&mut self, prefix: impl Into<String>, key: Vec<u8>) {
        let full_key = Self::make_key(prefix, key);
        let revision = self.store.get(&full_key).map(|(r, _)| r + 1).unwrap_or(0);
        self.store.insert(full_key.clone(), (revision, Vec::new()));
        self.dirty.insert(full_key);
    }

    fn make_key(prefix: impl Into<String>, key: Vec<u8>) -> String {
        format!("{}/{}", prefix.into(), hex::encode(key))
    }

    fn get_dirty(&self) -> Vec<(String, (u64, Vec<u8>))> {
        let mut res = Vec::new();
        for key in self.dirty.iter() {
            res.push((key.clone(), self.store.get(key).cloned().unwrap()));
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

const NODE_ENTRY_PREFIX: &str = "node/entry";
const NODE_ENTRY_PREFIX_FIRST: &str = "node/entry/0";
const NODE_ENTRY_PREFIX_LAST: &str = "node/entry/g";
const NODE_STATE_PREFIX: &str = "node/state";

impl ThreadMemoPersister {
    /// Enter a persistence context
    ///
    /// Entering while the thread is already in a context will panic
    ///
    /// Returns a [`Context`] object, which can be used to retrieve the
    /// modified entries and exit the context.
    pub fn enter(&self, state: BTreeMap<String, (u64, Vec<u8>)>) -> Context {
        MEMOS.with(|m| {
            if m.borrow().is_some() {
                panic!("already entered a persist context");
            }
            *m.borrow_mut() = Some(State::new(state));
        });
        Context {}
    }

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
pub struct Context {}

impl Context {
    pub fn exit(self) -> Vec<(String, (u64, Vec<u8>))> {
        MEMOS.with(|m| {
            let mut m = m.borrow_mut();
            let dirty = m.as_ref().expect("persist context was already cleared").get_dirty();
            *m = None;
            dirty
        })
    }
}

impl Drop for Context {
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
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, state: &NodeState, _seed: &[u8]) {
        self.update_node(node_id, state).unwrap();
        let key = node_id.serialize().to_vec();
        // Note: we don't save the seed on external storage, for security reasons
        let entry = NodeEntry {
            seed: Vec::new(),
            key_derivation_style: config.key_derivation_style as u8,
            network: config.network.to_string(),
        };
        let value = to_vec(&entry).unwrap();
        self.with_state(|state| state.insert(NODE_ENTRY_PREFIX, key, value));
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), ()> {
        let key = node_id.serialize().to_vec();
        let state_entry: NodeStateEntry = state.into();
        let state_value = to_vec(&state_entry).unwrap();
        self.with_state(|state| state.insert(NODE_STATE_PREFIX, key, state_value));
        Ok(())
    }

    fn delete_node(&self, node_id: &PublicKey) {
        let key = node_id.serialize().to_vec();
        self.with_state(|state| {
            state.remove(NODE_ENTRY_PREFIX, key.clone());
            state.remove(NODE_STATE_PREFIX, key);
        });
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        todo!()
    }

    fn new_chain_tracker(&self, node_id: &PublicKey, tracker: &ChainTracker<ChainMonitor>) {
        todo!()
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), ()> {
        todo!()
    }

    fn get_tracker(&self, node_id: &PublicKey) -> Result<ChainTracker<ChainMonitor>, ()> {
        todo!()
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()> {
        todo!()
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, ()> {
        todo!()
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, CoreChannelEntry)> {
        todo!()
    }

    fn update_node_allowlist(&self, node_id: &PublicKey, allowlist: Vec<String>) -> Result<(), ()> {
        todo!()
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Vec<String> {
        todo!()
    }

    fn get_nodes(&self) -> Vec<(PublicKey, CoreNodeEntry)> {
        let mut res = Vec::new();
        self.with_state(|state| {
            state
                .store
                .range(NODE_ENTRY_PREFIX_FIRST.to_string()..NODE_ENTRY_PREFIX_LAST.to_string())
                .filter(|(_k, (_r, value))| !value.is_empty())
                .for_each(|(key, (_r, value))| {
                    let key = hex::decode(key.split('/').last().unwrap()).unwrap();
                    let node_id = PublicKey::from_slice(&key).unwrap();
                    let entry: NodeEntry = serde_json::from_slice(value).unwrap();
                    let state_value = state.get(NODE_STATE_PREFIX, key).unwrap();
                    let state_entry: NodeStateEntry = serde_json::from_slice(state_value).unwrap();
                    let node_state = NodeState {
                        invoices: Default::default(),
                        issued_invoices: Default::default(),
                        payments: Default::default(),
                        excess_amount: 0,
                        log_prefix: "".to_string(),
                        velocity_control: state_entry.velocity_control.into(),
                    };
                    let node_entry = CoreNodeEntry {
                        seed: entry.seed,
                        key_derivation_style: entry.key_derivation_style as u8,
                        network: entry.network,
                        state: node_state,
                    };
                    res.push((node_id, node_entry));
                });
        });
        res
    }

    fn clear_database(&self) {
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
        let (node_id, node_arc, _stub, seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let persist_ctx = persister.enter(BTreeMap::new());
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state(), &seed);
        let nodes = persister.get_nodes();
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
        let (node_id, node_arc, _stub, seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let persist_ctx = persister.enter(BTreeMap::new());
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state(), &seed);
        persister.update_node(&node_id, &*node.get_state()).unwrap();
        let dirty = persist_ctx.exit();
        // updating the same record twice in one transaction should not increment the revision
        assert_eq!(dirty.len(), 2);
        assert_eq!(dirty[0].1 .0, 0);
        assert_eq!(dirty[1].1 .0, 0);
        let store = BTreeMap::from_iter(dirty.into_iter());
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
        let (node_id, node_arc, _stub, seed) = make_node_and_channel(channel_id0.clone());

        let node = &*node_arc;

        let ctx = persister.enter(BTreeMap::new());
        persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state(), &seed);
        let nodes = persister.get_nodes();
        assert_eq!(nodes.len(), 1);
        persister.delete_node(&node_id);
        let nodes = persister.get_nodes();
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
        persister.get_nodes();
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
