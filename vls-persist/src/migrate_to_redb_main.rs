use hex::FromHex;
use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{Node, NodeConfig, NodeServices, NodeState};
use lightning_signer::persist::model::{ChannelEntry, NodeEntry};
use lightning_signer::persist::{ChainTrackerListenerEntry, Error, MemorySeedPersister, Persist};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::policy::validator::ValidatorFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::test_utils::{make_genesis_starting_time_factory, TEST_NODE_CONFIG};
use lightning_signer::SendSync;
use std::env::args;
use std::fs;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, Mutex};
#[allow(deprecated)]
use vls_persist::kv_json::KVJsonPersister;
use vls_persist::kvv::redb::RedbKVVStore;

struct SettablePersister(Mutex<Box<dyn Persist>>);

impl SendSync for SettablePersister {}

impl Persist for SettablePersister {
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        self.0.lock().unwrap().new_node(node_id, config, state)
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        self.0.lock().unwrap().update_node(node_id, state)
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        self.0.lock().unwrap().delete_node(node_id)
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        self.0.lock().unwrap().new_channel(node_id, stub)
    }

    fn delete_channel(&self, node_id: &PublicKey, channel: &ChannelId) -> Result<(), Error> {
        self.0.lock().unwrap().delete_channel(node_id, channel)
    }

    fn new_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        self.0.lock().unwrap().new_tracker(node_id, tracker)
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        self.0.lock().unwrap().update_tracker(node_id, tracker)
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<(ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>), Error> {
        self.0.lock().unwrap().get_tracker(node_id, validator_factory)
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        self.0.lock().unwrap().update_channel(node_id, channel)
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<ChannelEntry, Error> {
        self.0.lock().unwrap().get_channel(node_id, channel_id)
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, ChannelEntry)>, Error> {
        self.0.lock().unwrap().get_node_channels(node_id)
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        self.0.lock().unwrap().update_node_allowlist(node_id, allowlist)
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        self.0.lock().unwrap().get_node_allowlist(node_id)
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, NodeEntry)>, Error> {
        self.0.lock().unwrap().get_nodes()
    }

    fn clear_database(&self) -> Result<(), Error> {
        todo!()
    }
}

fn main() {
    if args().len() < 3 {
        println!("Usage: {} FROM TO", args().nth(0).unwrap());
        return;
    }
    let from_path = PathBuf::from(args().nth(1).unwrap());
    let from_path_seed = from_path.join("node.seed");
    let to_path = PathBuf::from(args().nth(2).unwrap());
    if to_path.exists() {
        println!("{} already exists", to_path.to_str().unwrap());
        exit(1);
    }
    let to_path_seed = to_path.join("node.seed");

    #[allow(deprecated)]
    let old_persister = Box::new(KVJsonPersister::new(from_path.to_str().unwrap()));

    let seed = Vec::from_hex(fs::read_to_string(&from_path_seed).expect("read seed").trim())
        .expect("bad hex");
    let seed_persister = Arc::new(MemorySeedPersister::new(seed));
    let persister = Arc::new(SettablePersister(Mutex::new(old_persister)));
    let node_services = NodeServices {
        validator_factory: Arc::new(SimpleValidatorFactory::new()),
        starting_time_factory: make_genesis_starting_time_factory(TEST_NODE_CONFIG.network),
        persister: persister.clone(),
        clock: Arc::new(StandardClock()),
    };
    let nodes = Node::restore_nodes(node_services, seed_persister).unwrap();
    assert_eq!(nodes.len(), 1);
    let node = nodes.values().next().unwrap();
    println!("migrating node ID {}", node.get_id());

    // create the destination directory
    fs::create_dir_all(&to_path).expect("create destination directory");
    // copy the seed
    fs::copy(&from_path_seed, to_path_seed).expect("copy seed");

    let new_persister = RedbKVVStore::new(&to_path);
    *persister.0.lock().unwrap() = Box::new(new_persister);
    node.persist_all();

    println!("done");
}
