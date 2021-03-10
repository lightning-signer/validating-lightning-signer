use std::sync::Arc;

use bitcoin::Network;
use kv::Json;
use lightning::util::logger::Logger;

use lightning_signer::persist::model::{ChannelEntry, NodeChannelId, NodeEntry};
use lightning_signer::persist::{util, Persist};
use lightning_signer::server::my_signer::channel_nonce_to_id;
use lightning_signer::util::test_utils::{TEST_NODE_CONFIG, TestLogger};
use lightning_signer::persist::persist_json::KVJsonPersister;

pub fn main() {
    let persister = KVJsonPersister::new("/tmp/signer.kv");
    persister.clear_database();
    let channel_nonce = "nonce0".as_bytes().to_vec();
    let channel_id = channel_nonce_to_id(&channel_nonce);
    let channel_nonce1 = "nonce1".as_bytes().to_vec();
    let channel_id1 = channel_nonce_to_id(&channel_nonce1);

    let logger: Arc<dyn Logger> = Arc::new(TestLogger::with_id("server".to_owned()));
    let (node_id, node_arc, stub) = util::make_node_and_channel(&logger, &channel_nonce, channel_id);
    let node = &*node_arc;

    persister.new_node(&node_id, &TEST_NODE_CONFIG, &[3u8; 32], Network::Regtest);

    persister.new_channel(&node_id, &stub).unwrap();

    let dummy_pubkey= util::make_dummy_pubkey(0x12);
    let setup = util::create_test_channel_setup(dummy_pubkey);
    let channel = node.ready_channel(channel_id, Some(channel_id1), setup).unwrap();

    for (id, entry) in persister.get_node_channels(&node_id) {
        println!("{} {}", id, Json(entry));
    }
    persister.update_channel(&node_id, &channel).unwrap();
    for (id, entry) in persister.get_node_channels(&node_id) {
        println!("{} {}", id, Json(entry));
    }

    println!("Nodes:");
    for item in persister.node_bucket.iter() {
        let item = item.expect("item");
        let entry_json: Json<NodeEntry> = item.value().unwrap();
        let id: Vec<u8> = item.key().unwrap();
        println!("{}: {}", hex::encode(id), entry_json);
    }

    println!("Channels:");
    for item in persister.channel_bucket.iter() {
        let item = item.expect("item");
        let entry_json: Json<ChannelEntry> = item.value().unwrap();
        let id: NodeChannelId = item.key().unwrap();
        println!("{}: {}", id, entry_json);
    }
}

