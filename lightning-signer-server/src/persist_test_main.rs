use bitcoin::Network;
use kv::Json;

use lightning_signer::persist::Persist;
use lightning_signer::signer::multi_signer::channel_nonce_to_id;
use lightning_signer::util::test_utils::TEST_NODE_CONFIG;
use lightning_signer_server::persist::model::{ChannelEntry, NodeChannelId, NodeEntry};
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use lightning_signer_server::persist::util;

pub fn main() {
    let persister = KVJsonPersister::new("/tmp/signer.kv");
    persister.clear_database();
    let channel_nonce = "nonce0".as_bytes().to_vec();
    let channel_id = channel_nonce_to_id(&channel_nonce);
    let channel_nonce1 = "nonce1".as_bytes().to_vec();
    let channel_id1 = channel_nonce_to_id(&channel_nonce1);

    let (node_id, node_arc, stub, _seed) = util::make_node_and_channel(&channel_nonce, channel_id);
    let node = &*node_arc;

    persister.new_node(&node_id, &TEST_NODE_CONFIG, &[3u8; 32], Network::Regtest);

    persister.new_channel(&node_id, &stub).unwrap();

    let dummy_pubkey = util::make_dummy_pubkey(0x12);
    let setup = util::create_test_channel_setup(dummy_pubkey);
    let channel = node
        .ready_channel(channel_id, Some(channel_id1), setup)
        .unwrap();

    for (id, entry) in persister.get_node_channels(&node_id) {
        println!("{} {:?}", id, entry);
    }
    persister.update_channel(&node_id, &channel).unwrap();
    for (id, entry) in persister.get_node_channels(&node_id) {
        println!("{} {:?}", id, entry);
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
