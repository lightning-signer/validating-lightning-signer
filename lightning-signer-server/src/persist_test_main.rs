use kv::Json;

use lightning_signer::channel::ChannelId;
use lightning_signer::persist::Persist;
use lightning_signer::util::test_utils::{self, hex_decode, TEST_CHANNEL_ID, TEST_NODE_CONFIG};
use lightning_signer_server::persist::model::{ChannelEntry, NodeChannelId, NodeEntry};
use lightning_signer_server::persist::persist_json::KVJsonPersister;

pub fn main() {
    let persister = KVJsonPersister::new("/tmp/signer.kv");
    persister.clear_database();
    let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
    let channel_id1 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

    let (node_id, node_arc, stub, _seed) = test_utils::make_node_and_channel(channel_id.clone());
    let node = &*node_arc;

    persister.new_node(&node_id, &TEST_NODE_CONFIG, &[3u8; 32]);

    persister.new_channel(&node_id, &stub).unwrap();

    let dummy_pubkey = test_utils::make_dummy_pubkey(0x12);
    let setup = test_utils::create_test_channel_setup(dummy_pubkey);
    let channel = node.ready_channel(channel_id, Some(channel_id1), setup, &vec![]).unwrap();

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
