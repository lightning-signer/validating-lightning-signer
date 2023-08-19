use std::time::Duration;

use lightning_signer::channel::ChannelId;
use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::node::{PaymentState, PaymentType};
use lightning_signer::persist::Persist;
use lightning_signer::util::test_utils::{self, hex_decode, TEST_CHANNEL_ID, TEST_NODE_CONFIG};
use vls_persist::kvv::redb::RedbKVVStore;
use vls_persist::kvv::KVVStore;

pub fn main() {
    let tempdir = tempfile::tempdir().unwrap();
    let persister = RedbKVVStore::new(&tempdir);
    persister.clear_database().unwrap();
    let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
    let channel_id1 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

    let (node_id, node_arc, stub, _seed) = test_utils::make_node_and_channel(channel_id.clone());
    let node = &*node_arc;
    let payment_state = PaymentState {
        invoice_hash: [2; 32],
        amount_msat: 0,
        payee: test_utils::make_dummy_pubkey(0x23),
        duration_since_epoch: Duration::new(1, 2),
        expiry_duration: Duration::new(2, 3),
        is_fulfilled: false,
        payment_type: PaymentType::Invoice,
    };
    node.get_state().invoices.insert(PaymentHash([1; 32]), payment_state);

    persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();

    persister.new_channel(&node_id, &stub).unwrap();

    let dummy_pubkey = test_utils::make_dummy_pubkey(0x12);
    let setup = test_utils::create_test_channel_setup(dummy_pubkey);
    let channel = node.ready_channel(channel_id, Some(channel_id1), setup, &vec![]).unwrap();

    for (id, entry) in persister.get_node_channels(&node_id).unwrap() {
        println!("{} {:?}", id, entry);
    }
    persister.update_channel(&node_id, &channel).unwrap();

    for item in persister.0.get_prefix("").unwrap() {
        println!("{:?}", item);
    }
}
