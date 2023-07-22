use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use lightning_signer::{
    bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey},
    channel::{ChannelId, ChannelSlot},
    lightning::{chain::keysinterface::InMemorySigner, ln::PaymentHash, util::ser::Writeable},
    node::{Node, NodeServices},
    persist::{MemorySeedPersister, Persist},
    policy::simple_validator::SimpleValidatorFactory,
    tx::tx::HTLCInfo2,
    util::{
        clock::StandardClock,
        ser_util::VecWriter,
        test_utils::{
            create_test_channel_setup, hex_decode, key::make_test_pubkey,
            make_genesis_starting_time_factory, make_node_and_channel, TEST_CHANNEL_ID,
            TEST_NODE_CONFIG,
        },
    },
    Arc,
};
use tempfile::{tempdir_in, TempDir};
use vls_persist::kv_json::KVJsonPersister;

fn make_temp_persister<'a>() -> (KVJsonPersister<'a>, TempDir, String) {
    let dir = tempdir_in(".").unwrap();
    let path = dir.path().to_owned();
    let path_str = path.to_str().unwrap();

    let persister = KVJsonPersister::new(path_str);
    persister.clear_database().unwrap();
    (persister, dir, path_str.to_string())
}

fn check_signer_roundtrip(existing_signer: &InMemorySigner, signer: &InMemorySigner) {
    let mut existing_w = VecWriter(Vec::new());
    existing_signer.write(&mut existing_w).unwrap();
    let mut w = VecWriter(Vec::new());
    signer.write(&mut w).unwrap();
}

fn persister_bench(c: &mut Criterion) {
    let secp_ctx = Secp256k1::new();
    let channel_id0 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(TEST_NODE_CONFIG.network);
    let clock = Arc::new(StandardClock());

    let (node_id, node_arc, stub, seed) = make_node_and_channel(channel_id0.clone());

    let node = &*node_arc;

    let seed_persister = Arc::new(MemorySeedPersister::new(seed.to_vec()));

    let (persister, _temp_dir, _path) = make_temp_persister();
    let persister: Arc<dyn Persist> = Arc::new(persister);
    persister.new_node(&node_id, &TEST_NODE_CONFIG, &*node.get_state()).unwrap();
    persister.new_chain_tracker(&node_id, &node.get_tracker()).unwrap();
    persister.new_channel(&node_id, &stub).unwrap();

    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister: persister.clone(),
        clock,
    };

    let nodes = Node::restore_nodes(services.clone(), seed_persister.clone()).unwrap();
    let restored_node = nodes.get(&node_id).unwrap();

    let slot = restored_node.get_channel(&stub.id0).unwrap();

    let guard = slot.lock().unwrap();
    if let ChannelSlot::Stub(s) = &*guard {
        check_signer_roundtrip(&stub.keys, &s.keys);
    } else {
        panic!()
    }

    // Ready the channel
    let counterparty_key = SecretKey::from_slice(&[0x12u8; 32]).unwrap();
    let counterparty_pubkey = PublicKey::from_secret_key(&secp_ctx, &counterparty_key);
    let setup = create_test_channel_setup(counterparty_pubkey);

    let channel_id1 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

    let mut channel = node
        .ready_channel(channel_id0.clone(), Some(channel_id1.clone()), setup.clone(), &vec![])
        .unwrap();

    channel
        .advance_holder_commitment(&counterparty_key, &counterparty_key, vec![], 123000, 0)
        .unwrap();

    let payment_hash = PaymentHash([0x34u8; 32]);
    let htlcs = vec![HTLCInfo2 { value_sat: 1000, payment_hash, cltv_expiry: 100 }];

    for offered_htlc in htlcs.clone() {
        node.add_keysend(
            make_test_pubkey(1),
            offered_htlc.payment_hash,
            offered_htlc.value_sat * 1000,
        )
        .unwrap();
    }

    channel
        .advance_holder_commitment(&counterparty_key, &counterparty_key, htlcs, 122000, 1)
        .unwrap();

    c.bench_function("persister", |b| {
        b.iter(|| {
            let mut tracker = node.get_tracker();
            tracker.height += 1;
            persister.update_tracker(&node_id, &tracker).unwrap();
            persister.update_channel(&node_id, &channel).unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = persister_bench
}

criterion_main!(benches);
