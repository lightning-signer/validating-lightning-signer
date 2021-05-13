use std::sync::Arc;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use lightning::ln::chan_utils::ChannelPublicKeys;

use lightning_signer::node::node::{
    ChannelId, ChannelSetup, ChannelSlot, ChannelStub, CommitmentType, Node,
};
use lightning_signer::signer::multi_signer::SyncLogger;
use lightning_signer::util::test_utils::{TEST_NODE_CONFIG, TEST_SEED};
use lightning_signer::persist::{Persist, DummyPersister};

pub fn do_with_channel_stub<F: Fn(&ChannelStub) -> ()>(node: &Node, channel_id: &ChannelId, f: F) {
    let guard = node.channels();
    let slot = guard.get(&channel_id).unwrap().lock().unwrap();
    match &*slot {
        ChannelSlot::Stub(s) => f(&s),
        ChannelSlot::Ready(_) => panic!("expected channel stub"),
    }
}

pub fn make_node_and_channel(
    logger: &Arc<dyn SyncLogger>,
    channel_nonce: &Vec<u8>,
    channel_id: ChannelId,
) -> (PublicKey, Arc<Node>, ChannelStub) {
    let (node_id, node) = make_node(logger);

    let (_, channel) = node
        .new_channel(Some(channel_id), Some(channel_nonce.clone()), &Arc::clone(&node))
        .unwrap(); // NOT TESTED
    (node_id, node, channel.unwrap())
}

pub(crate) fn make_node(logger: &Arc<dyn SyncLogger>) -> (PublicKey, Arc<Node>) {
    let mut seed = [0; 32];
    seed.copy_from_slice(hex::decode(TEST_SEED[1]).unwrap().as_slice());

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let node = Arc::new(Node::new(logger, TEST_NODE_CONFIG, &seed, Network::Testnet, &persister));
    let node_id = node.get_id();
    (node_id, node)
}

pub fn create_test_channel_setup(dummy_pubkey: PublicKey) -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 123456,
        push_value_msat: 555,
        funding_outpoint: Default::default(),
        holder_to_self_delay: 10,
        holder_shutdown_script: None,
        counterparty_points: ChannelPublicKeys {
            funding_pubkey: dummy_pubkey,
            revocation_basepoint: dummy_pubkey,
            payment_point: dummy_pubkey,
            delayed_payment_basepoint: dummy_pubkey,
            htlc_basepoint: dummy_pubkey,
        },
        counterparty_to_self_delay: 11,
        counterparty_shutdown_script: Default::default(),
        commitment_type: CommitmentType::Legacy,
    }
}

pub fn make_dummy_pubkey(x: u8) -> PublicKey {
    let secp_ctx = Secp256k1::signing_only();
    let seckey = SecretKey::from_slice(&[x; 32]).unwrap();
    let dummy_pubkey = PublicKey::from_secret_key(&secp_ctx, &seckey);
    dummy_pubkey
}
