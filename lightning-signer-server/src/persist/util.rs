use std::sync::Arc;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use lightning::ln::chan_utils::ChannelPublicKeys;

use lightning_signer::channel::{
    ChannelId, ChannelSetup, ChannelSlot, ChannelStub, CommitmentType,
};
use lightning_signer::node::Node;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::util::test_utils::{TEST_NODE_CONFIG, TEST_SEED};

pub fn do_with_channel_stub<F: Fn(&ChannelStub) -> ()>(node: &Node, channel_id: &ChannelId, f: F) {
    let guard = node.channels();
    let slot = guard.get(&channel_id).unwrap().lock().unwrap();
    match &*slot {
        ChannelSlot::Stub(s) => f(&s),
        ChannelSlot::Ready(_) => panic!("expected channel stub"),
    }
}

pub fn make_node_and_channel(
    channel_nonce: &Vec<u8>,
    channel_id: ChannelId,
) -> (PublicKey, Arc<Node>, ChannelStub, [u8; 32]) {
    let (node_id, node, seed) = make_node();

    let (_, channel) = node
        .new_channel(
            Some(channel_id),
            Some(channel_nonce.clone()),
            &Arc::clone(&node),
        )
        .unwrap();
    (node_id, node, channel.unwrap(), seed)
}

pub(crate) fn make_node() -> (PublicKey, Arc<Node>, [u8; 32]) {
    let mut seed = [0; 32];
    seed.copy_from_slice(hex::decode(TEST_SEED[1]).unwrap().as_slice());

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let node = Arc::new(Node::new(
        TEST_NODE_CONFIG,
        &seed,
        Network::Testnet,
        &persister,
        vec![],
    ));
    let node_id = node.get_id();
    (node_id, node, seed)
}

pub fn create_test_channel_setup(dummy_pubkey: PublicKey) -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 123456,
        push_value_msat: 555,
        funding_outpoint: Default::default(),
        holder_selected_contest_delay: 10,
        holder_shutdown_script: None,
        counterparty_points: ChannelPublicKeys {
            funding_pubkey: dummy_pubkey,
            revocation_basepoint: dummy_pubkey,
            payment_point: dummy_pubkey,
            delayed_payment_basepoint: dummy_pubkey,
            htlc_basepoint: dummy_pubkey,
        },
        counterparty_selected_contest_delay: 11,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::Legacy,
    }
}

pub fn make_dummy_pubkey(x: u8) -> PublicKey {
    let secp_ctx = Secp256k1::signing_only();
    let seckey = SecretKey::from_slice(&[x; 32]).unwrap();
    let dummy_pubkey = PublicKey::from_secret_key(&secp_ctx, &seckey);
    dummy_pubkey
}
