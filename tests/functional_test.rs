#![allow(unused_imports)]

extern crate lightning_signer;

use std::sync::{Arc, MutexGuard};

use bitcoin::{Block, BlockHeader, Network, OutPoint, Script, Transaction};
use bitcoin::consensus::serialize;
use bitcoinconsensus::{VERIFY_ALL, verify_with_flags};
use lightning::chain::chaininterface;
use lightning::chain::keysinterface::KeysInterface;
use lightning::ln::features::InitFeatures;
use lightning::ln::msgs::{ChannelMessageHandler, ChannelUpdate};
use lightning::util::config::{ChannelHandshakeConfig, UserConfig};
use lightning::util::events::MessageSendEventsProvider;
use lightning::util::logger::Logger;
use secp256k1::PublicKey;

use lightning_signer::{check_added_monitors, get_local_commitment_txn, check_spends};
use lightning_signer::server::my_signer::MySigner;
use lightning_signer::util::functional_test_utils::{
    close_channel, create_announced_chan_between_nodes, create_chanmon_cfgs, create_network,
    create_node_chanmgrs, NodeCfg, send_payment, TestChanMonCfg, TestChannelMonitor
};
use lightning_signer::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use lightning_signer::util::test_utils;

use self::lightning_signer::util::functional_test_utils::{
    claim_payment,
    create_announced_chan_between_nodes_with_value,
    route_payment};

pub fn create_node_cfgs_with_signer<'a>(
    node_count: usize,
    signer: &Arc<MySigner>,
    chanmon_cfgs: &'a Vec<TestChanMonCfg>,
) -> Vec<NodeCfg<'a>> {
    let mut nodes = Vec::new();

    for i in 0..node_count {
        let seed = [i as u8; 32];

        let node_id = signer.new_node();
        let keys_manager = LoopbackSignerKeysInterface {
            node_id,
            signer: Arc::clone(signer),
        };

        let chan_monitor = TestChannelMonitor::new(
            &chanmon_cfgs[i].chain_monitor,
            &chanmon_cfgs[i].tx_broadcaster,
            &chanmon_cfgs[i].logger,
            &chanmon_cfgs[i].fee_estimator,
        );

        nodes.push(NodeCfg {
            chain_monitor: &chanmon_cfgs[i].chain_monitor,
            logger: &chanmon_cfgs[i].logger,
            tx_broadcaster: &chanmon_cfgs[i].tx_broadcaster,
            fee_estimator: &chanmon_cfgs[i].fee_estimator,
            chan_monitor,
            keys_manager,
            node_seed: seed,
        });
    }

    nodes
}

#[test]
fn fake_network_with_signer_test() {
    // Simple test which builds a network of ChannelManagers, connects them to each other, and
    // tests that payments get routed and transactions broadcast in semi-reasonable ways.
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(4);
    let node_cfgs = create_node_cfgs_with_signer(4, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan_1 =
        create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
    let _chan_2 =
        create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());
    let _chan_3 =
        create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known());

    // Rebalance the network a bit by relaying one payment through all the channels...
    send_payment(&nodes[0], &vec![&nodes[1], &nodes[2], &nodes[3]][..], 8000000, 8_000_000);

    // Close channel normally
    close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
}

// Not currently used, but may be interesting for testing different to_self_delay values
// for peering nodes.
fn _alt_config() -> UserConfig {
    let mut cfg1 = UserConfig {
        own_channel_config: ChannelHandshakeConfig {
            minimum_depth: 6,
            our_to_self_delay: 145,
            our_htlc_minimum_msat: 1000,
        },
        peer_channel_config_limits: Default::default(),
        channel_options: Default::default()
    };
    cfg1.channel_options.announced_channel = true;
    cfg1.peer_channel_config_limits
        .force_announced_channel_preference = false;
    cfg1
}

#[test]
fn channel_force_close_test() {
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 99000000,
                                                              InitFeatures::known(), InitFeatures::known());

    // Close channel forcefully
    nodes[0].node.force_close_channel(&chan.2);
    assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[0], 1);

    // Cause the other node to sweep
    let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();

    // Check if closing tx correctly spends the funding
    check_spends!(node_txn[0], chan.3);

    let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
    nodes[1].block_notifier.block_connected(&Block { header, txdata: vec![node_txn[0].clone()] }, 0);
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[1], 1);
}

#[test]
fn justice_tx_test() {
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
    // node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
    let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
    assert_eq!(revoked_local_txn.len(), 1);
    // Only output is the full channel value back to nodes[0]:
    assert_eq!(revoked_local_txn[0].output.len(), 1);
    // Send a payment through, updating everyone's latest commitment txn
    send_payment(&nodes[0], &vec!(&nodes[1])[..], 5000000, 5_000_000);

    // Inform nodes[1] that nodes[0] broadcast a stale tx
    let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
    nodes[1].block_notifier.block_connected(&Block { header, txdata: vec![revoked_local_txn[0].clone()] }, 1);
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[1], 1);
}

#[test]
fn claim_htlc_test() {
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1000000, 59000000,
                                                              InitFeatures::known(), InitFeatures::known());
    // node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
    let payment_preimage = route_payment(&nodes[0], &vec!(&nodes[1])[..], 3000000).0;
    route_payment(&nodes[1], &vec!(&nodes[0])[..], 3000000).0;

    // Remote commitment txn with 4 outputs : to_local, to_remote, 1 outgoing HTLC, 1 incoming HTLC
    let remote_txn = get_local_commitment_txn!(nodes[0], chan.2);
    assert_eq!(remote_txn[0].output.len(), 4);
    assert_eq!(remote_txn[0].input.len(), 1);
    assert_eq!(remote_txn[0].input[0].previous_output.txid, chan.3.txid());

    // Check if closing tx correctly spends the funding
    check_spends!(remote_txn[0], chan.3);
    // Check if the HTLC sweep correctly spends the commitment
    check_spends!(remote_txn[1], remote_txn[0]);

    // Claim a HTLC without revocation (provide B monitor with preimage)
    nodes[1].node.claim_funds(payment_preimage, &None, 3_000_000);
    let header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };

    nodes[1].block_notifier.block_connected(&Block { header, txdata: vec![remote_txn[0].clone()] }, 1);
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 2);
    check_added_monitors!(nodes[1], 2);

    {
        let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
        // Check if closing tx correctly spends the funding
        check_spends!(node_txn[2], chan.3);
        // Check if the HTLC sweeps correctly spend the commitment
        check_spends!(node_txn[3], node_txn[2]);
        check_spends!(node_txn[4], node_txn[2]);
    }
}

#[test]
fn channel_force_close_with_htlc_test() {
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(3);
    let node_cfgs = create_node_cfgs_with_signer(3, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
    let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
    let _chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

    let _payment_preimage_1 = route_payment(&nodes[0], &vec!(&nodes[1], &nodes[2])[..], 3000000).0;

    // Close channel forcefully
    nodes[0].node.force_close_channel(&chan_1.2);
    assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[0], 1);

    let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();

    // Check if closing tx correctly spends the funding
    check_spends!(node_txn[0], chan_1.3);
}
