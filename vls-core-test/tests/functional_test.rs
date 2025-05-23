#![allow(unused_imports)]

extern crate lightning_signer;

use core::time::Duration;
use core::default::Default;
use std::cell::RefCell;
use std::rc::Rc;

use lightning_signer::Arc;
use lightning_signer::OrderedSet;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::monitor::ChainMonitor;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1};
use std::collections::BTreeSet;
use bitcoin::hashes::hex::ToHex;
use itertools::Itertools;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{Block, BlockHeader, Network, OutPoint, Script, Transaction, TxMerkleNode};
use bitcoin::hashes::Hash;
use lightning::chain::chaininterface;
use lightning::ln::channelmanager;
use lightning::ln::features::InitFeatures;
use lightning::ln::functional_test_utils::create_node_cfgs;
use lightning::ln::msgs::{ChannelMessageHandler, ChannelUpdate};
use lightning::util::config::{ChannelHandshakeConfig, UserConfig};
use lightning::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider, ClosureReason};
use lightning::util::logger::Logger;
use lightning_signer::lightning_invoice;

use lightning_signer::policy::null_validator::NullValidatorFactory;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use lightning_signer::util::test_utils;
use lightning_signer::util::test_utils::{TestChainMonitor, REGTEST_NODE_CONFIG, make_block, make_genesis_starting_time_factory, ChannelBalanceBuilder};
use lightning_signer::channel::{ChannelId, ChannelBalance};
use lightning_signer::node::{NodeConfig, NodeMonitor, NodeServices};
use lightning_signer::persist::{DummyPersister, DummySeedPersister};
use lightning_signer::policy::onchain_validator::OnchainValidatorFactory;
use lightning_signer::policy::simple_validator::{make_simple_policy, SimplePolicy, SimpleValidatorFactory};
use lightning_signer::lightning;
use lightning_signer::bitcoin;

use crate::lightning::ln::chan_utils::OFFERED_HTLC_SCRIPT_WEIGHT;
use crate::lightning::ln::functional_test_utils::ACCEPTED_HTLC_SCRIPT_WEIGHT;

#[allow(unused)]
#[macro_use]
mod functional_test_utils;

use functional_test_utils::*;

use test_log::test;

use log::debug;
use lightning_signer::util::clock::StandardClock;

const ANTI_REORG_DELAY: u32 = 6;

pub fn create_node_cfgs_with_signer<'a>(
    node_count: usize,
    signer: &Arc<MultiSigner>,
    chanmon_cfgs: &'a Vec<TestChanMonCfg>,
) -> Vec<NodeCfg<'a>> {
    let mut nodes = Vec::new();

    let config = REGTEST_NODE_CONFIG;

    for i in 0..node_count {
        let cfg = create_node_cfg(signer, chanmon_cfgs, config, i);
        nodes.push(cfg);
    }

    nodes
}

fn create_node_cfg<'a>(signer: &Arc<MultiSigner>, chanmon_cfgs: &'a Vec<TestChanMonCfg>, config: NodeConfig, idx: usize) -> NodeCfg<'a> {
    let seed = [idx as u8; 32];

    let seed_persister = Arc::new(DummySeedPersister {});

    let node_id = signer.new_node_with_seed(config, &seed, seed_persister).unwrap();

    let keys_manager = LoopbackSignerKeysInterface {
        node_id,
        signer: Arc::clone(signer),
    };

    let chain_monitor = TestChainMonitor::new(
        Some(&chanmon_cfgs[idx].chain_source),
        &chanmon_cfgs[idx].tx_broadcaster,
        Arc::clone(&chanmon_cfgs[idx].logger),
        &chanmon_cfgs[idx].fee_estimator,
        &chanmon_cfgs[idx].persister,
    );

    let cfg = NodeCfg {
        chain_source: &chanmon_cfgs[idx].chain_source,
        logger: Arc::clone(&chanmon_cfgs[idx].logger),
        tx_broadcaster: &chanmon_cfgs[idx].tx_broadcaster,
        fee_estimator: &chanmon_cfgs[idx].fee_estimator,
        chain_monitor,
        keys_manager,
        network_graph: chanmon_cfgs[idx].network_graph.clone(),
        node_seed: seed,
    };
    cfg
}

// Sum of all claimable channel balances for the node
fn channel_balance(node: &Node) -> ChannelBalance {
    node
        .keys_manager
        .signer
        .get_node(&node.keys_manager.node_id)
        .unwrap().channel_balance()
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn fake_network_with_signer_test() {
    // Simple test which builds a network of ChannelManagers, connects them to each other, and
    // tests that payments get routed and transactions broadcast in semi-reasonable ways.
    let signer = new_signer();

    let chanmon_cfgs = create_chanmon_cfgs(4);
    let node_cfgs = create_node_cfgs_with_signer(4, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);
    create_default_chan(&nodes, 1, 2);
    create_default_chan(&nodes, 2, 3);

    // Rebalance the network a bit by relaying one payment through all the channels...
    send_payment(
        &nodes[0],
        &vec![&nodes[1], &nodes[2], &nodes[3]][..],
        8000000,
    );

    // Close channel normally
    close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
   	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
}

fn new_signer() -> Arc<MultiSigner> {
    let validator_factory = Arc::new(OnchainValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(REGTEST_NODE_CONFIG.network);
    let clock = Arc::new(StandardClock());
    let persister = Arc::new(DummyPersister {});
    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys: vec![]
    };
    Arc::new(MultiSigner::new_with_test_mode(true, vec![], services))
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn invoice_test() {
    let network = Network::Regtest;
    let policy = make_simple_policy(network);
    // can't do routing enforcement yet because of #331
    // policy.enforce_balance = true;
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let starting_time_factory = make_genesis_starting_time_factory(REGTEST_NODE_CONFIG.network);
    let clock = Arc::new(StandardClock());
    let persister = Arc::new(DummyPersister {});
    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys: vec![]
    };
    let validating_signer = Arc::new(MultiSigner::new(services));

    let chanmon_cfgs = create_chanmon_cfgs(3);
    let mut node_cfgs = Vec::new();

    node_cfgs.push(create_node_cfg(&validating_signer, &chanmon_cfgs, REGTEST_NODE_CONFIG, 0));
    // routing nodes can't turn on invoice validation yet
    node_cfgs.push(create_node_cfg(&validating_signer, &chanmon_cfgs, REGTEST_NODE_CONFIG, 1));
    node_cfgs.push(create_node_cfg(&validating_signer, &chanmon_cfgs, REGTEST_NODE_CONFIG, 2));
    let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
    let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    create_default_chan(&nodes, 0, 1);
    create_default_chan(&nodes, 1, 2);

    let signer_node0 = nodes[0].keys_manager.get_node();
    let channel_keys0 = signer_node0.channels().keys().cloned().collect::<Vec<_>>();
    let signer_node1 = nodes[1].keys_manager.get_node();
    let signer_node2 = nodes[2].keys_manager.get_node();
    let channel_keys2 = signer_node2.channels().keys().cloned().collect::<Vec<_>>();
    // The actual balance is lower because of fees
    assert_eq!(holder_balances(&signer_node0, channel_keys0[0].clone(), true), (100_000, 99_817, 99_817));
    assert_eq!(holder_balances(&signer_node2, channel_keys2[0].clone(), false), (0, 0, 0));

    assert_eq!(signer_node0.get_state().excess_amount, 0);
    assert_eq!(signer_node1.get_state().excess_amount, 0);
    assert_eq!(signer_node2.get_state().excess_amount, 0);

    assert_eq!(channel_balance(&nodes[0]), ChannelBalanceBuilder::new().claimable(100_000).channel_count(1).build());
    assert_eq!(channel_balance(&nodes[1]), ChannelBalanceBuilder::new().claimable(100_000).channel_count(2).build());
    assert_eq!(channel_balance(&nodes[2]), ChannelBalanceBuilder::new().channel_count(1).build());

    // Send 0 -> 1 -> 2
    send_payment(
        &nodes[0],
        &vec![&nodes[1], &nodes[2]][..],
        7_000_000,
    );

    // an extra satoshi was consumed as fee
    assert_eq!(holder_balances(&signer_node0, channel_keys0[0].clone(), true), (92_999, 92_816, 92_816));
    assert_eq!(holder_balances(&signer_node2, channel_keys2[0].clone(), false), (7_000, 7_000, 7_000));

    assert_eq!(signer_node0.get_state().excess_amount, 0);
    // Gained routing fee
    // assert_eq!(signer_node1.get_state().excess_amount, 1);
    assert_eq!(signer_node2.get_state().excess_amount, 0);

    assert_eq!(channel_balance(&nodes[0]), ChannelBalanceBuilder::new().claimable(92_999).channel_count(1).build());
    assert_eq!(channel_balance(&nodes[1]), ChannelBalanceBuilder::new().claimable(100_001).channel_count(2).build());
    assert_eq!(channel_balance(&nodes[2]), ChannelBalanceBuilder::new().claimable(7_000).channel_count(1).build());
}

// Get the holder policy balance, as well as the actual balance in the holder and counterparty txs
fn holder_balances(signer_node0: &Arc<lightning_signer::node::Node>, id: ChannelId, is_outbound: bool) -> (u64, u64, u64) {
    signer_node0.with_channel(&id, |chan| {
        let estate = &chan.enforcement_state;
        let nstate = signer_node0.get_state();
        let claimable_balance = estate.current_holder_commit_info.clone().unwrap().claimable_balance(&*nstate, is_outbound, if is_outbound { 100000 } else { 0 });
        Ok((claimable_balance,
            estate.current_holder_commit_info.as_ref().unwrap().to_broadcaster_value_sat,
            estate.current_counterparty_commit_info.as_ref().unwrap().to_countersigner_value_sat,
        ))
    }).expect("channel")
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn dust_test() {
    let signer = new_signer();
    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    create_default_chan(&nodes, 0, 1);

    send_payment(&nodes[0], &vec![&nodes[1]], 1234);
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn simple_payment_test() {
    let signer = new_signer();
    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    create_default_chan(&nodes, 0, 1);

    send_payment(&nodes[0], &vec![&nodes[1]], 3333000);
}

fn create_default_chan(nodes: &Vec<Node>, a: usize, b: usize) {
    create_announced_chan_between_nodes(
        &nodes,
        a,
        b,
    );
}

// Not currently used, but may be interesting for testing different to_self_delay values
// for peering nodes.
fn _alt_config() -> UserConfig {
    let mut cfg1 = UserConfig {
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 6,
            our_to_self_delay: 145,
            our_htlc_minimum_msat: 1000,
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            negotiate_scid_privacy: false,
            announced_channel: true,
            commit_upfront_shutdown_pubkey: false,
            their_channel_reserve_proportional_millionths: 0,
            negotiate_anchors_zero_fee_htlc_tx: false,
            our_max_accepted_htlcs: 50,
        },
        channel_handshake_limits: Default::default(),
        channel_config: Default::default(),
        accept_forwards_to_priv_channels: true,
        accept_inbound_channels: true,
        manually_accept_inbound_channels: false,
        accept_intercept_htlcs: false,
        accept_mpp_keysend: false,
    };
    cfg1.channel_handshake_limits
        .force_announced_channel_preference = false;
    cfg1
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn channel_force_close_test() {
    let signer = new_signer();

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan = create_announced_chan_between_nodes_with_value(
        &nodes,
        0,
        1,
        100000,
        0,
    );

    // Close channel forcefully
    let cp_id = nodes[1].node.get_our_node_id();
    let _ = nodes[0].node.force_close_broadcasting_latest_txn(&chan.2, &cp_id);

    check_closed_broadcast!(nodes[0], true);

    // assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[0], 1);

    // Cause the other node to sweep
    let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
    assert_eq!(node_txn.len(), 1);

    // Check if closing tx correctly spends the funding
    check_spends!(node_txn[0], chan.3);

    let headers = tip_for_node(&nodes[1]);
    let block = make_block(headers.0, vec![node_txn[0].clone()]);

    connect_block(
        &nodes[1],
        &block,
        &headers.1,
    );
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 2);
    check_added_monitors!(nodes[1], 1);
    check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
    check_closed_event!(nodes[0], 1, ClosureReason::HolderForceClosed);
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn justice_tx_test() {
    let signer = new_signer();

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan_1 = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
    );
    // node[0] is gonna to revoke an old state thus node[1] should be able to claim the revoked output
    let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);
    assert_eq!(revoked_local_txn.len(), 1);
    // Only output is the full channel value back to nodes[0]:
    assert_eq!(revoked_local_txn[0].output.len(), 1);
    // Send a payment through, updating everyone's latest commitment txn
    send_payment(&nodes[0], &vec![&nodes[1]][..], 5000000);

    mine_transaction(&nodes[1], &revoked_local_txn[0]);
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 2);
    check_added_monitors!(nodes[1], 1);
    let node1_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
    assert_eq!(node1_txn.len(), 1); // ChannelMonitor: penalty tx
    check_spends!(node1_txn[0], revoked_local_txn[0]);
    check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn claim_htlc_outputs_single_tx() {
    let signer = new_signer();

    // Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
    let chanmon_cfgs = create_chanmon_cfgs(2);
    //chanmon_cfgs[0].keys_manager.disable_revocation_policy_check = true;
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Disable validation on node 0 so we can sign revoked commitment below
    nodes[0]
        .keys_manager
        .signer
        .get_node(&nodes[0].keys_manager.node_id)
        .unwrap()
        .set_validator_factory(Arc::new(NullValidatorFactory {}));

    let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1);

    assert_eq!(channel_balance(&nodes[0]), ChannelBalanceBuilder::new().claimable(100_000).channel_count(1).build());
    assert_eq!(channel_balance(&nodes[1]), ChannelBalanceBuilder::new().channel_count(1).build());

    // Rebalance the network to generate htlc in the two directions
    send_payment(&nodes[0], &[&nodes[1]], 8_000_000);
    // node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
    // time as two different claim transactions as we're gonna to timeout htlc with given a high current height
    let payment_preimage_1 = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
    let (_payment_preimage_2, payment_hash_2, _payment_secret_2) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);

    // Get the will-be-revoked local txn from node[0]
    let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);

    //Revoke the old state
    claim_payment(&nodes[0], &vec!(&nodes[1])[..], payment_preimage_1);

    {
        // NOTE - we use a longer conf height because find_route adds a random offset to the CLTV
        confirm_transaction_at(&nodes[0], &revoked_local_txn[0], 300);
        check_added_monitors!(nodes[0], 1);
        confirm_transaction_at(&nodes[1], &revoked_local_txn[0], 300);
        check_added_monitors!(nodes[1], 1);
        check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
        let events = nodes[0].node.get_and_clear_pending_events();
        expect_pending_htlcs_forwardable_from_events!(nodes[0], events[0..1], true);
        match events.last().unwrap() {
            Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {}
            _ => panic!("Unexpected event"),
        }

        connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
        assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

        let mut node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

		// Check the pair local commitment and HTLC-timeout broadcast due to HTLC expiration
		assert_eq!(node_txn[0].input.len(), 1);
		check_spends!(node_txn[0], chan_1.3);
		assert_eq!(node_txn[1].input.len(), 1);
		let witness_script = node_txn[1].input[0].witness.last().unwrap();
		assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
		check_spends!(node_txn[1], node_txn[0]);

		// Filter out any non justice transactions.
		node_txn.retain(|tx| tx.input[0].previous_output.txid == revoked_local_txn[0].txid());
		assert!(node_txn.len() > 3);

		assert_eq!(node_txn[0].input.len(), 1);
		assert_eq!(node_txn[1].input.len(), 1);
		assert_eq!(node_txn[2].input.len(), 1);

		check_spends!(node_txn[0], revoked_local_txn[0]);
		check_spends!(node_txn[1], revoked_local_txn[0]);
		check_spends!(node_txn[2], revoked_local_txn[0]);

		let mut witness_lens = BTreeSet::new();
		witness_lens.insert(node_txn[0].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[1].input[0].witness.last().unwrap().len());
		witness_lens.insert(node_txn[2].input[0].witness.last().unwrap().len());
		assert_eq!(witness_lens.len(), 3);
		assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
		assert_eq!(*witness_lens.iter().skip(1).next().unwrap(), OFFERED_HTLC_SCRIPT_WEIGHT); // revoked offered HTLC
		assert_eq!(*witness_lens.iter().skip(2).next().unwrap(), ACCEPTED_HTLC_SCRIPT_WEIGHT); // revoked received HTLC

		// Finally, mine the penalty transactions and check that we get an HTLC failure after
		// ANTI_REORG_DELAY confirmations.
		mine_transaction(&nodes[1], &node_txn[0]);
		mine_transaction(&nodes[1], &node_txn[1]);
		mine_transaction(&nodes[1], &node_txn[2]);
		connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
		expect_payment_failed!(nodes[1], payment_hash_2, false);
    }
    get_announce_close_broadcast_events(&nodes, 0, 1);
    assert_eq!(nodes[0].node.list_channels().len(), 0);
    assert_eq!(nodes[1].node.list_channels().len(), 0);
}

fn do_test_onchain_htlc_settlement_after_close(broadcast_alice: bool, go_onchain_before_fulfill: bool) {
	// If we route an HTLC, then learn the HTLC's preimage after the upstream channel has been
	// force-closed, we must claim that HTLC on-chain. (Given an HTLC forwarded from Alice --> Bob -->
	// Carol, Alice would be the upstream node, and Carol the downstream.)
	//
	// Steps of the test:
	// 1) Alice sends a HTLC to Carol through Bob.
	// 2) Carol doesn't settle the HTLC.
	// 3) If broadcast_alice is true, Alice force-closes her channel with Bob. Else Bob force closes.
	// Steps 4 and 5 may be reordered depending on go_onchain_before_fulfill.
	// 4) Bob sees the Alice's commitment on his chain or vice versa. An offered output is present
	//    but can't be claimed as Bob doesn't have yet knowledge of the preimage.
	// 5) Carol release the preimage to Bob off-chain.
	// 6) Bob claims the offered output on the broadcasted commitment.
    debug!("broadcast_alice: {}, go_onchain_before_fulfill: {}",
           broadcast_alice, go_onchain_before_fulfill);
    // If we route an HTLC, then learn the HTLC's preimage after the upstream channel has been
    // force-closed, we must claim that HTLC on-chain. (Given an HTLC forwarded from Alice --> Bob -->
    // Carol, Alice would be the upstream node, and Carol the downstream.)
    //
    // Steps of the test:
    // 1) Alice sends a HTLC to Carol through Bob.
    // 2) Carol doesn't settle the HTLC.
    // 3) If broadcast_alice is true, Alice force-closes her channel with Bob. Else Bob force closes.
    // Steps 4 and 5 may be reordered depending on go_onchain_before_fulfill.
    // 4) Bob sees the Alice's commitment on his chain or vice versa. An offered output is present
    //    but can't be claimed as Bob doesn't have yet knowledge of the preimage.
    // 5) Carol release the preimage to Bob off-chain.
    // 6) Bob claims the offered output on the broadcasted commitment.
    let signer = new_signer();

    let chanmon_cfgs = create_chanmon_cfgs(3);
    let node_cfgs = create_node_cfgs_with_signer(3, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
    let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let chan_ab = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100000, 10001);
	create_announced_chan_between_nodes_with_value(&nodes, 1, 2, 100000, 10001);

	// Steps (1) and (2):
	// Send an HTLC Alice --> Bob --> Carol, but Carol doesn't settle the HTLC back.
	let (payment_preimage, payment_hash, _payment_secret) = route_payment(&nodes[0], &[&nodes[1], &nodes[2]], 3_000_000);

	// Check that Alice's commitment transaction now contains an output for this HTLC.
	let alice_txn = get_local_commitment_txn!(nodes[0], chan_ab.2);
	check_spends!(alice_txn[0], chan_ab.3);
	assert_eq!(alice_txn[0].output.len(), 2);
	check_spends!(alice_txn[1], alice_txn[0]); // 2nd transaction is a non-final HTLC-timeout
	assert_eq!(alice_txn.len(), 2);

	// Steps (3) and (4):
	// If `go_onchain_before_fufill`, broadcast the relevant commitment transaction and check that Bob
	// responds by (1) broadcasting a channel update and (2) adding a new ChannelMonitor.
	let mut force_closing_node = 0; // Alice force-closes
	let mut counterparty_node = 1; // Bob if Alice force-closes

	// Bob force-closes
	if !broadcast_alice {
		force_closing_node = 1;
		counterparty_node = 0;
	}
	nodes[force_closing_node].node.force_close_broadcasting_latest_txn(&chan_ab.2, &nodes[counterparty_node].node.get_our_node_id()).unwrap();
	check_closed_broadcast!(nodes[force_closing_node], true);
	check_added_monitors!(nodes[force_closing_node], 1);
	check_closed_event!(nodes[force_closing_node], 1, ClosureReason::HolderForceClosed);
	if go_onchain_before_fulfill {
		let txn_to_broadcast = match broadcast_alice {
			true => alice_txn.clone(),
			false => get_local_commitment_txn!(nodes[1], chan_ab.2)
		};
        let headers = tip_for_node(&nodes[1]);
        let block = make_block(headers.0, vec![txn_to_broadcast[0].clone()]);

        connect_block(&nodes[1], &block, &headers.1);
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors!(nodes[1], 1);
			check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
		}
	}

	// Step (5):
	// Carol then claims the funds and sends an update_fulfill message to Bob, and they go through the
	// process of removing the HTLC from their commitment transactions.
	nodes[2].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[2], 1);
	expect_payment_claimed!(nodes[2], payment_hash, 3_000_000);

	let carol_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	assert!(carol_updates.update_add_htlcs.is_empty());
	assert!(carol_updates.update_fail_htlcs.is_empty());
	assert!(carol_updates.update_fail_malformed_htlcs.is_empty());
	assert!(carol_updates.update_fee.is_none());
	assert_eq!(carol_updates.update_fulfill_htlcs.len(), 1);

	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &carol_updates.update_fulfill_htlcs[0]);
	expect_payment_forwarded!(nodes[1], nodes[0], nodes[2], if go_onchain_before_fulfill || force_closing_node == 1 { None } else { Some(1000) }, false, false);
	// If Alice broadcasted but Bob doesn't know yet, here he prepares to tell her about the preimage.
	if !go_onchain_before_fulfill && broadcast_alice {
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
				assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		};
	}
	nodes[1].node.handle_commitment_signed(&nodes[2].node.get_our_node_id(), &carol_updates.commitment_signed);
	// One monitor update for the preimage to update the Bob<->Alice channel, one monitor update
	// Carol<->Bob's updated commitment transaction info.
	check_added_monitors!(nodes[1], 2);

	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);
	let bob_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let bob_updates = match events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[2].node.get_our_node_id());
			(*updates).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[2].node.handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bob_revocation);
	check_added_monitors!(nodes[2], 1);
	nodes[2].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &bob_updates.commitment_signed);
	check_added_monitors!(nodes[2], 1);

	let events = nodes[2].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let carol_revocation = match events[0] {
		MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	nodes[1].node.handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &carol_revocation);
	check_added_monitors!(nodes[1], 1);

	// If this test requires the force-closed channel to not be on-chain until after the fulfill,
	// here's where we put said channel's commitment tx on-chain.
	let mut txn_to_broadcast = alice_txn.clone();
	if !broadcast_alice { txn_to_broadcast = get_local_commitment_txn!(nodes[1], chan_ab.2); }
	if !go_onchain_before_fulfill {
        let headers = tip_for_node(&nodes[1]);
        let block = make_block(headers.0, vec![txn_to_broadcast[0].clone()]);

        connect_block(&nodes[1], &block, &headers.1);
		// If Bob was the one to force-close, he will have already passed these checks earlier.
		if broadcast_alice {
			check_closed_broadcast!(nodes[1], true);
			check_added_monitors!(nodes[1], 1);
			check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
		}
		let bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
		if broadcast_alice {
			assert_eq!(bob_txn.len(), 1);
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
		} else {
			assert_eq!(bob_txn.len(), 2);
			check_spends!(bob_txn[0], chan_ab.3);
		}
	}

	// Step (6):
	// Finally, check that Bob broadcasted a preimage-claiming transaction for the HTLC output on the
	// broadcasted commitment transaction.
	{
		// If Alice force-closed, Bob only broadcasts a HTLC-output-claiming transaction. Otherwise,
		// Bob force-closed and broadcasts the commitment transaction along with a
		// HTLC-output-claiming transaction.
		let bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
		if broadcast_alice {
			assert_eq!(bob_txn.len(), 1);
			check_spends!(bob_txn[0], txn_to_broadcast[0]);
		} else {
			assert_eq!(bob_txn.len(), 2);
			check_spends!(bob_txn[1], txn_to_broadcast[0]);
		}
	}
}

#[test]
#[ignore = "needs sync up with the new ldk version because the execution will not terminate"]
fn test_onchain_htlc_settlement_after_close() {
    do_test_onchain_htlc_settlement_after_close(true, true);
    do_test_onchain_htlc_settlement_after_close(false, true); // Technically redundant, but may as well
    do_test_onchain_htlc_settlement_after_close(true, false);
    do_test_onchain_htlc_settlement_after_close(false, false);
}

macro_rules! check_spendable_outputs {
    ($node: expr, $der_idx: expr, $keysinterface: expr, $chan_value: expr) => {{
        let mut events = $node
            .chain_monitor
            .chain_monitor
            .get_and_clear_pending_events();
        let mut txn = Vec::new();
        let mut all_outputs = Vec::new();
        for event in events.drain(..) {
            match event {
                Event::SpendableOutputs { mut outputs, .. } => {
                    for outp in outputs.drain(..) {
                        txn.push(
                            $keysinterface
                                .spend_spendable_outputs(
                                    &[&outp],
                                    Vec::new(),
                                    Builder::new()
                                        .push_opcode(opcodes::all::OP_RETURN)
                                        .into_script(),
                                    253,
                                )
                                .unwrap(),
                        );
                        all_outputs.push(outp);
                    }
                }
                _ => panic!("Unexpected event"),
            };
        }
        if all_outputs.len() > 1 {
            if let Ok(tx) = $keysinterface.spend_spendable_outputs(
                &all_outputs.iter().map(|a| a).collect::<Vec<_>>(),
                Vec::new(),
                Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                253,
            ) {
                txn.push(tx);
            }
        }
        txn
    }};
}

#[test]
#[ignore = "needs sync up with the new ldk version"]
fn test_static_output_closing_tx() {
    let signer = new_signer();

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
    );

    send_payment(&nodes[0], &vec![&nodes[1]][..], 8000000);
    let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

    mine_transaction(&nodes[0], &closing_tx);
	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
    connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

    let spend_txn = check_spendable_outputs!(nodes[0], 2, node_cfgs[0].keys_manager, 100000);
    assert_eq!(spend_txn.len(), 1);
    check_spends!(spend_txn[0], closing_tx);

    mine_transaction(&nodes[1], &closing_tx);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
    connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

    let spend_txn = check_spendable_outputs!(nodes[1], 2, node_cfgs[1].keys_manager, 100000);
    assert_eq!(spend_txn.len(), 1);
    check_spends!(spend_txn[0], closing_tx);
}

// Local Variables:
// inhibit-rust-format-buffer: t
// End:
