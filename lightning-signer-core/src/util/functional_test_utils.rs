#![allow(missing_docs)]
//! A bunch of useful utilities for building networks of nodes and exchanging messages between
//! nodes for functional tests.

use core::cell::RefCell;
use crate::Rc;
use crate::sync::Mutex;

use bitcoin;
use bitcoin::{Block, Network, PackedLockTime, Transaction, TxOut};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use chain::transaction::OutPoint;
use lightning::chain;
use lightning::chain::{Confirm, Listen, chaininterface};
use lightning::ln;
use lightning::ln::channelmanager::{ChainParameters, MIN_FINAL_CLTV_EXPIRY};
use lightning::chain::BestBlock;
use lightning::ln::features::InvoiceFeatures;
use lightning::ln::functional_test_utils::{ConnectStyle, test_default_channel_config};
use lightning::ln::PaymentSecret;
use lightning::routing::router::{PaymentParameters, Route, RouteParameters};
use lightning::util;
use lightning::util::config::UserConfig;
use lightning::util::test_utils;
use lightning::util::events::PaymentPurpose;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use ln::{PaymentHash, PaymentPreimage};
use ln::channelmanager::ChannelManager;
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};

use crate::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use crate::util::test_utils::{make_block, proof_for_block, TestChainMonitor, TestPersister};

use core::cmp;
use std::sync::Arc;
use bitcoin::bech32::ToBase32;
use log::info;

pub const CHAN_CONFIRM_DEPTH: u32 = 10;

/// Mine the given transaction in the next block and then mine CHAN_CONFIRM_DEPTH - 1 blocks on
/// top, giving the given transaction CHAN_CONFIRM_DEPTH confirmations.
pub fn confirm_transaction<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
    confirm_transaction_at(node, tx, node.best_block_info().1 + 1);
    connect_blocks(node, CHAN_CONFIRM_DEPTH - 1);
}
/// Mine a signle block containing the given transaction
pub fn mine_transaction<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
    let height = node.best_block_info().1 + 1;
    confirm_transaction_at(node, tx, height);
}
/// Mine the given transaction at the given height, mining blocks as required to build to that
/// height
pub fn confirm_transaction_at<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, tx: &Transaction, conf_height: u32) {
    let first_connect_height = node.best_block_info().1 + 1;
    assert!(first_connect_height <= conf_height);
    if conf_height - first_connect_height >= 1 {
        connect_blocks(node, conf_height - first_connect_height);
    }
    let mut txs = Vec::new();
    for i in 0..*node.network_chan_count.borrow() { // Make sure we don't end up with channels at the same short id by offsetting by chan_count
        txs.push(Transaction { version: 0, lock_time: PackedLockTime(i), input: Vec::new(), output: Vec::new() });
    }
    txs.push(tx.clone());
    let block = make_block(tip_for_node(node), txs);
    connect_block(node, &block);
}

pub fn tip_for_node(node: &Node) -> BlockHeader {
    let node = node.keys_manager.get_node();
    let tracker = node.get_tracker();
    tracker.tip().clone()
}

pub fn connect_blocks<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, depth: u32) -> BlockHash {
    let skip_intermediaries = match *node.connect_style.borrow() {
        ConnectStyle::BestBlockFirstSkippingBlocks|ConnectStyle::TransactionsFirstSkippingBlocks|
        ConnectStyle::BestBlockFirstReorgsOnlyTip|ConnectStyle::TransactionsFirstReorgsOnlyTip => true,
        _ => false,
    };

    let coinbase = Transaction {
        version: 0,
        lock_time: PackedLockTime(depth),
        input: vec![],
        output: vec![]
    };
    let mut block = make_block(tip_for_node(node), vec![coinbase]);
    assert!(depth >= 1);
    for d in 0..depth - 1 {
        let coinbase = Transaction {
            version: 0,
            lock_time: PackedLockTime(d),
            input: vec![],
            output: vec![]
        };
        do_connect_block(node, &block, skip_intermediaries);
        block = make_block(tip_for_node(node), vec![coinbase]);
    }
    connect_block(node, &block);
    block.header.block_hash()
}

pub fn connect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, block: &Block) {
    do_connect_block(node, block, false);
}

fn do_connect_block<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, block: &Block, skip_intermediaries: bool) {
    let height = node.best_block_info().1 + 1;
    let proof = proof_for_block(block);

    node.keys_manager.get_node().get_tracker().add_block(block.header, block.txdata.clone(), proof).unwrap();
    if !skip_intermediaries {
        let txdata: Vec<_> = block.txdata.iter().enumerate().collect();
        match *node.connect_style.borrow() {
            ConnectStyle::BestBlockFirst|ConnectStyle::BestBlockFirstSkippingBlocks|ConnectStyle::BestBlockFirstReorgsOnlyTip => {
                node.chain_monitor.chain_monitor.best_block_updated(&block.header, height);
                node.chain_monitor.chain_monitor.transactions_confirmed(&block.header, &txdata, height);
                node.node.best_block_updated(&block.header, height);
                node.node.transactions_confirmed(&block.header, &txdata, height);
            },
            ConnectStyle::TransactionsFirst|ConnectStyle::TransactionsFirstSkippingBlocks|ConnectStyle::TransactionsFirstReorgsOnlyTip => {
                node.chain_monitor.chain_monitor.transactions_confirmed(&block.header, &txdata, height);
                node.chain_monitor.chain_monitor.best_block_updated(&block.header, height);
                node.node.transactions_confirmed(&block.header, &txdata, height);
                node.node.best_block_updated(&block.header, height);
            },
            ConnectStyle::FullBlockViaListen => {
                node.chain_monitor.chain_monitor.block_connected(&block, height);
                node.node.block_connected(&block, height);
            }
        }
    }

    node.node.test_process_background_events();
    node.blocks.borrow_mut().push((block.header, height));
}

pub fn disconnect_block<'a, 'b, 'c, 'd>(
    node: &'a Node<'b, 'c, 'd>,
    header: &BlockHeader,
    height: u32,
) {
    node.chain_monitor
        .chain_monitor
        .block_disconnected(header, height);
    node.node.block_disconnected(header, height);
}

pub struct TestChanMonCfg {
    pub tx_broadcaster: TestBroadcaster,
    pub fee_estimator: test_utils::TestFeeEstimator,
    pub chain_source: test_utils::TestChainSource,
    pub persister: TestPersister,
    pub logger: Arc<test_utils::TestLogger>,
    pub network_graph: NetworkGraph<Arc<test_utils::TestLogger>>,
}

pub struct NodeCfg<'a> {
    pub chain_source: &'a test_utils::TestChainSource,
    pub tx_broadcaster: &'a TestBroadcaster,
    pub fee_estimator: &'a test_utils::TestFeeEstimator,
    pub chain_monitor: TestChainMonitor<'a>,
    pub keys_manager: LoopbackSignerKeysInterface,
    pub logger: Arc<test_utils::TestLogger>,
    pub network_graph: &'a NetworkGraph<Arc<test_utils::TestLogger>>,
    pub node_seed: [u8; 32],
}

pub struct Node<'a, 'b: 'a, 'c: 'b> {
    pub chain_source: &'c test_utils::TestChainSource,
    pub tx_broadcaster: &'c TestBroadcaster,
    pub chain_monitor: &'b TestChainMonitor<'c>,
    pub keys_manager: &'b LoopbackSignerKeysInterface,
    pub node: &'a ChannelManager<
        LoopbackChannelSigner,
        &'b TestChainMonitor<'c>,
        &'c TestBroadcaster,
        &'b LoopbackSignerKeysInterface,
        &'c test_utils::TestFeeEstimator,
        Arc<test_utils::TestLogger>,
    >,
    pub network_graph: &'c NetworkGraph<Arc<test_utils::TestLogger>>,
    pub net_graph_msg_handler: P2PGossipSync<&'c NetworkGraph<Arc<test_utils::TestLogger>>, &'c test_utils::TestChainSource, Arc<test_utils::TestLogger>>,
    pub node_seed: [u8; 32],
    pub network_payment_count: Rc<RefCell<u8>>,
    pub network_chan_count: Rc<RefCell<u32>>,
    pub logger: Arc<test_utils::TestLogger>,
    pub blocks: RefCell<Vec<(BlockHeader, u32)>>,
    pub connect_style: Rc<RefCell<ConnectStyle>>,
    pub use_invoices: bool,
}
impl<'a, 'b, 'c> Node<'a, 'b, 'c> {
    pub fn best_block_hash(&self) -> BlockHash {
        self.blocks.borrow_mut().last().unwrap().0.block_hash()
    }
    pub fn best_block_info(&self) -> (BlockHash, u32) {
        self.blocks.borrow_mut().last().map(|(a, b)| (a.block_hash(), *b)).unwrap()
    }
}

impl<'a, 'b, 'c> Drop for Node<'a, 'b, 'c> {
    fn drop(&mut self) {
        if !::std::thread::panicking() {
            // Check that we processed all pending events
            assert!(self.node.get_and_clear_pending_msg_events().is_empty());
            assert!(self.node.get_and_clear_pending_events().is_empty());
            assert!(self.chain_monitor.added_monitors.lock().unwrap().is_empty());
        }
    }
}

pub fn create_chan_between_nodes<'a, 'b, 'c, 'd>(
    node_a: &'a Node<'b, 'c, 'd>,
    node_b: &'a Node<'b, 'c, 'd>,
    a_flags: InitFeatures,
    b_flags: InitFeatures,
) -> (
    msgs::ChannelAnnouncement,
    msgs::ChannelUpdate,
    msgs::ChannelUpdate,
    [u8; 32],
    Transaction,
) {
    create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001, a_flags, b_flags)
}

pub fn create_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(
    node_a: &'a Node<'b, 'c, 'd>,
    node_b: &'a Node<'b, 'c, 'd>,
    channel_value: u64,
    push_msat: u64,
    a_flags: InitFeatures,
    b_flags: InitFeatures,
) -> (
    msgs::ChannelAnnouncement,
    msgs::ChannelUpdate,
    msgs::ChannelUpdate,
    [u8; 32],
    Transaction,
) {
    let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(
        node_a,
        node_b,
        channel_value,
        push_msat,
        a_flags,
        b_flags,
    );
    let (announcement, as_update, bs_update) =
        create_chan_between_nodes_with_value_b(node_a, node_b, &funding_locked);
    (announcement, as_update, bs_update, channel_id, tx)
}

macro_rules! get_revoke_commit_msgs {
    ($node: expr, $node_id: expr) => {{
        let events = $node.node.get_and_clear_pending_msg_events();
        assert_eq!(events.len(), 2);
        (
            match events[0] {
                MessageSendEvent::SendRevokeAndACK {
                    ref node_id,
                    ref msg,
                } => {
                    assert_eq!(*node_id, $node_id);
                    (*msg).clone()
                }
                _ => panic!("Unexpected event"),
            },
            match events[1] {
                MessageSendEvent::UpdateHTLCs {
                    ref node_id,
                    ref updates,
                } => {
                    assert_eq!(*node_id, $node_id);
                    assert!(updates.update_add_htlcs.is_empty());
                    assert!(updates.update_fulfill_htlcs.is_empty());
                    assert!(updates.update_fail_htlcs.is_empty());
                    assert!(updates.update_fail_malformed_htlcs.is_empty());
                    assert!(updates.update_fee.is_none());
                    updates.commitment_signed.clone()
                }
                _ => panic!("Unexpected event"),
            },
        )
    }};
}

macro_rules! get_event_msg {
    ($node: expr, $event_type: path, $node_id: expr) => {{
        let events = $node.node.get_and_clear_pending_msg_events();
        assert_eq!(events.len(), 1);
        match events[0] {
            $event_type {
                ref node_id,
                ref msg,
            } => {
                assert_eq!(*node_id, $node_id);
                (*msg).clone()
            }
            _ => panic!("Unexpected event"),
        }
    }};
}

///
#[macro_export]
macro_rules! get_htlc_update_msgs {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
					assert_eq!(*node_id, $node_id);
					(*updates).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

///
#[macro_export]
macro_rules! get_local_commitment_txn {
    ($node: expr, $channel_id: expr) => {{
        let outpoints = $node.chain_monitor.chain_monitor.list_monitors();
        let mut commitment_txn = None;
        for funding_txo in outpoints.iter() {
            if funding_txo.to_channel_id() == $channel_id {
                let monitor = $node.chain_monitor.chain_monitor.get_monitor(funding_txo.clone()).unwrap();
                commitment_txn =
                    Some(monitor.unsafe_get_latest_holder_commitment_txn(&$node.logger));
                break;
            }
        }
        commitment_txn.unwrap()
    }};
}

/// Check that a channel's closing channel update has been broadcasted, and optionally
/// check whether an error message event has occurred.
#[macro_export]
macro_rules! check_closed_broadcast {
	($node: expr, $with_error_msg: expr) => {{
        use lightning::util::events::MessageSendEvent;
        use lightning::ln::msgs::ErrorAction;

		let events = $node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), if $with_error_msg { 2 } else { 1 });
		match events[0] {
			MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
				assert_eq!(msg.contents.flags & 2, 2);
			},
			_ => panic!("Unexpected event"),
		}
		if $with_error_msg {
			match events[1] {
				MessageSendEvent::HandleError { action: ErrorAction::SendErrorMessage { ref msg }, node_id: _ } => {
					// TODO: Check node_id
					Some(msg.clone())
				},
				_ => panic!("Unexpected event"),
			}
		} else { None }
	}}
}

///
#[macro_export]
macro_rules! check_added_monitors {
    ($node: expr, $count: expr) => {{
        let mut added_monitors = $node.chain_monitor.added_monitors.lock().unwrap();
        assert_eq!(added_monitors.len(), $count);
        added_monitors.clear();
    }};
}

pub fn create_funding_transaction<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, expected_chan_value: u64, expected_user_chan_id: u64) -> ([u8; 32], Transaction, OutPoint) {
    let chan_id = *node.network_chan_count.borrow();

    let events = node.node.get_and_clear_pending_events();
    assert_eq!(events.len(), 1);
    match events[0] {
        Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id, .. } => {
            assert_eq!(*channel_value_satoshis, expected_chan_value);
            assert_eq!(user_channel_id, expected_user_chan_id);

            let tx = Transaction { version: chan_id as i32, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: vec![TxOut {
                value: *channel_value_satoshis, script_pubkey: output_script.clone(),
            }]};
            let funding_outpoint = OutPoint { txid: tx.txid(), index: 0 };
            (*temporary_channel_id, tx, funding_outpoint)
        },
        _ => panic!("Unexpected event"),
    }
}

pub fn create_chan_between_nodes_with_value_init<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> Transaction {
    node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42, None).unwrap();
    node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), a_flags, &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id()));
    node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), b_flags, &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id()));

    let (temporary_channel_id, tx, funding_output) = create_funding_transaction(node_a, channel_value, 42);

    let cp_id = node_b.node.get_our_node_id();
    node_a.node.funding_transaction_generated(&temporary_channel_id, &cp_id, tx.clone()).unwrap();
    check_added_monitors!(node_a, 0);

    node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id()));
    {
        let mut added_monitors = node_b.chain_monitor.added_monitors.lock().unwrap();
        assert_eq!(added_monitors.len(), 1);
        assert_eq!(added_monitors[0].0, funding_output);
        added_monitors.clear();
    }

    node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id()));
    {
        let mut added_monitors = node_a.chain_monitor.added_monitors.lock().unwrap();
        assert_eq!(added_monitors.len(), 1);
        assert_eq!(added_monitors[0].0, funding_output);
        added_monitors.clear();
    }

    let events_4 = node_a.node.get_and_clear_pending_events();
    assert_eq!(events_4.len(), 0);

    assert_eq!(node_a.tx_broadcaster.txn_broadcasted.lock().unwrap().len(), 1);
    assert_eq!(node_a.tx_broadcaster.txn_broadcasted.lock().unwrap()[0], tx);
    node_a.tx_broadcaster.txn_broadcasted.lock().unwrap().clear();

    tx
}

pub fn create_chan_between_nodes_with_value_confirm_first<'a, 'b, 'c, 'd>(node_recv: &'a Node<'b, 'c, 'c>, node_conf: &'a Node<'b, 'c, 'd>, tx: &Transaction, conf_height: u32) {
    confirm_transaction_at(node_conf, tx, conf_height);
    connect_blocks(node_conf, CHAN_CONFIRM_DEPTH - 1);
    node_recv.node.handle_channel_ready(&node_conf.node.get_our_node_id(), &get_event_msg!(node_conf, MessageSendEvent::SendChannelReady, node_recv.node.get_our_node_id()));
}

pub fn create_chan_between_nodes_with_value_confirm_second<'a, 'b, 'c>(node_recv: &Node<'a, 'b, 'c>, node_conf: &Node<'a, 'b, 'c>) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32]) {
    let channel_id;
    let events_6 = node_conf.node.get_and_clear_pending_msg_events();
    assert_eq!(events_6.len(), 3);
    ((match events_6[0] {
        MessageSendEvent::SendChannelReady { ref node_id, ref msg } => {
            channel_id = msg.channel_id.clone();
            assert_eq!(*node_id, node_recv.node.get_our_node_id());
            msg.clone()
        },
        _ => panic!("Unexpected event"),
    }, match events_6[2] {
        MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
            assert_eq!(*node_id, node_recv.node.get_our_node_id());
            msg.clone()
        },
        _ => panic!("Unexpected event"),
    }), channel_id)
}

pub fn create_chan_between_nodes_with_value_confirm<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, tx: &Transaction) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32]) {
    let conf_height = cmp::max(node_a.best_block_info().1 + 1, node_b.best_block_info().1 + 1);
    create_chan_between_nodes_with_value_confirm_first(node_a, node_b, tx, conf_height);
    confirm_transaction_at(node_a, tx, conf_height);
    connect_blocks(node_a, CHAN_CONFIRM_DEPTH - 1);
    create_chan_between_nodes_with_value_confirm_second(node_b, node_a)
}

pub fn create_chan_between_nodes_with_value_a<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> ((msgs::ChannelReady, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
    let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
    let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
    (msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, as_funding_msgs: &(msgs::ChannelReady, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
    node_b.node.handle_channel_ready(&node_a.node.get_our_node_id(), &as_funding_msgs.0);
    let bs_announcement_sigs = get_event_msg!(node_b, MessageSendEvent::SendAnnouncementSignatures, node_a.node.get_our_node_id());
    node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_funding_msgs.1);

    let events_7 = node_b.node.get_and_clear_pending_msg_events();
    assert_eq!(events_7.len(), 1);
    let (announcement, bs_update) = match events_7[0] {
        MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
            (msg, update_msg)
        },
        _ => panic!("Unexpected event"),
    };

    node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &bs_announcement_sigs);
    let events_8 = node_a.node.get_and_clear_pending_msg_events();
    assert_eq!(events_8.len(), 1);
    let as_update = match events_8[0] {
        MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
            assert!(*announcement == *msg);
            assert_eq!(update_msg.contents.short_channel_id, announcement.contents.short_channel_id);
            assert_eq!(update_msg.contents.short_channel_id, bs_update.contents.short_channel_id);
            update_msg
        },
        _ => panic!("Unexpected event"),
    };

    *node_a.network_chan_count.borrow_mut() += 1;

    ((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
}

pub fn create_announced_chan_between_nodes<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
    create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 0, a_flags, b_flags)
}

pub fn create_announced_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
    let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat, a_flags, b_flags);
    update_nodes_with_chan_announce(nodes, a, b, &chan_announcement.0, &chan_announcement.1, &chan_announcement.2);
    (chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
}

pub fn update_nodes_with_chan_announce<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, ann: &msgs::ChannelAnnouncement, upd_1: &msgs::ChannelUpdate, upd_2: &msgs::ChannelUpdate) {
    nodes[a].node.broadcast_node_announcement([0, 0, 0], [0; 32], Vec::new());
    let a_events = nodes[a].node.get_and_clear_pending_msg_events();
    assert!(a_events.len() >= 2);

    // ann should be re-generated by broadcast_node_announcement - check that we have it.
    let mut found_ann_1 = false;
    for event in a_events.iter() {
        match event {
            MessageSendEvent::BroadcastChannelAnnouncement { ref msg, .. } => {
                if msg == ann { found_ann_1 = true; }
            },
            MessageSendEvent::BroadcastNodeAnnouncement { .. } => {},
            _ => panic!("Unexpected event {:?}", event),
        }
    }
    assert!(found_ann_1);

    let a_node_announcement = match a_events.last().unwrap() {
        MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
            (*msg).clone()
        },
        _ => panic!("Unexpected event"),
    };

    nodes[b].node.broadcast_node_announcement([1, 1, 1], [1; 32], Vec::new());
    let b_events = nodes[b].node.get_and_clear_pending_msg_events();
    assert!(b_events.len() >= 2);

    // ann should be re-generated by broadcast_node_announcement - check that we have it.
    let mut found_ann_2 = false;
    for event in b_events.iter() {
        match event {
            MessageSendEvent::BroadcastChannelAnnouncement { ref msg, .. } => {
                if msg == ann { found_ann_2 = true; }
            },
            MessageSendEvent::BroadcastNodeAnnouncement { .. } => {},
            _ => panic!("Unexpected event"),
        }
    }
    assert!(found_ann_2);

    let b_node_announcement = match b_events.last().unwrap() {
        MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
            (*msg).clone()
        },
        _ => panic!("Unexpected event"),
    };

    for node in nodes {
        assert!(node.net_graph_msg_handler.handle_channel_announcement(ann).unwrap());
        node.net_graph_msg_handler.handle_channel_update(upd_1).unwrap();
        node.net_graph_msg_handler.handle_channel_update(upd_2).unwrap();
        node.net_graph_msg_handler.handle_node_announcement(&a_node_announcement).unwrap();
        node.net_graph_msg_handler.handle_node_announcement(&b_node_announcement).unwrap();

        // Note that channel_updates are also delivered to ChannelManagers to ensure we have
        // forwarding info for local channels even if its not accepted in the network graph.
        node.node.handle_channel_update(&nodes[a].node.get_our_node_id(), &upd_1);
        node.node.handle_channel_update(&nodes[b].node.get_our_node_id(), &upd_2);
    }
}

///
#[macro_export]
macro_rules! check_spends {
	($tx: expr, $($spends_txn: expr),*) => {
		{
			let get_output = |out_point: &bitcoin::blockdata::transaction::OutPoint| {
				$(
					if out_point.txid == $spends_txn.txid() {
						return $spends_txn.output.get(out_point.vout as usize).cloned()
					}
				)*
				None
			};
			let mut total_value_in = 0;
			for input in $tx.input.iter() {
				total_value_in += get_output(&input.previous_output).unwrap().value;
			}
			let mut total_value_out = 0;
			for output in $tx.output.iter() {
				total_value_out += output.value;
			}
			let min_fee = ($tx.weight() as u64 + 3) / 4; // One sat per vbyte (ie per weight/4, rounded up)
			// Input amount - output amount = fee, so check that out + min_fee is smaller than input
			assert!(total_value_out + min_fee <= total_value_in);
			$tx.verify(get_output).unwrap();
		}
	}
}

macro_rules! get_closing_signed_broadcast {
    ($node: expr, $dest_pubkey: expr) => {{
        let events = $node.get_and_clear_pending_msg_events();
        assert!(events.len() == 1 || events.len() == 2);
        (
            match events[events.len() - 1] {
                MessageSendEvent::BroadcastChannelUpdate { ref msg } => msg.clone(),
                _ => panic!("Unexpected event"),
            },
            if events.len() == 2 {
                match events[0] {
                    MessageSendEvent::SendClosingSigned {
                        ref node_id,
                        ref msg,
                    } => {
                        assert_eq!(*node_id, $dest_pubkey);
                        Some(msg.clone())
                    }
                    _ => panic!("Unexpected event"),
                }
            } else {
                None
            },
        )
    }};
}

///
#[macro_export]
macro_rules! check_closed_event {
       ($node: expr, $events: expr, $reason: expr) => {{
               let events = $node.node.get_and_clear_pending_events();
               assert_eq!(events.len(), $events);
               let expected_reason = $reason;
               for event in events {
                       match event {
                               Event::ChannelClosed { ref reason, .. } => {
                                       assert_eq!(*reason, expected_reason);
                               },
                               _ => panic!("Unexpected event"),
                       }
               }
       }}
}

pub fn close_channel<'a, 'b, 'c>(outbound_node: &Node<'a, 'b, 'c>, inbound_node: &Node<'a, 'b, 'c>, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
    let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
    let (node_b, broadcaster_b, struct_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) } else { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) };
    let (tx_a, tx_b);

    let cp_id = node_b.get_our_node_id();
    node_a.close_channel(channel_id, &cp_id).unwrap();
    node_b.handle_shutdown(&node_a.get_our_node_id(), &InitFeatures::known(), &get_event_msg!(struct_a, MessageSendEvent::SendShutdown, node_b.get_our_node_id()));

    let events_1 = node_b.get_and_clear_pending_msg_events();
    assert!(events_1.len() >= 1);
    let shutdown_b = match events_1[0] {
        MessageSendEvent::SendShutdown { ref node_id, ref msg } => {
            assert_eq!(node_id, &node_a.get_our_node_id());
            msg.clone()
        },
        _ => panic!("Unexpected event"),
    };

    let closing_signed_b = if !close_inbound_first {
        assert_eq!(events_1.len(), 1);
        None
    } else {
        Some(match events_1[1] {
            MessageSendEvent::SendClosingSigned { ref node_id, ref msg } => {
                assert_eq!(node_id, &node_a.get_our_node_id());
                msg.clone()
            },
            _ => panic!("Unexpected event"),
        })
    };

    node_a.handle_shutdown(&node_b.get_our_node_id(), &InitFeatures::known(), &shutdown_b);
    let (as_update, bs_update) = if close_inbound_first {
        assert!(node_a.get_and_clear_pending_msg_events().is_empty());
        node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());

        node_b.handle_closing_signed(&node_a.get_our_node_id(), &get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id()));
        assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
        tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
        let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

        node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
        let (as_update, none_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());
        assert!(none_a.is_none());
        assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
        tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
        (as_update, bs_update)
    } else {
        let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

        node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a);
        node_a.handle_closing_signed(&node_b.get_our_node_id(), &get_event_msg!(struct_b, MessageSendEvent::SendClosingSigned, node_a.get_our_node_id()));

        assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
        tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
        let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

        node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap());
        let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
        assert!(none_b.is_none());
        assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
        tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
        (as_update, bs_update)
    };
    assert_eq!(tx_a, tx_b);
    check_spends!(tx_a, funding_tx);

    (as_update, bs_update, tx_a)
}

pub struct SendEvent {
    pub node_id: PublicKey,
    pub msgs: Vec<msgs::UpdateAddHTLC>,
    pub commitment_msg: msgs::CommitmentSigned,
}

impl SendEvent {
    pub fn from_commitment_update(
        node_id: PublicKey,
        updates: msgs::CommitmentUpdate,
    ) -> SendEvent {
        assert!(updates.update_fulfill_htlcs.is_empty());
        assert!(updates.update_fail_htlcs.is_empty());
        assert!(updates.update_fail_malformed_htlcs.is_empty());
        assert!(updates.update_fee.is_none());
        SendEvent {
            node_id: node_id,
            msgs: updates.update_add_htlcs,
            commitment_msg: updates.commitment_signed,
        }
    }

    pub fn from_event(event: MessageSendEvent) -> SendEvent {
        match event {
            MessageSendEvent::UpdateHTLCs { node_id, updates } => {
                SendEvent::from_commitment_update(node_id, updates)
            }
            _ => panic!("Unexpected event type!"),
        }
    }

    pub fn from_node<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>) -> SendEvent {
        let mut events = node.node.get_and_clear_pending_msg_events();
        assert_eq!(events.len(), 1);
        SendEvent::from_event(events.pop().unwrap())
    }
}

macro_rules! commitment_signed_dance {
    ($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */) => {{
        check_added_monitors!($node_a, 0);
        assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
        $node_a
            .node
            .handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed);
        check_added_monitors!($node_a, 1);
        commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, false);
    }};
    ($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */, true /* return last RAA */) => {{
        let (as_revoke_and_ack, as_commitment_signed) =
            get_revoke_commit_msgs!($node_a, $node_b.node.get_our_node_id());
        check_added_monitors!($node_b, 0);
        assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
        $node_b
            .node
            .handle_revoke_and_ack(&$node_a.node.get_our_node_id(), &as_revoke_and_ack);
        assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
        check_added_monitors!($node_b, 1);
        $node_b
            .node
            .handle_commitment_signed(&$node_a.node.get_our_node_id(), &as_commitment_signed);
        let (bs_revoke_and_ack, extra_msg_option) = {
            let events = $node_b.node.get_and_clear_pending_msg_events();
            assert!(events.len() <= 2);
            (
                match events[0] {
                    MessageSendEvent::SendRevokeAndACK {
                        ref node_id,
                        ref msg,
                    } => {
                        assert_eq!(*node_id, $node_a.node.get_our_node_id());
                        (*msg).clone()
                    }
                    _ => panic!("Unexpected event"),
                },
                events.get(1).map(|e| e.clone()),
            )
        };
        check_added_monitors!($node_b, 1);
        if $fail_backwards {
            assert!($node_a.node.get_and_clear_pending_events().is_empty());
            assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
        }
        (extra_msg_option, bs_revoke_and_ack)
    }};
    ($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */, false /* return extra message */, true /* return last RAA */) => {{
        check_added_monitors!($node_a, 0);
        assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
        $node_a
            .node
            .handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed);
        check_added_monitors!($node_a, 1);
        let (extra_msg_option, bs_revoke_and_ack) =
            commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
        assert!(extra_msg_option.is_none());
        bs_revoke_and_ack
    }};
    ($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */) => {{
        let (extra_msg_option, bs_revoke_and_ack) =
            commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
        $node_a
            .node
            .handle_revoke_and_ack(&$node_b.node.get_our_node_id(), &bs_revoke_and_ack);
        check_added_monitors!($node_a, 1);
        extra_msg_option
    }};
    ($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, false /* no extra message */) => {{
        assert!(
            commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true).is_none()
        );
    }};
    ($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr) => {{
        commitment_signed_dance!($node_a, $node_b, $commitment_signed, $fail_backwards, true);
        if $fail_backwards {
            expect_pending_htlcs_forwardable!($node_a);
            check_added_monitors!($node_a, 1);
        } else {
            assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
        }
    }};
}

#[macro_export]
macro_rules! get_route {
	($send_node: expr, $payment_params: expr, $recv_value: expr, $cltv: expr) => {{
        let params = RouteParameters {
            payment_params: $payment_params,
            final_value_msat: $recv_value,
            final_cltv_expiry_delta: TEST_FINAL_CLTV
        };
		use lightning::chain::keysinterface::KeysInterface;
		let scorer = lightning::util::test_utils::TestScorer::with_penalty(0);
		let keys_manager = lightning::util::test_utils::TestKeysInterface::new(&[0u8; 32], bitcoin::network::constants::Network::Testnet);
		let random_seed_bytes = keys_manager.get_secure_random_bytes();
		lightning::routing::router::find_route(
			&$send_node.node.get_our_node_id(), &params, &$send_node.network_graph,
			Some(&$send_node.node.list_usable_channels().iter().collect::<Vec<_>>()),
			Arc::clone(&$send_node.logger), &scorer, &random_seed_bytes
		)
	}}
}

/// Get a payment preimage and hash.
macro_rules! get_payment_preimage_hash {
	($dest_node: expr) => {
		{
			let payment_preimage = PaymentPreimage([*$dest_node.network_payment_count.borrow(); 32]);
			*$dest_node.network_payment_count.borrow_mut() += 1;
			let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
			let payment_secret = $dest_node.node.create_inbound_payment_for_hash(payment_hash, None, 7200).unwrap();
			(payment_preimage, payment_hash, payment_secret)
		}
	}
}

macro_rules! expect_pending_htlcs_forwardable {
    ($node: expr) => {{
        let events = $node.node.get_and_clear_pending_events();
        assert_eq!(events.len(), 1);
        match events[0] {
            Event::PendingHTLCsForwardable { .. } => {}
            _ => panic!("Unexpected event"),
        };
        $node.node.process_pending_htlc_forwards();
    }};
}

///
#[macro_export]
macro_rules! expect_pending_htlcs_forwardable_from_events {
	($node: expr, $events: expr, $ignore: expr) => {{
		assert_eq!($events.len(), 1);
		match $events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
		if $ignore {
			$node.node.process_pending_htlc_forwards();
		}
	}}
}

#[macro_export]
macro_rules! expect_payment_claimed {
	($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			lightning::util::events::Event::PaymentClaimed { ref payment_hash, amount_msat, .. } => {
				assert_eq!($expected_payment_hash, *payment_hash);
				assert_eq!($expected_recv_value, amount_msat);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

macro_rules! expect_payment_sent {
    ($node: expr, $expected_payment_preimage: expr) => {
        let events = $node.node.get_and_clear_pending_events();
        assert!(events.len() > 1);
        match events[0] {
            Event::PaymentSent {
                ref payment_preimage, ..
            } => {
                assert_eq!($expected_payment_preimage, *payment_preimage);
            }
            _ => panic!("Unexpected event"),
        }
    };
}

///
#[macro_export]
macro_rules! expect_pending_htlcs_forwardable_ignore {
	($node: expr) => {{
        use lightning::util::events::Event;
        use lightning::util::events::EventsProvider;
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { .. } => { },
			_ => panic!("Unexpected event"),
		};
	}}
}

///
#[macro_export]
macro_rules! expect_payment_forwarded {
	($node: expr, $expected_fee: expr, $upstream_force_closed: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentForwarded { fee_earned_msat, claim_from_onchain_tx, .. } => {
				assert_eq!(fee_earned_msat, $expected_fee);
				assert_eq!(claim_from_onchain_tx, $upstream_force_closed);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

///
#[macro_export]
macro_rules! expect_payment_failed {
	($node: expr, $expected_payment_hash: expr, $rejected_by_dest: expr $(, $expected_error_code: expr, $expected_error_data: expr)*) => {
        use lightning::util::events::Event;
        use lightning::util::events::EventsProvider;
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentPathFailed { ref payment_hash, rejected_by_dest, .. } => {
				assert_eq!(*payment_hash, $expected_payment_hash, "unexpected payment_hash");
				assert_eq!(rejected_by_dest, $rejected_by_dest, "unexpected rejected_by_dest value");
				// assert!(error_code.is_some(), "expected error_code.is_some() = true");
				// assert!(error_data.is_some(), "expected error_data.is_some() = true");
				// $(
				// 	assert_eq!(error_code.unwrap(), $expected_error_code, "unexpected error code");
				// 	assert_eq!(&error_data.as_ref().unwrap()[..], $expected_error_data, "unexpected error data");
				// )*
			},
			_ => panic!("Unexpected event"),
		}
	}
}

pub fn send_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_paths: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: PaymentSecret) {
    origin_node.node.send_payment(&route, our_payment_hash, &Some(our_payment_secret)).unwrap();
    check_added_monitors!(origin_node, expected_paths.len());
    pass_along_route(origin_node, expected_paths, recv_value, our_payment_hash, our_payment_secret);
}

pub fn do_pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool, clear_recipient_events: bool, expected_preimage: Option<PaymentPreimage>) {
    let mut payment_event = SendEvent::from_event(ev);
    let mut prev_node = origin_node;

    for (idx, &node) in expected_path.iter().enumerate() {
        assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

        node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
        check_added_monitors!(node, 0);
        commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

        expect_pending_htlcs_forwardable!(node);

        if idx == expected_path.len() - 1 && clear_recipient_events {
            let events_2 = node.node.get_and_clear_pending_events();
            if payment_received_expected {
                assert_eq!(events_2.len(), 1);
                match events_2[0] {
                    Event::PaymentReceived { ref payment_hash, ref purpose, amount_msat} => {
                        assert_eq!(our_payment_hash, *payment_hash);
                        match &purpose {
                            PaymentPurpose::InvoicePayment { payment_preimage, payment_secret, .. } => {
                                assert_eq!(expected_preimage, *payment_preimage);
                                assert_eq!(our_payment_secret.unwrap(), *payment_secret);
                            },
                            PaymentPurpose::SpontaneousPayment(payment_preimage) => {
                                assert_eq!(expected_preimage.unwrap(), *payment_preimage);
                                assert!(our_payment_secret.is_none());
                            },
                        }
                        assert_eq!(amount_msat, recv_value);
                    },
                    _ => panic!("Unexpected event"),
                }
            } else {
                assert!(events_2.is_empty());
            }
        } else if idx != expected_path.len() - 1 {
            let mut events_2 = node.node.get_and_clear_pending_msg_events();
            assert_eq!(events_2.len(), 1);
            check_added_monitors!(node, 1);
            payment_event = SendEvent::from_event(events_2.remove(0));
            assert_eq!(payment_event.msgs.len(), 1);
        }

        prev_node = node;
    }
}

pub fn pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool, expected_preimage: Option<PaymentPreimage>) {
    do_pass_along_path(origin_node, expected_path, recv_value, our_payment_hash, our_payment_secret, ev, payment_received_expected, true, expected_preimage);
}

pub fn pass_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: PaymentSecret) {
    let mut events = origin_node.node.get_and_clear_pending_msg_events();
    assert_eq!(events.len(), expected_route.len());
    for (path_idx, (ev, expected_path)) in events.drain(..).zip(expected_route.iter()).enumerate() {
        // Once we've gotten through all the HTLCs, the last one should result in a
        // PaymentReceived (but each previous one should not!), .
        let expect_payment = path_idx == expected_route.len() - 1;
        pass_along_path(origin_node, expected_path, recv_value, our_payment_hash.clone(), Some(our_payment_secret), ev, expect_payment, None);
    }
}

pub fn send_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash, PaymentSecret) {
    let (our_payment_preimage, our_payment_hash, our_payment_secret) = get_payment_preimage_hash!(expected_route.last().unwrap());
    if origin_node.use_invoices {
        let destination_node = expected_route[expected_route.len() - 1];
        let payee_pubkey = destination_node.node.get_our_node_id();
        let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
            .payment_hash(Sha256::from_slice(&our_payment_hash.0).unwrap())
            .payment_secret(our_payment_secret)
            .description("invoice".to_string())
            .amount_milli_satoshis(recv_value)
            .current_timestamp()
            .min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY as u64)
            .payee_pub_key(payee_pubkey)
            .build_raw().expect("build");
        let hrp = invoice.hrp.to_string().as_bytes().to_vec();
        let data = invoice.data.to_base32();
        let sig = destination_node.keys_manager.get_node()
            .sign_invoice(&hrp, &data).expect("sign invoice");
        let signed_invoice = invoice.sign::<_, ()>(|_| Ok(sig)).unwrap();

        origin_node.keys_manager.add_invoice(signed_invoice);
    }

    send_along_route_with_secret(origin_node, route, &[expected_route], recv_value, our_payment_hash, our_payment_secret);
    (our_payment_preimage, our_payment_hash, our_payment_secret)
}

pub fn claim_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_preimage: PaymentPreimage) {
    for path in expected_paths.iter() {
        assert_eq!(path.last().unwrap().node.get_our_node_id(), expected_paths[0].last().unwrap().node.get_our_node_id());
    }
    expected_paths[0].last().unwrap().node.claim_funds(our_payment_preimage);

    let claim_event = expected_paths[0].last().unwrap().node.get_and_clear_pending_events();
    assert_eq!(claim_event.len(), 1);
    match claim_event[0] {
        Event::PaymentClaimed { purpose: PaymentPurpose::SpontaneousPayment(preimage), .. }|
        Event::PaymentClaimed { purpose: PaymentPurpose::InvoicePayment { payment_preimage: Some(preimage), ..}, .. } =>
            assert_eq!(preimage, our_payment_preimage),
        Event::PaymentClaimed { purpose: PaymentPurpose::InvoicePayment { .. }, payment_hash, .. } =>
            assert_eq!(&payment_hash.0, &Sha256::hash(&our_payment_preimage.0)[..]),
        _ => panic!(),
    }

    check_added_monitors!(expected_paths[0].last().unwrap(), expected_paths.len());

    macro_rules! msgs_from_ev {
		($ev: expr) => {
			match $ev {
				&MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
					assert!(update_add_htlcs.is_empty());
					assert_eq!(update_fulfill_htlcs.len(), 1);
					assert!(update_fail_htlcs.is_empty());
					assert!(update_fail_malformed_htlcs.is_empty());
					assert!(update_fee.is_none());
					((update_fulfill_htlcs[0].clone(), commitment_signed.clone()), node_id.clone())
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
    let mut per_path_msgs: Vec<((msgs::UpdateFulfillHTLC, msgs::CommitmentSigned), PublicKey)> = Vec::with_capacity(expected_paths.len());
    let events = expected_paths[0].last().unwrap().node.get_and_clear_pending_msg_events();
    assert_eq!(events.len(), expected_paths.len());
    for ev in events.iter() {
        per_path_msgs.push(msgs_from_ev!(ev));
    }

    for (expected_route, (path_msgs, next_hop)) in expected_paths.iter().zip(per_path_msgs.drain(..)) {
        let mut next_msgs = Some(path_msgs);
        let mut expected_next_node = next_hop;

        macro_rules! last_update_fulfill_dance {
			($node: expr, $prev_node: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
					check_added_monitors!($node, 0);
					assert!($node.node.get_and_clear_pending_msg_events().is_empty());
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
				}
			}
		}
        macro_rules! mid_update_fulfill_dance {
			($node: expr, $prev_node: expr, $new_msgs: expr) => {
				{
					$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0);
            		let events = $node.node.get_and_clear_pending_events();
            		assert_eq!(events.len(), 1);
					check_added_monitors!($node, 1);
					let new_next_msgs = if $new_msgs {
						let events = $node.node.get_and_clear_pending_msg_events();
						assert_eq!(events.len(), 1);
						let (res, nexthop) = msgs_from_ev!(&events[0]);
						expected_next_node = nexthop;
						Some(res)
					} else {
						assert!($node.node.get_and_clear_pending_msg_events().is_empty());
						None
					};
					commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
					next_msgs = new_next_msgs;
				}
			}
		}

        let mut prev_node = expected_route.last().unwrap();
        for (idx, node) in expected_route.iter().rev().enumerate().skip(1) {
            assert_eq!(expected_next_node, node.node.get_our_node_id());
            let update_next_msgs = !skip_last || idx != expected_route.len() - 1;
            if next_msgs.is_some() {
                mid_update_fulfill_dance!(node, prev_node, update_next_msgs);
            } else {
                assert!(!update_next_msgs);
                assert!(node.node.get_and_clear_pending_msg_events().is_empty());
            }
            if !skip_last && idx == expected_route.len() - 1 {
                assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
            }

            prev_node = node;
        }

        if !skip_last {
            last_update_fulfill_dance!(origin_node, expected_route.first().unwrap());
            expect_payment_sent!(origin_node, our_payment_preimage);
        }
    }
}

pub fn claim_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], our_payment_preimage: PaymentPreimage) {
    claim_payment_along_route(origin_node, &[expected_route], false, our_payment_preimage);
}

pub const TEST_FINAL_CLTV: u32 = 70;

pub fn route_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash, PaymentSecret) {
    let payment_params = PaymentParameters::from_node_id(expected_route.last().unwrap().node.get_our_node_id())
        .with_features(InvoiceFeatures::known());
    let route = get_route!(origin_node, payment_params, recv_value, TEST_FINAL_CLTV).unwrap();
    assert_eq!(route.paths.len(), 1);
    assert_eq!(route.paths[0].len(), expected_route.len());
    for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
        assert_eq!(hop.pubkey, node.node.get_our_node_id());
    }

    let res = send_along_route(origin_node, route, expected_route, recv_value);
    (res.0, res.1, res.2)
}

pub fn send_payment<'a, 'b, 'c>(origin: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64)  {
    let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
    claim_payment(&origin, expected_route, our_payment_preimage);
}

pub struct TestBroadcaster {
    pub txn_broadcasted: Mutex<Vec<Transaction>>,
}
impl chaininterface::BroadcasterInterface for TestBroadcaster {
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.txn_broadcasted.lock().unwrap().push(tx.clone());
    }
}

pub fn create_chanmon_cfgs<'a>(node_count: usize) -> Vec<TestChanMonCfg> {
    let mut chan_mon_cfgs = Vec::new();
    for i in 0..node_count {
        let tx_broadcaster = TestBroadcaster {
            txn_broadcasted: Mutex::new(Vec::new()),
        };
        let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: Mutex::new(253) };
        let chain_source = test_utils::TestChainSource::new(Network::Regtest);
        let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
        let persister = TestPersister::new();
        let network_graph = NetworkGraph::new(chain_source.genesis_hash, logger.clone());
        let cfg = TestChanMonCfg {
            tx_broadcaster,
            fee_estimator,
            chain_source,
            logger,
            persister,
            network_graph
        };
        chan_mon_cfgs.push(cfg);
    }

    chan_mon_cfgs
}

pub fn create_node_chanmgrs<'a, 'b>(
    node_count: usize,
    cfgs: &'a Vec<NodeCfg<'b>>,
    node_config: &[Option<UserConfig>],
) -> Vec<
    ChannelManager<
        LoopbackChannelSigner,
        &'a TestChainMonitor<'b>,
        &'b TestBroadcaster,
        &'a LoopbackSignerKeysInterface,
        &'b test_utils::TestFeeEstimator,
        Arc<test_utils::TestLogger>,
    >,
> {
    let mut chanmgrs = Vec::new();
    for i in 0..node_count {
        let network = Network::Regtest;
        let params = ChainParameters {
            network,
            best_block: BestBlock::from_genesis(network),
        };
        let node = ChannelManager::new(cfgs[i].fee_estimator, &cfgs[i].chain_monitor, cfgs[i].tx_broadcaster, Arc::clone(&cfgs[i].logger), &cfgs[i].keys_manager, if node_config[i].is_some() { node_config[i].clone().unwrap() } else { test_default_channel_config() }, params);
        chanmgrs.push(node);
    }

    chanmgrs
}

pub fn create_network<'a, 'b: 'a, 'c: 'b>(
    node_count: usize,
    cfgs: &'b Vec<NodeCfg<'c>>,
    chan_mgrs: &'a Vec<
        ChannelManager<
            LoopbackChannelSigner,
            &'b TestChainMonitor<'c>,
            &'c TestBroadcaster,
            &'b LoopbackSignerKeysInterface,
            &'c test_utils::TestFeeEstimator,
            Arc<test_utils::TestLogger>,
        >,
    >,
) -> Vec<Node<'a, 'b, 'c>> {
    let mut nodes = Vec::new();
    let chan_count = Rc::new(RefCell::new(0));
    let payment_count = Rc::new(RefCell::new(0));

    for i in 0..node_count {
        info!("node {} {}", i, chan_mgrs[i].get_our_node_id().to_hex());
        let net_graph_msg_handler = P2PGossipSync::new(cfgs[i].network_graph, None, Arc::clone(&cfgs[i].logger));
        let connect_style = Rc::new(RefCell::new(ConnectStyle::FullBlockViaListen));
        nodes.push(Node {
            chain_source: cfgs[i].chain_source,
            tx_broadcaster: cfgs[i].tx_broadcaster,
            chain_monitor: &cfgs[i].chain_monitor,
            keys_manager: &cfgs[i].keys_manager,
            node: &chan_mgrs[i],
            network_graph: cfgs[i].network_graph,
            net_graph_msg_handler,
            node_seed: cfgs[i].node_seed,
            network_chan_count: chan_count.clone(),
            network_payment_count: payment_count.clone(),
            logger: Arc::clone(&cfgs[i].logger),
            blocks: RefCell::new(vec![(genesis_block(Network::Regtest).header, 0)]),
            connect_style: Rc::clone(&connect_style),
            use_invoices: false
        })
    }

    for i in 0..node_count {
        for j in (i+1)..node_count {
            let init = msgs::Init { features: InitFeatures::known(), remote_network_address: None };
            nodes[i].node.peer_connected(&nodes[j].node.get_our_node_id(), &init);
            nodes[j].node.peer_connected(&nodes[i].node.get_our_node_id(), &init);
        }
    }

    nodes
}

pub fn dump_node_txn(prefix: &str, node: &Node) {
    let node_txn = node.tx_broadcaster.txn_broadcasted.lock().unwrap();
    dump_txn(prefix, &*node_txn);
}

pub fn dump_txn(prefix: &str, txn: &Vec<Transaction>) {
    println!("{}", prefix);
    for x in txn {
        println!("{} {} {:?}", prefix, x.txid(), x);
    }
}

pub fn get_announce_close_broadcast_events<'a, 'b, 'c>(nodes: &Vec<Node<'a, 'b, 'c>>, a: usize, b: usize)  {
    let events_1 = nodes[a].node.get_and_clear_pending_msg_events();
    assert_eq!(events_1.len(), 2);
    let as_update = match events_1[0] {
        MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
            msg.clone()
        },
        _ => panic!("Unexpected event"),
    };
    match events_1[1] {
        MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
            assert_eq!(node_id, nodes[b].node.get_our_node_id());
            assert_eq!(msg.data, "Channel closed because commitment or closing transaction was confirmed on chain.");
        },
        _ => panic!("Unexpected event"),
    }

    let events_2 = nodes[b].node.get_and_clear_pending_msg_events();
    assert_eq!(events_2.len(), 2);
    let bs_update = match events_2[0] {
        MessageSendEvent::BroadcastChannelUpdate { ref msg } => {
            msg.clone()
        },
        _ => panic!("Unexpected event"),
    };
    match events_2[1] {
        MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
            assert_eq!(node_id, nodes[a].node.get_our_node_id());
            assert_eq!(msg.data, "Channel closed because commitment or closing transaction was confirmed on chain.");
        },
        _ => panic!("Unexpected event"),
    }

    for node in nodes {
        node.net_graph_msg_handler.handle_channel_update(&as_update).unwrap();
        node.net_graph_msg_handler.handle_channel_update(&bs_update).unwrap();
    }
}

// Local Variables:
// inhibit-rust-format-buffer: t
// End:
