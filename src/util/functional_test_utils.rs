//! A bunch of useful utilities for building networks of nodes and exchanging messages between
//! nodes for functional tests.

// FILE NOT TESTED

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;

use bitcoin;
use bitcoin::{Network, Transaction, TxOut};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::hash_types::BlockHash;
use bitcoin::util::hash::BitcoinHash;
use bitcoin_hashes::Hash;
use bitcoin_hashes::sha256::Hash as Sha256;
use chain::chaininterface;
use chain::transaction::OutPoint;
use lightning::chain;
use lightning::chain::chaininterface::ChainWatchInterface;
use lightning::ln;
use lightning::ln::channelmanager::PaymentSecret;
use lightning::ln::channelmonitor;
use lightning::ln::channelmonitor::HTLCUpdate;
use lightning::routing::network_graph::NetGraphMsgHandler;
use lightning::routing::router::{get_route, Route};
use lightning::util;
use lightning::util::config::UserConfig;
use ln::channelmanager::{ChannelManager, PaymentHash, PaymentPreimage};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, RoutingMessageHandler};
use secp256k1::key::PublicKey;
use util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};

use crate::util::test_utils;
use crate::util::test_utils::{TestFeeEstimator, TestLogger};
use crate::util::loopback::{LoopbackSignerKeysInterface, LoopbackChannelSigner};

pub const CHAN_CONFIRM_DEPTH: u32 = 100;

pub fn confirm_transaction<'a, 'b: 'a>(notifier: &'a chaininterface::BlockNotifierRef<'b, &chaininterface::ChainWatchInterfaceUtil>, chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction, chan_id: u32) {
	assert!(chain.does_match_tx(tx));
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	notifier.block_connected_checked(&header, 1, &[tx; 1], &[chan_id as usize; 1]);
	for i in 2..CHAN_CONFIRM_DEPTH {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		notifier.block_connected_checked(&header, i, &vec![], &[0; 0]);
	}
}

pub fn connect_blocks<'a, 'b>(notifier: &'a chaininterface::BlockNotifierRef<'b, &chaininterface::ChainWatchInterfaceUtil>, depth: u32, height: u32, parent: bool, prev_blockhash: BlockHash) -> BlockHash {
	let mut header = BlockHeader { version: 0x2000000, prev_blockhash: if parent { prev_blockhash } else { Default::default() }, merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	notifier.block_connected_checked(&header, height + 1, &Vec::new(), &Vec::new());
	for i in 2..depth + 1 {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		notifier.block_connected_checked(&header, height + i, &Vec::new(), &Vec::new());
	}
	header.bitcoin_hash()
}

pub struct TestChanMonCfg {
	pub tx_broadcaster: test_utils::TestBroadcaster,
	pub fee_estimator: test_utils::TestFeeEstimator,
	pub chain_monitor: chaininterface::ChainWatchInterfaceUtil,
	pub logger: test_utils::TestLogger,
}

pub struct NodeCfg<'a> {
	pub chain_monitor: &'a chaininterface::ChainWatchInterfaceUtil,
	pub tx_broadcaster: &'a test_utils::TestBroadcaster,
	pub fee_estimator: &'a test_utils::TestFeeEstimator,
	pub chan_monitor: TestChannelMonitor<'a>,
	pub keys_manager: LoopbackSignerKeysInterface,
	pub logger: &'a test_utils::TestLogger,
	pub node_seed: [u8; 32],
}

pub struct Node<'a, 'b: 'a, 'c: 'b> {
	pub block_notifier: chaininterface::BlockNotifierRef<'a, &'c chaininterface::ChainWatchInterfaceUtil>,
	pub chain_monitor: &'c chaininterface::ChainWatchInterfaceUtil,
	pub tx_broadcaster: &'c test_utils::TestBroadcaster,
	pub chan_monitor: &'b TestChannelMonitor<'c>,
	pub keys_manager: &'b LoopbackSignerKeysInterface,
	pub node: &'a ChannelManager<LoopbackChannelSigner, &'b TestChannelMonitor<'c>, &'c test_utils::TestBroadcaster, &'b LoopbackSignerKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>,
	pub net_graph_msg_handler: NetGraphMsgHandler<&'c chaininterface::ChainWatchInterfaceUtil, &'c test_utils::TestLogger>,
	pub node_seed: [u8; 32],
	pub network_payment_count: Rc<RefCell<u8>>,
	pub network_chan_count: Rc<RefCell<u32>>,
	pub logger: &'c test_utils::TestLogger,
}

impl<'a, 'b, 'c> Drop for Node<'a, 'b, 'c> {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Check that we processed all pending events
			assert!(self.node.get_and_clear_pending_msg_events().is_empty());
			assert!(self.node.get_and_clear_pending_events().is_empty());
			assert!(self.chan_monitor.added_monitors.lock().unwrap().is_empty());
		}
	}
}

pub fn create_chan_between_nodes<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001, a_flags, b_flags)
}

pub fn create_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(node_a, node_b, &funding_locked);
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

#[macro_export]
macro_rules! get_local_commitment_txn {
	($node: expr, $channel_id: expr) => {
		{
			let mut monitors = $node.chan_monitor.simple_monitor.monitors.lock().unwrap();
			let mut commitment_txn = None;
			for (funding_txo, monitor) in monitors.iter_mut() {
				if funding_txo.to_channel_id() == $channel_id {
					commitment_txn = Some(monitor.unsafe_get_latest_local_commitment_txn(&$node.logger));
					break;
				}
			}
			commitment_txn.unwrap()
		}
	}
}

#[macro_export]
macro_rules! check_added_monitors {
	($node: expr, $count: expr) => {
		{
			let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), $count);
			added_monitors.clear();
		}
	}
}

pub fn create_funding_transaction<'a, 'b, 'c>(node: &Node<'a, 'b, 'c>, expected_chan_value: u64, expected_user_chan_id: u64) -> ([u8; 32], Transaction, OutPoint) {
	let chan_id = *node.network_chan_count.borrow();

	let events = node.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(*channel_value_satoshis, expected_chan_value);
			assert_eq!(user_channel_id, expected_user_chan_id);

			let tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
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

	node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
	check_added_monitors!(node_a, 0);

	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id()));
	{
		let mut added_monitors = node_b.chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id()));
	{
		let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		assert_eq!(added_monitors[0].0, funding_output);
		added_monitors.clear();
	}

	let events_4 = node_a.node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	tx
}

pub fn create_chan_between_nodes_with_value_confirm_first<'a, 'b, 'c, 'd>(node_recv: &'a Node<'b, 'c, 'c>, node_conf: &'a Node<'b, 'c, 'd>, tx: &Transaction) {
	confirm_transaction(&node_conf.block_notifier, &node_conf.chain_monitor, &tx, tx.version);
	node_recv.node.handle_funding_locked(&node_conf.node.get_our_node_id(), &get_event_msg!(node_conf, MessageSendEvent::SendFundingLocked, node_recv.node.get_our_node_id()));
}

pub fn create_chan_between_nodes_with_value_confirm_second<'a, 'b, 'c>(node_recv: &Node<'a, 'b, 'c>, node_conf: &Node<'a, 'b, 'c>) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	let channel_id;
	let events_6 = node_conf.node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 2);
	((match events_6[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
			channel_id = msg.channel_id.clone();
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}, match events_6[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_recv.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}), channel_id)
}

pub fn create_chan_between_nodes_with_value_confirm<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	create_chan_between_nodes_with_value_confirm_first(node_a, node_b, tx);
	confirm_transaction(&node_a.block_notifier, &node_a.chain_monitor, &tx, tx.version);
	create_chan_between_nodes_with_value_confirm_second(node_b, node_a)
}

pub fn create_chan_between_nodes_with_value_a<'a, 'b, 'c, 'd>(node_a: &'a Node<'b, 'c, 'd>, node_b: &'a Node<'b, 'c, 'd>, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat, a_flags, b_flags);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, node_b: &Node<'a, 'b, 'c>, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
	node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &as_funding_msgs.0);
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
			update_msg
		},
		_ => panic!("Unexpected event"),
	};

	*node_a.network_chan_count.borrow_mut() += 1;

	((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
}

pub fn create_announced_chan_between_nodes<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001, a_flags, b_flags)
}

pub fn create_announced_chan_between_nodes_with_value<'a, 'b, 'c, 'd>(nodes: &'a Vec<Node<'b, 'c, 'd>>, a: usize, b: usize, channel_value: u64, push_msat: u64, a_flags: InitFeatures, b_flags: InitFeatures) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat, a_flags, b_flags);

	nodes[a].node.broadcast_node_announcement([0, 0, 0], [0; 32], Vec::new());
	let a_events = nodes[a].node.get_and_clear_pending_msg_events();
	assert_eq!(a_events.len(), 1);
	let a_node_announcement = match a_events[0] {
		MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	nodes[b].node.broadcast_node_announcement([1, 1, 1], [1; 32], Vec::new());
	let b_events = nodes[b].node.get_and_clear_pending_msg_events();
	assert_eq!(b_events.len(), 1);
	let b_node_announcement = match b_events[0] {
		MessageSendEvent::BroadcastNodeAnnouncement { ref msg } => {
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};

	for node in nodes {
		assert!(node.net_graph_msg_handler.handle_channel_announcement(&chan_announcement.0).unwrap());
		node.net_graph_msg_handler.handle_channel_update(&chan_announcement.1).unwrap();
		node.net_graph_msg_handler.handle_channel_update(&chan_announcement.2).unwrap();
		node.net_graph_msg_handler.handle_node_announcement(&a_node_announcement).unwrap();
		node.net_graph_msg_handler.handle_node_announcement(&b_node_announcement).unwrap();
	}
	(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
}

macro_rules! check_spends {
    ($tx: expr, $spends_tx: expr) => {{
        $tx.verify(|out_point| {
            if out_point.txid == $spends_tx.txid() {
                $spends_tx.output.get(out_point.vout as usize).cloned()
            } else {
                None
            }
        })
        .unwrap();
    }};
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

pub fn close_channel<'a, 'b, 'c>(outbound_node: &Node<'a, 'b, 'c>, inbound_node: &Node<'a, 'b, 'c>, channel_id: &[u8; 32], funding_tx: Transaction, close_inbound_first: bool) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, Transaction) {
	let (node_a, broadcaster_a, struct_a) = if close_inbound_first { (&inbound_node.node, &inbound_node.tx_broadcaster, inbound_node) } else { (&outbound_node.node, &outbound_node.tx_broadcaster, outbound_node) };
	let (node_b, broadcaster_b) = if close_inbound_first { (&outbound_node.node, &outbound_node.tx_broadcaster) } else { (&inbound_node.node, &inbound_node.tx_broadcaster) };
	let (tx_a, tx_b);

	node_a.close_channel(channel_id).unwrap();
	node_b.handle_shutdown(&node_a.get_our_node_id(), &get_event_msg!(struct_a, MessageSendEvent::SendShutdown, node_b.get_our_node_id()));

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

	node_a.handle_shutdown(&node_b.get_our_node_id(), &shutdown_b);
	let (as_update, bs_update) = if close_inbound_first {
		assert!(node_a.get_and_clear_pending_msg_events().is_empty());
		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
		let (as_update, closing_signed_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a.unwrap());
		let (bs_update, none_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());
		assert!(none_b.is_none());
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		(as_update, bs_update)
	} else {
		let closing_signed_a = get_event_msg!(struct_a, MessageSendEvent::SendClosingSigned, node_b.get_our_node_id());

		node_b.handle_closing_signed(&node_a.get_our_node_id(), &closing_signed_a);
		assert_eq!(broadcaster_b.txn_broadcasted.lock().unwrap().len(), 1);
		tx_b = broadcaster_b.txn_broadcasted.lock().unwrap().remove(0);
		let (bs_update, closing_signed_b) = get_closing_signed_broadcast!(node_b, node_a.get_our_node_id());

		node_a.handle_closing_signed(&node_b.get_our_node_id(), &closing_signed_b.unwrap());
		let (as_update, none_a) = get_closing_signed_broadcast!(node_a, node_b.get_our_node_id());
		assert!(none_a.is_none());
		assert_eq!(broadcaster_a.txn_broadcasted.lock().unwrap().len(), 1);
		tx_a = broadcaster_a.txn_broadcasted.lock().unwrap().remove(0);
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

macro_rules! check_added_monitors {
    ($node: expr, $count: expr) => {{
        let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
        assert_eq!(added_monitors.len(), $count);
        added_monitors.clear();
    }};
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

macro_rules! get_payment_preimage_hash {
    ($node: expr) => {{
        let payment_preimage = PaymentPreimage([*$node.network_payment_count.borrow(); 32]);
        *$node.network_payment_count.borrow_mut() += 1;
        let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
        (payment_preimage, payment_hash)
    }};
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

macro_rules! expect_payment_sent {
    ($node: expr, $expected_payment_preimage: expr) => {
        let events = $node.node.get_and_clear_pending_events();
        assert_eq!(events.len(), 1);
        match events[0] {
            Event::PaymentSent {
                ref payment_preimage,
            } => {
                assert_eq!($expected_payment_preimage, *payment_preimage);
            }
            _ => panic!("Unexpected event"),
        }
    };
}

pub fn send_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_paths: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>) {
	origin_node.node.send_payment(&route, our_payment_hash, &our_payment_secret).unwrap();
	check_added_monitors!(origin_node, expected_paths.len());
	pass_along_route(origin_node, expected_paths, recv_value, our_payment_hash, our_payment_secret);
}

pub fn pass_along_path<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_path: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>, ev: MessageSendEvent, payment_received_expected: bool) {
	let mut payment_event = SendEvent::from_event(ev);
	let mut prev_node = origin_node;

	for (idx, &node) in expected_path.iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]);
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(node);

		if idx == expected_path.len() - 1 {
			let events_2 = node.node.get_and_clear_pending_events();
			if payment_received_expected {
				assert_eq!(events_2.len(), 1);
				match events_2[0] {
					Event::PaymentReceived { ref payment_hash, ref payment_secret, amt } => {
						assert_eq!(our_payment_hash, *payment_hash);
						assert_eq!(our_payment_secret, *payment_secret);
						assert_eq!(amt, recv_value);
					},
					_ => panic!("Unexpected event"),
				}
			} else {
				assert!(events_2.is_empty());
			}
		} else {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors!(node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		}

		prev_node = node;
	}
}

pub fn pass_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&[&Node<'a, 'b, 'c>]], recv_value: u64, our_payment_hash: PaymentHash, our_payment_secret: Option<PaymentSecret>) {
	let mut events = origin_node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), expected_route.len());
	for (path_idx, (ev, expected_path)) in events.drain(..).zip(expected_route.iter()).enumerate() {
		// Once we've gotten through all the HTLCs, the last one should result in a
		// PaymentReceived (but each previous one should not!), .
		let expect_payment = path_idx == expected_route.len() - 1;
		pass_along_path(origin_node, expected_path, recv_value, our_payment_hash.clone(), our_payment_secret, ev, expect_payment);
	}
}

pub fn send_along_route_with_hash<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64, our_payment_hash: PaymentHash) {
	send_along_route_with_secret(origin_node, route, &[expected_route], recv_value, our_payment_hash, None);
}

pub fn send_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, route: Route, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	send_along_route_with_hash(origin_node, route, expected_route, recv_value, our_payment_hash);
	(our_payment_preimage, our_payment_hash)
}

pub fn claim_payment_along_route_with_secret<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_paths: &[&[&Node<'a, 'b, 'c>]], skip_last: bool, our_payment_preimage: PaymentPreimage, our_payment_secret: Option<PaymentSecret>, expected_amount: u64) {
	for path in expected_paths.iter() {
		assert_eq!(path.last().unwrap().node.get_our_node_id(), expected_paths[0].last().unwrap().node.get_our_node_id());
	}
	assert!(expected_paths[0].last().unwrap().node.claim_funds(our_payment_preimage, &our_payment_secret, expected_amount));
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

pub fn claim_payment_along_route<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], skip_last: bool, our_payment_preimage: PaymentPreimage, expected_amount: u64) {
	claim_payment_along_route_with_secret(origin_node, &[expected_route], skip_last, our_payment_preimage, None, expected_amount);
}

pub fn claim_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], our_payment_preimage: PaymentPreimage, expected_amount: u64) {
	claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage, expected_amount);
}

pub const TEST_FINAL_CLTV: u32 = 32;

pub fn route_payment<'a, 'b, 'c>(origin_node: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let net_graph_msg_handler = &origin_node.net_graph_msg_handler;
	let logger = test_utils::TestLogger::new();
	let route = get_route(&origin_node.node.get_our_node_id(), &net_graph_msg_handler.network_graph.read().unwrap(), &expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV, &logger).unwrap();
	assert_eq!(route.paths.len(), 1);
	assert_eq!(route.paths[0].len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.paths[0].iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	send_along_route(origin_node, route, expected_route, recv_value)
}

pub fn send_payment<'a, 'b, 'c>(origin: &Node<'a, 'b, 'c>, expected_route: &[&Node<'a, 'b, 'c>], recv_value: u64, expected_value: u64)  {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage, expected_value);
}

pub fn create_chanmon_cfgs(node_count: usize) -> Vec<TestChanMonCfg> {
	let mut chan_mon_cfgs = Vec::new();
	for i in 0..node_count {
		let tx_broadcaster = test_utils::TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())};
		let fee_estimator = test_utils::TestFeeEstimator { sat_per_kw: 253 };
		let chain_monitor = chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet);
		let logger = test_utils::TestLogger::with_id(format!("node {}", i));
		chan_mon_cfgs.push(TestChanMonCfg{ tx_broadcaster, fee_estimator, chain_monitor, logger });
	}

	chan_mon_cfgs
}

pub fn create_node_chanmgrs<'a, 'b>(node_count: usize, cfgs: &'a Vec<NodeCfg<'b>>, node_config: &[Option<UserConfig>]) -> Vec<ChannelManager<LoopbackChannelSigner, &'a TestChannelMonitor<'b>, &'b test_utils::TestBroadcaster, &'a LoopbackSignerKeysInterface, &'b test_utils::TestFeeEstimator, &'b test_utils::TestLogger>> {
	let mut chanmgrs = Vec::new();
	for i in 0..node_count {
		let mut default_config = UserConfig::default();
		default_config.channel_options.announced_channel = true;
		default_config.peer_channel_config_limits.force_announced_channel_preference = false;
		default_config.own_channel_config.our_htlc_minimum_msat = 1000; // sanitization being done by the sender, to exerce receiver logic we need to lift of limit
		let node = ChannelManager::new(Network::Testnet, cfgs[i].fee_estimator, &cfgs[i].chan_monitor, cfgs[i].tx_broadcaster, cfgs[i].logger.clone(), &cfgs[i].keys_manager, if node_config[i].is_some() { node_config[i].clone().unwrap() } else { default_config }, 0);
		chanmgrs.push(node);
	}

	chanmgrs
}

pub fn create_network<'a, 'b: 'a, 'c: 'b>(node_count: usize, cfgs: &'b Vec<NodeCfg<'c>>, chan_mgrs: &'a Vec<ChannelManager<LoopbackChannelSigner, &'b TestChannelMonitor<'c>, &'c test_utils::TestBroadcaster, &'b LoopbackSignerKeysInterface, &'c test_utils::TestFeeEstimator, &'c test_utils::TestLogger>>) -> Vec<Node<'a, 'b, 'c>> {
	let mut nodes = Vec::new();
	let chan_count = Rc::new(RefCell::new(0));
	let payment_count = Rc::new(RefCell::new(0));

	for i in 0..node_count {
		let block_notifier = chaininterface::BlockNotifier::new(cfgs[i].chain_monitor);
		block_notifier.register_listener(&cfgs[i].chan_monitor.simple_monitor as &chaininterface::ChainListener);
		block_notifier.register_listener(&chan_mgrs[i] as &chaininterface::ChainListener);
		let net_graph_msg_handler = NetGraphMsgHandler::new(cfgs[i].chain_monitor, cfgs[i].logger);
		nodes.push(Node{ chain_monitor: &cfgs[i].chain_monitor, block_notifier,
		                 tx_broadcaster: cfgs[i].tx_broadcaster, chan_monitor: &cfgs[i].chan_monitor,
		                 keys_manager: &cfgs[i].keys_manager, node: &chan_mgrs[i], net_graph_msg_handler,
		                 node_seed: cfgs[i].node_seed, network_chan_count: chan_count.clone(),
		                 network_payment_count: payment_count.clone(), logger: cfgs[i].logger,
		})
	}

	nodes
}

pub struct TestChannelMonitor<'a> {
    pub added_monitors: Mutex<Vec<(OutPoint, ())>>,
    pub latest_monitor_update_id: Mutex<HashMap<[u8; 32], (OutPoint, u64)>>,
    pub simple_monitor: channelmonitor::SimpleManyChannelMonitor<
        OutPoint,
        LoopbackChannelSigner,
        &'a chaininterface::BroadcasterInterface,
        &'a TestFeeEstimator,
        &'a TestLogger,
        &'a ChainWatchInterface,
    >,
    pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
    // If this is set to Some(), after the next return, we'll always return this until update_ret
    // is changed:
    pub next_update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
}

impl<'a> TestChannelMonitor<'a> {
    pub fn new(
        chain_monitor: &'a chaininterface::ChainWatchInterface,
        broadcaster: &'a chaininterface::BroadcasterInterface,
        logger: &'a TestLogger,
        fee_estimator: &'a TestFeeEstimator,
    ) -> Self {
        Self {
            added_monitors: Mutex::new(Vec::new()),
            latest_monitor_update_id: Mutex::new(HashMap::new()),
            simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(
                chain_monitor,
                broadcaster,
                logger,
                fee_estimator,
            ),
            update_ret: Mutex::new(Ok(())),
            next_update_ret: Mutex::new(None),
        }
    }
}

impl<'a> channelmonitor::ManyChannelMonitor for TestChannelMonitor<'a> {
	type Keys = LoopbackChannelSigner;

	fn add_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<LoopbackChannelSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		self.added_monitors.lock().unwrap().push((funding_txo, ()));
		self.simple_monitor.add_monitor(funding_txo, monitor)
	}

	fn update_monitor(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		self.added_monitors.lock().unwrap().push((funding_txo, ()));
		self.simple_monitor.update_monitor(funding_txo, update)
	}

	fn get_and_clear_pending_htlcs_updated(&self) -> Vec<HTLCUpdate> {
		return self.simple_monitor.get_and_clear_pending_htlcs_updated();
	}
}
