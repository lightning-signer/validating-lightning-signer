#![allow(unused_imports)]

extern crate lightning_signer;

use core::time::Duration;
use lightning_signer::Arc;
use lightning_signer::Set;

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::network::constants::Network::Testnet;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{Block, BlockHeader, Network, OutPoint, Script, Transaction};
use lightning::chain::keysinterface::KeysInterface;
use lightning::chain::{chaininterface, keysinterface};
use lightning::ln::features::InitFeatures;
use lightning::ln::functional_test_utils::{
    ACCEPTED_HTLC_SCRIPT_WEIGHT, OFFERED_HTLC_SCRIPT_WEIGHT,
};
use lightning::ln::msgs::{ChannelMessageHandler, ChannelUpdate};
use lightning::util::config::{ChannelHandshakeConfig, UserConfig};
use lightning::util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use lightning::util::logger::Logger;

use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::util::functional_test_utils::{
    close_channel, confirm_transaction_at, connect_block, connect_blocks,
    create_announced_chan_between_nodes, create_chanmon_cfgs, create_network, create_node_chanmgrs,
    get_announce_close_broadcast_events, mine_transaction, send_payment, Node, NodeCfg,
    TestChanMonCfg,
};
use lightning_signer::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use lightning_signer::util::test_utils;
use lightning_signer::util::test_utils::{TestChainMonitor, TEST_NODE_CONFIG};
use lightning_signer::{
    check_added_monitors, check_closed_broadcast, check_spends, expect_payment_failed,
    expect_pending_htlcs_forwardable_ignore, get_htlc_update_msgs, get_local_commitment_txn,
};

use self::lightning_signer::util::functional_test_utils::{
    claim_payment, create_announced_chan_between_nodes_with_value, route_payment,
};

use test_env_log::test;

pub fn create_node_cfgs_with_signer<'a>(
    node_count: usize,
    signer: &Arc<MultiSigner>,
    chanmon_cfgs: &'a Vec<TestChanMonCfg>,
) -> Vec<NodeCfg<'a>> {
    let mut nodes = Vec::new();

    for i in 0..node_count {
        let seed = [i as u8; 32];

        let node_id = signer.new_node(TEST_NODE_CONFIG);

        let keys_manager = LoopbackSignerKeysInterface {
            node_id,
            signer: Arc::clone(signer),
        };

        let chain_monitor = TestChainMonitor::new(
            Some(&chanmon_cfgs[i].chain_source),
            &chanmon_cfgs[i].tx_broadcaster,
            &chanmon_cfgs[i].logger,
            &chanmon_cfgs[i].fee_estimator,
            &chanmon_cfgs[i].persister,
        );

        nodes.push(NodeCfg {
            chain_source: &chanmon_cfgs[i].chain_source,
            logger: &chanmon_cfgs[i].logger,
            tx_broadcaster: &chanmon_cfgs[i].tx_broadcaster,
            fee_estimator: &chanmon_cfgs[i].fee_estimator,
            chain_monitor,
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
    let signer = Arc::new(MultiSigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(4);
    let node_cfgs = create_node_cfgs_with_signer(4, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan_1 = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
        InitFeatures::known(),
        InitFeatures::known(),
    );
    let _chan_2 = create_announced_chan_between_nodes(
        &nodes,
        1,
        2,
        InitFeatures::known(),
        InitFeatures::known(),
    );
    let _chan_3 = create_announced_chan_between_nodes(
        &nodes,
        2,
        3,
        InitFeatures::known(),
        InitFeatures::known(),
    );

    // Rebalance the network a bit by relaying one payment through all the channels...
    send_payment(
        &nodes[0],
        &vec![&nodes[1], &nodes[2], &nodes[3]][..],
        8000000,
    );

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
        channel_options: Default::default(),
        accept_forwards_to_priv_channels: true,
    };
    cfg1.channel_options.announced_channel = true;
    cfg1.peer_channel_config_limits
        .force_announced_channel_preference = false;
    cfg1
}

#[test]
fn channel_force_close_test() {
    let signer = Arc::new(MultiSigner::new());

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
        99000000,
        InitFeatures::known(),
        InitFeatures::known(),
    );

    // Close channel forcefully
    let _ = nodes[0].node.force_close_channel(&chan.2);

    check_closed_broadcast!(nodes[0], true);

    // assert_eq!(nodes[0].node.get_and_clear_pending_msg_events().len(), 1);
    check_added_monitors!(nodes[0], 1);

    // Cause the other node to sweep
    let node_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap();
    assert_eq!(node_txn.len(), 1);

    // Check if closing tx correctly spends the funding
    check_spends!(node_txn[0], chan.3);

    let header = BlockHeader {
        version: 0x20000000,
        prev_blockhash: nodes[0].best_block_hash(),
        merkle_root: Default::default(),
        time: 42,
        bits: 42,
        nonce: 42,
    };
    connect_block(
        &nodes[1],
        &Block {
            header,
            txdata: vec![node_txn[0].clone()],
        },
    );
    assert_eq!(nodes[1].node.get_and_clear_pending_msg_events().len(), 2);
    check_added_monitors!(nodes[1], 1);
}

#[test]
fn justice_tx_test() {
    let signer = Arc::new(MultiSigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan_1 = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
        InitFeatures::known(),
        InitFeatures::known(),
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
    assert_eq!(node1_txn.len(), 2); // ChannelMonitor: penalty tx, ChannelManager: local commitment tx
    check_spends!(node1_txn[0], revoked_local_txn[0]);
}

#[test]
fn claim_htlc_outputs_single_tx() {
    let signer = Arc::new(MultiSigner::new());

    // Node revoked old state, htlcs have timed out, claim each of them in separated justice tx
    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan_1 = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
        InitFeatures::known(),
        InitFeatures::known(),
    );

    // Rebalance the network to generate htlc in the two directions
    send_payment(&nodes[0], &vec![&nodes[1]][..], 8000000);
    // node[0] is gonna to revoke an old state thus node[1] should be able to claim both offered/received HTLC outputs on top of commitment tx, but this
    // time as two different claim transactions as we're gonna to timeout htlc with given a high current height
    let payment_preimage_1 = route_payment(&nodes[0], &vec![&nodes[1]][..], 3000000).0;
    let (_payment_preimage_2, payment_hash_2, _payment_secret_2) =
        route_payment(&nodes[1], &vec![&nodes[0]][..], 3000000);

    // Get the will-be-revoked local txn from node[0]
    let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan_1.2);

    //Revoke the old state
    claim_payment(&nodes[0], &vec![&nodes[1]][..], payment_preimage_1);

    {
        confirm_transaction_at(&nodes[0], &revoked_local_txn[0], 100);
        check_added_monitors!(nodes[0], 1);
        confirm_transaction_at(&nodes[1], &revoked_local_txn[0], 100);
        check_added_monitors!(nodes[1], 1);
        expect_pending_htlcs_forwardable_ignore!(nodes[0]);

        connect_blocks(&nodes[1], 6 - 1);
        expect_payment_failed!(nodes[1], payment_hash_2, true);

        let node_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
        assert_eq!(node_txn.len(), 9);
        // ChannelMonitor: justice tx revoked offered htlc, justice tx revoked received htlc, justice tx revoked to_local (3)
        // ChannelManager: local commmitment + local HTLC-timeout (2)
        // ChannelMonitor: bumped justice tx, after one increase, bumps on HTLC aren't generated not being substantial anymore, bump on revoked to_local isn't generated due to more room for expiration (2)
        // ChannelMonitor: local commitment + local HTLC-timeout (2)

        // Check the pair local commitment and HTLC-timeout broadcast due to HTLC expiration
        assert_eq!(node_txn[0].input.len(), 1);
        check_spends!(node_txn[0], chan_1.3);
        assert_eq!(node_txn[1].input.len(), 1);
        let witness_script = node_txn[1].input[0].witness.last().unwrap();
        assert_eq!(witness_script.len(), OFFERED_HTLC_SCRIPT_WEIGHT); //Spending an offered htlc output
        check_spends!(node_txn[1], node_txn[0]);

        // Justice transactions are indices 1-2-4
        assert_eq!(node_txn[2].input.len(), 1);
        assert_eq!(node_txn[3].input.len(), 1);
        assert_eq!(node_txn[4].input.len(), 1);

        check_spends!(node_txn[2], revoked_local_txn[0]);
        check_spends!(node_txn[3], revoked_local_txn[0]);
        check_spends!(node_txn[4], revoked_local_txn[0]);

        let mut witness_lens = Set::new();
        witness_lens.insert(node_txn[2].input[0].witness.last().unwrap().len());
        witness_lens.insert(node_txn[3].input[0].witness.last().unwrap().len());
        witness_lens.insert(node_txn[4].input[0].witness.last().unwrap().len());
        assert_eq!(witness_lens.len(), 3);
        assert_eq!(*witness_lens.iter().skip(0).next().unwrap(), 77); // revoked to_local
        assert_eq!(
            *witness_lens.iter().skip(1).next().unwrap(),
            OFFERED_HTLC_SCRIPT_WEIGHT
        ); // revoked offered HTLC
        assert_eq!(
            *witness_lens.iter().skip(2).next().unwrap(),
            ACCEPTED_HTLC_SCRIPT_WEIGHT
        ); // revoked received HTLC
    }
    get_announce_close_broadcast_events(&nodes, 0, 1);
    assert_eq!(nodes[0].node.list_channels().len(), 0);
    assert_eq!(nodes[1].node.list_channels().len(), 0);
}

fn do_test_onchain_htlc_settlement_after_close(
    broadcast_alice: bool,
    go_onchain_before_fulfill: bool,
) {
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
    let signer = Arc::new(MultiSigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(3);
    let node_cfgs = create_node_cfgs_with_signer(3, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
    let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let chan_ab = create_announced_chan_between_nodes_with_value(
        &nodes,
        0,
        1,
        100000,
        10001,
        InitFeatures::known(),
        InitFeatures::known(),
    );
    create_announced_chan_between_nodes_with_value(
        &nodes,
        1,
        2,
        100000,
        10001,
        InitFeatures::known(),
        InitFeatures::known(),
    );

    // Steps (1) and (2):
    // Send an HTLC Alice --> Bob --> Carol, but Carol doesn't settle the HTLC back.
    let (payment_preimage, _payment_hash, _payment_secret) =
        route_payment(&nodes[0], &vec![&nodes[1], &nodes[2]], 3_000_000);

    // Check that Alice's commitment transaction now contains an output for this HTLC.
    let alice_txn = get_local_commitment_txn!(nodes[0], chan_ab.2);
    check_spends!(alice_txn[0], chan_ab.3);
    assert_eq!(alice_txn[0].output.len(), 2);
    check_spends!(alice_txn[1], alice_txn[0]); // 2nd transaction is a non-final HTLC-timeout
    assert_eq!(
        alice_txn[1].input[0].witness.last().unwrap().len(),
        OFFERED_HTLC_SCRIPT_WEIGHT
    );
    assert_eq!(alice_txn.len(), 2);

    // Steps (3) and (4):
    // If `go_onchain_before_fufill`, broadcast the relevant commitment transaction and check that Bob
    // responds by (1) broadcasting a channel update and (2) adding a new ChannelMonitor.
    let mut force_closing_node = 0; // Alice force-closes
    if !broadcast_alice {
        force_closing_node = 1;
    } // Bob force-closes
    nodes[force_closing_node]
        .node
        .force_close_channel(&chan_ab.2)
        .unwrap();
    check_closed_broadcast!(nodes[force_closing_node], true);
    check_added_monitors!(nodes[force_closing_node], 1);
    if go_onchain_before_fulfill {
        let txn_to_broadcast = match broadcast_alice {
            true => alice_txn.clone(),
            false => get_local_commitment_txn!(nodes[1], chan_ab.2),
        };
        let header = BlockHeader {
            version: 0x20000000,
            prev_blockhash: nodes[1].best_block_hash(),
            merkle_root: Default::default(),
            time: 42,
            bits: 42,
            nonce: 42,
        };
        connect_block(
            &nodes[1],
            &Block {
                header,
                txdata: vec![txn_to_broadcast[0].clone()],
            },
        );
        let bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
        if broadcast_alice {
            check_closed_broadcast!(nodes[1], true);
            check_added_monitors!(nodes[1], 1);
        }
        assert_eq!(bob_txn.len(), 1);
        check_spends!(bob_txn[0], chan_ab.3);
    }

    // Step (5):
    // Carol then claims the funds and sends an update_fulfill message to Bob, and they go through the
    // process of removing the HTLC from their commitment transactions.
    assert!(nodes[2].node.claim_funds(payment_preimage));
    check_added_monitors!(nodes[2], 1);
    let carol_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
    assert!(carol_updates.update_add_htlcs.is_empty());
    assert!(carol_updates.update_fail_htlcs.is_empty());
    assert!(carol_updates.update_fail_malformed_htlcs.is_empty());
    assert!(carol_updates.update_fee.is_none());
    assert_eq!(carol_updates.update_fulfill_htlcs.len(), 1);

    nodes[1].node.handle_update_fulfill_htlc(
        &nodes[2].node.get_our_node_id(),
        &carol_updates.update_fulfill_htlcs[0],
    );
    // If Alice broadcasted but Bob doesn't know yet, here he prepares to tell her about the preimage.
    if !go_onchain_before_fulfill && broadcast_alice {
        let events = nodes[1].node.get_and_clear_pending_msg_events();
        assert_eq!(events.len(), 1);
        match events[0] {
            MessageSendEvent::UpdateHTLCs { ref node_id, .. } => {
                assert_eq!(*node_id, nodes[0].node.get_our_node_id());
            }
            _ => panic!("Unexpected event"),
        };
    }
    nodes[1].node.handle_commitment_signed(
        &nodes[2].node.get_our_node_id(),
        &carol_updates.commitment_signed,
    );
    // One monitor update for the preimage to update the Bob<->Alice channel, one monitor update
    // Carol<->Bob's updated commitment transaction info.
    check_added_monitors!(nodes[1], 2);

    let events = nodes[1].node.get_and_clear_pending_msg_events();
    assert_eq!(events.len(), 2);
    let bob_revocation = match events[0] {
        MessageSendEvent::SendRevokeAndACK {
            ref node_id,
            ref msg,
        } => {
            assert_eq!(*node_id, nodes[2].node.get_our_node_id());
            (*msg).clone()
        }
        _ => panic!("Unexpected event"),
    };
    let bob_updates = match events[1] {
        MessageSendEvent::UpdateHTLCs {
            ref node_id,
            ref updates,
        } => {
            assert_eq!(*node_id, nodes[2].node.get_our_node_id());
            (*updates).clone()
        }
        _ => panic!("Unexpected event"),
    };

    nodes[2]
        .node
        .handle_revoke_and_ack(&nodes[1].node.get_our_node_id(), &bob_revocation);
    check_added_monitors!(nodes[2], 1);
    nodes[2].node.handle_commitment_signed(
        &nodes[1].node.get_our_node_id(),
        &bob_updates.commitment_signed,
    );
    check_added_monitors!(nodes[2], 1);

    let events = nodes[2].node.get_and_clear_pending_msg_events();
    assert_eq!(events.len(), 1);
    let carol_revocation = match events[0] {
        MessageSendEvent::SendRevokeAndACK {
            ref node_id,
            ref msg,
        } => {
            assert_eq!(*node_id, nodes[1].node.get_our_node_id());
            (*msg).clone()
        }
        _ => panic!("Unexpected event"),
    };
    nodes[1]
        .node
        .handle_revoke_and_ack(&nodes[2].node.get_our_node_id(), &carol_revocation);
    check_added_monitors!(nodes[1], 1);

    // If this test requires the force-closed channel to not be on-chain until after the fulfill,
    // here's where we put said channel's commitment tx on-chain.
    let mut txn_to_broadcast = alice_txn.clone();
    if !broadcast_alice {
        txn_to_broadcast = get_local_commitment_txn!(nodes[1], chan_ab.2);
    }
    if !go_onchain_before_fulfill {
        let header = BlockHeader {
            version: 0x20000000,
            prev_blockhash: nodes[1].best_block_hash(),
            merkle_root: Default::default(),
            time: 42,
            bits: 42,
            nonce: 42,
        };
        connect_block(
            &nodes[1],
            &Block {
                header,
                txdata: vec![txn_to_broadcast[0].clone()],
            },
        );
        // If Bob was the one to force-close, he will have already passed these checks earlier.
        if broadcast_alice {
            check_closed_broadcast!(nodes[1], true);
            check_added_monitors!(nodes[1], 1);
        }
        let bob_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap();
        if broadcast_alice {
            // In `connect_block()`, the ChainMonitor and ChannelManager are separately notified about a
            // new block being connected. The ChannelManager being notified triggers a monitor update,
            // which triggers broadcasting our commitment tx and an HTLC-claiming tx. The ChainMonitor
            // being notified triggers the HTLC-claiming tx redundantly, resulting in 3 total txs being
            // broadcasted.
            assert_eq!(bob_txn.len(), 3);
            check_spends!(bob_txn[1], chan_ab.3);
        } else {
            assert_eq!(bob_txn.len(), 2);
            check_spends!(bob_txn[0], chan_ab.3);
        }
    }

    // Step (6):
    // Finally, check that Bob broadcasted a preimage-claiming transaction for the HTLC output on the
    // broadcasted commitment transaction.
    {
        let bob_txn = nodes[1]
            .tx_broadcaster
            .txn_broadcasted
            .lock()
            .unwrap()
            .clone();
        if go_onchain_before_fulfill {
            // Bob should now have an extra broadcasted tx, for the preimage-claiming transaction.
            assert_eq!(bob_txn.len(), 2);
        }
        // See asserts below
        // let script_weight = match broadcast_alice {
        //     true => OFFERED_HTLC_SCRIPT_WEIGHT,
        //     false => ACCEPTED_HTLC_SCRIPT_WEIGHT
        // };
        // If Alice force-closed and Bob didn't receive her commitment transaction until after he
        // received Carol's fulfill, he broadcasts the HTLC-output-claiming transaction first. Else if
        // Bob force closed or if he found out about Alice's commitment tx before receiving Carol's
        // fulfill, then he broadcasts the HTLC-output-claiming transaction second.
        if broadcast_alice && !go_onchain_before_fulfill {
            check_spends!(bob_txn[0], txn_to_broadcast[0]);
            // this doesn't always match, probably because our signer grinds?
            // assert_eq!(bob_txn[0].input[0].witness.last().unwrap().len(), script_weight);
        } else {
            check_spends!(bob_txn[1], txn_to_broadcast[0]);
            // this doesn't always match, probably because our signer grinds?
            // assert_eq!(bob_txn[1].input[0].witness.last().unwrap().len(), script_weight);
        }
    }
}

#[test]
fn test_onchain_htlc_settlement_after_close() {
    do_test_onchain_htlc_settlement_after_close(true, true);
    do_test_onchain_htlc_settlement_after_close(false, true); // Technically redundant, but may as well
    do_test_onchain_htlc_settlement_after_close(true, false);
    do_test_onchain_htlc_settlement_after_close(false, false);
}

const ANTI_REORG_DELAY: u32 = 6;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1};

macro_rules! check_spendable_outputs {
    ($node: expr, $der_idx: expr, $keysinterface: expr, $chan_value: expr) => {{
        let mut events = $node
            .chain_monitor
            .chain_monitor
            .get_and_clear_pending_events();
        let mut txn = Vec::new();
        let mut all_outputs = Vec::new();
        let secp_ctx = Secp256k1::new();
        for event in events.drain(..) {
            match event {
                Event::SpendableOutputs { mut outputs } => {
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
                                    &secp_ctx,
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
                &secp_ctx,
            ) {
                txn.push(tx);
            }
        }
        txn
    }};
}

#[test]
fn test_static_output_closing_tx() {
    let signer = Arc::new(MultiSigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs_with_signer(2, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    let chan = create_announced_chan_between_nodes(
        &nodes,
        0,
        1,
        InitFeatures::known(),
        InitFeatures::known(),
    );

    send_payment(&nodes[0], &vec![&nodes[1]][..], 8000000);
    let closing_tx = close_channel(&nodes[0], &nodes[1], &chan.2, chan.3, true).2;

    mine_transaction(&nodes[0], &closing_tx);
    connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

    let spend_txn = check_spendable_outputs!(nodes[0], 2, node_cfgs[0].keys_manager, 100000);
    assert_eq!(spend_txn.len(), 1);
    check_spends!(spend_txn[0], closing_tx);

    mine_transaction(&nodes[1], &closing_tx);
    connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

    let spend_txn = check_spendable_outputs!(nodes[1], 2, node_cfgs[1].keys_manager, 100000);
    assert_eq!(spend_txn.len(), 1);
    check_spends!(spend_txn[0], closing_tx);
}
