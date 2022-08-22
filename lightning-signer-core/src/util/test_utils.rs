use std::time::Duration;

use core::cmp;

use bitcoin;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{hex, hex::FromHex, Hash};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{
    self, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey, SignOnly,
};
use bitcoin::util::hash::bitcoin_merkle_root;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{
    Address, Block, BlockHash, BlockHeader, EcdsaSighashType, OutPoint as BitcoinOutPoint,
    PackedLockTime, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
};
use chain::chaininterface;
use lightning::chain;
use lightning::chain::chainmonitor::MonitorUpdateId;
use lightning::chain::channelmonitor::MonitorEvent;
use lightning::chain::keysinterface::{BaseSign, InMemorySigner};
use lightning::chain::transaction::OutPoint;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::ln::chan_utils::{
    build_htlc_transaction, derive_private_key, get_anchor_redeemscript, get_htlc_redeemscript,
    get_revokeable_redeemscript, make_funding_redeemscript, ChannelPublicKeys,
    ChannelTransactionParameters, CommitmentTransaction, CounterpartyChannelTransactionParameters,
    DirectedChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::ln::{chan_utils, PaymentHash};
use lightning::util::test_utils;

use super::key_utils::{
    make_test_bitcoin_pubkey, make_test_counterparty_points, make_test_privkey, make_test_pubkey,
};
use crate::channel::{
    Channel, ChannelBase, ChannelId, ChannelSetup, ChannelStub, CommitmentType, TypedSignature,
};
use crate::node::{Node, NodeConfig};
use crate::node::{NodeServices, SpendType};
use crate::persist::{DummyPersister, Persist};
use crate::policy::simple_validator::SimpleValidatorFactory;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::signer::derive::KeyDerivationStyle;
use crate::signer::StartingTimeFactory;
use crate::tx::script::{
    get_p2wpkh_redeemscript, get_to_countersignatory_with_anchors_redeemscript,
    ANCHOR_OUTPUT_VALUE_SATOSHI,
};
use crate::tx::tx::{sort_outputs, CommitmentInfo2, HTLCInfo2};
use crate::util::clock::StandardClock;
use crate::util::crypto_utils::{derive_public_key, payload_for_p2wpkh, payload_for_p2wsh};
use crate::util::loopback::LoopbackChannelSigner;
use crate::util::status::Status;
use crate::wallet::Wallet;
use crate::Arc;

// Status assertions:

#[cfg(test)]
macro_rules! assert_status_ok {
    ($status: expr) => {
        if $status.is_err() {
            panic!("unexpected Status: {:#?}", $status.unwrap_err());
        }
    };
}

#[cfg(test)]
macro_rules! assert_invalid_argument_err {
    ($status: expr, $msg: expr) => {
        assert!($status.is_err());
        let err = $status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), $msg);
    };
}

#[cfg(test)]
macro_rules! assert_failed_precondition_err {
    ($status: expr, $msg: expr) => {
        assert!($status.is_err());
        let err = $status.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), $msg);
    };
}

// ValidationError assertions:

#[allow(unused)]
#[cfg(test)]
macro_rules! assert_validation_ok {
    ($res: expr) => {
        if $res.is_err() {
            // avoid printing the backtrace ...
            panic!("unexepected ValidationError: {:#?}", $res.unwrap_err().kind);
        }
    };
}

#[cfg(test)]
macro_rules! assert_policy_err {
    ($res: expr, $msg: expr) => {
        assert!($res.is_err());
        // avoid printing the backtrace ...
        assert_eq!($res.unwrap_err().kind, policy_error($msg.to_string()).kind);
    };
}

pub struct TestPersister {
    pub update_ret: Mutex<Result<(), chain::ChannelMonitorUpdateErr>>,
}

impl TestPersister {
    pub fn new() -> Self {
        Self { update_ret: Mutex::new(Ok(())) }
    }

    pub fn set_update_ret(&self, ret: Result<(), chain::ChannelMonitorUpdateErr>) {
        *self.update_ret.lock().unwrap() = ret;
    }
}

impl chainmonitor::Persist<LoopbackChannelSigner> for TestPersister {
    fn persist_new_channel(
        &self,
        _funding_txo: OutPoint,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
        _id: MonitorUpdateId,
    ) -> Result<(), chain::ChannelMonitorUpdateErr> {
        self.update_ret.lock().unwrap().clone()
    }

    fn update_persisted_channel(
        &self,
        _funding_txo: OutPoint,
        _update: &Option<channelmonitor::ChannelMonitorUpdate>,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
        _id: MonitorUpdateId,
    ) -> Result<(), chain::ChannelMonitorUpdateErr> {
        self.update_ret.lock().unwrap().clone()
    }
}

pub struct TestChainMonitor<'a> {
    pub added_monitors: Mutex<Vec<(OutPoint, ())>>,
    pub latest_monitor_update_id: Mutex<Map<[u8; 32], (OutPoint, u64)>>,
    pub chain_monitor: chainmonitor::ChainMonitor<
        LoopbackChannelSigner,
        &'a test_utils::TestChainSource,
        &'a chaininterface::BroadcasterInterface,
        &'a test_utils::TestFeeEstimator,
        Arc<test_utils::TestLogger>,
        &'a chainmonitor::Persist<LoopbackChannelSigner>,
    >,
    pub update_ret: Mutex<Option<Result<(), chain::ChannelMonitorUpdateErr>>>,
    // If this is set to Some(), after the next return, we'll always return this until update_ret
    // is changed:
    pub next_update_ret: Mutex<Option<Result<(), chain::ChannelMonitorUpdateErr>>>,
}
impl<'a> TestChainMonitor<'a> {
    pub fn new(
        chain_source: Option<&'a test_utils::TestChainSource>,
        broadcaster: &'a chaininterface::BroadcasterInterface,
        logger: Arc<test_utils::TestLogger>,
        fee_estimator: &'a test_utils::TestFeeEstimator,
        persister: &'a chainmonitor::Persist<LoopbackChannelSigner>,
    ) -> Self {
        Self {
            added_monitors: Mutex::new(Vec::new()),
            latest_monitor_update_id: Mutex::new(Map::new()),
            chain_monitor: chainmonitor::ChainMonitor::new(
                chain_source,
                broadcaster,
                logger,
                fee_estimator,
                persister,
            ),
            update_ret: Mutex::new(None),
            next_update_ret: Mutex::new(None),
        }
    }
}
impl<'a> chain::Watch<LoopbackChannelSigner> for TestChainMonitor<'a> {
    fn watch_channel(
        &self,
        funding_txo: OutPoint,
        monitor: channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
    ) -> Result<(), chain::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id
            .lock()
            .unwrap()
            .insert(funding_txo.to_channel_id(), (funding_txo, monitor.get_latest_update_id()));
        self.added_monitors.lock().unwrap().push((funding_txo, ()));
        let watch_res = self.chain_monitor.watch_channel(funding_txo, monitor);

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret);
        }
        if ret.is_some() {
            assert!(watch_res.is_ok());
            return ret.unwrap();
        }
        watch_res
    }

    fn update_channel(
        &self,
        funding_txo: OutPoint,
        update: channelmonitor::ChannelMonitorUpdate,
    ) -> Result<(), chain::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id
            .lock()
            .unwrap()
            .insert(funding_txo.to_channel_id(), (funding_txo, update.update_id));
        let update_res = self.chain_monitor.update_channel(funding_txo, update);
        self.added_monitors.lock().unwrap().push((funding_txo, ()));

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret);
        }
        if ret.is_some() {
            assert!(update_res.is_ok());
            return ret.unwrap();
        }
        update_res
    }

    fn release_pending_monitor_events(
        &self,
    ) -> Vec<(OutPoint, Vec<MonitorEvent>, Option<PublicKey>)> {
        self.chain_monitor.release_pending_monitor_events()
    }
}

pub fn pubkey_from_secret_hex(h: &str, secp_ctx: &Secp256k1<SignOnly>) -> PublicKey {
    PublicKey::from_secret_key(
        secp_ctx,
        &SecretKey::from_slice(&Vec::from_hex(h).unwrap()[..]).unwrap(),
    )
}

pub fn make_test_chain_state() -> ChainState {
    ChainState {
        current_height: 1000,
        funding_depth: 0,
        funding_double_spent_depth: 0,
        closing_depth: 0,
    }
}

pub fn make_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub fn make_test_channel_keys() -> InMemorySigner {
    let secp_ctx = Secp256k1::signing_only();
    let channel_value_sat = 3_000_000;
    let mut inmemkeys = InMemorySigner::new(
        &secp_ctx,
        make_test_privkey(254), // node_secret
        make_test_privkey(1),   // funding_key
        make_test_privkey(2),   // revocation_base_key
        make_test_privkey(3),   // payment_key
        make_test_privkey(4),   // delayed_payment_base_key
        make_test_privkey(5),   // htlc_base_key
        [4u8; 32],              // commitment_seed
        channel_value_sat,
        [0u8; 32],
    );
    // This needs to match make_test_channel_setup above.
    inmemkeys.ready_channel(&ChannelTransactionParameters {
        holder_pubkeys: inmemkeys.pubkeys().clone(),
        holder_selected_contest_delay: 5,
        is_outbound_from_holder: true,
        counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
            pubkeys: make_test_counterparty_points(),
            selected_contest_delay: 5,
        }),
        funding_outpoint: Some(OutPoint { txid: Txid::all_zeros(), index: 0 }),
        opt_anchors: None,
    });
    inmemkeys
}

/// A starting time factory which uses fixed values for testing
pub struct FixedStartingTimeFactory {
    starting_time_secs: u64,
    starting_time_nanos: u32,
}

impl StartingTimeFactory for FixedStartingTimeFactory {
    fn starting_time(&self) -> (u64, u32) {
        (self.starting_time_secs, self.starting_time_nanos)
    }
}

impl FixedStartingTimeFactory {
    /// Make a starting time factory which uses fixed values for testing
    pub fn new(starting_time_secs: u64, starting_time_nanos: u32) -> Arc<dyn StartingTimeFactory> {
        Arc::new(FixedStartingTimeFactory { starting_time_secs, starting_time_nanos })
    }
}

/// Make a starting time factory which uses the genesis block timestamp
pub fn make_genesis_starting_time_factory(network: Network) -> Arc<dyn StartingTimeFactory> {
    let genesis = genesis_block(network);
    let now = Duration::from_secs(genesis.header.time as u64);
    FixedStartingTimeFactory::new(now.as_secs(), now.subsec_nanos())
}

pub fn init_node(node_config: NodeConfig, seedstr: &str) -> Arc<Node> {
    let mut seed = [0; 32];
    seed.copy_from_slice(Vec::from_hex(seedstr).unwrap().as_slice());

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(node_config.network);
    let clock = Arc::new(StandardClock());
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };

    let node = Node::new(node_config, &seed, vec![], services);
    Arc::new(node)
}

pub fn init_node_and_channel(
    node_config: NodeConfig,
    seedstr: &str,
    setup: ChannelSetup,
) -> (Arc<Node>, ChannelId) {
    let node = init_node(node_config, seedstr);
    {
        let mut tracker = node.get_tracker();
        let header = make_testnet_header(tracker.tip(), TxMerkleNode::all_zeros());
        tracker.add_block(header, vec![], None).unwrap();
        let header = make_testnet_header(tracker.tip(), TxMerkleNode::all_zeros());
        tracker.add_block(header, vec![], None).unwrap();
        let header = make_testnet_header(tracker.tip(), TxMerkleNode::all_zeros());
        tracker.add_block(header, vec![], None).unwrap();
    }
    let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
    node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");
    let holder_shutdown_key_path = vec![];
    node.ready_channel(channel_id.clone(), None, setup, &holder_shutdown_key_path)
        .expect("ready channel");
    (node, channel_id)
}

pub fn make_test_funding_wallet_addr(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    node: &Node,
    i: u32,
    is_p2sh: bool,
) -> Address {
    let child_path = vec![i];
    let pubkey = node.get_wallet_pubkey(&secp_ctx, &child_path).unwrap();

    // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
    if !is_p2sh {
        Address::p2wpkh(&pubkey, node.network()).unwrap()
    } else {
        Address::p2shwpkh(&pubkey, node.network()).unwrap()
    }
}

pub fn make_test_funding_wallet_input() -> TxIn {
    TxIn {
        previous_output: bitcoin::OutPoint { txid: Txid::all_zeros(), vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    }
}

pub fn make_test_funding_wallet_output(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    node: &Node,
    i: u32,
    value: u64,
    is_p2sh: bool,
) -> TxOut {
    let child_path = vec![i];
    let pubkey = node.get_wallet_pubkey(&secp_ctx, &child_path).unwrap();

    // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
    let addr = if !is_p2sh {
        Address::p2wpkh(&pubkey, node.network()).unwrap()
    } else {
        Address::p2shwpkh(&pubkey, node.network()).unwrap()
    };

    TxOut { value, script_pubkey: addr.script_pubkey() }
}

pub fn make_test_funding_channel_outpoint(
    node: &Node,
    setup: &ChannelSetup,
    channel_id: &ChannelId,
    value: u64,
) -> TxOut {
    node.with_channel_base(channel_id, |base| {
        let funding_redeemscript = make_funding_redeemscript(
            &base.get_channel_basepoints().funding_pubkey,
            &setup.counterparty_points.funding_pubkey,
        );
        let script_pubkey = payload_for_p2wsh(&funding_redeemscript).script_pubkey();
        Ok(TxOut { value, script_pubkey })
    })
    .expect("TxOut")
}

pub fn make_test_funding_tx_with_ins_outs(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: inputs, output: outputs }
}

pub fn make_test_wallet_dest(
    node_ctx: &TestNodeContext,
    wallet_index: u32,
    spend_type: SpendType,
) -> (Script, Vec<u32>) {
    let child_path = vec![wallet_index];
    let pubkey = node_ctx.node.get_wallet_pubkey(&node_ctx.secp_ctx, &child_path).unwrap();

    let script_pubkey = match spend_type {
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node_ctx.node.network()),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node_ctx.node.network()),
        _ => panic!("invalid spend_type {:?}", spend_type),
    }
    .unwrap()
    .script_pubkey();

    (script_pubkey, vec![wallet_index])
}

pub fn make_test_nonwallet_dest(
    node_ctx: &TestNodeContext,
    index: u8,
    spend_type: SpendType,
) -> (Script, Vec<u32>) {
    let pubkey = make_test_bitcoin_pubkey(index);
    let script_pubkey = match spend_type {
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node_ctx.node.network()),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node_ctx.node.network()),
        _ => panic!("invalid spend_type {:?}", spend_type),
    }
    .unwrap()
    .script_pubkey();

    (script_pubkey, vec![])
}

// Bundles node-specific context used for unit tests.
pub struct TestNodeContext {
    pub node: Arc<Node>,
    pub secp_ctx: Secp256k1<secp256k1::SignOnly>,
}

// Bundles channel-specific context used for unit tests.
pub struct TestChannelContext {
    pub channel_id: ChannelId,
    pub setup: ChannelSetup,
    pub counterparty_keys: InMemorySigner,
}

// Bundles funding tx context used for unit tests.
pub struct TestFundingTxContext {
    pub inputs: Vec<TxIn>,
    pub ipaths: Vec<Vec<u32>>,
    pub ivals: Vec<u64>,
    pub ispnds: Vec<SpendType>,
    pub iuckeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
    pub outputs: Vec<TxOut>,
    pub opaths: Vec<Vec<u32>>,
}

// Bundles commitment tx context used for unit tests.
#[derive(Clone)]
pub struct TestCommitmentTxContext {
    pub commit_num: u64,
    pub feerate_per_kw: u32,
    pub to_broadcaster: u64,
    pub to_countersignatory: u64,
    pub offered_htlcs: Vec<HTLCInfo2>,
    pub received_htlcs: Vec<HTLCInfo2>,
    pub tx: Option<CommitmentTransaction>,
}

pub fn test_node_ctx(ndx: usize) -> TestNodeContext {
    let node = init_node(TEST_NODE_CONFIG, TEST_SEED[ndx]);
    let secp_ctx = Secp256k1::signing_only();

    TestNodeContext { node, secp_ctx }
}

pub fn make_test_counterparty_keys(
    node_ctx: &TestNodeContext,
    channel_id: &ChannelId,
    value_sat: u64,
) -> InMemorySigner {
    node_ctx
        .node
        .with_channel_base(channel_id, |stub| {
            // These need to match make_test_counterparty_points() above ...
            let mut cpkeys = InMemorySigner::new(
                &node_ctx.secp_ctx,
                make_test_privkey(254), // node_secret
                make_test_privkey(104), // funding_key
                make_test_privkey(100), // revocation_base_key
                make_test_privkey(101), // payment_key
                make_test_privkey(102), // delayed_payment_base_key
                make_test_privkey(103), // htlc_base_key
                [3u8; 32],              // commitment_seed
                value_sat,              // channel_value
                [0u8; 32],              // Key derivation parameters
            );
            // This needs to match make_test_channel_setup above.
            cpkeys.ready_channel(&ChannelTransactionParameters {
                holder_pubkeys: cpkeys.pubkeys().clone(),
                holder_selected_contest_delay: 7,
                is_outbound_from_holder: false,
                counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                    pubkeys: stub.get_channel_basepoints(),
                    selected_contest_delay: 6,
                }),
                funding_outpoint: Some(OutPoint { txid: Txid::all_zeros(), index: 0 }),
                opt_anchors: None,
            });
            Ok(cpkeys)
        })
        .unwrap()
}

pub fn test_chan_ctx(
    node_ctx: &TestNodeContext,
    nn: usize,
    channel_value_sat: u64,
) -> TestChannelContext {
    let push_value_msat = 0;
    test_chan_ctx_with_push_val(node_ctx, nn, channel_value_sat, push_value_msat)
}

pub fn test_chan_ctx_with_push_val(
    node_ctx: &TestNodeContext,
    nn: usize,
    channel_value_sat: u64,
    push_value_msat: u64,
) -> TestChannelContext {
    let channel_id = ChannelId::new(&nn.to_le_bytes());
    let setup = ChannelSetup {
        is_outbound: true,
        channel_value_sat,
        push_value_msat,
        funding_outpoint: BitcoinOutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    };

    node_ctx.node.new_channel(Some(channel_id.clone()), &node_ctx.node).expect("new_channel");

    // Make counterparty keys that match.
    let counterparty_keys = make_test_counterparty_keys(&node_ctx, &channel_id, channel_value_sat);
    TestChannelContext { channel_id, setup, counterparty_keys }
}

pub fn set_next_holder_commit_num_for_testing(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
) {
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);
            Ok(())
        })
        .unwrap();
}

pub fn set_next_counterparty_commit_num_for_testing(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
    current_point: PublicKey,
) {
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, current_point);
            Ok(())
        })
        .unwrap();
}

pub fn set_next_counterparty_revoke_num_for_testing(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    revoke_num: u64,
) {
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(revoke_num);
            Ok(())
        })
        .unwrap();
}

pub fn test_funding_tx_ctx() -> TestFundingTxContext {
    TestFundingTxContext {
        inputs: vec![],
        ipaths: vec![],
        ivals: vec![],
        ispnds: vec![],
        iuckeys: vec![],
        outputs: vec![],
        opaths: vec![],
    }
}

pub fn funding_tx_add_wallet_input(
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    wallet_ndx: u32,
    value_sat: u64,
) {
    let ndx = tx_ctx.inputs.len();
    let mut txin = make_test_funding_wallet_input();
    // hack, we collude w/ funding_tx_validate_sig, vout signals which input
    txin.previous_output.vout = ndx as u32;
    tx_ctx.inputs.push(txin);
    tx_ctx.ipaths.push(vec![wallet_ndx]);
    tx_ctx.ivals.push(value_sat);
    tx_ctx.ispnds.push(if is_p2sh { SpendType::P2shP2wpkh } else { SpendType::P2wpkh });
    tx_ctx.iuckeys.push(None);
}

pub fn funding_tx_add_wallet_output(
    node_ctx: &TestNodeContext,
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    wallet_ndx: u32,
    value_sat: u64,
) {
    tx_ctx.outputs.push(make_test_funding_wallet_output(
        &node_ctx.secp_ctx,
        &node_ctx.node,
        wallet_ndx,
        value_sat,
        is_p2sh,
    ));
    tx_ctx.opaths.push(vec![wallet_ndx]);
}

pub fn funding_tx_add_channel_outpoint(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    tx_ctx: &mut TestFundingTxContext,
    value_sat: u64,
) -> u32 {
    let ndx = tx_ctx.outputs.len();
    tx_ctx.outputs.push(make_test_funding_channel_outpoint(
        &node_ctx.node,
        &chan_ctx.setup,
        &chan_ctx.channel_id,
        value_sat,
    ));
    tx_ctx.opaths.push(vec![]);
    ndx as u32
}

pub fn funding_tx_add_unknown_output(
    node_ctx: &TestNodeContext,
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    unknown_ndx: u32,
    value_sat: u64,
) {
    tx_ctx.outputs.push(make_test_funding_wallet_output(
        &node_ctx.secp_ctx,
        &node_ctx.node,
        unknown_ndx + 10_000, // lazy, it's really in the wallet
        value_sat,
        is_p2sh,
    ));
    tx_ctx.opaths.push(vec![]); // this is what makes it unknown
}

pub fn funding_tx_add_allowlist_output(
    node_ctx: &TestNodeContext,
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    unknown_ndx: u32,
    value_sat: u64,
) {
    let wallet_ndx = unknown_ndx + 10_000; // lazy, it's really in the wallet
    tx_ctx.outputs.push(make_test_funding_wallet_output(
        &node_ctx.secp_ctx,
        &node_ctx.node,
        wallet_ndx,
        value_sat,
        is_p2sh,
    ));
    tx_ctx.opaths.push(vec![]); // don't consider wallet
    let child_path = vec![wallet_ndx];
    let pubkey = node_ctx.node.get_wallet_pubkey(&node_ctx.secp_ctx, &child_path).unwrap();
    let addr = Address::p2wpkh(&pubkey, node_ctx.node.network()).unwrap();
    node_ctx.node.add_allowlist(&vec![addr.to_string()]).expect("add_allowlist");
}

pub fn funding_tx_from_ctx(tx_ctx: &TestFundingTxContext) -> bitcoin::Transaction {
    make_test_funding_tx_with_ins_outs(tx_ctx.inputs.clone(), tx_ctx.outputs.clone())
}

pub fn funding_tx_ready_channel(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    tx: &bitcoin::Transaction,
    vout: u32,
) -> Option<Status> {
    let txid = tx.txid();
    chan_ctx.setup.funding_outpoint = BitcoinOutPoint { txid, vout };
    let holder_shutdown_key_path = vec![];
    node_ctx
        .node
        .ready_channel(
            chan_ctx.channel_id.clone(),
            None,
            chan_ctx.setup.clone(),
            &holder_shutdown_key_path,
        )
        .err()
}

pub fn synthesize_ready_channel(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    outpoint: BitcoinOutPoint,
    next_holder_commit_num: u64,
) {
    chan_ctx.setup.funding_outpoint = outpoint;
    let holder_shutdown_key_path = vec![];
    node_ctx
        .node
        .ready_channel(
            chan_ctx.channel_id.clone(),
            None,
            chan_ctx.setup.clone(),
            &holder_shutdown_key_path,
        )
        .expect("Channel");
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state.set_next_holder_commit_num_for_testing(next_holder_commit_num);
            Ok(())
        })
        .expect("synthesized channel");
}

pub fn funding_tx_sign(
    node_ctx: &TestNodeContext,
    tx_ctx: &TestFundingTxContext,
    tx: &bitcoin::Transaction,
) -> Result<Vec<Vec<Vec<u8>>>, Status> {
    node_ctx.node.sign_onchain_tx(
        &tx,
        &tx_ctx.ipaths,
        &tx_ctx.ivals,
        &tx_ctx.ispnds,
        tx_ctx.iuckeys.clone(),
        &tx_ctx.opaths,
    )
}

pub fn funding_tx_validate_sig(
    node_ctx: &TestNodeContext,
    tx_ctx: &TestFundingTxContext,
    tx: &mut bitcoin::Transaction,
    witvec: &Vec<Vec<Vec<u8>>>,
) {
    for ndx in 0..tx.input.len() {
        tx.input[ndx].witness = Witness::from_vec(witvec[ndx].clone())
    }
    let verify_result = tx.verify(|outpoint| {
        // hack, we collude w/ funding_tx_add_wallet_input
        let input_ndx = outpoint.vout as usize;
        let txout = TxOut {
            value: tx_ctx.ivals[input_ndx],
            script_pubkey: make_test_funding_wallet_addr(
                &node_ctx.secp_ctx,
                &node_ctx.node,
                tx_ctx.ipaths[input_ndx][0],
                false,
            )
            .script_pubkey(),
        };
        Some(txout)
    });
    assert!(verify_result.is_ok());
}

pub fn fund_test_channel(node_ctx: &TestNodeContext, channel_amount: u64) -> TestChannelContext {
    let is_p2sh = false;
    let incoming = channel_amount + 2_000_000;
    let fee = 1000;
    let change = incoming - channel_amount - fee;

    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
    let mut tx_ctx = test_funding_tx_ctx();

    funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
    funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
    let outpoint_ndx =
        funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

    let mut tx = funding_tx_from_ctx(&tx_ctx);

    funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

    let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
    let (csig, hsigs) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
    validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
        .expect("valid holder commitment");

    let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
    funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);

    chan_ctx
}

pub fn channel_initial_holder_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
) -> TestCommitmentTxContext {
    let fee = 1000;
    let commit_num = 0;
    let feerate_per_kw = 0;
    let to_broadcaster = chan_ctx.setup.channel_value_sat - fee;
    let to_countersignatory = 0;
    let offered_htlcs = vec![];
    let received_htlcs = vec![];
    channel_commitment(
        node_ctx,
        chan_ctx,
        commit_num,
        feerate_per_kw,
        to_broadcaster,
        to_countersignatory,
        offered_htlcs,
        received_htlcs,
    )
}

pub fn channel_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
    feerate_per_kw: u32,
    to_broadcaster: u64,
    to_countersignatory: u64,
    offered_htlcs: Vec<HTLCInfo2>,
    received_htlcs: Vec<HTLCInfo2>,
) -> TestCommitmentTxContext {
    let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            let per_commitment_point = chan.get_per_commitment_point(commit_num)?;
            let txkeys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

            let tx = chan
                .make_holder_commitment_tx(
                    commit_num,
                    &txkeys,
                    feerate_per_kw,
                    to_broadcaster,
                    to_countersignatory,
                    htlcs.clone(),
                )
                .expect("holder_commitment_tx");
            Ok(TestCommitmentTxContext {
                commit_num,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                offered_htlcs: offered_htlcs.clone(),
                received_htlcs: received_htlcs.clone(),
                tx: Some(tx),
            })
        })
        .expect("TestCommitmentTxContext")
}

// Setup node and channel state.
pub fn setup_funded_channel(
    next_holder_commit_num: u64,
    next_counterparty_commit_num: u64,
    next_counterparty_revoke_num: u64,
) -> (TestNodeContext, TestChannelContext) {
    let setup = make_test_channel_setup();
    setup_funded_channel_with_setup(
        setup,
        next_holder_commit_num,
        next_counterparty_commit_num,
        next_counterparty_revoke_num,
    )
}

// Setup node and channel state with specified setup.
pub fn setup_funded_channel_with_setup(
    setup: ChannelSetup,
    next_holder_commit_num: u64,
    next_counterparty_commit_num: u64,
    next_counterparty_revoke_num: u64,
) -> (TestNodeContext, TestChannelContext) {
    let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

    let secp_ctx = Secp256k1::signing_only();
    let node_ctx = TestNodeContext { node, secp_ctx };
    let channel_value_sat = setup.channel_value_sat;
    let counterparty_keys = make_test_counterparty_keys(&node_ctx, &channel_id, channel_value_sat);
    let mut chan_ctx = TestChannelContext { channel_id, setup, counterparty_keys };

    // Pretend we funded the channel and ran for a while ...
    chan_ctx.setup.funding_outpoint =
        bitcoin::OutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 };
    node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            let point = make_test_pubkey((next_counterparty_commit_num + 1) as u8);
            chan.enforcement_state.set_next_holder_commit_num_for_testing(next_holder_commit_num);
            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(next_counterparty_commit_num, point);
            chan.enforcement_state
                .set_next_counterparty_revoke_num_for_testing(next_counterparty_revoke_num);
            Ok(())
        })
        .expect("ready happy");

    (node_ctx, chan_ctx)
}

// Construct counterparty signatures for a holder commitment.
// Mimics InMemorySigner::sign_counterparty_commitment w/ transposition.
pub fn counterparty_sign_holder_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &mut TestCommitmentTxContext,
) -> (Signature, Vec<Signature>) {
    let (commitment_sig, htlc_sigs) = node_ctx
        .node
        .with_ready_channel(&chan_ctx.channel_id, |chan| {
            let funding_redeemscript = make_funding_redeemscript(
                &chan.keys.pubkeys().funding_pubkey,
                &chan.keys.counterparty_pubkeys().funding_pubkey,
            );
            let tx = commit_tx_ctx.tx.as_ref().unwrap();
            let trusted_tx = tx.trust();
            let keys = trusted_tx.keys();
            let built_tx = trusted_tx.built_transaction();
            let commitment_sig = built_tx.sign(
                &chan_ctx.counterparty_keys.funding_key,
                &funding_redeemscript,
                chan_ctx.setup.channel_value_sat,
                &node_ctx.secp_ctx,
            );
            let per_commitment_point = chan
                .get_per_commitment_point(commit_tx_ctx.commit_num)
                .expect("per_commitment_point");
            let txkeys = chan.make_holder_tx_keys(&per_commitment_point).expect("txkeys");
            let commitment_txid = built_tx.txid;

            let counterparty_htlc_key = derive_private_key(
                &node_ctx.secp_ctx,
                &per_commitment_point,
                &chan_ctx.counterparty_keys.htlc_base_key,
            )
            .expect("counterparty_htlc_key");

            let build_feerate =
                if chan_ctx.setup.option_anchors_zero_fee_htlc() { 0 } else { tx.feerate_per_kw() };

            let mut htlc_sigs = Vec::with_capacity(tx.htlcs().len());
            for htlc in tx.htlcs() {
                let htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    chan_ctx.setup.counterparty_selected_contest_delay,
                    htlc,
                    chan_ctx.setup.option_anchors(),
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                );
                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, chan_ctx.setup.option_anchors(), &keys);
                let sig_hash_type = if chan_ctx.setup.option_anchors() {
                    EcdsaSighashType::SinglePlusAnyoneCanPay
                } else {
                    EcdsaSighashType::All
                };
                let htlc_sighash = Message::from_slice(
                    &SighashCache::new(&htlc_tx)
                        .segwit_signature_hash(
                            0,
                            &htlc_redeemscript,
                            htlc.amount_msat / 1000,
                            sig_hash_type,
                        )
                        .unwrap()[..],
                )
                .unwrap();
                htlc_sigs.push(node_ctx.secp_ctx.sign_ecdsa(&htlc_sighash, &counterparty_htlc_key));
            }
            Ok((commitment_sig, htlc_sigs))
        })
        .unwrap();
    (commitment_sig, htlc_sigs)
}

pub fn validate_holder_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &TestCommitmentTxContext,
    commit_sig: &Signature,
    htlc_sigs: &Vec<Signature>,
) -> Result<(PublicKey, Option<SecretKey>), Status> {
    let htlcs = Channel::htlcs_info2_to_oic(
        commit_tx_ctx.offered_htlcs.clone(),
        commit_tx_ctx.received_htlcs.clone(),
    );
    node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
        let channel_parameters = chan.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();

        // NOTE - the unit tests calling this method may be
        // setting up a commitment with a bogus
        // commitment_number on purpose.  To allow this we
        // need to temporarily set the channel's
        // next_holder_commit_num while fetching the
        // commitment_point and then restore it.
        let save_commit_num = chan.enforcement_state.next_holder_commit_num;
        chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_tx_ctx.commit_num);
        let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
        chan.enforcement_state.set_next_holder_commit_num_for_testing(save_commit_num);

        let keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

        let redeem_scripts = build_tx_scripts(
            &keys,
            commit_tx_ctx.to_broadcaster,
            commit_tx_ctx.to_countersignatory,
            &htlcs,
            &parameters,
            &chan.keys.pubkeys().funding_pubkey,
            &chan.setup.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

        chan.validate_holder_commitment_tx(
            &commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
            &output_witscripts,
            commit_tx_ctx.commit_num,
            commit_tx_ctx.feerate_per_kw,
            commit_tx_ctx.offered_htlcs.clone(),
            commit_tx_ctx.received_htlcs.clone(),
            &commit_sig,
            &htlc_sigs,
        )
    })
}

pub fn sign_holder_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &TestCommitmentTxContext,
) -> Result<(Signature, Vec<Signature>), Status> {
    node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
        chan.sign_holder_commitment_tx_phase2(commit_tx_ctx.commit_num)
    })
}

// Try and use the funding tx helpers before this comment, the following are compat.

pub fn make_test_funding_tx_with_change(
    inputs: Vec<TxIn>,
    value: u64,
    opath: Vec<u32>,
    change_addr: &Address,
) -> (Vec<u32>, bitcoin::Transaction) {
    let outputs = vec![TxOut { value, script_pubkey: change_addr.script_pubkey() }];
    let tx = make_test_funding_tx_with_ins_outs(inputs, outputs);
    (opath, tx)
}

pub fn make_test_funding_tx(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    node: &Node,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, bitcoin::Transaction) {
    let opath = vec![0];
    let change_addr =
        Address::p2wpkh(&node.get_wallet_pubkey(&secp_ctx, &opath).unwrap(), Network::Testnet)
            .unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_funding_tx_with_p2shwpkh_change(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    node: &Node,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, bitcoin::Transaction) {
    let opath = vec![0];
    let change_addr =
        Address::p2shwpkh(&node.get_wallet_pubkey(&secp_ctx, &opath).unwrap(), Network::Testnet)
            .unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_commitment_tx() -> bitcoin::Transaction {
    let input = TxIn {
        previous_output: BitcoinOutPoint { txid: Txid::all_zeros(), vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };
    bitcoin::Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            script_pubkey: payload_for_p2wpkh(&make_test_bitcoin_pubkey(1).inner).script_pubkey(),
            value: 300,
        }],
    }
}

pub fn make_test_commitment_info() -> CommitmentInfo2 {
    CommitmentInfo2::new(
        true,
        make_test_pubkey(0x20),
        3_000_000,
        make_test_pubkey(0x21),
        make_test_pubkey(0x22),
        2_000_000,
        10,
        vec![],
        vec![],
        7500,
    )
}

pub const TEST_NODE_CONFIG: NodeConfig =
    NodeConfig { network: Network::Testnet, key_derivation_style: KeyDerivationStyle::Native };

pub const REGTEST_NODE_CONFIG: NodeConfig =
    NodeConfig { network: Network::Regtest, key_derivation_style: KeyDerivationStyle::Native };

pub const TEST_SEED: &[&str] = &[
    "6c696768746e696e672d31000000000000000000000000000000000000000000",
    "6c696768746e696e672d32000000000000000000000000000000000000000000",
];

pub const TEST_CHANNEL_ID: &[&str] = &[
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0200000000000000000000000000000000000000000000000000000000000000",
];

pub fn build_tx_scripts(
    keys: &TxCreationKeys,
    to_broadcaster_value_sat: u64,
    to_countersignatory_value_sat: u64,
    htlcs: &Vec<HTLCOutputInCommitment>,
    channel_parameters: &DirectedChannelTransactionParameters,
    broadcaster_funding_key: &PublicKey,
    countersignatory_funding_key: &PublicKey,
) -> Result<Vec<Script>, ()> {
    let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
    let contest_delay = channel_parameters.contest_delay();

    let mut txouts: Vec<(TxOut, (Option<HTLCOutputInCommitment>, Script))> = Vec::new();

    if to_countersignatory_value_sat > 0 {
        let (redeem_script, script_pubkey) = if channel_parameters.opt_anchors() {
            let script = get_to_countersignatory_with_anchors_redeemscript(
                &countersignatory_pubkeys.payment_point,
            );
            (script.clone(), script.to_v0_p2wsh())
        } else {
            (Script::new(), get_p2wpkh_redeemscript(&countersignatory_pubkeys.payment_point))
        };
        txouts.push((
            TxOut { script_pubkey, value: to_countersignatory_value_sat },
            (None, redeem_script),
        ))
    }

    if to_broadcaster_value_sat > 0 {
        let redeem_script = get_revokeable_redeemscript(
            &keys.revocation_key,
            contest_delay,
            &keys.broadcaster_delayed_payment_key,
        );
        txouts.push((
            TxOut { script_pubkey: redeem_script.to_v0_p2wsh(), value: to_broadcaster_value_sat },
            (None, redeem_script),
        ));
    }

    if channel_parameters.opt_anchors() {
        if to_broadcaster_value_sat > 0 || !htlcs.is_empty() {
            let anchor_script = get_anchor_redeemscript(broadcaster_funding_key);
            txouts.push((
                TxOut {
                    script_pubkey: anchor_script.to_v0_p2wsh(),
                    value: ANCHOR_OUTPUT_VALUE_SATOSHI,
                },
                (None, anchor_script),
            ));
        }

        if to_countersignatory_value_sat > 0 || !htlcs.is_empty() {
            let anchor_script = get_anchor_redeemscript(countersignatory_funding_key);
            txouts.push((
                TxOut {
                    script_pubkey: anchor_script.to_v0_p2wsh(),
                    value: ANCHOR_OUTPUT_VALUE_SATOSHI,
                },
                (None, anchor_script),
            ));
        }
    }

    for htlc in htlcs {
        let script = get_htlc_redeemscript(&htlc, channel_parameters.opt_anchors(), &keys);
        let txout = TxOut { script_pubkey: script.to_v0_p2wsh(), value: htlc.amount_msat / 1000 };
        txouts.push((txout, (Some(htlc.clone()), script)));
    }

    // Sort output in BIP-69 order (amount, scriptPubkey).  Tie-breaks based on HTLC
    // CLTV expiration height.
    sort_outputs(&mut txouts, |a, b| {
        if let &(Some(ref a_htlcout), _) = a {
            if let &(Some(ref b_htlcout), _) = b {
                a_htlcout
                    .cltv_expiry
                    .cmp(&b_htlcout.cltv_expiry)
                    // Note that due to hash collisions, we have to have a fallback comparison
                    // here for fuzztarget mode (otherwise at least chanmon_fail_consistency
                    // may fail)!
                    .then(a_htlcout.payment_hash.0.cmp(&b_htlcout.payment_hash.0))
            // For non-HTLC outputs, if they're copying our SPK we don't really care if we
            // close the channel due to mismatches - they're doing something dumb:
            } else {
                cmp::Ordering::Equal
            }
        } else {
            cmp::Ordering::Equal
        }
    });

    let mut scripts = Vec::with_capacity(txouts.len());
    for (_, (_, script)) in txouts.drain(..) {
        scripts.push(script);
    }
    Ok(scripts)
}

pub fn get_channel_funding_pubkey(node: &Node, channel_id: &ChannelId) -> PublicKey {
    let res: Result<PublicKey, Status> =
        node.with_ready_channel(&channel_id, |chan| Ok(chan.keys.pubkeys().funding_pubkey));
    res.unwrap()
}

pub fn get_channel_htlc_pubkey(
    node: &Node,
    channel_id: &ChannelId,
    remote_per_commitment_point: &PublicKey,
) -> PublicKey {
    let res: Result<PublicKey, Status> = node.with_ready_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = derive_public_key(
            &secp_ctx,
            &remote_per_commitment_point,
            &chan.keys.pubkeys().htlc_basepoint,
        )
        .unwrap();
        Ok(pubkey)
    });
    res.unwrap()
}

pub fn get_channel_delayed_payment_pubkey(
    node: &Node,
    channel_id: &ChannelId,
    remote_per_commitment_point: &PublicKey,
) -> PublicKey {
    let res: Result<PublicKey, Status> = node.with_ready_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = derive_public_key(
            &secp_ctx,
            &remote_per_commitment_point,
            &chan.keys.pubkeys().delayed_payment_basepoint,
        )
        .unwrap();
        Ok(pubkey)
    });
    res.unwrap()
}

pub fn get_channel_revocation_pubkey(
    node: &Node,
    channel_id: &ChannelId,
    revocation_point: &PublicKey,
) -> PublicKey {
    let res: Result<PublicKey, Status> = node.with_ready_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = chan_utils::derive_public_revocation_key(
            secp_ctx,
            revocation_point, // matches revocation_secret
            &chan.keys.pubkeys().revocation_basepoint,
        )
        .unwrap();
        Ok(pubkey)
    });
    res.unwrap()
}

pub fn check_signature(
    tx: &bitcoin::Transaction,
    input: usize,
    signature: TypedSignature,
    pubkey: &PublicKey,
    input_value_sat: u64,
    redeemscript: &Script,
) {
    check_signature_with_sighash_type(
        tx,
        input,
        signature,
        pubkey,
        input_value_sat,
        redeemscript,
        EcdsaSighashType::All,
    );
}

pub fn check_counterparty_htlc_signature(
    tx: &bitcoin::Transaction,
    input: usize,
    signature: TypedSignature,
    pubkey: &PublicKey,
    input_value_sat: u64,
    redeemscript: &Script,
    opt_anchors: bool,
) {
    let sighash_type =
        if opt_anchors { EcdsaSighashType::SinglePlusAnyoneCanPay } else { EcdsaSighashType::All };
    check_signature_with_sighash_type(
        tx,
        input,
        signature,
        pubkey,
        input_value_sat,
        redeemscript,
        sighash_type,
    );
}

pub fn check_signature_with_sighash_type(
    tx: &bitcoin::Transaction,
    input: usize,
    signature: TypedSignature,
    pubkey: &PublicKey,
    input_value_sat: u64,
    redeemscript: &Script,
    sighash_type: EcdsaSighashType,
) {
    let sighash = Message::from_slice(
        &SighashCache::new(tx)
            .segwit_signature_hash(input, &redeemscript, input_value_sat, sighash_type)
            .unwrap()[..],
    )
    .expect("sighash");
    assert_eq!(signature.typ, sighash_type);
    let secp_ctx = Secp256k1::new();
    secp_ctx.verify_ecdsa(&sighash, &signature.sig, &pubkey).expect("verify");
}

pub fn sign_commitment_tx_with_mutators_setup(
    commitment_type: CommitmentType,
) -> (Arc<Node>, ChannelSetup, ChannelId, Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
    let mut setup = make_test_channel_setup();
    setup.commitment_type = commitment_type;
    let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

    let htlc1 =
        HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

    let htlc2 =
        HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

    let htlc3 =
        HTLCInfo2 { value_sat: 10_003, payment_hash: PaymentHash([5; 32]), cltv_expiry: 4 << 16 };
    let offered_htlcs = vec![htlc1];
    let received_htlcs = vec![htlc2, htlc3];
    (node, setup, channel_id, offered_htlcs, received_htlcs)
}

pub fn setup_validated_holder_commitment<TxBuilderMutator, KeysMutator>(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
    mutate_tx_builder: TxBuilderMutator,
    mutate_keys: KeysMutator,
) -> Result<TestCommitmentTxContext, Status>
where
    TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
    KeysMutator: Fn(&mut TxCreationKeys),
{
    let to_broadcaster = 1_979_997;
    let to_countersignatory = 1_000_000;
    let feerate_per_kw = 1200;
    let htlc1 =
        HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

    let htlc2 =
        HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

    let htlc3 =
        HTLCInfo2 { value_sat: 10_003, payment_hash: PaymentHash([5; 32]), cltv_expiry: 4 << 16 };
    let offered_htlcs = vec![htlc1];
    let received_htlcs = vec![htlc2, htlc3];

    let mut commit_tx_ctx0 = TestCommitmentTxContext {
        commit_num: commit_num,
        feerate_per_kw,
        to_broadcaster,
        to_countersignatory,
        offered_htlcs: offered_htlcs.clone(),
        received_htlcs: received_htlcs.clone(),
        tx: None,
    };

    mutate_tx_builder(&mut commit_tx_ctx0);

    commit_tx_ctx0 = channel_commitment(
        &node_ctx,
        &chan_ctx,
        commit_tx_ctx0.commit_num,
        commit_tx_ctx0.feerate_per_kw,
        commit_tx_ctx0.to_broadcaster,
        commit_tx_ctx0.to_countersignatory,
        commit_tx_ctx0.offered_htlcs.clone(),
        commit_tx_ctx0.received_htlcs.clone(),
    );

    let (commit_sig0, htlc_sigs0) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx0);

    node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
        let commit_tx_ctx = commit_tx_ctx0.clone();
        let commit_sig = commit_sig0.clone();
        let htlc_sigs = htlc_sigs0.clone();

        let channel_parameters = chan.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();
        let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;

        let mut keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

        mutate_keys(&mut keys);

        let htlcs = Channel::htlcs_info2_to_oic(
            commit_tx_ctx.offered_htlcs.clone(),
            commit_tx_ctx.received_htlcs.clone(),
        );
        let redeem_scripts = build_tx_scripts(
            &keys,
            commit_tx_ctx.to_broadcaster,
            commit_tx_ctx.to_countersignatory,
            &htlcs,
            &parameters,
            &chan.keys.pubkeys().funding_pubkey,
            &chan.setup.counterparty_points.funding_pubkey,
        )
        .expect("scripts");
        let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

        let tx = commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction.clone();

        chan.validate_holder_commitment_tx(
            &tx,
            &output_witscripts,
            commit_tx_ctx.commit_num,
            commit_tx_ctx.feerate_per_kw,
            commit_tx_ctx.offered_htlcs.clone(),
            commit_tx_ctx.received_htlcs.clone(),
            &commit_sig,
            &htlc_sigs,
        )?;

        Ok(commit_tx_ctx)
    })
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, hex::Error> {
    Vec::from_hex(s)
}

pub fn hex_encode(o: &[u8]) -> String {
    o.to_hex()
}

pub fn make_tx(inputs: Vec<TxIn>) -> Transaction {
    Transaction {
        version: 0,
        lock_time: PackedLockTime::ZERO,
        input: inputs,
        output: vec![Default::default()],
    }
}

pub fn make_txin(vout: u32) -> TxIn {
    TxIn {
        previous_output: make_outpoint(vout),
        script_sig: Default::default(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    }
}

pub fn make_outpoint(vout: u32) -> BitcoinOutPoint {
    BitcoinOutPoint { txid: Txid::all_zeros(), vout }
}

pub fn make_header(tip: BlockHeader, merkle_root: TxMerkleNode) -> BlockHeader {
    let bits = tip.bits;
    mine_header_with_bits(tip.block_hash(), merkle_root, bits)
}

pub fn make_block(tip: BlockHeader, txs: Vec<Transaction>) -> Block {
    assert!(!txs.is_empty());
    let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
    let merkle_root = bitcoin_merkle_root(txids.iter().map(Txid::as_hash)).unwrap().into();
    let header = make_header(tip, merkle_root);
    Block { header, txdata: txs }
}

pub fn proof_for_block(block: &Block) -> Option<PartialMerkleTree> {
    if block.txdata.is_empty() {
        return None;
    }
    let txids: Vec<Txid> = block.txdata.iter().map(|tx| tx.txid()).collect();
    let matches: Vec<bool> = txids.iter().map(|_| true).collect();
    Some(PartialMerkleTree::from_txids(&txids, &matches))
}

pub fn make_testnet_header(tip: BlockHeader, merkle_root: TxMerkleNode) -> BlockHeader {
    // use lower bits so it doesn't take forever
    let regtest_genesis = genesis_block(Network::Regtest);
    let bits = regtest_genesis.header.bits;
    mine_header_with_bits(tip.block_hash(), merkle_root, bits)
}

pub fn mine_header_with_bits(
    prev_hash: BlockHash,
    merkle_root: TxMerkleNode,
    bits: u32,
) -> BlockHeader {
    let mut nonce = 0;
    loop {
        let header = BlockHeader {
            version: 0,
            prev_blockhash: prev_hash,
            merkle_root,
            time: 0,
            bits,
            nonce,
        };
        if header.validate_pow(&header.target()).is_ok() {
            // println!("mined block with nonce {}", nonce);
            return header;
        }
        nonce += 1;
    }
}

pub fn make_node_and_channel(
    channel_id: ChannelId,
) -> (PublicKey, Arc<Node>, ChannelStub, [u8; 32]) {
    let (node_id, node, seed) = make_node();

    let (_, channel) = node.new_channel(Some(channel_id), &Arc::clone(&node)).unwrap();
    (node_id, node, channel.unwrap(), seed)
}

pub(crate) fn make_node() -> (PublicKey, Arc<Node>, [u8; 32]) {
    let mut seed = [0; 32];
    seed.copy_from_slice(hex_decode(TEST_SEED[1]).unwrap().as_slice());

    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(TEST_NODE_CONFIG.network);
    let clock = Arc::new(StandardClock());

    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };

    let node = Arc::new(Node::new(TEST_NODE_CONFIG, &seed, vec![], services));
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
