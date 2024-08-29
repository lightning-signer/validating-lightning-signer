pub mod invoice;
pub mod key;

use std::time::{Duration, SystemTime};

use core::cmp;

use bitcoin::absolute::LockTime;
use bitcoin::block::Version;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::{hex, hex::FromHex, Hash};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{self, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::sighash::SighashCache;
use bitcoin::{self, merkle_tree, CompactTarget, ScriptBuf};
use bitcoin::{Address, Block, BlockHash, Sequence, Transaction, TxIn, TxOut, Witness};
use chain::chaininterface;
use lightning::chain::chainmonitor::MonitorUpdateId;
use lightning::chain::channelmonitor::MonitorEvent;
use lightning::chain::transaction::OutPoint;
use lightning::chain;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::ln::chan_utils::{
    build_htlc_transaction, derive_private_key, get_anchor_redeemscript, get_htlc_redeemscript,
    get_revokeable_redeemscript, make_funding_redeemscript, ChannelPublicKeys,
    ChannelTransactionParameters, CommitmentTransaction, CounterpartyChannelTransactionParameters,
    DirectedChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::ln::channel_keys::{
    DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint, RevocationKey,
};
use lightning::ln::features::ChannelTypeFeatures;
use lightning::ln::ChannelId as LnChannelId;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::sign::{ChannelSigner, InMemorySigner};
use lightning::util::test_utils;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use push_decoder::Listener;
use txoo::proof::TxoProof;

use crate::chain::tracker::{ChainListener, Headers};
use crate::channel::{
    Channel, ChannelBalance, ChannelBase, ChannelId, ChannelSetup, ChannelStub, CommitmentType,
    TypedSignature,
};
use crate::invoice::Invoice;
use crate::node::{Node, NodeConfig};
use crate::node::{NodeServices, SpendType};
use crate::persist::DummyPersister;
use crate::policy::simple_validator::SimpleValidatorFactory;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::signer::derive::KeyDerivationStyle;
use crate::signer::StartingTimeFactory;
use crate::tx::script::{
    get_p2wpkh_redeemscript, get_to_countersignatory_with_anchors_redeemscript,
    ANCHOR_OUTPUT_VALUE_SATOSHI,
};
use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
use crate::util::clock::StandardClock;
use crate::util::crypto_utils::{derive_public_key, payload_for_p2wpkh, payload_for_p2wsh};
use crate::util::loopback::LoopbackChannelSigner;
use crate::util::status::Status;
use crate::wallet::Wallet;
use crate::{Arc, CommitmentPointProvider};
use key::{
    make_test_bitcoin_pubkey, make_test_counterparty_points, make_test_privkey, make_test_pubkey,
};
use vls_common::HexEncode;

use super::crypto_utils;
use super::status::internal_error;

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
            panic!("unexepected ValidationError: {:#?}", $res.unwrap_err());
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
    pub update_ret: Mutex<chain::ChannelMonitorUpdateStatus>,
}

impl TestPersister {
    pub fn new() -> Self {
        Self { update_ret: Mutex::new(chain::ChannelMonitorUpdateStatus::Completed) }
    }

    pub fn set_update_ret(&self, ret: chain::ChannelMonitorUpdateStatus) {
        *self.update_ret.lock().unwrap() = ret;
    }
}

impl chainmonitor::Persist<LoopbackChannelSigner> for TestPersister {
    fn persist_new_channel(
        &self,
        _funding_txo: OutPoint,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
        _id: MonitorUpdateId,
    ) -> chain::ChannelMonitorUpdateStatus {
        self.update_ret.lock().unwrap().clone()
    }

    fn archive_persisted_channel(&self, _channel_funding_outpoint: OutPoint) {}

    fn update_persisted_channel(
        &self,
        _channel_id: OutPoint,
        _update: Option<&channelmonitor::ChannelMonitorUpdate>,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
        _update_id: MonitorUpdateId,
    ) -> chain::ChannelMonitorUpdateStatus {
        self.update_ret.lock().unwrap().clone()
    }
}

pub struct TestChainMonitor<'a> {
    pub added_monitors: Mutex<Vec<(OutPoint, ())>>,
    pub latest_monitor_update_id: Mutex<Map<[u8; 32], (OutPoint, u64)>>,
    pub chain_monitor: chainmonitor::ChainMonitor<
        LoopbackChannelSigner,
        &'a test_utils::TestChainSource,
        &'a dyn chaininterface::BroadcasterInterface,
        &'a test_utils::TestFeeEstimator,
        Arc<test_utils::TestLogger>,
        &'a dyn chainmonitor::Persist<LoopbackChannelSigner>,
    >,
    pub update_ret: Mutex<Option<chain::ChannelMonitorUpdateStatus>>,
    // If this is set to Some(), after the next return, we'll always return this until update_ret
    // is changed:
    pub next_update_ret: Mutex<Option<chain::ChannelMonitorUpdateStatus>>,
}
impl<'a> TestChainMonitor<'a> {
    pub fn new(
        chain_source: Option<&'a test_utils::TestChainSource>,
        broadcaster: &'a dyn chaininterface::BroadcasterInterface,
        logger: Arc<test_utils::TestLogger>,
        fee_estimator: &'a test_utils::TestFeeEstimator,
        persister: &'a dyn chainmonitor::Persist<LoopbackChannelSigner>,
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
    ) -> Result<chain::ChannelMonitorUpdateStatus, ()> {
        self.latest_monitor_update_id.lock().unwrap().insert(
            LnChannelId::v1_from_funding_outpoint(funding_txo).0,
            (funding_txo, monitor.get_latest_update_id()),
        );
        self.added_monitors.lock().unwrap().push((funding_txo, ()));
        let watch_res = self.chain_monitor.watch_channel(funding_txo, monitor)?;

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret);
        }
        if ret.is_some() {
            assert_eq!(watch_res, chain::ChannelMonitorUpdateStatus::Completed);
            return Ok(ret.unwrap());
        }
        Ok(watch_res)
    }

    fn update_channel(
        &self,
        funding_txo: OutPoint,
        update: &channelmonitor::ChannelMonitorUpdate,
    ) -> chain::ChannelMonitorUpdateStatus {
        self.latest_monitor_update_id.lock().unwrap().insert(
            LnChannelId::v1_from_funding_outpoint(funding_txo).0,
            (funding_txo, update.update_id),
        );
        let update_res = self.chain_monitor.update_channel(funding_txo, update);
        self.added_monitors.lock().unwrap().push((funding_txo, ()));

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret);
        }
        if ret.is_some() {
            assert_eq!(update_res, chain::ChannelMonitorUpdateStatus::Completed);
            return ret.unwrap();
        }
        update_res
    }

    fn release_pending_monitor_events(
        &self,
    ) -> Vec<(OutPoint, LnChannelId, Vec<MonitorEvent>, Option<PublicKey>)> {
        self.chain_monitor.release_pending_monitor_events()
    }
}

pub fn pubkey_from_secret_hex(h: &str, secp_ctx: &Secp256k1<secp256k1::SignOnly>) -> PublicKey {
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
        funding_outpoint: bitcoin::OutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub fn make_test_channel_setup_with_points(
    is_outbound: bool,
    counterparty_points: ChannelPublicKeys,
) -> ChannelSetup {
    ChannelSetup {
        is_outbound,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: bitcoin::OutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points,
        counterparty_selected_contest_delay: 6,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::AnchorsZeroFeeHtlc,
    }
}

pub fn next_state(
    channel: &mut Channel,
    channel1: &mut Channel,
    commit_num: u64,
    to_holder: u64,
    to_counterparty: u64,
    offered: Vec<HTLCInfo2>,
    received: Vec<HTLCInfo2>,
) {
    let per_commitment_point = channel.get_per_commitment_point(commit_num).unwrap();
    let per_commitment_point1 = channel1.get_per_commitment_point(commit_num).unwrap();

    let (sig, htlc_sigs) = channel
        .sign_counterparty_commitment_tx_phase2(
            &per_commitment_point1,
            commit_num,
            0,
            to_holder,
            to_counterparty,
            received.clone(),
            offered.clone(),
        )
        .unwrap();

    let (sig1, htlc_sigs1) = channel1
        .sign_counterparty_commitment_tx_phase2(
            &per_commitment_point,
            commit_num,
            0,
            to_counterparty,
            to_holder,
            offered.clone(),
            received.clone(),
        )
        .unwrap();

    channel
        .validate_holder_commitment_tx_phase2(
            commit_num,
            0,
            to_holder,
            to_counterparty,
            offered.clone(),
            received.clone(),
            &sig1,
            &htlc_sigs1,
        )
        .unwrap();
    channel.revoke_previous_holder_commitment(commit_num).unwrap();

    channel1
        .validate_holder_commitment_tx_phase2(
            commit_num,
            0,
            to_counterparty,
            to_holder,
            received.clone(),
            offered.clone(),
            &sig,
            &htlc_sigs,
        )
        .unwrap();
    channel1.revoke_previous_holder_commitment(commit_num).unwrap();

    if commit_num > 0 {
        let revoke = channel.get_per_commitment_secret(commit_num - 1).unwrap();
        let revoke1 = channel1.get_per_commitment_secret(commit_num - 1).unwrap();
        channel1.validate_counterparty_revocation(commit_num - 1, &revoke).unwrap();
        channel.validate_counterparty_revocation(commit_num - 1, &revoke1).unwrap();
    }
}

pub fn make_test_channel_keys() -> InMemorySigner {
    let secp_ctx = Secp256k1::signing_only();
    let channel_value_sat = 3_000_000;
    let mut inmemkeys = InMemorySigner::new(
        &secp_ctx,
        make_test_privkey(1), // funding_key
        make_test_privkey(2), // revocation_base_key
        make_test_privkey(3), // payment_key
        make_test_privkey(4), // delayed_payment_base_key
        make_test_privkey(5), // htlc_base_key
        [4u8; 32],            // commitment_seed
        channel_value_sat,
        [0u8; 32],
        [0; 32],
    );
    // This needs to match make_test_channel_setup above.
    let mut features = ChannelTypeFeatures::empty();
    features.set_anchors_zero_fee_htlc_tx_optional();
    inmemkeys.provide_channel_parameters(&ChannelTransactionParameters {
        holder_pubkeys: inmemkeys.pubkeys().clone(),
        holder_selected_contest_delay: 5,
        is_outbound_from_holder: true,
        counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
            pubkeys: make_test_counterparty_points(),
            selected_contest_delay: 5,
        }),
        funding_outpoint: Some(OutPoint { txid: Txid::all_zeros(), index: 0 }),
        channel_type_features: features,
    });
    inmemkeys
}

pub fn make_test_invoice(x: u8, amt: u64) -> Invoice {
    let payment_preimage = PaymentPreimage([x; 32]);
    let payment_hash = Sha256Hash::hash(&payment_preimage.0);
    let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
    Invoice::Bolt11(
        InvoiceBuilder::new(Currency::Regtest)
            .description("test".into())
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret([x; 32]))
            .duration_since_epoch(Duration::from_secs(123456789))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(amt)
            .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
            .unwrap(),
    )
}

pub fn make_current_test_invoice(x: u8, amt: u64) -> Invoice {
    let payment_preimage = PaymentPreimage([x; 32]);
    let payment_hash = Sha256Hash::hash(&payment_preimage.0);
    let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
    Invoice::Bolt11(
        InvoiceBuilder::new(Currency::Regtest)
            .description("test".into())
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret([x; 32]))
            .duration_since_epoch(SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap())
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(amt)
            .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
            .unwrap(),
    )
}

/// A starting time factory which uses fixed values for testing
pub struct FixedStartingTimeFactory {
    starting_time_secs: u64,
    starting_time_nanos: u32,
}

impl SendSync for FixedStartingTimeFactory {}

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

    let persister = Arc::new(DummyPersister {});
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(node_config.network);
    let clock = Arc::new(StandardClock());
    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys: vec![],
    };

    let node = Node::new(node_config, &seed, vec![], services);
    Arc::new(node)
}

pub fn init_node_and_channel(
    node_config: NodeConfig,
    seedstr: &str,
    setup: ChannelSetup,
) -> (Arc<Node>, ChannelId) {
    let node = init_node(node_config, seedstr);
    let channel_id = init_channel(setup, node.clone());
    (node, channel_id)
}

pub fn init_channel(setup: ChannelSetup, node: Arc<Node>) -> ChannelId {
    {
        let mut tracker = node.get_tracker();
        for _ in 0..3 {
            let (header, proof) = make_testnet_header(tracker.tip(), tracker.height());
            tracker.add_block(header, proof).unwrap();
        }
    }
    let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
    node.new_channel(Some(channel_id.clone()), &node).expect("new_channel");
    let holder_shutdown_key_path = vec![];
    node.setup_channel(channel_id.clone(), None, setup, &holder_shutdown_key_path)
        .expect("ready channel");
    channel_id
}

pub fn make_test_funding_wallet_addr(node: &Node, i: u32, stype: SpendType) -> Address {
    let child_path = vec![i];
    let pubkey = node.get_wallet_pubkey(&child_path).unwrap();
    match stype {
        SpendType::P2pkh => Address::p2pkh(&pubkey, node.network()),
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node.network()).unwrap(),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node.network()).unwrap(),
        _ => panic!("unexpected SpendType {:?}", stype),
    }
}

// Construct the previous tx so the funding input can pass validation (#224)
pub fn make_test_previous_tx(
    node: &Node,
    values: &Vec<(u32, u64, SpendType)>,
) -> (Transaction, Txid) {
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint { txid: Txid::all_zeros(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        }],
        output: values
            .iter()
            .map(|(wallet_ndx, val, stype)| TxOut {
                value: *val,
                script_pubkey: make_test_funding_wallet_addr(&node, *wallet_ndx, *stype)
                    .script_pubkey(),
            })
            .collect(),
    };
    let txid = tx.txid();
    (tx, txid)
}

pub fn make_test_funding_wallet_input(
    node: &Node,
    stype: SpendType,
    wallet_ndx: u32,
    value: u64,
) -> (Transaction, TxIn) {
    // Have to build the predecessor tx so it's txid is valid ...
    let (previous_tx, txid) = make_test_previous_tx(node, &vec![(wallet_ndx, value, stype)]);
    (
        previous_tx,
        TxIn {
            previous_output: bitcoin::OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        },
    )
}

pub fn make_test_funding_wallet_output(node: &Node, i: u32, value: u64, stype: SpendType) -> TxOut {
    let child_path = vec![i];
    let pubkey = node.get_wallet_pubkey(&child_path).unwrap();

    // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
    let addr = match stype {
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node.network()).unwrap(),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node.network()).unwrap(),
        _ => panic!("unexpected SpendType {:?}", stype),
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
    Transaction { version: 2, lock_time: LockTime::ZERO, input: inputs, output: outputs }
}

pub fn make_test_wallet_dest(
    node_ctx: &TestNodeContext,
    wallet_index: u32,
    stype: SpendType,
) -> (ScriptBuf, Vec<u32>) {
    let child_path = vec![wallet_index];
    let pubkey = node_ctx.node.get_wallet_pubkey(&child_path).unwrap();

    let script_pubkey = match stype {
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node_ctx.node.network()),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node_ctx.node.network()),
        _ => panic!("unexpected SpendType {:?}", stype),
    }
    .unwrap()
    .script_pubkey();

    (script_pubkey, vec![wallet_index])
}

pub fn make_test_nonwallet_dest(
    node_ctx: &TestNodeContext,
    index: u8,
    stype: SpendType,
) -> (ScriptBuf, Vec<u32>) {
    let pubkey = make_test_bitcoin_pubkey(index);
    let script_pubkey = match stype {
        SpendType::P2wpkh => Address::p2wpkh(&pubkey, node_ctx.node.network()),
        SpendType::P2shP2wpkh => Address::p2shwpkh(&pubkey, node_ctx.node.network()),
        _ => panic!("unexpected SpendType {:?}", stype),
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
    pub prev_outs: Vec<TxOut>,
    pub ispnds: Vec<SpendType>,
    pub iuckeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
    pub outputs: Vec<TxOut>,
    pub opaths: Vec<Vec<u32>>,
    pub input_txs: Vec<Transaction>,
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
                make_test_privkey(104), // funding_key
                make_test_privkey(100), // revocation_base_key
                make_test_privkey(101), // payment_key
                make_test_privkey(102), // delayed_payment_base_key
                make_test_privkey(103), // htlc_base_key
                [3u8; 32],              // commitment_seed
                value_sat,              // channel_value
                [0u8; 32],              // Key derivation parameters
                [0; 32],
            );

            let mut features = ChannelTypeFeatures::empty();
            features.set_anchors_zero_fee_htlc_tx_optional();

            // This needs to match make_test_channel_setup above.
            cpkeys.provide_channel_parameters(&ChannelTransactionParameters {
                holder_pubkeys: cpkeys.pubkeys().clone(),
                holder_selected_contest_delay: 7,
                is_outbound_from_holder: false,
                counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                    pubkeys: stub.get_channel_basepoints(),
                    selected_contest_delay: 6,
                }),
                funding_outpoint: Some(OutPoint { txid: Txid::all_zeros(), index: 0 }),
                channel_type_features: features,
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
        funding_outpoint: bitcoin::OutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
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
        .with_channel(&chan_ctx.channel_id, |chan| {
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
        .with_channel(&chan_ctx.channel_id, |chan| {
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
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(revoke_num);
            Ok(())
        })
        .unwrap();
}

impl TestFundingTxContext {
    pub fn new() -> Self {
        TestFundingTxContext {
            inputs: vec![],
            ipaths: vec![],
            prev_outs: vec![],
            ispnds: vec![],
            iuckeys: vec![],
            outputs: vec![],
            opaths: vec![],
            input_txs: vec![],
        }
    }

    pub fn add_wallet_input(
        &mut self,
        node_ctx: &TestNodeContext,
        spendtype: SpendType,
        wallet_ndx: u32,
        value_sat: u64,
    ) {
        let (input_tx, txin) =
            make_test_funding_wallet_input(&node_ctx.node, spendtype, wallet_ndx, value_sat);
        self.inputs.push(txin);
        self.ipaths.push(vec![wallet_ndx]);
        self.prev_outs.push(input_tx.output[0].clone());
        self.ispnds.push(spendtype);
        self.iuckeys.push(None);
        self.input_txs.push(input_tx);
    }

    pub fn add_wallet_output(
        &mut self,
        node_ctx: &TestNodeContext,
        spendtype: SpendType,
        wallet_ndx: u32,
        value_sat: u64,
    ) {
        self.outputs.push(make_test_funding_wallet_output(
            &node_ctx.node,
            wallet_ndx,
            value_sat,
            spendtype,
        ));
        self.opaths.push(vec![wallet_ndx]);
    }

    pub fn add_channel_outpoint(
        &mut self,
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        value_sat: u64,
    ) -> u32 {
        let ndx = self.outputs.len();
        self.outputs.push(make_test_funding_channel_outpoint(
            &node_ctx.node,
            &chan_ctx.setup,
            &chan_ctx.channel_id,
            value_sat,
        ));
        self.opaths.push(vec![]);
        ndx as u32
    }

    pub fn add_unknown_output(
        &mut self,
        node_ctx: &TestNodeContext,
        spendtype: SpendType,
        unknown_ndx: u32,
        value_sat: u64,
    ) {
        self.outputs.push(make_test_funding_wallet_output(
            &node_ctx.node,
            unknown_ndx + 10_000, // lazy, it's really in the wallet
            value_sat,
            spendtype,
        ));
        self.opaths.push(vec![]); // this is what makes it unknown
    }

    pub fn add_allowlist_output(
        &mut self,
        node_ctx: &TestNodeContext,
        stype: SpendType,
        unknown_ndx: u32,
        value_sat: u64,
    ) {
        let wallet_ndx = unknown_ndx + 10_000; // lazy, it's really in the wallet
        self.outputs.push(make_test_funding_wallet_output(
            &node_ctx.node,
            wallet_ndx,
            value_sat,
            stype,
        ));
        self.opaths.push(vec![]); // don't consider wallet
        let child_path = vec![wallet_ndx];
        let pubkey = node_ctx.node.get_wallet_pubkey(&child_path).unwrap();
        let addr = Address::p2wpkh(&pubkey, node_ctx.node.network()).unwrap();
        node_ctx.node.add_allowlist(&vec![addr.to_string()]).expect("add_allowlist");
    }

    pub fn to_tx(&self) -> Transaction {
        make_test_funding_tx_with_ins_outs(self.inputs.clone(), self.outputs.clone())
    }

    pub fn sign(
        &self,
        node_ctx: &TestNodeContext,
        tx: &Transaction,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        let segwit_flags = tx.input.iter().map(|_| true).collect::<Vec<_>>();
        node_ctx.node.check_and_sign_onchain_tx(
            &tx,
            segwit_flags.as_slice(),
            &self.ipaths,
            &self.prev_outs,
            self.iuckeys.clone(),
            &self.opaths,
        )
    }

    pub fn sign_non_segwit_input(
        &self,
        node_ctx: &TestNodeContext,
        tx: &Transaction,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        let segwit_flags = tx.input.iter().map(|_| false).collect::<Vec<_>>();
        node_ctx.node.check_and_sign_onchain_tx(
            &tx,
            segwit_flags.as_slice(),
            &self.ipaths,
            &self.prev_outs,
            self.iuckeys.clone(),
            &self.opaths,
        )
    }

    pub fn validate_sig(
        &mut self,
        _node_ctx: &TestNodeContext,
        tx: &mut Transaction,
        witvec: &[Vec<Vec<u8>>],
    ) {
        // Index the input_txs by their txid
        let in_tx_map: OrderedMap<_, _> =
            self.input_txs.iter().map(|in_tx| (in_tx.txid(), in_tx)).collect();

        for ndx in 0..tx.input.len() {
            tx.input[ndx].witness = Witness::from_slice(&witvec[ndx])
        }

        let verify_result = tx.verify(|outpoint| {
            let in_tx = in_tx_map.get(&outpoint.txid).unwrap();
            let txout = in_tx.output.get(outpoint.vout as usize).unwrap().clone();
            Some(txout)
        });
        assert!(verify_result.is_ok());
    }
}

pub fn funding_tx_setup_channel(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    tx: &Transaction,
    vout: u32,
) -> Option<Status> {
    let txid = tx.txid();
    chan_ctx.setup.funding_outpoint = bitcoin::OutPoint { txid, vout };
    let holder_shutdown_key_path = vec![];
    node_ctx
        .node
        .setup_channel(
            chan_ctx.channel_id.clone(),
            None,
            chan_ctx.setup.clone(),
            &holder_shutdown_key_path,
        )
        .err()
}

pub fn synthesize_setup_channel(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    outpoint: bitcoin::OutPoint,
    next_holder_commit_num: u64,
) {
    chan_ctx.setup.funding_outpoint = outpoint;
    let holder_shutdown_key_path = vec![];
    node_ctx
        .node
        .setup_channel(
            chan_ctx.channel_id.clone(),
            None,
            chan_ctx.setup.clone(),
            &holder_shutdown_key_path,
        )
        .expect("Channel");
    node_ctx
        .node
        .with_channel(&chan_ctx.channel_id, |chan| {
            chan.enforcement_state.set_next_holder_commit_num_for_testing(next_holder_commit_num);
            Ok(())
        })
        .expect("synthesized channel");
}

pub fn fund_test_channel(node_ctx: &TestNodeContext, channel_amount: u64) -> TestChannelContext {
    let stype = SpendType::P2wpkh;
    let incoming = channel_amount + 2_000_000;
    let fee = 1000;
    let change = incoming - channel_amount - fee;

    let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
    let mut tx_ctx = TestFundingTxContext::new();

    tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
    tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
    let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

    let mut tx = tx_ctx.to_tx();

    funding_tx_setup_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

    let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
    let (csig, hsigs) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
    validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
        .expect("valid holder commitment");

    let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
    tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);

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
        .with_channel(&chan_ctx.channel_id, |chan| {
            let per_commitment_point = chan.get_per_commitment_point(commit_num)?;
            let txkeys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

            let tx = chan.make_holder_commitment_tx(
                commit_num,
                &txkeys,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );
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
        .with_channel(&chan_ctx.channel_id, |chan| {
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
        .with_channel(&chan_ctx.channel_id, |chan| {
            let funding_redeemscript = make_funding_redeemscript(
                &chan.keys.pubkeys().funding_pubkey,
                &chan.counterparty_pubkeys().funding_pubkey,
            );
            let tx = commit_tx_ctx.tx.as_ref().unwrap();
            let trusted_tx = tx.trust();
            let keys = trusted_tx.keys();
            let built_tx = trusted_tx.built_transaction();
            let commitment_sig = built_tx.sign_counterparty_commitment(
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
            );

            let build_feerate =
                if chan_ctx.setup.is_zero_fee_htlc() { 0 } else { tx.feerate_per_kw() };

            let mut htlc_sigs = Vec::with_capacity(tx.htlcs().len());
            for htlc in tx.htlcs() {
                let htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    chan_ctx.setup.counterparty_selected_contest_delay,
                    htlc,
                    &chan_ctx.setup.features(),
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                );
                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, &chan_ctx.setup.features(), &keys);
                let sig_hash_type = if chan_ctx.setup.is_anchors() {
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
    htlc_sigs: &[Signature],
) -> Result<(PublicKey, Option<SecretKey>), Status> {
    let htlcs = Channel::htlcs_info2_to_oic(
        commit_tx_ctx.offered_htlcs.clone(),
        commit_tx_ctx.received_htlcs.clone(),
    );
    node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
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
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();

        for offered_htlc in commit_tx_ctx.offered_htlcs.clone() {
            node_ctx.node.add_keysend(
                make_test_pubkey(1),
                offered_htlc.payment_hash,
                offered_htlc.value_sat * 1000,
            )?;
        }

        chan.validate_holder_commitment_tx(
            &commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction,
            &output_witscripts,
            commit_tx_ctx.commit_num,
            commit_tx_ctx.feerate_per_kw,
            commit_tx_ctx.offered_htlcs.clone(),
            commit_tx_ctx.received_htlcs.clone(),
            &commit_sig,
            &htlc_sigs,
        )?;
        if commit_tx_ctx.commit_num == 0 {
            Ok((chan.activate_initial_commitment()?, None))
        } else {
            chan.revoke_previous_holder_commitment(commit_tx_ctx.commit_num)
        }
    })
}

pub fn sign_holder_commitment(
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &TestCommitmentTxContext,
) -> Result<(Signature, Vec<Signature>), Status> {
    node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
        chan.sign_holder_commitment_tx_phase2(commit_tx_ctx.commit_num)
    })
}

// Try and use the funding tx helpers before this comment, the following are compat.

pub fn make_test_funding_tx_with_change(
    inputs: Vec<TxIn>,
    value: u64,
    opath: Vec<u32>,
    change_addr: &Address,
) -> (Vec<u32>, Transaction) {
    let outputs = vec![TxOut { value, script_pubkey: change_addr.script_pubkey() }];
    let tx = make_test_funding_tx_with_ins_outs(inputs, outputs);
    (opath, tx)
}

pub fn make_test_funding_tx(node: &Node, inputs: Vec<TxIn>, value: u64) -> (Vec<u32>, Transaction) {
    let opath = vec![0];
    let change_addr =
        Address::p2wpkh(&node.get_wallet_pubkey(&opath).unwrap(), Network::Testnet).unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_funding_tx_with_p2shwpkh_change(
    node: &Node,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, Transaction) {
    let opath = vec![0];
    let change_addr =
        Address::p2shwpkh(&node.get_wallet_pubkey(&opath).unwrap(), Network::Testnet).unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_commitment_tx() -> Transaction {
    let input = TxIn {
        previous_output: bitcoin::OutPoint { txid: Txid::all_zeros(), vout: 0 },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            script_pubkey: payload_for_p2wpkh(&make_test_bitcoin_pubkey(1).inner).script_pubkey(),
            value: 300,
        }],
    }
}

pub fn make_test_commitment_info() -> CommitmentInfo2 {
    CommitmentInfo2::new(true, 3_000_000, 2_000_000, vec![], vec![], 7500)
}

pub const TEST_NODE_CONFIG: NodeConfig = NodeConfig {
    network: Network::Testnet,
    key_derivation_style: KeyDerivationStyle::Native,
    use_checkpoints: false,
    allow_deep_reorgs: false,
};

pub const REGTEST_NODE_CONFIG: NodeConfig = NodeConfig {
    network: Network::Regtest,
    key_derivation_style: KeyDerivationStyle::Native,
    use_checkpoints: false,
    allow_deep_reorgs: false,
};

pub const TEST_SEED: &[&str] = &[
    "6c696768746e696e672d31000000000000000000000000000000000000000000",
    "6c696768746e696e672d32000000000000000000000000000000000000000000",
];

pub const TEST_CHANNEL_ID: &[&str] = &[
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0200000000000000000000000000000000000000000000000000000000000000",
];

fn sort_outputs<T, C: Fn(&T, &T) -> cmp::Ordering>(outputs: &mut Vec<(TxOut, T)>, tie_breaker: C) {
    outputs.sort_unstable_by(|a, b| {
        a.0.value.cmp(&b.0.value).then_with(|| {
            a.0.script_pubkey[..].cmp(&b.0.script_pubkey[..]).then_with(|| tie_breaker(&a.1, &b.1))
        })
    });
}

pub fn build_tx_scripts(
    keys: &TxCreationKeys,
    to_broadcaster_value_sat: u64,
    to_countersignatory_value_sat: u64,
    htlcs: &[HTLCOutputInCommitment],
    channel_parameters: &DirectedChannelTransactionParameters,
    broadcaster_funding_key: &PublicKey,
    countersignatory_funding_key: &PublicKey,
) -> Result<Vec<ScriptBuf>, ()> {
    let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
    let contest_delay = channel_parameters.contest_delay();

    let mut txouts: Vec<(TxOut, (Option<HTLCOutputInCommitment>, ScriptBuf))> = Vec::new();

    let features = channel_parameters.channel_type_features();
    let is_anchors = features.supports_anchors_nonzero_fee_htlc_tx()
        || features.supports_anchors_zero_fee_htlc_tx();

    if to_countersignatory_value_sat > 0 {
        let (redeem_script, script_pubkey) = if is_anchors {
            let script = get_to_countersignatory_with_anchors_redeemscript(
                &countersignatory_pubkeys.payment_point,
            );
            (script.clone(), script.to_v0_p2wsh())
        } else {
            (ScriptBuf::new(), get_p2wpkh_redeemscript(&countersignatory_pubkeys.payment_point))
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

    if is_anchors {
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
        let script = get_htlc_redeemscript(&htlc, features, &keys);
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
        node.with_channel(&channel_id, |chan| Ok(chan.keys.pubkeys().funding_pubkey));
    res.unwrap()
}

pub fn get_channel_htlc_pubkey(
    node: &Node,
    channel_id: &ChannelId,
    remote_per_commitment_point: &PublicKey,
) -> PublicKey {
    let res: Result<PublicKey, Status> = node.with_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = derive_public_key(
            &secp_ctx,
            &remote_per_commitment_point,
            &chan.keys.pubkeys().htlc_basepoint.0,
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
    let res: Result<PublicKey, Status> = node.with_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = derive_public_key(
            &secp_ctx,
            &remote_per_commitment_point,
            &chan.keys.pubkeys().delayed_payment_basepoint.0,
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
    let res: Result<RevocationKey, Status> = node.with_channel(&channel_id, |chan| {
        let secp_ctx = &chan.secp_ctx;
        let pubkey = crypto_utils::derive_public_revocation_key(
            secp_ctx,
            revocation_point, // matches revocation_secret
            &chan.keys.pubkeys().revocation_basepoint,
        )
        .map_err(|_| internal_error("failed to derive_public_revocation_key"))?;
        Ok(pubkey)
    });
    res.unwrap().0
}

pub fn check_signature(
    tx: &Transaction,
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
    tx: &Transaction,
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
    tx: &Transaction,
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

    node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
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
        let output_witscripts: Vec<_> =
            redeem_scripts.iter().map(|s| s.as_bytes().to_vec()).collect();

        let tx = commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction.clone();

        for offered_htlc in commit_tx_ctx.offered_htlcs.clone() {
            node_ctx.node.add_keysend(
                make_test_pubkey(1),
                offered_htlc.payment_hash,
                offered_htlc.value_sat * 1000,
            )?;
        }

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
        if commit_tx_ctx.commit_num == 0 {
            chan.activate_initial_commitment()?;
        } else {
            chan.revoke_previous_holder_commitment(commit_tx_ctx.commit_num)?;
        }

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
        lock_time: LockTime::ZERO,
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

pub fn make_outpoint(vout: u32) -> bitcoin::OutPoint {
    bitcoin::OutPoint { txid: Txid::all_zeros(), vout }
}

pub fn make_header(tip: BlockHeader, merkle_root: TxMerkleNode) -> BlockHeader {
    let bits = tip.bits;
    mine_header_with_bits(tip.block_hash(), merkle_root, bits)
}

pub fn make_block(prev_header: BlockHeader, txs: Vec<Transaction>) -> Block {
    assert!(!txs.is_empty());
    let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
    let merkle_root = merkle_tree::calculate_root(txids.into_iter()).unwrap();
    let merkle_root = TxMerkleNode::from_raw_hash(merkle_root.into());
    let header = make_header(prev_header, merkle_root);
    Block { header, txdata: txs }
}

pub fn make_testnet_header(tip: &Headers, tip_height: u32) -> (BlockHeader, TxoProof) {
    let txs: Vec<Transaction> = vec![Transaction {
        version: 0,
        lock_time: LockTime::from_consensus(tip_height + 1),
        input: vec![],
        output: vec![],
    }];
    let tx_ids: Vec<_> = txs.iter().map(|tx| tx.txid().to_raw_hash()).collect();
    let merkle_root = merkle_tree::calculate_root(tx_ids.into_iter()).unwrap();
    let merkle_root = TxMerkleNode::from_raw_hash(merkle_root.into());
    let regtest_genesis = genesis_block(Network::Regtest);
    let bits = regtest_genesis.header.bits;
    let header = mine_header_with_bits(tip.0.block_hash(), merkle_root, bits);
    let block = Block { header, txdata: txs };
    let proof = TxoProof::prove_unchecked(&block, &tip.1, tip_height + 1);
    (header, proof)
}

pub fn mine_header_with_bits(
    prev_hash: BlockHash,
    merkle_root: TxMerkleNode,
    bits: CompactTarget,
) -> BlockHeader {
    let mut nonce = 0;
    loop {
        let header = BlockHeader {
            version: Version::from_consensus(0),
            prev_blockhash: prev_hash,
            merkle_root,
            time: 0,
            bits,
            nonce,
        };
        if header.validate_pow(header.target()).is_ok() {
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
    (node_id, node, channel.unwrap().unwrap_stub().clone(), seed)
}

pub fn make_node() -> (PublicKey, Arc<Node>, [u8; 32]) {
    let mut seed = [0; 32];
    seed.copy_from_slice(hex_decode(TEST_SEED[1]).unwrap().as_slice());

    let services = make_services();

    let node = Arc::new(Node::new(TEST_NODE_CONFIG, &seed, vec![], services));
    let node_id = node.get_id();
    (node_id, node, seed)
}

pub fn make_services() -> NodeServices {
    let persister = Arc::new(DummyPersister {});
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let starting_time_factory = make_genesis_starting_time_factory(TEST_NODE_CONFIG.network);
    let clock = Arc::new(StandardClock());

    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys: vec![],
    };
    services
}

pub fn create_test_channel_setup(dummy_pubkey: PublicKey) -> ChannelSetup {
    let mut txid = [1; 32];
    txid[0] = 2;
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 123456,
        push_value_msat: 0,
        funding_outpoint: bitcoin::OutPoint { txid: Txid::from_slice(&txid).unwrap(), vout: 1 },
        holder_selected_contest_delay: 10,
        holder_shutdown_script: None,
        counterparty_points: ChannelPublicKeys {
            funding_pubkey: dummy_pubkey,
            revocation_basepoint: RevocationBasepoint(dummy_pubkey),
            payment_point: dummy_pubkey,
            delayed_payment_basepoint: DelayedPaymentBasepoint(dummy_pubkey),
            htlc_basepoint: HtlcBasepoint(dummy_pubkey),
        },
        counterparty_selected_contest_delay: 11,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub struct ChannelBalanceBuilder {
    inner: ChannelBalance,
}

impl ChannelBalanceBuilder {
    pub fn new() -> ChannelBalanceBuilder {
        ChannelBalanceBuilder { inner: ChannelBalance::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0) }
    }

    pub fn claimable(mut self, claimable: u64) -> Self {
        self.inner.claimable = claimable;
        self
    }

    pub fn received_htlc(mut self, received_htlc: u64) -> Self {
        self.inner.received_htlc = received_htlc;
        self
    }

    pub fn offered_htlc(mut self, offered_htlc: u64) -> Self {
        self.inner.offered_htlc = offered_htlc;
        self
    }

    pub fn sweeping(mut self, sweeping: u64) -> Self {
        self.inner.sweeping = sweeping;
        self
    }

    pub fn stub_count(mut self, stub_count: u32) -> Self {
        self.inner.stub_count = stub_count;
        self
    }

    pub fn unconfirmed_count(mut self, unconfirmed_count: u32) -> Self {
        self.inner.unconfirmed_count = unconfirmed_count;
        self
    }

    pub fn channel_count(mut self, channel_count: u32) -> Self {
        self.inner.channel_count = channel_count;
        self
    }

    pub fn closing_count(mut self, closing_count: u32) -> Self {
        self.inner.closing_count = closing_count;
        self
    }

    pub fn received_htlc_count(mut self, received_htlc_count: u32) -> Self {
        self.inner.received_htlc_count = received_htlc_count;
        self
    }

    pub fn offered_htlc_count(mut self, offered_htlc_count: u32) -> Self {
        self.inner.offered_htlc_count = offered_htlc_count;
        self
    }

    pub fn build(self) -> ChannelBalance {
        self.inner
    }
}

/// A mock listener for testing
pub struct MockListener {
    watch: bitcoin::OutPoint,
    watch2: Mutex<Option<bitcoin::OutPoint>>,
    watch_delta: Mutex<(Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>)>,
}

impl SendSync for MockListener {}

impl Clone for MockListener {
    fn clone(&self) -> Self {
        // We just need this to have the right `Ord` semantics
        // the value of `watched` doesn't matter
        let watch2 = self.watch2.lock().unwrap();
        let watch_delta = self.watch_delta.lock().unwrap();
        Self {
            watch: self.watch,
            watch2: Mutex::new(*watch2),
            watch_delta: Mutex::new(watch_delta.clone()),
        }
    }
}

impl ChainListener for MockListener {
    type Key = bitcoin::OutPoint;

    fn key(&self) -> &Self::Key {
        &self.watch
    }

    fn on_add_block(
        &self,
        txs: &[Transaction],
        _block_hash: &BlockHash,
    ) -> (Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>) {
        for tx in txs {
            for input in tx.input.iter() {
                let mut watch2 = self.watch2.lock().unwrap();
                if input.previous_output == self.watch {
                    let add = bitcoin::OutPoint { txid: tx.txid(), vout: 0 };
                    *watch2 = Some(add);
                    return (vec![add], vec![self.watch]);
                }
                if Some(input.previous_output) == *watch2 {
                    return (vec![], vec![input.previous_output]);
                }
            }
        }
        (vec![], vec![])
    }

    fn on_add_streamed_block_end(
        &self,
        _block_hash: &BlockHash,
    ) -> (Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>) {
        let watch_delta = self.watch_delta.lock().unwrap();
        watch_delta.clone()
    }

    fn on_remove_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>) {
        self.on_add_block(txs, block_hash)
    }

    fn on_remove_streamed_block_end(
        &self,
        _block_hash: &BlockHash,
    ) -> (Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>) {
        unimplemented!()
    }

    fn on_push<F>(&self, f: F)
    where
        F: FnOnce(&mut dyn Listener),
    {
        f(&mut MockPushListener(&self));
    }
}

struct MockPushListener<'a>(&'a MockListener);

impl<'a> Listener for MockPushListener<'a> {
    fn on_block_start(&mut self, _header: &BlockHeader) {}

    fn on_transaction_start(&mut self, _version: i32) {}

    fn on_transaction_input(&mut self, input: &TxIn) {
        let watch2 = self.0.watch2.lock().unwrap();
        let mut watch_delta = self.0.watch_delta.lock().unwrap();
        let watch = self.0.watch;
        if input.previous_output == watch {
            watch_delta.1.push(watch);
        }
        if Some(input.previous_output) == *watch2 {
            watch_delta.1.push(input.previous_output);
        }
    }

    fn on_transaction_output(&mut self, _txout: &TxOut) {}

    fn on_transaction_end(&mut self, _locktime: LockTime, txid: Txid) {
        let mut watch2 = self.0.watch2.lock().unwrap();
        let mut watch_delta = self.0.watch_delta.lock().unwrap();
        let watch = self.0.watch;
        if watch_delta.1.contains(&watch) {
            let add = bitcoin::OutPoint { txid, vout: 0 };
            watch_delta.0.push(add);
            *watch2 = Some(add);
        }
    }

    fn on_block_end(&mut self) {}
}

impl MockListener {
    /// Create a new mock listener
    pub fn new(watch: bitcoin::OutPoint) -> Self {
        MockListener { watch, watch2: Mutex::new(None), watch_delta: Mutex::new((vec![], vec![])) }
    }
}

pub struct DummyCommitmentPointProvider {}

impl SendSync for DummyCommitmentPointProvider {}

impl CommitmentPointProvider for DummyCommitmentPointProvider {
    fn get_holder_commitment_point(&self, _commitment_number: u64) -> PublicKey {
        todo!()
    }

    fn get_counterparty_commitment_point(&self, _commitment_number: u64) -> Option<PublicKey> {
        todo!()
    }

    fn get_transaction_parameters(&self) -> ChannelTransactionParameters {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn CommitmentPointProvider> {
        Box::new(DummyCommitmentPointProvider {})
    }
}
