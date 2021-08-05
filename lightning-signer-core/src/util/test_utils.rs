use crate::prelude::*;
use crate::Arc;
use core::cmp;

use bitcoin;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::hash_types::Txid;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::ripemd160::Hash as Ripemd160Hash;
use bitcoin::hashes::{Hash, hex::FromHex, hex};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, SignOnly, Signature};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{Address, OutPoint as BitcoinOutPoint, SigHashType, TxIn, TxOut};
use chain::chaininterface;
use lightning::chain;
use lightning::chain::channelmonitor::MonitorEvent;
use lightning::chain::keysinterface::{BaseSign, InMemorySigner};
use lightning::chain::transaction::OutPoint;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::ln::chan_utils::{
    build_htlc_transaction, derive_private_key, get_htlc_redeemscript, get_revokeable_redeemscript,
    make_funding_redeemscript, ChannelPublicKeys, ChannelTransactionParameters,
    CommitmentTransaction, CounterpartyChannelTransactionParameters,
    DirectedChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::util::test_utils;

use crate::node::{
    Channel, ChannelBase, ChannelId, ChannelSetup, CommitmentType, Node, NodeConfig,
};
use crate::signer::multi_signer::{channel_nonce_to_id, MultiSigner, SpendType};
use crate::signer::my_keys_manager::KeyDerivationStyle;
use crate::tx::tx::{sort_outputs, HTLCInfo2};
use crate::util::crypto_utils::{payload_for_p2wpkh, payload_for_p2wsh};
use crate::util::enforcing_trait_impls::EnforcingSigner;
use crate::util::loopback::LoopbackChannelSigner;
use crate::util::status::Status;
use bitcoin::hashes::hex::ToHex;

pub struct TestPersister {
    pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
}

impl TestPersister {
    pub fn new() -> Self {
        Self {
            update_ret: Mutex::new(Ok(())),
        }
    }

    // BEGIN NOT TESTED
    pub fn set_update_ret(&self, ret: Result<(), channelmonitor::ChannelMonitorUpdateErr>) {
        *self.update_ret.lock().unwrap() = ret;
    }
    // END NOT TESTED
}

impl channelmonitor::Persist<LoopbackChannelSigner> for TestPersister {
    fn persist_new_channel(
        &self,
        _funding_txo: OutPoint,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
    ) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.update_ret.lock().unwrap().clone()
    }

    fn update_persisted_channel(
        &self,
        _funding_txo: OutPoint,
        _update: &channelmonitor::ChannelMonitorUpdate,
        _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>,
    ) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
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
        &'a test_utils::TestLogger,
        &'a channelmonitor::Persist<LoopbackChannelSigner>,
    >,
    pub update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
    // If this is set to Some(), after the next return, we'll always return this until update_ret
    // is changed:
    pub next_update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
}
impl<'a> TestChainMonitor<'a> {
    pub fn new(
        chain_source: Option<&'a test_utils::TestChainSource>,
        broadcaster: &'a chaininterface::BroadcasterInterface,
        logger: &'a test_utils::TestLogger,
        fee_estimator: &'a test_utils::TestFeeEstimator,
        persister: &'a channelmonitor::Persist<LoopbackChannelSigner>,
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
    ) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id.lock().unwrap().insert(
            funding_txo.to_channel_id(),
            (funding_txo, monitor.get_latest_update_id()),
        );
        self.added_monitors.lock().unwrap().push((funding_txo, ()));
        let watch_res = self.chain_monitor.watch_channel(funding_txo, monitor);

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret); // NOT TESTED
        }
        if ret.is_some() {
            // BEGIN NOT TESTED
            assert!(watch_res.is_ok());
            return ret.unwrap();
            // END NOT TESTED
        }
        watch_res
    }

    fn update_channel(
        &self,
        funding_txo: OutPoint,
        update: channelmonitor::ChannelMonitorUpdate,
    ) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id
            .lock()
            .unwrap()
            .insert(funding_txo.to_channel_id(), (funding_txo, update.update_id));
        let update_res = self.chain_monitor.update_channel(funding_txo, update);
        self.added_monitors.lock().unwrap().push((funding_txo, ()));

        let ret = self.update_ret.lock().unwrap().clone();
        if let Some(next_ret) = self.next_update_ret.lock().unwrap().take() {
            *self.update_ret.lock().unwrap() = Some(next_ret); // NOT TESTED
        }
        if ret.is_some() {
            // BEGIN NOT TESTED
            assert!(update_res.is_ok());
            return ret.unwrap();
            // END NOT TESTED
        }
        update_res
    }

    fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
        return self.chain_monitor.release_pending_monitor_events();
    }
}

pub fn pubkey_from_secret_hex(h: &str, secp_ctx: &Secp256k1<SignOnly>) -> PublicKey {
    PublicKey::from_secret_key(
        secp_ctx,
        &SecretKey::from_slice(&Vec::from_hex(h).unwrap()[..]).unwrap(),
    )
}

pub fn make_test_bitcoin_key(i: u8) -> (bitcoin::PublicKey, bitcoin::PrivateKey) {
    let secp_ctx = Secp256k1::signing_only();
    let secret_key = SecretKey::from_slice(&[i; 32]).unwrap();
    let private_key = bitcoin::PrivateKey {
        compressed: true,
        network: Network::Testnet,
        key: secret_key,
    };
    return (private_key.public_key(&secp_ctx), private_key);
}

pub fn make_test_bitcoin_pubkey(i: u8) -> bitcoin::PublicKey {
    make_test_bitcoin_key(i).0
}

pub fn make_test_key(i: u8) -> (PublicKey, SecretKey) {
    let secp_ctx = Secp256k1::signing_only();
    let secret_key = SecretKey::from_slice(&[i; 32]).unwrap();
    return (
        PublicKey::from_secret_key(&secp_ctx, &secret_key),
        secret_key,
    );
}

pub fn make_test_pubkey(i: u8) -> PublicKey {
    make_test_key(i).0
}

pub fn make_test_privkey(i: u8) -> SecretKey {
    make_test_key(i).1
}

pub fn make_test_counterparty_points() -> ChannelPublicKeys {
    ChannelPublicKeys {
        funding_pubkey: make_test_pubkey(104),
        revocation_basepoint: make_test_pubkey(100),
        payment_point: make_test_pubkey(101),
        delayed_payment_basepoint: make_test_pubkey(102),
        htlc_basepoint: make_test_pubkey(103),
    }
}

pub fn make_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub fn make_test_channel_keys() -> EnforcingSigner {
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
        funding_outpoint: Some(OutPoint {
            txid: Default::default(),
            index: 0,
        }),
    });
    EnforcingSigner::new(inmemkeys)
}

pub fn init_node(signer: &MultiSigner, node_config: NodeConfig, seedstr: &str) -> PublicKey {
    let mut seed = [0; 32];
    seed.copy_from_slice(Vec::from_hex(seedstr).unwrap().as_slice());
    signer.new_node_from_seed(node_config, &seed).unwrap()
}

pub fn init_node_and_channel(
    signer: &MultiSigner,
    node_config: NodeConfig,
    seedstr: &str,
    setup: ChannelSetup,
) -> (PublicKey, ChannelId) {
    let node_id = init_node(signer, node_config, seedstr);
    let channel_nonce = "nonce1".as_bytes().to_vec();
    let channel_id = channel_nonce_to_id(&channel_nonce);
    let node = signer.get_node(&node_id).expect("node does not exist");
    signer
        .new_channel(&node_id, Some(channel_nonce), Some(channel_id))
        .expect("new_channel");
    node.ready_channel(channel_id, None, setup)
        .expect("ready channel");
    (node_id, channel_id)
}

pub fn make_test_funding_wallet_addr(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    node: &Node,
    i: u32,
    is_p2sh: bool,
) -> Address {
    let child_path = vec![i];
    let pubkey = node
        .get_wallet_key(&secp_ctx, &child_path)
        .unwrap()
        .public_key(&secp_ctx);

    // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
    if !is_p2sh {
        Address::p2wpkh(&pubkey, node.network).unwrap()
    } else {
        Address::p2shwpkh(&pubkey, node.network).unwrap()
    }
}

pub fn make_test_funding_wallet_input() -> TxIn {
    TxIn {
        previous_output: bitcoin::OutPoint {
            txid: Default::default(),
            vout: 0,
        },
        script_sig: Script::new(),
        sequence: 0,
        witness: vec![],
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
    let pubkey = node
        .get_wallet_key(&secp_ctx, &child_path)
        .unwrap()
        .public_key(&secp_ctx);

    // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
    let addr = if !is_p2sh {
        Address::p2wpkh(&pubkey, node.network).unwrap()
    } else {
        Address::p2shwpkh(&pubkey, node.network).unwrap()
    };

    TxOut {
        value,
        script_pubkey: addr.script_pubkey(),
    }
}

pub fn make_test_funding_channel_outpoint(
    signer: &MultiSigner,
    node_id: &PublicKey,
    setup: &ChannelSetup,
    channel_id: &ChannelId,
    value: u64,
) -> TxOut {
    signer
        .with_channel_base(node_id, channel_id, |base| {
            let funding_redeemscript = make_funding_redeemscript(
                &base.get_channel_basepoints().funding_pubkey,
                &setup.counterparty_points.funding_pubkey,
            );
            let script_pubkey = payload_for_p2wsh(&funding_redeemscript).script_pubkey();
            Ok(TxOut {
                value,
                script_pubkey,
            })
        })
        .expect("TxOut")
}

pub fn make_test_funding_tx_with_ins_outs(
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: inputs,
        output: outputs,
    }
}

// Bundles global context used for unit tests.
pub struct TestSignerContext {
    pub secp_ctx: Secp256k1<secp256k1::SignOnly>,
    pub signer: MultiSigner,
}

// Bundles node-specific context used for unit tests.
pub struct TestNodeContext {
    pub node_id: PublicKey,
    pub node: Arc<Node>,
}

// Bundles channel-specific context used for unit tests.
pub struct TestChannelContext {
    pub channel_id: ChannelId,
    pub setup: ChannelSetup,
    pub counterparty_keys: EnforcingSigner,
}

// Bundles funding tx context used for unit tests.
pub struct TestFundingTxContext {
    pub inputs: Vec<TxIn>,
    pub ipaths: Vec<Vec<u32>>,
    pub ivals: Vec<u64>,
    pub ispnds: Vec<SpendType>,
    pub iuckeys: Vec<Option<SecretKey>>,
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

pub fn test_sign_ctx() -> TestSignerContext {
    let secp_ctx = Secp256k1::signing_only();
    let signer = MultiSigner::new();
    TestSignerContext { secp_ctx, signer }
}

pub fn test_node_ctx(sign_ctx: &TestSignerContext, ndx: usize) -> TestNodeContext {
    let node_id = init_node(&sign_ctx.signer, TEST_NODE_CONFIG, TEST_SEED[ndx]);
    let node = sign_ctx.signer.get_node(&node_id).unwrap();
    TestNodeContext { node_id, node }
}

pub fn test_chan_ctx(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    nn: usize,
    value_sat: u64,
) -> TestChannelContext {
    let channel_nonce0 = format!("nonce{}", nn).as_bytes().to_vec();
    let channel_id = channel_nonce_to_id(&channel_nonce0);
    let setup = ChannelSetup {
        is_outbound: true,
        channel_value_sat: value_sat,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::StaticRemoteKey,
    };

    sign_ctx
        .signer
        .new_channel(&node_ctx.node_id, Some(channel_nonce0), Some(channel_id))
        .expect("new_channel");

    // Make counterparty keys that match.
    let counterparty_keys = sign_ctx
        .signer
        .with_channel_base(&node_ctx.node_id, &channel_id, |stub| {
            // These need to match make_test_counterparty_points() above ...
            let mut cpinmemkeys = InMemorySigner::new(
                &sign_ctx.secp_ctx,
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
            cpinmemkeys.ready_channel(&ChannelTransactionParameters {
                holder_pubkeys: cpinmemkeys.pubkeys().clone(),
                holder_selected_contest_delay: 7,
                is_outbound_from_holder: false,
                counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                    pubkeys: stub.get_channel_basepoints(),
                    selected_contest_delay: 6,
                }),
                funding_outpoint: Some(OutPoint {
                    txid: Default::default(),
                    index: 0,
                }),
            });
            Ok(EnforcingSigner::new(cpinmemkeys))
        })
        .unwrap();
    TestChannelContext {
        channel_id,
        setup,
        counterparty_keys,
    }
}

pub fn set_next_holder_commit_num_for_testing(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
) {
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            chan.keys.set_next_holder_commit_num_for_testing(commit_num);
            Ok(())
        })
        .unwrap();
}

pub fn set_next_counterparty_commit_num_for_testing(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_num: u64,
    current_point: PublicKey,
) {
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            chan.keys
                .set_next_counterparty_commit_num_for_testing(commit_num, current_point);
            Ok(())
        })
        .unwrap();
}

pub fn set_next_counterparty_revoke_num_for_testing(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    revoke_num: u64,
) {
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            chan.keys
                .set_next_counterparty_revoke_num_for_testing(revoke_num);
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
    tx_ctx.ispnds.push(if is_p2sh {
        SpendType::P2shP2wpkh
    } else {
        SpendType::P2wpkh
    });
    tx_ctx.iuckeys.push(None);
}

pub fn funding_tx_add_wallet_output(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    wallet_ndx: u32,
    value_sat: u64,
) {
    tx_ctx.outputs.push(make_test_funding_wallet_output(
        &sign_ctx.secp_ctx,
        &node_ctx.node,
        wallet_ndx,
        value_sat,
        is_p2sh,
    ));
    tx_ctx.opaths.push(vec![wallet_ndx]);
}

pub fn funding_tx_add_channel_outpoint(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    tx_ctx: &mut TestFundingTxContext,
    value_sat: u64,
) -> u32 {
    let ndx = tx_ctx.outputs.len();
    tx_ctx.outputs.push(make_test_funding_channel_outpoint(
        &sign_ctx.signer,
        &node_ctx.node_id,
        &chan_ctx.setup,
        &chan_ctx.channel_id,
        value_sat,
    ));
    tx_ctx.opaths.push(vec![]);
    ndx as u32
}

pub fn funding_tx_add_unknown_output(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    tx_ctx: &mut TestFundingTxContext,
    is_p2sh: bool,
    unknown_ndx: u32,
    value_sat: u64,
) {
    tx_ctx.outputs.push(make_test_funding_wallet_output(
        &sign_ctx.secp_ctx,
        &node_ctx.node,
        unknown_ndx + 10_000, // lazy, it's really in the wallet
        value_sat,
        is_p2sh,
    ));
    tx_ctx.opaths.push(vec![]); // this is what makes it unknown
}

pub fn funding_tx_from_ctx(tx_ctx: &TestFundingTxContext) -> bitcoin::Transaction {
    make_test_funding_tx_with_ins_outs(tx_ctx.inputs.clone(), tx_ctx.outputs.clone())
}

pub fn funding_tx_ready_channel(
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    tx: &bitcoin::Transaction,
    vout: u32,
) {
    let txid = tx.txid();
    chan_ctx.setup.funding_outpoint = BitcoinOutPoint { txid, vout };
    node_ctx
        .node
        .ready_channel(chan_ctx.channel_id, None, chan_ctx.setup.clone())
        .expect("Channel");
}

pub fn synthesize_ready_channel(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &mut TestChannelContext,
    outpoint: BitcoinOutPoint,
    next_holder_commit_num: u64,
) {
    chan_ctx.setup.funding_outpoint = outpoint;
    node_ctx
        .node
        .ready_channel(chan_ctx.channel_id, None, chan_ctx.setup.clone())
        .expect("Channel");
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            chan.keys
                .set_next_holder_commit_num_for_testing(next_holder_commit_num);
            Ok(())
        })
        .expect("synthesized channel");
}

pub fn funding_tx_sign(
    node_ctx: &TestNodeContext,
    tx_ctx: &TestFundingTxContext,
    tx: &bitcoin::Transaction,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Status> {
    node_ctx.node.sign_funding_tx(
        &tx,
        &tx_ctx.ipaths,
        &tx_ctx.ivals,
        &tx_ctx.ispnds,
        &tx_ctx.iuckeys,
        &tx_ctx.opaths,
    )
}

pub fn funding_tx_validate_sig(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    tx_ctx: &TestFundingTxContext,
    tx: &mut bitcoin::Transaction,
    witvec: &Vec<(Vec<u8>, Vec<u8>)>,
) {
    for ndx in 0..tx.input.len() {
        tx.input[ndx].witness = vec![witvec[ndx].0.clone(), witvec[ndx].1.clone()];
    }
    let verify_result = tx.verify(|outpoint| {
        // hack, we collude w/ funding_tx_add_wallet_input
        let input_ndx = outpoint.vout as usize;
        let txout = TxOut {
            value: tx_ctx.ivals[input_ndx],
            script_pubkey: make_test_funding_wallet_addr(
                &sign_ctx.secp_ctx,
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

pub fn fund_test_channel(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    channel_amount: u64,
) -> TestChannelContext {
    let is_p2sh = false;
    let incoming = channel_amount + 2_000_000;
    let fee = 1000;
    let change = incoming - channel_amount - fee;

    let mut chan_ctx = test_chan_ctx(&sign_ctx, &node_ctx, 1, channel_amount);
    let mut tx_ctx = test_funding_tx_ctx();

    funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
    funding_tx_add_wallet_output(&sign_ctx, &node_ctx, &mut tx_ctx, is_p2sh, 1, change);
    let outpoint_ndx = funding_tx_add_channel_outpoint(
        &sign_ctx,
        &node_ctx,
        &chan_ctx,
        &mut tx_ctx,
        channel_amount,
    );

    let mut tx = funding_tx_from_ctx(&tx_ctx);

    funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

    let mut commit_tx_ctx = channel_initial_commitment(&sign_ctx, &node_ctx, &chan_ctx);
    let (csig, hsigs) =
        counterparty_sign_holder_commitment(&sign_ctx, &node_ctx, &chan_ctx, &mut commit_tx_ctx);
    validate_holder_commitment(
        &sign_ctx,
        &node_ctx,
        &chan_ctx,
        &commit_tx_ctx,
        &csig,
        &hsigs,
    )
    .expect("valid holder commitment");

    let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
    funding_tx_validate_sig(&sign_ctx, &node_ctx, &tx_ctx, &mut tx, &witvec);

    chan_ctx
}

pub fn channel_initial_commitment(
    sign_ctx: &TestSignerContext,
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
        sign_ctx,
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
    sign_ctx: &TestSignerContext,
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
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            let tx = chan
                .make_holder_commitment_tx(
                    commit_num,
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

// Construct counterparty signatures for a holder commitment.
// Mimics InMemorySigner::sign_counterparty_commitment w/ transposition.
pub fn counterparty_sign_holder_commitment(
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &mut TestCommitmentTxContext,
) -> (Signature, Vec<Signature>) {
    let (commitment_sig, htlc_sigs) = sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            let funding_redeemscript = make_funding_redeemscript(
                &chan.keys.pubkeys().funding_pubkey,
                &chan.keys.counterparty_pubkeys().funding_pubkey,
            );
            let tx = &commit_tx_ctx.tx.as_ref().unwrap();
            let trusted_tx = tx.trust();
            let keys = trusted_tx.keys();
            let built_tx = trusted_tx.built_transaction();
            let commitment_sig = built_tx.sign(
                &chan_ctx.counterparty_keys.funding_key(),
                &funding_redeemscript,
                chan_ctx.setup.channel_value_sat,
                &sign_ctx.secp_ctx,
            );
            let per_commitment_point = chan
                .get_per_commitment_point(commit_tx_ctx.commit_num)
                .expect("per_commitment_point");
            let txkeys = chan
                .make_holder_tx_keys(&per_commitment_point)
                .expect("txkeys");
            let commitment_txid = built_tx.txid;

            let counterparty_htlc_key = derive_private_key(
                &sign_ctx.secp_ctx,
                &per_commitment_point,
                &chan_ctx.counterparty_keys.htlc_base_key(),
            )
            .expect("counterparty_htlc_key");

            let mut htlc_sigs = Vec::with_capacity(tx.htlcs().len());
            for htlc in tx.htlcs() {
                let htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    tx.feerate_per_kw(),
                    chan_ctx.setup.counterparty_selected_contest_delay,
                    htlc,
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                );
                let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);
                let htlc_sighash = Message::from_slice(
                    &SigHashCache::new(&htlc_tx).signature_hash(
                        0,
                        &htlc_redeemscript,
                        htlc.amount_msat / 1000,
                        SigHashType::All,
                    )[..],
                )
                .unwrap();
                htlc_sigs.push(
                    sign_ctx
                        .secp_ctx
                        .sign(&htlc_sighash, &counterparty_htlc_key),
                );
            }
            Ok((commitment_sig, htlc_sigs))
        })
        .unwrap();
    (commitment_sig, htlc_sigs)
}

pub fn validate_holder_commitment(
    sign_ctx: &TestSignerContext,
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
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();
            let parameters = channel_parameters.as_holder_broadcastable();

            // NOTE - the unit tests calling this method may be
            // setting up a commitment with a bogus
            // commitment_number on purpose.  To allow this we
            // need to temporarily set the channel's
            // next_holder_commit_num while fetching the
            // commitment_point and then restore it.
            let save_commit_num = chan.keys.next_holder_commit_num();
            chan.keys
                .set_next_holder_commit_num_for_testing(commit_tx_ctx.commit_num);
            let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
            chan.keys
                .set_next_holder_commit_num_for_testing(save_commit_num);

            let keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

            let redeem_scripts = build_tx_scripts(
                &keys,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                &htlcs,
                &parameters,
            )
            .expect("scripts");
            let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

            chan.validate_holder_commitment_tx(
                &commit_tx_ctx
                    .tx
                    .as_ref()
                    .unwrap()
                    .trust()
                    .built_transaction()
                    .transaction,
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
    sign_ctx: &TestSignerContext,
    node_ctx: &TestNodeContext,
    chan_ctx: &TestChannelContext,
    commit_tx_ctx: &TestCommitmentTxContext,
) -> Result<Signature, Status> {
    let htlcs = Channel::htlcs_info2_to_oic(
        commit_tx_ctx.offered_htlcs.clone(),
        commit_tx_ctx.received_htlcs.clone(),
    );
    let mut payment_hashmap = Map::new();
    for htlc in &htlcs {
        payment_hashmap.insert(
            Ripemd160Hash::hash(&htlc.payment_hash.0).into_inner(),
            htlc.payment_hash,
        );
    }
    sign_ctx
        .signer
        .with_ready_channel(&node_ctx.node_id, &chan_ctx.channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();
            let parameters = channel_parameters.as_holder_broadcastable();

            // NOTE - the unit tests calling this method may be
            // setting up a commitment with a bogus
            // commitment_number on purpose.  To allow this we
            // need to temporarily set the channel's
            // next_holder_commit_num while fetching the
            // commitment_point and then restore it.
            let save_commit_num = chan.keys.next_holder_commit_num();
            chan.keys
                .set_next_holder_commit_num_for_testing(commit_tx_ctx.commit_num);
            let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
            chan.keys
                .set_next_holder_commit_num_for_testing(save_commit_num);

            let keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

            let redeem_scripts = build_tx_scripts(
                &keys,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                &htlcs,
                &parameters,
            )
            .expect("scripts");
            let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

            chan.sign_holder_commitment_tx(
                &commit_tx_ctx
                    .tx
                    .as_ref()
                    .unwrap()
                    .trust()
                    .built_transaction()
                    .transaction,
                &output_witscripts,
                &payment_hashmap,
                commit_tx_ctx.commit_num,
            )
        })
}

// Try and use the funding tx helpers before this comment, the following are compat.

pub fn make_test_funding_tx_with_change(
    inputs: Vec<TxIn>,
    value: u64,
    opath: Vec<u32>,
    change_addr: &Address,
) -> (Vec<u32>, bitcoin::Transaction) {
    let outputs = vec![TxOut {
        value,
        script_pubkey: change_addr.script_pubkey(),
    }];
    let tx = make_test_funding_tx_with_ins_outs(inputs, outputs);
    (opath, tx)
}

pub fn make_test_funding_tx(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    signer: &MultiSigner,
    node_id: &PublicKey,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, bitcoin::Transaction) {
    let opath = vec![0];
    let change_addr = Address::p2wpkh(
        &signer
            .get_node(&node_id)
            .unwrap()
            .get_wallet_key(&secp_ctx, &opath)
            .unwrap()
            .public_key(&secp_ctx),
        Network::Testnet,
    )
    .unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_funding_tx_with_p2shwpkh_change(
    secp_ctx: &Secp256k1<secp256k1::SignOnly>,
    signer: &MultiSigner,
    node_id: &PublicKey,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, bitcoin::Transaction) {
    let opath = vec![0];
    let change_addr = Address::p2shwpkh(
        &signer
            .get_node(&node_id)
            .unwrap()
            .get_wallet_key(&secp_ctx, &opath)
            .unwrap()
            .public_key(&secp_ctx),
        Network::Testnet,
    )
    .unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

pub fn make_test_commitment_tx() -> bitcoin::Transaction {
    let input = TxIn {
        previous_output: BitcoinOutPoint {
            txid: Default::default(),
            vout: 0,
        },
        script_sig: Script::new(),
        sequence: 0,
        witness: vec![],
    };
    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![input],
        output: vec![TxOut {
            script_pubkey: payload_for_p2wpkh(&make_test_bitcoin_pubkey(1).key).script_pubkey(),
            value: 300,
        }],
    }
}

pub const TEST_NODE_CONFIG: NodeConfig = NodeConfig {
    key_derivation_style: KeyDerivationStyle::Native,
};

pub const TEST_SEED: &[&str] = &[
    "6c696768746e696e672d31000000000000000000000000000000000000000000",
    "6c696768746e696e672d32000000000000000000000000000000000000000000",
];

pub const TEST_CHANNEL_ID: &[&str] =
    &["0a78009591722cc84825ca95ee7ffa52428047ed12c9076044ebfe8665f9657f"]; // TEST_SEED[1], "nonce1"

fn script_for_p2wpkh(key: &PublicKey) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(&WPubkeyHash::hash(&key.serialize())[..])
        .into_script()
}

pub fn build_tx_scripts(
    keys: &TxCreationKeys,
    to_broadcaster_value_sat: u64,
    to_countersignatory_value_sat: u64,
    htlcs: &Vec<HTLCOutputInCommitment>,
    channel_parameters: &DirectedChannelTransactionParameters,
) -> Result<Vec<Script>, ()> {
    let countersignatory_pubkeys = channel_parameters.countersignatory_pubkeys();
    let contest_delay = channel_parameters.contest_delay();

    let mut txouts: Vec<(TxOut, (Option<HTLCOutputInCommitment>, Script))> = Vec::new();

    if to_countersignatory_value_sat > 0 {
        let script = script_for_p2wpkh(&countersignatory_pubkeys.payment_point);
        txouts.push((
            TxOut {
                script_pubkey: script.clone(),
                value: to_countersignatory_value_sat,
            },
            (None, Script::new()),
        )) // NOT TESTED
    }

    if to_broadcaster_value_sat > 0 {
        let redeem_script = get_revokeable_redeemscript(
            &keys.revocation_key,
            contest_delay,
            &keys.broadcaster_delayed_payment_key,
        );
        txouts.push((
            TxOut {
                script_pubkey: redeem_script.to_v0_p2wsh(),
                value: to_broadcaster_value_sat,
            },
            (None, redeem_script),
        ));
    }

    for htlc in htlcs {
        let script = get_htlc_redeemscript(&htlc, &keys);
        let txout = TxOut {
            script_pubkey: script.to_v0_p2wsh(),
            value: htlc.amount_msat / 1000,
        };
        txouts.push((txout, (Some(htlc.clone()), script)));
    }

    // Sort output in BIP-69 order (amount, scriptPubkey).  Tie-breaks based on HTLC
    // CLTV expiration height.
    sort_outputs(&mut txouts, |a, b| {
        // BEGIN NOT TESTED
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
        // END NOT TESTED
    });

    let mut scripts = Vec::with_capacity(txouts.len());
    for (_, (_, script)) in txouts.drain(..) {
        scripts.push(script);
    }
    Ok(scripts)
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, hex::Error> {
    Vec::from_hex(s)
}

pub fn hex_encode(o: &[u8]) -> String {
    o.to_hex()
}
