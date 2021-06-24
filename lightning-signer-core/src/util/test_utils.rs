use crate::Map;
use crate::{Arc, Mutex};
use core::cmp;

use bitcoin;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::hash_types::Txid;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey, SignOnly};
use bitcoin::{Address, OutPoint as BitcoinOutPoint, TxIn, TxOut};
use chain::chaininterface;
use lightning::chain;
use lightning::chain::channelmonitor::MonitorEvent;
use lightning::chain::keysinterface::{BaseSign, InMemorySigner};
use lightning::chain::transaction::OutPoint;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::ln::chan_utils::{
    get_htlc_redeemscript, get_revokeable_redeemscript, make_funding_redeemscript,
    ChannelPublicKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
    DirectedChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::util::test_utils;

use crate::node::{ChannelId, ChannelSetup, CommitmentType, Node, NodeConfig};
use crate::signer::multi_signer::{channel_nonce_to_id, MultiSigner, SpendType};
use crate::signer::my_keys_manager::KeyDerivationStyle;
use crate::tx::tx::sort_outputs;
use crate::util::crypto_utils::{payload_for_p2wpkh, payload_for_p2wsh};
use crate::util::enforcing_trait_impls::EnforcingSigner;
use crate::util::loopback::LoopbackChannelSigner;
use crate::util::status::Status;

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
        &SecretKey::from_slice(&hex::decode(h).unwrap()[..]).unwrap(),
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
    seed.copy_from_slice(hex::decode(seedstr).unwrap().as_slice());
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

pub struct TestFundingNodeContext {
    pub secp_ctx: Secp256k1<secp256k1::SignOnly>,
    pub signer: MultiSigner,
    pub node_id: PublicKey,
    pub node: Arc<Node>,
}

pub struct TestFundingChannelContext {
    pub setup: ChannelSetup,
    pub channel_id: ChannelId,
}

pub struct TestFundingTxContext {
    pub inputs: Vec<TxIn>,
    pub ipaths: Vec<Vec<u32>>,
    pub ivals: Vec<u64>,
    pub ispnds: Vec<SpendType>,
    pub iuckeys: Vec<Option<SecretKey>>,
    pub outputs: Vec<TxOut>,
    pub opaths: Vec<Vec<u32>>,
}

pub fn funding_tx_node_ctx() -> TestFundingNodeContext {
    let secp_ctx = Secp256k1::signing_only();
    let signer = MultiSigner::new();
    let node_id = init_node(&signer, TEST_NODE_CONFIG, TEST_SEED[1]);
    let node = signer.get_node(&node_id).unwrap();
    TestFundingNodeContext {
        secp_ctx,
        signer,
        node_id,
        node,
    }
}

pub fn funding_tx_chan_ctx(
    node_ctx: &TestFundingNodeContext,
    nn: usize,
) -> TestFundingChannelContext {
    let setup = make_test_channel_setup();
    let channel_nonce0 = format!("nonce{}", nn).as_bytes().to_vec();
    let channel_id = channel_nonce_to_id(&channel_nonce0);
    node_ctx
        .signer
        .new_channel(&node_ctx.node_id, Some(channel_nonce0), Some(channel_id))
        .expect("new_channel");
    TestFundingChannelContext { setup, channel_id }
}

pub fn funding_tx_ctx() -> TestFundingTxContext {
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
    node_ctx: &TestFundingNodeContext,
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
    node_ctx: &TestFundingNodeContext,
    chan_ctx: &TestFundingChannelContext,
    tx_ctx: &mut TestFundingTxContext,
    value_sat: u64,
) -> u32 {
    let ndx = tx_ctx.outputs.len();
    tx_ctx.outputs.push(make_test_funding_channel_outpoint(
        &node_ctx.signer,
        &node_ctx.node_id,
        &chan_ctx.setup,
        &chan_ctx.channel_id,
        value_sat,
    ));
    tx_ctx.opaths.push(vec![]);
    ndx as u32
}

pub fn funding_tx_add_unknown_output(
    node_ctx: &TestFundingNodeContext,
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

pub fn funding_tx_from_ctx(tx_ctx: &TestFundingTxContext) -> bitcoin::Transaction {
    make_test_funding_tx_with_ins_outs(tx_ctx.inputs.clone(), tx_ctx.outputs.clone())
}

pub fn funding_tx_ready_channel(
    node_ctx: &TestFundingNodeContext,
    chan_ctx: &mut TestFundingChannelContext,
    tx: &bitcoin::Transaction,
    vout: u32,
) {
    // Replace the funding outpoint placeholder.
    let txid = tx.txid();
    chan_ctx.setup.funding_outpoint = BitcoinOutPoint { txid, vout };

    node_ctx
        .node
        .ready_channel(chan_ctx.channel_id, None, chan_ctx.setup.clone())
        .expect("Channel");
}

pub fn funding_tx_sign(
    node_ctx: &TestFundingNodeContext,
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
    node_ctx: &TestFundingNodeContext,
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
