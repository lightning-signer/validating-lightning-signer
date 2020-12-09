use std::cmp;
use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin;
use bitcoin::{OutPoint as BitcoinOutPoint, TxOut};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::hash_types::Txid;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};
use chain::chaininterface;
use lightning::chain;
use lightning::chain::{chainmonitor, channelmonitor};
use lightning::chain::channelmonitor::MonitorEvent;
use lightning::chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};
use lightning::chain::transaction::OutPoint;
use lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters, DirectedChannelTransactionParameters, get_htlc_redeemscript, get_revokeable_redeemscript, HTLCOutputInCommitment, TxCreationKeys};
use lightning::util::logger::{Level, Logger, Record};
use lightning::util::test_utils;

use crate::node::node::{ChannelSetup, CommitmentType, NodeConfig};
use crate::server::my_keys_manager::{KeyDerivationStyle, MyKeysManager};
use crate::tx::tx::sort_outputs;
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;
use crate::util::loopback::LoopbackChannelSigner;

pub struct TestLogger {
    level: Level,
    id: String,
    pub lines: Mutex<HashMap<(String, String), usize>>,
}

impl TestLogger {
    pub fn new() -> TestLogger {
        Self::with_id("".to_owned())
    }
    pub fn with_id(id: String) -> TestLogger {
        TestLogger {
            level: Level::Trace,
            id,
            lines: Mutex::new(HashMap::new()),
        }
    }
    // BEGIN NOT TESTED
    pub fn enable(&mut self, level: Level) {
        self.level = level;
    }
    pub fn assert_log(&self, module: String, line: String, count: usize) {
        let log_entries = self.lines.lock().unwrap();
        assert_eq!(log_entries.get(&(module, line)), Some(&count));
    }
    // END NOT TESTED
}

impl Logger for TestLogger {
    fn log(&self, record: &Record) {
        *self
            .lines
            .lock()
            .unwrap()
            .entry((record.module_path.to_string(), format!("{}", record.args)))
            .or_insert(0) += 1;
        if self.level >= record.level {
            println!(
                "{:<5} {} [{} : {}, {}] {}",
                record.level.to_string(),
                self.id,
                record.module_path,
                record.file,
                record.line,
                record.args
            );
        }
    }
}

pub struct TestPersister {
    pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>
}

impl TestPersister {
    pub fn new() -> Self {
        Self {
            update_ret: Mutex::new(Ok(()))
        }
    }

    pub fn set_update_ret(&self, ret: Result<(), channelmonitor::ChannelMonitorUpdateErr>) {
        *self.update_ret.lock().unwrap() = ret;
    }
}

impl channelmonitor::Persist<LoopbackChannelSigner> for TestPersister {
    fn persist_new_channel(&self, _funding_txo: OutPoint, _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.update_ret.lock().unwrap().clone()
    }

    fn update_persisted_channel(&self, _funding_txo: OutPoint, _update: &channelmonitor::ChannelMonitorUpdate, _data: &channelmonitor::ChannelMonitor<LoopbackChannelSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.update_ret.lock().unwrap().clone()
    }
}

pub struct TestChainMonitor<'a> {
    pub added_monitors: Mutex<Vec<(OutPoint, ())>>,
    pub latest_monitor_update_id: Mutex<HashMap<[u8; 32], (OutPoint, u64)>>,
    pub chain_monitor: chainmonitor::ChainMonitor<LoopbackChannelSigner, &'a test_utils::TestChainSource, &'a chaininterface::BroadcasterInterface, &'a test_utils::TestFeeEstimator, &'a test_utils::TestLogger, &'a channelmonitor::Persist<LoopbackChannelSigner>>,
    pub update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
    // If this is set to Some(), after the next return, we'll always return this until update_ret
    // is changed:
    pub next_update_ret: Mutex<Option<Result<(), channelmonitor::ChannelMonitorUpdateErr>>>,
}
impl<'a> TestChainMonitor<'a> {
    pub fn new(chain_source: Option<&'a test_utils::TestChainSource>, broadcaster: &'a chaininterface::BroadcasterInterface, logger: &'a test_utils::TestLogger, fee_estimator: &'a test_utils::TestFeeEstimator, persister: &'a channelmonitor::Persist<LoopbackChannelSigner>) -> Self {
        Self {
            added_monitors: Mutex::new(Vec::new()),
            latest_monitor_update_id: Mutex::new(HashMap::new()),
            chain_monitor: chainmonitor::ChainMonitor::new(chain_source, broadcaster, logger, fee_estimator, persister),
            update_ret: Mutex::new(None),
            next_update_ret: Mutex::new(None),
        }
    }
}
impl<'a> chain::Watch for TestChainMonitor<'a> {
    type Keys = LoopbackChannelSigner;

    fn watch_channel(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor<LoopbackChannelSigner>) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, monitor.get_latest_update_id()));
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

    fn update_channel(&self, funding_txo: OutPoint, update: channelmonitor::ChannelMonitorUpdate) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.latest_monitor_update_id.lock().unwrap().insert(funding_txo.to_channel_id(), (funding_txo, update.update_id));
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

    fn release_pending_monitor_events(&self) -> Vec<MonitorEvent> {
        return self.chain_monitor.release_pending_monitor_events();
    }
}

// END NOT TESTED

pub fn pubkey_from_secret_hex(h: &str, secp_ctx: &Secp256k1<SignOnly>) -> PublicKey {
    PublicKey::from_secret_key(
        secp_ctx,
        &SecretKey::from_slice(&hex::decode(h).unwrap()[..]).unwrap(),
    )
}

// BEGIN NOT TESTED

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

// END NOT TESTED

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

// FIXME - this channel setup is unreasonably small, 300 is less than dust limit ...
pub fn make_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 300,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_to_self_delay: 5,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_to_self_delay: 5,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::Legacy,
    }
}

pub fn make_static_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 300,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_to_self_delay: 5,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_to_self_delay: 5,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub fn make_reasonable_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        holder_to_self_delay: 5,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_to_self_delay: 5,
        counterparty_shutdown_script: Script::new(),
        commitment_type: CommitmentType::Legacy,
    }
}

pub fn make_test_channel_keys() -> EnforcingChannelKeys {
    let secp_ctx = Secp256k1::signing_only();
    let channel_value_sat = 3_000_000;
    let mut inmemkeys = InMemoryChannelKeys::new(
        &secp_ctx,
        make_test_privkey(1), // funding_key
        make_test_privkey(2), // revocation_base_key
        make_test_privkey(3), // payment_key
        make_test_privkey(4), // delayed_payment_base_key
        make_test_privkey(5), // htlc_base_key
        [4u8; 32],            // commitment_seed
        channel_value_sat,
        MyKeysManager::derivation_params(),
    );
    // This needs to match make_test_channel_setup above.
    inmemkeys.ready_channel(&ChannelTransactionParameters {
        holder_pubkeys: inmemkeys.pubkeys().clone(),
        holder_selected_contest_delay: 5,
        is_outbound_from_holder: true,
        counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
            pubkeys: make_test_counterparty_points(),
            selected_contest_delay: 5
        }),
        funding_outpoint: Some(OutPoint { txid: Default::default(), index: 0 })
    });
    EnforcingChannelKeys::new(inmemkeys)
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
    Builder::new().push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(&WPubkeyHash::hash(&key.serialize())[..])
        .into_script()
}

pub fn build_tx_scripts(keys: &TxCreationKeys, to_broadcaster_value_sat: u64, to_countersignatory_value_sat: u64, htlcs: &mut Vec<HTLCOutputInCommitment>, channel_parameters: &DirectedChannelTransactionParameters) -> Result<Vec<Script>, ()> {
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
        ))
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
        if let &(Some(ref a_htlcout), _) = a {
            if let &(Some(ref b_htlcout), _) = b {
                a_htlcout.cltv_expiry.cmp(&b_htlcout.cltv_expiry)
                    // Note that due to hash collisions, we have to have a fallback comparison
                    // here for fuzztarget mode (otherwise at least chanmon_fail_consistency
                    // may fail)!
                    .then(a_htlcout.payment_hash.0.cmp(&b_htlcout.payment_hash.0))
                // For non-HTLC outputs, if they're copying our SPK we don't really care if we
                // close the channel due to mismatches - they're doing something dumb:
            } else { cmp::Ordering::Equal }
        } else { cmp::Ordering::Equal }
    });

    let mut scripts = Vec::with_capacity(txouts.len());
    for (_, (_, script)) in txouts.drain(..) {
        scripts.push(script);
    }
    Ok(scripts)
}

