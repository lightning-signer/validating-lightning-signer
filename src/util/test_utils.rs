use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::constants::Network;
use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::keysinterface;
use chain::transaction::OutPoint;
use lightning::chain;
use lightning::chain::keysinterface::ChannelKeys;
use lightning::ln;
use lightning::util::logger::{Level, Logger, Record};
use ln::channelmonitor;
use ln::channelmonitor::HTLCUpdate;
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};

use crate::util::enforcing_trait_impls::EnforcingChannelKeys;

pub struct TestVecWriter(pub Vec<u8>);

pub struct TestFeeEstimator {
    pub sat_per_kw: u64,
}

impl chaininterface::FeeEstimator for TestFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u64 {
        self.sat_per_kw
    }
}

pub struct TestChannelMonitor<ChanSigner: ChannelKeys> {
    pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor<ChanSigner>)>>,
    pub simple_monitor: channelmonitor::SimpleManyChannelMonitor<OutPoint, ChanSigner>,
    pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
}

impl<ChanSigner: ChannelKeys> TestChannelMonitor<ChanSigner> {
    pub fn new(
        chain_monitor: Arc<chaininterface::ChainWatchInterface>,
        broadcaster: Arc<chaininterface::BroadcasterInterface>,
        logger: Arc<Logger>,
        fee_estimator: Arc<chaininterface::FeeEstimator>,
    ) -> Self {
        Self {
            added_monitors: Mutex::new(Vec::new()),
            simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(
                chain_monitor,
                broadcaster,
                logger,
                fee_estimator,
            ),
            update_ret: Mutex::new(Ok(())),
        }
    }
}

impl<ChanSigner: ChannelKeys> channelmonitor::ManyChannelMonitor<ChanSigner>
    for TestChannelMonitor<ChanSigner>
{
    fn add_update_monitor(
        &self,
        funding_txo: OutPoint,
        monitor: channelmonitor::ChannelMonitor<ChanSigner>,
    ) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
        self.added_monitors
            .lock()
            .unwrap()
            .push((funding_txo, monitor.clone()));
        assert!(self
            .simple_monitor
            .add_update_monitor(funding_txo, monitor)
            .is_ok());

        self.update_ret.lock().unwrap().clone()
    }

    fn fetch_pending_htlc_updated(&self) -> Vec<HTLCUpdate> {
        return self.simple_monitor.fetch_pending_htlc_updated();
    }
}

pub struct TestBroadcaster {
    pub txn_broadcasted: Mutex<Vec<Transaction>>,
}

impl chaininterface::BroadcasterInterface for TestBroadcaster {
    // BEGIN NOT TESTED
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.txn_broadcasted.lock().unwrap().push(tx.clone());
    }
    // END NOT TESTED
}

pub struct TestLogger {
    level: Level,
    id: String,
    pub lines: Mutex<HashMap<(String, String), usize>>,
}

impl TestLogger {
    // BEGIN NOT TESTED
    pub fn new() -> TestLogger {
        Self::with_id("".to_owned())
    }
    // END NOT TESTED
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

pub struct TestKeysInterface {
    backing: keysinterface::KeysManager,
    pub override_session_priv: Mutex<Option<SecretKey>>,
    pub override_channel_id_priv: Mutex<Option<[u8; 32]>>,
}

impl keysinterface::KeysInterface for TestKeysInterface {
    type ChanKeySigner = EnforcingChannelKeys;

    fn get_node_secret(&self) -> SecretKey {
        self.backing.get_node_secret()
    }
    fn get_destination_script(&self) -> Script {
        self.backing.get_destination_script()
    }
    fn get_shutdown_pubkey(&self) -> PublicKey {
        self.backing.get_shutdown_pubkey()
    }
    fn get_channel_keys(
        &self,
        channel_id: [u8; 32],
        inbound: bool,
        channel_value_satoshis: u64,
    ) -> EnforcingChannelKeys {
        EnforcingChannelKeys::new(self.backing.get_channel_keys(
            channel_id,
            inbound,
            channel_value_satoshis,
        ))
    }

    fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
        match *self.override_session_priv.lock().unwrap() {
            Some(key) => (key.clone(), [0; 32]),
            None => self.backing.get_onion_rand(),
        }
    }

    fn get_channel_id(&self) -> [u8; 32] {
        match *self.override_channel_id_priv.lock().unwrap() {
            Some(key) => key.clone(),
            None => self.backing.get_channel_id(),
        }
    }
}

impl TestKeysInterface {
    pub fn new(seed: &[u8; 32], network: Network, logger: Arc<Logger>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        Self {
            backing: keysinterface::KeysManager::new(
                seed,
                network,
                logger,
                now.as_secs(),
                now.subsec_nanos(),
            ),
            override_session_priv: Mutex::new(None),
            override_channel_id_priv: Mutex::new(None),
        }
    }
}

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
// END NOT TESTED

// BEGIN NOT TESTED
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
