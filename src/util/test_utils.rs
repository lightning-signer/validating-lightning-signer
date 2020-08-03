use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::OutPoint as BitcoinOutPoint;
use chain::chaininterface;
use chain::chaininterface::ConfirmationTarget;
use chain::keysinterface;
use lightning::chain;
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::util::logger::{Level, Logger, Record};
use lightning::util::ser::Writer;
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};

use crate::node::node::ChannelSetup;
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;

pub struct TestVecWriter(pub Vec<u8>);

// BEGIN NOT TESTED

impl Writer for TestVecWriter {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
    fn size_hint(&mut self, size: usize) {
        self.0.reserve_exact(size);
    }
}

// END NOT TESTED

pub struct TestFeeEstimator {
    pub sat_per_kw: u32,
}

impl chaininterface::FeeEstimator for TestFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u32 {
        self.sat_per_kw
    }
}

pub struct TestBroadcaster {
    pub txn_broadcasted: Mutex<Vec<Transaction>>,
}

impl chaininterface::BroadcasterInterface for TestBroadcaster {
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.txn_broadcasted.lock().unwrap().push(tx.clone());
    }
}

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

pub struct TestKeysInterface {
    backing: keysinterface::KeysManager,
    pub override_session_priv: Mutex<Option<SecretKey>>,
    pub override_channel_id_priv: Mutex<Option<[u8; 32]>>,
}

// BEGIN NOT TESTED

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
    fn get_channel_keys(&self, inbound: bool, channel_value_sat: u64) -> EnforcingChannelKeys {
        EnforcingChannelKeys::new(self.backing.get_channel_keys(inbound, channel_value_sat))
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
    pub fn new(seed: &[u8; 32], network: Network) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        Self {
            backing: keysinterface::KeysManager::new(
                seed,
                network,
                now.as_secs(),
                now.subsec_nanos(),
            ),
            override_session_priv: Mutex::new(None),
            override_channel_id_priv: Mutex::new(None),
        }
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

pub fn make_test_remote_points() -> ChannelPublicKeys {
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
        channel_value_sat: 300,
        push_value_msat: 0,
        funding_outpoint: BitcoinOutPoint {
            txid: Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        },
        local_to_self_delay: 5,
        local_shutdown_script: None,
        remote_points: make_test_remote_points(),
        remote_to_self_delay: 5,
        remote_shutdown_script: Script::new(),
        option_static_remotekey: false,
    }
}

pub const TEST_SEED: &[&str] = &[
    "6c696768746e696e672d31000000000000000000000000000000000000000000",
    "6c696768746e696e672d32000000000000000000000000000000000000000000",
];

pub const TEST_CHANNEL_ID: &[&str] =
    &["0a78009591722cc84825ca95ee7ffa52428047ed12c9076044ebfe8665f9657f"]; // TEST_SEED[1], "nonce1"
