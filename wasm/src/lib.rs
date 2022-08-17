#[macro_use]
extern crate log;

use std::str::FromStr;
use std::time::Duration;

use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::{ecdsa::Signature as BitcoinSignature, PublicKey};
use bitcoin::{Network, OutPoint};
use lightning::ln::chan_utils::ChannelPublicKeys;
use log::LevelFilter;
use wasm_bindgen::prelude::*;
use web_sys;

use lightning_signer::channel::{ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::node::{Node, NodeConfig, NodeServices};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::util::clock::ManualClock;
use lightning_signer::util::key_utils::make_test_key;
use lightning_signer::Arc;
use lightning_signer::{bitcoin, lightning};

use crate::console_log::setup_log;
use crate::utils::set_panic_hook;
use lightning_signer::util::status::Status;

mod console_log;
mod utils;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen(js_name = "ChannelId")]
pub struct JSChannelId(ChannelId);

#[wasm_bindgen(js_class = "ChannelId")]
impl JSChannelId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("ChannelId({})", self.0.as_slice().to_hex())
    }
}

#[wasm_bindgen]
pub struct Signature(Vec<u8>);

#[wasm_bindgen]
impl Signature {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("Signature({})", self.0.to_hex())
    }
}

impl From<BitcoinSignature> for Signature {
    fn from(s: BitcoinSignature) -> Self {
        Signature(s.serialize_compact().to_vec())
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub enum JSCommitmentType {
    // no longer supported - Legacy,
    StaticRemoteKey,
    Anchors,
}

#[wasm_bindgen(js_name = "OutPoint")]
#[derive(Copy, Clone)]
pub struct JSOutPoint(OutPoint);

#[wasm_bindgen(js_class = "OutPoint")]
impl JSOutPoint {
    #[wasm_bindgen]
    pub fn default() -> JSOutPoint {
        JSOutPoint(OutPoint::default())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("outpoint({})", self.0.to_string())
    }
}

#[wasm_bindgen(js_name = "PublicKey")]
#[derive(Copy, Clone)]
pub struct JSPublicKey(PublicKey);

#[wasm_bindgen(js_class = "PublicKey")]
impl JSPublicKey {
    #[wasm_bindgen]
    pub fn new_test_key(i: u8) -> JSPublicKey {
        JSPublicKey(make_test_key(i).0)
    }
}

#[wasm_bindgen(js_name = "ChannelPublicKeys")]
#[derive(Copy, Clone)]
pub struct JSChannelPublicKeys {
    funding_pubkey: PublicKey,
    revocation_basepoint: PublicKey,
    payment_point: PublicKey,
    delayed_payment_basepoint: PublicKey,
    htlc_basepoint: PublicKey,
}

#[wasm_bindgen(js_class = "ChannelPublicKeys")]
impl JSChannelPublicKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        funding_pubkey: JSPublicKey,
        revocation_basepoint: JSPublicKey,
        payment_point: JSPublicKey,
        delayed_payment_basepoint: JSPublicKey,
        htlc_basepoint: JSPublicKey,
    ) -> Self {
        JSChannelPublicKeys {
            funding_pubkey: funding_pubkey.0,
            revocation_basepoint: revocation_basepoint.0,
            payment_point: payment_point.0,
            delayed_payment_basepoint: delayed_payment_basepoint.0,
            htlc_basepoint: htlc_basepoint.0,
        }
    }
}

#[wasm_bindgen(js_name = "ChannelSetup")]
pub struct JSChannelSetup {
    pub is_outbound: bool,
    pub channel_value_sat: u64,
    pub push_value_msat: u64,
    pub funding_outpoint: JSOutPoint,
    pub holder_selected_contest_delay: u16,
    // pub holder_shutdown_script: Option<Script>,
    pub counterparty_points: JSChannelPublicKeys,
    pub counterparty_selected_contest_delay: u16,
    // pub counterparty_shutdown_script: Option<Script>,
    pub commitment_type: JSCommitmentType,
}

#[wasm_bindgen(js_class = "ChannelSetup")]
impl JSChannelSetup {
    #[wasm_bindgen(constructor)]
    pub fn new(
        is_outbound: bool,
        channel_value_sat: u64,
        push_value_msat: u64,
        funding_outpoint: JSOutPoint,
        holder_selected_contest_delay: u16,
        counterparty_points: JSChannelPublicKeys,
        counterparty_selected_contest_delay: u16,
    ) -> Self {
        JSChannelSetup {
            is_outbound,
            channel_value_sat,
            push_value_msat,
            funding_outpoint,
            holder_selected_contest_delay,
            counterparty_points,
            counterparty_selected_contest_delay,
            commitment_type: JSCommitmentType::StaticRemoteKey,
        }
    }
}

#[wasm_bindgen(js_name = "Node")]
pub struct JSNode {
    node: Arc<Node>,
}

#[wasm_bindgen(js_name = "ValidationError")]
pub struct JSValidationError {
    message: String,
}

#[wasm_bindgen(js_class = "ValidationError")]
impl JSValidationError {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.message.clone()
    }
}

#[wasm_bindgen(js_class = "Node")]
impl JSNode {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("node({})", self.node.get_id().to_string())
    }

    #[wasm_bindgen]
    pub fn new_channel(&self) -> JSChannelId {
        let (channel_id, _) = self.node.new_channel(None, &self.node).unwrap();
        JSChannelId(channel_id)
    }

    pub fn ready_channel(&self, id: &JSChannelId, s: &JSChannelSetup) -> Result<(), JsValue> {
        let p = s.counterparty_points;
        let cp_points = ChannelPublicKeys {
            funding_pubkey: p.funding_pubkey,
            revocation_basepoint: p.revocation_basepoint,
            payment_point: p.payment_point,
            delayed_payment_basepoint: p.delayed_payment_basepoint,
            htlc_basepoint: p.htlc_basepoint,
        };
        let setup = ChannelSetup {
            is_outbound: s.is_outbound,
            channel_value_sat: s.channel_value_sat,
            push_value_msat: s.push_value_msat,
            funding_outpoint: s.funding_outpoint.0,
            holder_selected_contest_delay: s.holder_selected_contest_delay,
            holder_shutdown_script: None,
            counterparty_points: cp_points,
            counterparty_selected_contest_delay: s.counterparty_selected_contest_delay,
            counterparty_shutdown_script: None,
            commitment_type: CommitmentType::Legacy,
        };
        let _channel =
            self.node.ready_channel(id.0.clone(), None, setup, &vec![]).map_err(from_status)?;
        Ok(())
    }

    pub fn sign_holder_commitment(
        &self,
        channel_id: &JSChannelId,
        commit_num: u64,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
    ) -> Result<Signature, JsValue> {
        self.node
            .with_ready_channel(&channel_id.0, |chan| {
                chan.sign_holder_commitment_tx_phase2_redundant(
                    commit_num,
                    0, // feerate not used
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                    vec![],
                )
                .map(|p| p.0.into())
            })
            .map_err(|s| from_status(s).into())
    }
}

fn from_status(s: Status) -> JSValidationError {
    JSValidationError { message: s.message().to_string() }
}

#[wasm_bindgen]
pub fn make_node() -> JSNode {
    let config =
        NodeConfig { network: Network::Testnet, key_derivation_style: KeyDerivationStyle::Native };
    let mut seed = [0u8; 32];
    randomize_buffer(&mut seed);

    let starting_time_factory = RandomStartingTimeFactory::new();

    // TODO remove in production :)
    debug!("SEED {}", seed.to_hex());
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let clock = Arc::new(ManualClock::new(Duration::ZERO));
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let node = Node::new(config, &seed, vec![], services);
    JSNode { node: Arc::new(node) }
}

#[wasm_bindgen]
pub fn setup() {
    set_panic_hook();
    setup_log();
}

#[cfg(target_arch = "wasm32")]
fn randomize_buffer(seed: &mut [u8; 32]) {
    use web_sys::{window, Crypto};

    let window = window().expect("window");
    let crypto: Crypto = window.crypto().expect("crypto");
    crypto.get_random_values_with_u8_array(seed).expect("random");
}

#[cfg(not(target_arch = "wasm32"))]
fn randomize_buffer(_seed: &mut [u8; 32]) {
    // TODO
}

/// A starting time factory which uses random entropy
struct RandomStartingTimeFactory {}

#[cfg(target_arch = "wasm32")]
impl StartingTimeFactory for RandomStartingTimeFactory {
    // LDK: KeysManager: starting_time isn't strictly required to actually be a time, but it must
    // absolutely, without a doubt, be unique to this instance
    fn starting_time(&self) -> (u64, u32) {
        use web_sys::{window, Crypto};
        let window = window().expect("window");
        let crypto: Crypto = window.crypto().expect("crypto");
        let mut secs_bytes = [0u8; 8];
        let mut nanos_bytes = [0u8; 4];
        crypto.get_random_values_with_u8_array(&mut secs_bytes).expect("random");
        crypto.get_random_values_with_u8_array(&mut nanos_bytes).expect("random");
        (u64::from_le_bytes(secs_bytes), u32::from_le_bytes(nanos_bytes))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StartingTimeFactory for RandomStartingTimeFactory {
    fn starting_time(&self) -> (u64, u32) {
        // TODO
        (1, 1)
    }
}

impl RandomStartingTimeFactory {
    pub fn new() -> Arc<dyn StartingTimeFactory> {
        Arc::new(RandomStartingTimeFactory {})
    }
}

#[wasm_bindgen]
pub fn set_log_level(level: String) {
    log::set_max_level(LevelFilter::from_str(&level).expect("level name"));
}

#[wasm_bindgen]
pub fn greet() {
    web_sys::console::log_1(&format!("here1").into());
}
