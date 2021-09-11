use bitcoin::{Network, OutPoint};
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::chan_utils::ChannelPublicKeys;
use wasm_bindgen::prelude::*;
use web_sys;

use lightning_signer::Arc;
use lightning_signer::channel::{ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::{bitcoin, lightning};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::util::key_utils::{make_test_counterparty_points, make_test_key};

use crate::utils::set_panic_hook;

mod utils;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub struct JSChannelId(ChannelId);

#[wasm_bindgen]
impl JSChannelId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("ChannelId({})", self.0.0.to_hex())
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub enum JSCommitmentType {
    // no longer supported - Legacy,
    StaticRemoteKey,
    Anchors,
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct JSOutPoint(OutPoint);

#[wasm_bindgen]
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

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct JSPublicKey(PublicKey);

#[wasm_bindgen]
impl JSPublicKey {
    #[wasm_bindgen]
    pub fn new_test_key(i: u8) -> JSPublicKey {
        JSPublicKey(make_test_key(i).0)
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct JSChannelPublicKeys {
    funding_pubkey: PublicKey,
    revocation_basepoint: PublicKey,
    payment_point: PublicKey,
    delayed_payment_basepoint: PublicKey,
    htlc_basepoint: PublicKey,
}

#[wasm_bindgen]
impl JSChannelPublicKeys {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let keys = make_test_counterparty_points();
        JSChannelPublicKeys {
            funding_pubkey: keys.funding_pubkey,
            revocation_basepoint: keys.revocation_basepoint,
            payment_point: keys.payment_point,
            delayed_payment_basepoint: keys.delayed_payment_basepoint,
            htlc_basepoint: keys.htlc_basepoint
        }
    }
}

#[wasm_bindgen]
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

#[wasm_bindgen]
impl JSChannelSetup {
    #[wasm_bindgen(constructor)]
    pub fn new(cp_keys: JSChannelPublicKeys, funding_outpoint: JSOutPoint) -> Self {
        JSChannelSetup {
            is_outbound: false,
            channel_value_sat: 10000,
            push_value_msat: 0,
            funding_outpoint,
            holder_selected_contest_delay: 6,
            counterparty_points: cp_keys,
            counterparty_selected_contest_delay: 6,
            commitment_type: JSCommitmentType::StaticRemoteKey
        }
    }
}

#[wasm_bindgen]
pub struct JSNode {
    node: Arc<Node>
}

#[wasm_bindgen]
impl JSNode {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("node({})", self.node.get_id().to_string())
    }

    #[wasm_bindgen]
    pub fn new_channel(&self) -> JSChannelId {
        let (channel_id, _) = self.node.new_channel(None, None, &self.node).unwrap();
        JSChannelId(channel_id)
    }

    pub fn ready_channel(&self, id: JSChannelId, s: JSChannelSetup) -> Result<(), JsValue> {
        let p = s.counterparty_points;
        let cp_points = ChannelPublicKeys {
            funding_pubkey: p.funding_pubkey,
            revocation_basepoint: p.revocation_basepoint,
            payment_point: p.payment_point,
            delayed_payment_basepoint: p.delayed_payment_basepoint,
            htlc_basepoint: p.htlc_basepoint
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
            commitment_type: CommitmentType::Legacy
        };
        let channel = self.node
            .ready_channel(
                id.0,
                None,
                setup,
                &vec![],
            ).map_err(|e| JsValue::from(e.message()))?;
        Ok(())
    }
}

#[wasm_bindgen]
pub fn make_node() -> JSNode {
    let config = NodeConfig {
        key_derivation_style: KeyDerivationStyle::Native,
    };
    let mut seed = [0u8; 32];
    randomize_buffer(&mut seed);
    println!("{}", seed.to_hex());
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister);
    let node = Node::new(config, &seed, Network::Testnet, &persister, vec![]);
    JSNode { node: Arc::new(node) }
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

#[wasm_bindgen]
pub fn greet() {
    web_sys::console::log_1(&format!("here1").into());
}