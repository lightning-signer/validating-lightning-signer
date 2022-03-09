use alloc::string::ToString;
use alloc::vec::Vec;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, OutPoint, PrivateKey, Txid};
use cortex_m_semihosting::hprintln;

use lightning_signer::channel::{ChannelSetup, CommitmentType};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::util::key_utils::make_test_counterparty_points;
use lightning_signer::Arc;

pub fn make_test_channel_setup() -> ChannelSetup {
    ChannelSetup {
        is_outbound: true,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: OutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points: make_test_counterparty_points(),
        counterparty_selected_contest_delay: 7,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub fn test_lightning_signer(postscript: fn()) {
    let config = NodeConfig {
        network: bitcoin::Network::Signet,
        key_derivation_style: KeyDerivationStyle::Native,
    };
    let seed = [0u8; 32];
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let validator_factory = Arc::new(SimpleValidatorFactory::new());
    let node = Arc::new(Node::new(config, &seed, &persister, Vec::new(), validator_factory));
    let (channel_id, _) = node.new_channel(None, None, &node).unwrap();
    hprintln!("stub channel ID: {}", channel_id).unwrap();
    let holder_shutdown_key_path = Vec::new();
    let channel = node
        .ready_channel(channel_id, None, make_test_channel_setup(), &holder_shutdown_key_path)
        .expect("ready_channel");
    hprintln!("channel ID: {}", channel.id0).unwrap();
    postscript();
}

pub fn test_bitcoin() {
    // Load a private key
    let raw = "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D";
    let pk = PrivateKey::from_wif(raw).unwrap();
    hprintln!("Seed WIF: {}", pk).unwrap();

    let secp = Secp256k1::new();

    // Derive address
    let pubkey = pk.public_key(&secp);
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();
    hprintln!("Address: {}", address).unwrap();

    assert_eq!(address.to_string(), "bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993".to_string());
}
