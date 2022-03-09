use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, OutPoint, PrivateKey, Txid};
#[cfg(feature = "device")]
use cortex_m_semihosting::hprintln;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::bech32::{u5, FromBase32, ToBase32};
use lightning_signer::bitcoin::{secp256k1, SigHashType};
use lightning_signer::bitcoin::secp256k1::SecretKey;
use lightning_signer::channel::{Channel, ChannelBase, ChannelSetup, CommitmentType};
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning_signer::lightning::util::invoice::construct_invoice_preimage;
use lightning_signer::lightning_invoice::{
    Currency, InvoiceBuilder, RawDataPart, RawHrp, RawInvoice, SignedRawInvoice,
};
use lightning_signer::node::{Node, NodeConfig};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::Arc;
use lightning_signer::util::crypto_utils::bitcoin_vec_to_signature;

#[cfg(feature = "device")]
macro_rules! myprintln {
    () => {{
        hprintln!().unwrap()
    }};
    ($s:expr) => {
        hprintln!($s).unwrap()
    };
    ($s:expr, $($tt:tt)*) => {{
        hprintln!($s, $($tt)*).unwrap()
    }};
}

#[cfg(not(feature = "device"))]
macro_rules! myprintln {
    () => {{
        println!();
    }};
    ($($tt:tt)*) => {{
        println!($($tt)*);
    }};
}

pub fn make_test_channel_setup(is_outbound: bool, counterparty_points: ChannelPublicKeys) -> ChannelSetup {
    ChannelSetup {
        is_outbound,
        channel_value_sat: 3_000_000,
        push_value_msat: 0,
        funding_outpoint: OutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
        holder_selected_contest_delay: 6,
        holder_shutdown_script: None,
        counterparty_points,
        counterparty_selected_contest_delay: 6,
        counterparty_shutdown_script: None,
        commitment_type: CommitmentType::StaticRemoteKey,
    }
}

pub(crate) fn do_sign_invoice(
    payee_key: &SecretKey,
    hrp_bytes: &[u8],
    invoice_data: &[u5],
) -> SignedRawInvoice {
    let hrp: RawHrp = String::from_utf8(hrp_bytes.to_vec()).expect("utf8").parse().expect("hrp");
    let data = RawDataPart::from_base32(invoice_data).expect("base32");
    let raw_invoice = RawInvoice { hrp, data };

    let invoice_preimage = construct_invoice_preimage(&hrp_bytes, &invoice_data);
    let secp_ctx = Secp256k1::signing_only();
    let hash = Sha256Hash::hash(&invoice_preimage);
    let message = secp256k1::Message::from_slice(&hash).unwrap();
    let sig = secp_ctx.sign_recoverable(&message, payee_key);

    raw_invoice.sign::<_, ()>(|_| Ok(sig)).unwrap()
}

fn make_test_invoice(
    payee: &Arc<Node>,
    description: &str,
    payment_hash: PaymentHash,
) -> SignedRawInvoice {
    let (hrp_bytes, invoice_data) = build_test_invoice(description, &payment_hash);
    let key = payee.get_node_secret();
    do_sign_invoice(&key, &hrp_bytes, &invoice_data)
}

fn build_test_invoice(description: &str, payment_hash: &PaymentHash) -> (Vec<u8>, Vec<u5>) {
    let raw_invoice = InvoiceBuilder::new(Currency::Bitcoin)
        .duration_since_epoch(Duration::from_secs(123456789))
        .amount_milli_satoshis(1_000_000_000)
        .payment_hash(Sha256Hash::from_slice(&payment_hash.0).unwrap())
        .payment_secret(PaymentSecret([0; 32]))
        .description(description.to_string())
        .build_raw()
        .expect("build");
    let hrp_str = raw_invoice.hrp.to_string();
    let hrp_bytes = hrp_str.as_bytes().to_vec();
    let invoice_data = raw_invoice.data.to_base32();
    (hrp_bytes, invoice_data)
}

pub fn test_lightning_signer(postscript: fn()) {
    let config = NodeConfig {
        network: bitcoin::Network::Signet,
        key_derivation_style: KeyDerivationStyle::Native,
    };
    let seed = [0u8; 32];
    let seed1 = [1u8; 32];
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let mut policy = make_simple_policy(Network::Testnet);
    policy.require_invoices = true;
    policy.enforce_balance = true;
    let factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let node = Arc::new(Node::new(config, &seed, &persister, Vec::new(), factory.clone()));
    let node1 = Arc::new(Node::new(config, &seed1, &persister, Vec::new(), factory));
    let (channel_id, _) = node.new_channel(None, None, &node).unwrap();
    let (channel_id1, _) = node1.new_channel(None, None, &node).unwrap();
    myprintln!("stub channel ID: {}", channel_id);
    let holder_shutdown_key_path = Vec::new();
    let points = node.get_channel(&channel_id).unwrap().lock().unwrap().get_channel_basepoints();
    let points1 = node1.get_channel(&channel_id1).unwrap().lock().unwrap().get_channel_basepoints();
    let mut channel = node
        .ready_channel(
            channel_id,
            None,
            make_test_channel_setup(true, points1),
            &holder_shutdown_key_path,
        )
        .expect("ready_channel");
    let mut channel1 = node1
        .ready_channel(
            channel_id1,
            None,
            make_test_channel_setup(false, points),
            &holder_shutdown_key_path,
        )
        .expect("ready_channel 1");

    // Initial commitment
    let mut commit_num = 0;
    next_state(&mut channel, &mut channel1, commit_num, 2_999_000, 0, vec![], vec![]);

    // Offer HTLC
    commit_num = 1;
    let preimage1 = PaymentPreimage([0; 32]);
    let hash1 = PaymentHash(Sha256Hash::hash(&preimage1.0).into_inner());

    let invoice = make_test_invoice(&node1, "invoice1", hash1);
    node.add_invoice(invoice).unwrap();
    let htlc = HTLCInfo2 { value_sat: 1_000_000, payment_hash: hash1, cltv_expiry: 50 };
    next_state(&mut channel, &mut channel1, commit_num, 1_999_000, 0, vec![htlc], vec![]);

    channel.htlcs_fulfilled(vec![preimage1]);

    myprintln!("channel ID: {}", channel.id0);
    postscript();
}

fn next_state(
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
    let sig = channel
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
    let sig1 = channel1
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
    channel.validate_holder_commitment_tx_phase2(
        commit_num,
        0,
        to_holder,
        to_counterparty,
        offered.clone(),
        received.clone(),
        &bitcoin_vec_to_signature(&sig1.0, SigHashType::All).unwrap(),
        &sig1.1.into_iter().map(|s| bitcoin_vec_to_signature(&s, SigHashType::All).unwrap()).collect(),
    ).unwrap();
    channel1.validate_holder_commitment_tx_phase2(
        commit_num,
        0,
        to_counterparty,
        to_holder,
        received.clone(),
        offered.clone(),
        &bitcoin_vec_to_signature(&sig.0, SigHashType::All).unwrap(),
        &sig.1.into_iter().map(|s| bitcoin_vec_to_signature(&s, SigHashType::All).unwrap()).collect(),
    ).unwrap();
}

pub fn test_bitcoin() {
    // Load a private key
    let raw = "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D";
    let pk = PrivateKey::from_wif(raw).unwrap();
    myprintln!("Seed WIF: {}", pk);

    let secp = Secp256k1::new();

    // Derive address
    let pubkey = pk.public_key(&secp);
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();
    myprintln!("Address: {}", address);

    assert_eq!(address.to_string(), "bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_test() {
        test_bitcoin();
    }

    #[test]
    fn signer_test() {
        test_lightning_signer(|| {});
    }
}
