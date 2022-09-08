use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use bitcoin::bech32::{u5, FromBase32, ToBase32};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, OutPoint, PrivateKey, Txid, Witness};
use bitcoin::{PackedLockTime, Script, Sequence, TxIn, TxOut};
#[cfg(feature = "device")]
use cortex_m_semihosting::hprintln;
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
use lightning_signer::bitcoin;
use lightning_signer::channel::{Channel, ChannelBase, ChannelSetup, CommitmentType};
use lightning_signer::lightning;
use lightning_signer::lightning_invoice::{
    Currency, InvoiceBuilder, RawDataPart, RawHrp, RawInvoice, SignedRawInvoice,
};
use lightning_signer::node::{Node, NodeConfig, NodeServices, SpendType};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::StartingTimeFactory;
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::util::clock::ManualClock;
use lightning_signer::wallet::Wallet;
use lightning_signer::Arc;

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

pub struct FixedStartingTimeFactory {
    starting_time_secs: u64,
    starting_time_nanos: u32,
}

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

fn make_test_funding_tx(
    node: &Node,
    inputs: Vec<TxIn>,
    value: u64,
) -> (Vec<u32>, bitcoin::Transaction) {
    let opath = vec![0];
    let change_addr = node.get_native_address(&opath).unwrap();
    make_test_funding_tx_with_change(inputs, value, opath, &change_addr)
}

fn make_test_funding_tx_with_change(
    inputs: Vec<TxIn>,
    value: u64,
    opath: Vec<u32>,
    change_addr: &Address,
) -> (Vec<u32>, bitcoin::Transaction) {
    let outputs = vec![TxOut { value, script_pubkey: change_addr.script_pubkey() }];
    let tx = make_test_funding_tx_with_ins_outs(inputs, outputs);
    (opath, tx)
}

pub fn make_test_funding_tx_with_ins_outs(
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

pub fn make_test_channel_setup(
    is_outbound: bool,
    counterparty_points: ChannelPublicKeys,
) -> ChannelSetup {
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

fn make_test_invoice(
    payee: &Arc<Node>,
    description: &str,
    payment_hash: PaymentHash,
) -> SignedRawInvoice {
    let (hrp_bytes, invoice_data) = build_test_invoice(description, &payment_hash);
    let hrp: RawHrp = String::from_utf8(hrp_bytes.to_vec()).expect("utf8").parse().expect("hrp");
    let data = RawDataPart::from_base32(&invoice_data).expect("base32");
    let raw_invoice = RawInvoice { hrp, data };
    let sig = payee.sign_invoice(&hrp_bytes, &invoice_data).unwrap();
    raw_invoice.sign::<_, ()>(|_| Ok(sig)).unwrap()
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
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let starting_time_factory = FixedStartingTimeFactory::new(1, 1);
    let clock = Arc::new(ManualClock::new(Duration::ZERO));
    let services = NodeServices {
        validator_factory: validator_factory.clone(),
        starting_time_factory,
        persister: persister.clone(),
        clock: clock.clone(),
    };
    let node = Arc::new(Node::new(config, &seed, Vec::new(), services.clone()));
    let starting_time_factory2 = FixedStartingTimeFactory::new(2, 2);
    let services2 = NodeServices {
        validator_factory,
        starting_time_factory: starting_time_factory2,
        persister,
        clock,
    };
    let node1 = Arc::new(Node::new(config, &seed1, Vec::new(), services2));

    assert_eq!(node.ecdh(&node1.get_id()), node1.ecdh(&node.get_id()));

    let (channel_id, _) = node.new_channel(None, &node).unwrap();
    let (channel_id1, _) = node1.new_channel(None, &node).unwrap();
    myprintln!("stub channel IDs: {} {}", channel_id, channel_id1);

    sign_funding(&node);

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

    // Fulfill HTLC
    commit_num = 2;
    channel.htlcs_fulfilled(vec![preimage1]);

    next_state(&mut channel, &mut channel1, commit_num, 1_999_000, 1_000_000, vec![], vec![]);

    channel.sign_holder_commitment_tx_phase2(2).unwrap();

    let holder_address = node.get_native_address(&vec![0]).unwrap();
    let counterparty_script = channel1.get_ldk_shutdown_script();

    channel
        .sign_mutual_close_tx_phase2(
            1_999_000,
            1_000_000,
            &Some(holder_address.script_pubkey()),
            &Some(counterparty_script),
            &vec![0],
        )
        .unwrap();

    // these are just to lightly cover these functions
    node.add_allowlist(&vec!["helloworld".to_string()]).expect_err("bad address");
    node.remove_allowlist(&vec!["helloworld".to_string()]).expect_err("bad address");
    node.sign_node_announcement(&vec![]).unwrap();
    node.sign_channel_update(&vec![]).unwrap();
    channel.sign_channel_announcement(&vec![]);

    postscript();
}

fn sign_funding(node: &Arc<Node>) {
    let ipaths = vec![vec![0u32], vec![1u32]];
    let ival0 = 100u64;
    let ival1 = 300u64;
    let chanamt = 300u64;
    let values_sat = vec![ival0, ival1];

    let input1 = TxIn {
        previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
        script_sig: Script::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };

    let input2 = TxIn {
        previous_output: OutPoint { txid: Txid::all_zeros(), vout: 1 },
        script_sig: Script::new(),
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    };
    let (opath, tx) = make_test_funding_tx(&node, vec![input1, input2], chanamt);
    let spendtypes = vec![SpendType::P2wpkh, SpendType::P2wpkh];
    let uniclosekeys = vec![None, None];

    let witvec = node
        .sign_onchain_tx(&tx, &ipaths, &values_sat, &spendtypes, uniclosekeys, &vec![opath])
        .expect("good sigs");
    assert_eq!(witvec.len(), 2);
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

    if commit_num > 0 {
        let revoke = channel.get_per_commitment_secret(commit_num - 1).unwrap();
        let revoke1 = channel1.get_per_commitment_secret(commit_num - 1).unwrap();
        channel1.validate_counterparty_revocation(commit_num - 1, &revoke).unwrap();
        channel.validate_counterparty_revocation(commit_num - 1, &revoke1).unwrap();
    }
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
