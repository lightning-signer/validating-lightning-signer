/// Direct access signer in the same process
pub mod direct;

use crate::tx_util::create_spending_transaction;
use bitcoind_client::{explorer_from_url, BlockExplorerType};
use lightning_signer::bitcoin::hashes::hex::ToHex;
use lightning_signer::bitcoin::psbt::serialize::Serialize;
use lightning_signer::bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning_signer::bitcoin::{Network, Script, Transaction, Witness};
use lightning_signer::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning_signer::lightning::chain::transaction::OutPoint;
use lightning_signer::node::{Allowable, SpendType, ToStringForNetwork};
use lightning_signer::util::status::Status;
use log::{debug, info, warn};
use url::Url;

/// Iterator
pub struct Iter<T: RecoverySign> {
    signers: Vec<T>,
}

impl<T: RecoverySign> Iterator for Iter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.signers.pop()
    }
}

/// Provide enough signer functionality to force-close all channels in a node
pub trait RecoveryKeys {
    type Signer: RecoverySign;
    fn iter(&self) -> Iter<Self::Signer>;
    fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        ipaths: &Vec<Vec<u32>>,
        values_sat: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status>;
}

/// Provide enough signer functionality to force-close a channel
pub trait RecoverySign {
    fn sign_holder_commitment_tx_for_recovery(
        &self,
    ) -> Result<(Transaction, Vec<Transaction>, Script, (SecretKey, Vec<Vec<u8>>), PublicKey), Status>;
    fn funding_outpoint(&self) -> OutPoint;
    fn counterparty_selected_contest_delay(&self) -> u16;
    fn get_per_commitment_point(&self) -> Result<PublicKey, Status>;
}

#[tokio::main(worker_threads = 2)]
pub async fn recover_close<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    address: &str,
    keys: R,
) {
    let explorer_client = match block_explorer_rpc {
        Some(url) => Some(explorer_from_url(network, block_explorer_type, url).await),
        None => None,
    };

    let mut sweeps = Vec::new();

    for signer in keys.iter() {
        println!("# funding {:?}", signer.funding_outpoint());

        let (tx, htlc_txs, revocable_script, uck, revocation_pubkey) =
            signer.sign_holder_commitment_tx_for_recovery().expect("sign");
        debug!("closing tx {:?}", &tx);
        info!("closing txid {}", tx.txid());
        if let Some(bitcoind_client) = &explorer_client {
            let funding_confirms = bitcoind_client
                .get_utxo_confirmations(&signer.funding_outpoint())
                .await
                .expect("get_txout for funding");
            if funding_confirms.is_some() {
                info!(
                    "channel is open ({} confirms), broadcasting force-close {}",
                    funding_confirms.unwrap(),
                    tx.txid()
                );
                bitcoind_client.broadcast_transaction(&tx).await.expect("failed to broadcast");
            } else {
                let required_confirms = signer.counterparty_selected_contest_delay();
                info!(
                    "channel is already closed, check outputs, waiting until {} confirms",
                    required_confirms
                );
                for (idx, out) in tx.output.iter().enumerate() {
                    let script = out.script_pubkey.clone();
                    if script == revocable_script {
                        info!("our revocable output {} @ {}", out.value, idx);
                        let out_point = OutPoint { txid: tx.txid(), index: idx as u16 };
                        let confirms = bitcoind_client
                            .get_utxo_confirmations(&out_point)
                            .await
                            .expect("get_txout for our output");
                        if let Some(confirms) = confirms {
                            info!("revocable output is unspent ({} confirms)", confirms);
                            if confirms >= required_confirms as u64 {
                                info!("revocable output is mature, broadcasting sweep");
                                let to_self_delay = signer.counterparty_selected_contest_delay();
                                let descriptor = DelayedPaymentOutputDescriptor {
                                    outpoint: out_point,
                                    per_commitment_point: signer
                                        .get_per_commitment_point()
                                        .expect("commitment point"),
                                    to_self_delay,
                                    output: tx.output[idx].clone(),
                                    revocation_pubkey,
                                    channel_keys_id: [0; 32], // unused
                                    channel_value_satoshis: 0,
                                };
                                sweeps.push((descriptor, uck.clone()));
                            } else {
                                warn!(
                                    "revocable output is immature ({} < {})",
                                    confirms, required_confirms
                                );
                            }
                        } else {
                            info!("revocable output is spent, skipping");
                        }
                    }
                }
            }
        } else {
            println!("tx: {}", tx.serialize().to_hex());
            for htlc_tx in htlc_txs {
                println!("HTLC tx: {}", htlc_tx.txid());
            }
        }
    }

    let wallet_path = vec![];
    let destination = Allowable::from_str(address, network).expect("address");
    info!("sweeping to {}", destination.to_string(network));
    let output_script = destination.to_script().expect("script");
    for (descriptor, uck) in sweeps {
        let feerate = 1000;
        let sweep_tx = spend_delayed_outputs(
            &keys,
            &[descriptor],
            uck,
            output_script.clone(),
            wallet_path.clone(),
            feerate,
        );
        debug!("sweep tx {:?}", &sweep_tx);
        info!("sweep txid {}", sweep_tx.txid());
        if let Some(bitcoind_client) = &explorer_client {
            bitcoind_client.broadcast_transaction(&sweep_tx).await.expect("failed to broadcast");
        }
    }
}

fn spend_delayed_outputs<R: RecoveryKeys>(
    keys: &R,
    descriptors: &[DelayedPaymentOutputDescriptor],
    unilateral_close_key: (SecretKey, Vec<Vec<u8>>),
    output_script: Script,
    opath: Vec<u32>,
    feerate_sat_per_1000_weight: u32,
) -> Transaction {
    let mut tx =
        create_spending_transaction(descriptors, output_script, feerate_sat_per_1000_weight)
            .expect("create_spending_transaction");
    let spendtypes = descriptors.iter().map(|_| SpendType::P2wsh).collect();
    let values_sat = descriptors.iter().map(|d| d.output.value).collect();
    let ipaths = descriptors.iter().map(|_| vec![]).collect();
    let uniclosekeys = descriptors.iter().map(|_| Some(unilateral_close_key.clone())).collect();
    let witnesses = keys
        .sign_onchain_tx(&tx, &ipaths, &values_sat, &spendtypes, uniclosekeys, &vec![opath])
        .expect("sign");
    assert_eq!(witnesses.len(), tx.input.len());
    for (idx, w) in witnesses.into_iter().enumerate() {
        tx.input[idx].witness = Witness::from_vec(w);
    }
    tx
}
