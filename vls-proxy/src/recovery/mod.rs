/// Direct access signer in the same process
pub mod direct;

use crate::tx_util::create_spending_transaction;
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Network, Script, Transaction, Witness};
use bitcoind_client::esplora_client::EsploraClient;
use bitcoind_client::{explorer_from_url, BlockExplorerType, Explorer};
use lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning::chain::transaction::OutPoint;
use lightning_signer::bitcoin::{PackedLockTime, Sequence, Txid};
use lightning_signer::node::{Allowable, SpendType, ToStringForNetwork};
use lightning_signer::util::status::Status;
use lightning_signer::{bitcoin, lightning};
use log::*;
use std::collections::BTreeMap;
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

#[derive(serde::Deserialize, Debug, Clone)]
struct UtxoResponse {
    txid: Txid,
    vout: u32,
    value: u64,
}

/// Provide enough signer functionality to force-close all channels in a node
pub trait RecoveryKeys {
    type Signer: RecoverySign;
    fn iter(&self) -> Iter<Self::Signer>;
    fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        segwit_flags: &[bool],
        ipaths: &Vec<Vec<u32>>,
        values_sat: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status>;
    fn wallet_address_native(&self, index: u32) -> Result<Address, Status>;
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
pub async fn recover_l1<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
    max_index: u32,
) {
    match block_explorer_type {
        BlockExplorerType::Esplora => {}
        _ => {
            panic!("only esplora supported for l1 recovery");
        }
    };

    let url = block_explorer_rpc.expect("must have block explorer rpc");
    let esplora = EsploraClient::new(url).await;

    let mut utxos = Vec::new();
    for index in 0..max_index {
        let address = keys.wallet_address_native(index).expect("address");
        utxos.append(
            &mut get_utxos(&esplora, address)
                .await
                .expect("get utxos")
                .into_iter()
                .map(|u| (index, u))
                .collect::<Vec<_>>(),
        );
    }

    if destination == "none" {
        info!("no destination specified, only printing txs");
    }

    let destination_address: Address =
        destination.parse().expect("destination address must be valid");
    assert!(
        destination_address.is_valid_for_network(network),
        "destination address must be valid for network"
    );

    let feerate_per_kw = get_feerate(&esplora).await.expect("get feerate");

    for chunk in utxos.chunks(10) {
        let tx = match make_l1_sweep(&keys, &destination_address, chunk, feerate_per_kw) {
            Some(value) => value,
            None => continue,
        };

        esplora.broadcast_transaction(&tx).await.expect("broadcast tx");
    }
}

// chunk is a list of (derivation-index, utxo)
fn make_l1_sweep<R: RecoveryKeys>(
    keys: &R,
    destination_address: &Address,
    chunk: &[(u32, UtxoResponse)],
    feerate_per_kw: u64,
) -> Option<Transaction> {
    let value = chunk.iter().map(|(_, u)| u.value).sum::<u64>();

    let mut tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: chunk
            .iter()
            .map(|(_, u)| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint { txid: u.txid, vout: u.vout },
                sequence: Sequence::ZERO,
                witness: Witness::default(),
                script_sig: Script::new(),
            })
            .collect(),
        output: vec![bitcoin::TxOut { value, script_pubkey: destination_address.script_pubkey() }],
    };
    let total_fee = feerate_per_kw * tx.weight() as u64 / 1000;
    if total_fee > value - 1000 {
        warn!("not enough value to pay fee {:?}", tx);
        return None;
    }
    tx.output[0].value -= total_fee;
    info!("sending tx {} - {}", tx.txid().to_hex(), tx.serialize().to_hex());

    let ipaths = chunk.iter().map(|(i, _)| vec![*i]).collect::<Vec<_>>();
    let values = chunk.iter().map(|(_, u)| u.value).collect::<Vec<_>>();
    let spendtypes = chunk.iter().map(|_| SpendType::P2wpkh).collect::<Vec<_>>();
    let unicosekeys = chunk.iter().map(|_| None).collect::<Vec<_>>();

    // sign transaction
    let witnesses = keys
        .sign_onchain_tx(&tx, &vec![], &ipaths, &values, &spendtypes, unicosekeys, &vec![vec![]])
        .expect("sign tx");

    for (i, witness) in witnesses.into_iter().enumerate() {
        tx.input[i].witness = Witness::from_vec(witness);
    }
    Some(tx)
}

// get the utxos for an address
async fn get_utxos(esplora: &EsploraClient, address: Address) -> Result<Vec<UtxoResponse>, ()> {
    let utxos: Vec<UtxoResponse> =
        esplora.get(&format!("address/{}/utxo", address)).await.map_err(|e| {
            error!("{}", e);
        })?;
    Ok(utxos)
}

// get the 24-block (4 hour) feerate
async fn get_feerate(esplora: &EsploraClient) -> Result<u64, ()> {
    let fees: BTreeMap<String, f64> = esplora.get("fee-estimates").await.map_err(|e| {
        error!("{}", e);
    })?;
    let feerate = (fees.get("24").expect("feerate") * 1000f64).ceil() as u64;
    Ok(feerate)
}

#[tokio::main(worker_threads = 2)]
pub async fn recover_close<R: RecoveryKeys>(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    destination: &str,
    keys: R,
) {
    let explorer_client = match block_explorer_rpc {
        Some(url) => Some(explorer_from_url(network, block_explorer_type, url).await),
        None => None,
    };

    let mut sweeps = Vec::new();

    for signer in keys.iter() {
        info!("# funding {:?}", signer.funding_outpoint());

        let (tx, htlc_txs, revocable_script, uck, revocation_pubkey) =
            signer.sign_holder_commitment_tx_for_recovery().expect("sign");
        debug!("closing tx {:?}", &tx);
        info!("closing txid {}", tx.txid());
        if let Some(bitcoind_client) = &explorer_client {
            let funding_confirms = bitcoind_client
                .get_utxo_confirmations(&signer.funding_outpoint().into_bitcoin_outpoint())
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
                            .get_utxo_confirmations(&out_point.into_bitcoin_outpoint())
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
            info!("tx: {}", tx.serialize().to_hex());
            for htlc_tx in htlc_txs {
                info!("HTLC tx: {}", htlc_tx.txid());
            }
        }
    }

    if destination == "none" {
        info!("no address specified, not sweeping");
        return;
    }

    let wallet_path = vec![];
    let destination_allowable = Allowable::from_str(destination, network).expect("address");
    info!("sweeping to {}", destination_allowable.to_string(network));
    let output_script = destination_allowable.to_script().expect("script");
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
    let input_txs = vec![]; // only need input txs for funding tx
    let witnesses = keys
        .sign_onchain_tx(
            &tx,
            &input_txs,
            &ipaths,
            &values_sat,
            &spendtypes,
            uniclosekeys,
            &vec![opath],
        )
        .expect("sign");
    assert_eq!(witnesses.len(), tx.input.len());
    for (idx, w) in witnesses.into_iter().enumerate() {
        tx.input[idx].witness = Witness::from_vec(w);
    }
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::direct::DirectRecoveryKeys;
    use lightning_signer::bitcoin::secp256k1::Secp256k1;
    use lightning_signer::util::test_utils::key::make_test_pubkey;
    use lightning_signer::util::test_utils::{
        init_node, make_test_previous_tx, TEST_NODE_CONFIG, TEST_SEED,
    };
    use std::collections::BTreeMap;

    #[ignore]
    #[tokio::test]
    async fn esplora_utxo_test() {
        fern::Dispatch::new().level(LevelFilter::Info).chain(std::io::stdout()).apply().unwrap();
        let address: Address = "19XBuBAa78zccvfFrNWKB6PhnA1mMRASeT".parse().unwrap();
        let esplora = EsploraClient::new("https://blockstream.info/api".parse().unwrap()).await;

        let fees: BTreeMap<String, f64> =
            esplora.get("fee-estimates").await.expect("fee_estimates");
        info!("fees: {:?}", fees);

        let utxos = get_utxos(&esplora, address.clone()).await.expect("get_utxos");
        info!("address {} has {:?}", address, utxos);
    }

    #[test]
    fn l1_sweep_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let pubkey = bitcoin::PublicKey::new(make_test_pubkey(2));
        let address = Address::p2wpkh(&pubkey, Network::Testnet).unwrap();

        node.add_allowlist(&[address.to_string()]).expect("add_allowlist");

        let secp = Secp256k1::signing_only();
        let values = vec![(123, 12345u64, SpendType::P2wpkh)];
        let (input_tx, input_txid) = make_test_previous_tx(&node, &values);
        let utxo = UtxoResponse { txid: input_txid, vout: 0, value: 12345 };

        let keys = DirectRecoveryKeys { node };
        let tx = make_l1_sweep(&keys, &address, &[(123, utxo)], 1000).expect("make_l1_sweep");
        tx.verify(|txo| {
            if txo.txid == input_txid && txo.vout == 0 {
                Some(input_tx.output[0].clone())
            } else {
                None
            }
        })
        .expect("verify");

        // won't verify if we change the input amount
        let utxo = UtxoResponse { txid: input_txid, vout: 0, value: 12346 };
        let tx = make_l1_sweep(&keys, &address, &[(123, utxo)], 1000).expect("make_l1_sweep");
        tx.verify(|txo| {
            if txo.txid == input_txid && txo.vout == 0 {
                Some(input_tx.output[0].clone())
            } else {
                None
            }
        })
        .expect_err("verify");
    }
}
