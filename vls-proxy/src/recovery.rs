use crate::tx_util::spend_delayed_outputs;
use bitcoind_client::{explorer_from_url, BlockExplorerType};
use lightning_signer::bitcoin::hashes::hex::ToHex;
use lightning_signer::bitcoin::psbt::serialize::Serialize;
use lightning_signer::bitcoin::Network;
use lightning_signer::channel::{ChannelBase, ChannelSlot};
use lightning_signer::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning_signer::lightning::chain::transaction::OutPoint;
use lightning_signer::node::{Allowable, Node, ToStringForNetwork};
use log::{debug, info, warn};
use std::sync::Arc;
use url::Url;

#[tokio::main(worker_threads = 2)]
pub async fn recover_close(
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    address: &str,
    node: Arc<Node>,
) {
    println!("allowlist {:?}", node.allowlist());
    let channels = node.channels();
    let explorer_client = match block_explorer_rpc {
        Some(url) => Some(explorer_from_url(network, block_explorer_type, url).await),
        None => None,
    };

    let mut sweeps = Vec::new();

    for (id, chan) in channels.iter() {
        let mut slot = chan.lock().unwrap();
        if let ChannelSlot::Ready(channel) = &mut *slot {
            println!("# funding {:?}", channel.keys.funding_outpoint());

            let (tx, htlc_txs, revocable_script, uck, revocation_pubkey) =
                channel.sign_holder_commitment_tx_for_recovery().expect("sign");
            debug!("closing tx {:?}", &tx);
            info!("closing txid {}", tx.txid());
            if let Some(bitcoind_client) = &explorer_client {
                let funding_confirms = bitcoind_client
                    .get_utxo_confirmations(channel.keys.funding_outpoint())
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
                    let required_confirms = channel.setup.counterparty_selected_contest_delay;
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
                                    let to_self_delay =
                                        channel.setup.counterparty_selected_contest_delay;
                                    let descriptor = DelayedPaymentOutputDescriptor {
                                        outpoint: out_point,
                                        per_commitment_point: channel
                                            .get_per_commitment_point(
                                                channel.enforcement_state.next_holder_commit_num
                                                    - 1,
                                            )
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
        } else {
            println!("# channel {} was not open, skipping", id);
        }
    }

    drop(channels);

    let wallet_path = vec![];
    let destination = Allowable::from_str(address, network).expect("address");
    info!("sweeping to {}", destination.to_string(network));
    let output_script = destination.to_script().expect("script");
    for (descriptor, uck) in sweeps {
        let feerate = 1000;
        let sweep_tx = spend_delayed_outputs(
            &node,
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
