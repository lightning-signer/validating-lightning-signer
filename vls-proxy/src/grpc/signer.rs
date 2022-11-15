use super::hsmd::{self, PingRequest, SignerRequest, SignerResponse};
use crate::tx_util::spend_delayed_outputs;
use crate::util::integration_test_seed_or_generate;
use crate::util::{make_validator_factory, read_allowlist};
use bitcoind_client::{explorer_from_url, BlockExplorerType};
use http::Uri;
use lightning_signer::bitcoin::hashes::hex::ToHex;
use lightning_signer::bitcoin::psbt::serialize::Serialize;
use lightning_signer::bitcoin::Network;
use lightning_signer::channel::{ChannelBase, ChannelSlot};
use lightning_signer::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning_signer::lightning::chain::transaction::OutPoint;
use lightning_signer::node::{NodeServices, ToStringForNetwork};
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::persist::SeedPersist;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::util::status::Status;
use lightning_signer_server::persist::kv_json::KVJsonPersister;
use log::{debug, error, info, warn};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use url::Url;
use vls_protocol_signer::handler::{Error, Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

/// Signer binary entry point for local integration test
#[tokio::main(worker_threads = 2)]
pub async fn start_signer_localhost(port: u16) {
    let loopback = Ipv4Addr::LOCALHOST;
    let addr = SocketAddrV4::new(loopback, port);
    let uri = Uri::builder()
        .scheme("http")
        .authority(addr.to_string().as_str())
        .path_and_query("/")
        .build()
        .expect("uri"); // infallible by construction

    let network = Network::Regtest; // FIXME
    let integration_test = true;
    connect("remote_hsmd.kv", uri, network, integration_test).await;
    info!("signer stopping");
}

/// Signer binary entry point
#[tokio::main(worker_threads = 2)]
pub async fn start_signer(datadir: &str, uri: Uri, network: Network, integration_test: bool) {
    info!("signer starting on {} connecting to {}", network, uri);
    connect(datadir, uri, network, integration_test).await;
    info!("signer stopping");
}

#[tokio::main(worker_threads = 2)]
pub async fn recover_close(
    datadir: &str,
    network: Network,
    block_explorer_type: BlockExplorerType,
    block_explorer_rpc: Option<Url>,
    address: &str,
) {
    let root_handler = make_handler(datadir, network, false);
    let node = root_handler.node();
    node.set_allowlist(&[address.to_string()]).expect("add destination to allowlist");
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
    let destination = node.allowables()[0].clone();
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

fn make_handler(datadir: &str, network: Network, integration_test: bool) -> RootHandler {
    let data_path = format!("{}/{}", datadir, network.to_string());
    let persister = Arc::new(KVJsonPersister::new(&data_path));
    let seed_persister = Arc::new(FileSeedPersister::new(&data_path));
    let seed = get_or_generate_seed(network, seed_persister, integration_test);
    let allowlist = read_allowlist();
    let starting_time_factory = ClockStartingTimeFactory::new();
    let validator_factory = make_validator_factory(network);
    let clock = Arc::new(StandardClock());
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let handler_builder =
        RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist.clone());
    let (root_handler, _muts) = handler_builder.build();

    root_handler
}

// NOTE - For this signer mode it is easier to use the ALLOWLIST file to maintain the
// allowlist. Replace existing entries w/ the current ALLOWLIST file contents.
fn reset_allowlist(root_handler: &RootHandler, allowlist: &Vec<String>) {
    let node = root_handler.node();
    node.set_allowlist(&allowlist).expect("allowlist");
    info!("allowlist={:?}", node.allowlist().expect("allowlist"));
}

async fn connect(datadir: &str, uri: Uri, network: Network, integration_test: bool) {
    let mut client = hsmd::hsmd_client::HsmdClient::connect(uri).await.expect("client connect");
    let result = client.ping(PingRequest { message: "hello".to_string() }).await.expect("ping");
    let reply = result.into_inner();
    info!("ping result {}", reply.message);
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let root_handler = make_handler(datadir, network, integration_test);
    reset_allowlist(&root_handler, &read_allowlist());

    let mut request_stream = client.signer_stream(response_stream).await.unwrap().into_inner();

    while let Some(item) = request_stream.next().await {
        match item {
            Ok(request) => {
                let request_id = request.request_id;
                let response = handle(request, &root_handler);
                match response {
                    Ok(response) => {
                        let res = sender.send(response).await;
                        if res.is_err() {
                            error!("stream closed");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("received error from handler: {:?}", e);
                        let response = SignerResponse {
                            request_id,
                            message: vec![],
                            error: format!("{:?}", e),
                        };
                        let res = sender.send(response).await;
                        if res.is_err() {
                            error!("stream closed");
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                error!("error on stream: {}", e);
                break;
            }
        }
    }
}

fn get_or_generate_seed(
    network: Network,
    seed_persister: Arc<dyn SeedPersist>,
    integration_test: bool,
) -> [u8; 32] {
    if let Some(seed) = seed_persister.get("node") {
        info!("loaded seed");
        seed.as_slice().try_into().expect("seed length in storage")
    } else {
        if network == Network::Bitcoin || !integration_test {
            info!("generating new seed");
            // for mainnet, we generate our own seed
            let seed = generate_seed();
            seed_persister.put("node", &seed);
            seed
        } else {
            // for testnet, we allow the test framework to optionally supply the seed
            let seed = integration_test_seed_or_generate();
            seed_persister.put("node", &seed);
            seed
        }
    }
}

fn handle(request: SignerRequest, root_handler: &RootHandler) -> StdResult<SignerResponse, Error> {
    let msg = msgs::from_vec(request.message)?;
    info!(
        "signer got request {} dbid {} - {:?}",
        request.request_id,
        request.context.as_ref().map(|c| c.dbid).unwrap_or(0),
        msg
    );
    let reply = if let Some(context) = request.context {
        if context.dbid > 0 {
            let peer = PubKey(
                context
                    .peer_id
                    .try_into()
                    .map_err(|_| Error::SigningError(Status::invalid_argument("peer id")))?,
            );
            let handler = root_handler.for_new_client(context.dbid, peer, context.dbid);
            handler.handle(msg)?
        } else {
            root_handler.handle(msg)?
        }
    } else {
        root_handler.handle(msg)?
    };
    info!("signer sending reply {} - {:?}", request.request_id, reply);
    // TODO handle memorized mutations
    let (res, _muts) = reply;
    Ok(SignerResponse {
        request_id: request.request_id,
        message: res.as_vec(),
        error: String::new(),
    })
}
