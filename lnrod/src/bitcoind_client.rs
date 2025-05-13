use std::collections::HashMap;
use std::convert::TryInto;
use std::iter::FromIterator;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use log::{debug, error, info, warn};

use anyhow::{anyhow, Result};
use bitcoin::address::Address;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, BlockHash};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning_block_sync::http::JsonResponse;
use lightning_block_sync::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource};
use lightning_signer::bitcoin::blockdata::constants::ChainHash;
use lightning_signer::bitcoin::Network;
use lightning_signer::{bitcoin, lightning};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::convert::{BlockchainInfo, FundedTx, RawTx, SignedTx};
use jsonrpc_async::error as rpc_error;
use jsonrpc_async::simple_http::SimpleHttpTransport;
use jsonrpc_async::Client;
use lightning_signer::lightning::routing::utxo::{UtxoLookup, UtxoResult};
use url::Url;

// TODO why are we using tokio mutexes here?
#[derive(Clone)]
pub struct BitcoindClient {
    rpc: Arc<Mutex<Client>>,
    url: Url,
    fees: Arc<HashMap<ConfirmationTarget, AtomicU32>>,
    queued_transactions: Arc<Mutex<Vec<Transaction>>>,
    latest_tip: Arc<Mutex<BlockHash>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    JsonRpc(jsonrpc_async::error::Error),
    Json(serde_json::error::Error),
    Io(std::io::Error),
}

impl From<jsonrpc_async::error::Error> for Error {
    fn from(e: jsonrpc_async::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

impl BitcoindClient {
    pub async fn new(
        host: String,
        port: u16,
        rpc_user: String,
        rpc_password: String,
        rpc_path: String,
    ) -> std::io::Result<Self> {
        let url_s = format!("http://{}:{}{}", host, port, rpc_path);
        let mut url = Url::parse(&url_s).expect("bitcoin RPC URL");
        url.set_username(&rpc_user).unwrap();
        url.set_password(Some(&rpc_password)).unwrap();
        println!("Connecting to bitcoind at {}", url);
        let mut builder = SimpleHttpTransport::builder().url(&url_s).await.unwrap();
        builder = builder.auth(rpc_user, Some(rpc_password));
        let rpc = Client::with_transport(builder.build());

        let mut fees: HashMap<ConfirmationTarget, AtomicU32> = HashMap::new();
        fees.insert(ConfirmationTarget::UrgentOnChainSweep, AtomicU32::new(5000));
        fees.insert(ConfirmationTarget::MinAllowedAnchorChannelRemoteFee, AtomicU32::new(3));
        fees.insert(ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee, AtomicU32::new(3));
        fees.insert(ConfirmationTarget::AnchorChannelFee, AtomicU32::new(253));
        fees.insert(ConfirmationTarget::NonAnchorChannelFee, AtomicU32::new(2000));
        fees.insert(ConfirmationTarget::ChannelCloseMinimum, AtomicU32::new(253));
        fees.insert(ConfirmationTarget::MaximumFeeEstimate, AtomicU32::new(5000));

        let client = Self {
            rpc: Arc::new(Mutex::new(rpc)),
            url,
            fees: Arc::new(fees),
            queued_transactions: Arc::new(Mutex::new(Vec::new())),
            latest_tip: Arc::new(Mutex::new(BlockHash::all_zeros())),
        };
        // Fast fail if any connectivity issue
        client.get_blockchain_info().await;
        Ok(client)
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub async fn create_raw_transaction(&self, outputs: HashMap<String, u64>) -> RawTx {
        let outs_converted =
            serde_json::to_value([serde_json::Map::from_iter(outputs.iter().map(|(k, v)| {
                (k.clone(), serde_json::Value::from(Amount::from_sat(*v).to_btc()))
            }))])
            .unwrap();

        self.call_into("createrawtransaction", &vec![json!([]), outs_converted]).await.unwrap()
    }

    pub async fn fund_raw_transaction(&self, raw_tx: RawTx) -> FundedTx {
        self.call_into("fundrawtransaction", &vec![json!(raw_tx.0)]).await.unwrap()
    }

    pub async fn sign_raw_transaction_with_wallet(&self, tx_hex: String) -> SignedTx {
        self.call_into("signrawtransactionwithwallet", &vec![json!(tx_hex)]).await.unwrap()
    }

    pub async fn get_new_address(&self, label: String, network: Network) -> Address {
        let addr: String = self.call("getnewaddress", &vec![json!(label)]).await.unwrap();
        let unchecked_addr = Address::from_str(addr.as_str()).unwrap();
        unchecked_addr.require_network(network).unwrap()
    }

    pub async fn set_label(&self, address: Address, label: String) {
        let _: () = self.call("setlabel", &vec![json!(address), json!(label)]).await.unwrap();
    }

    pub async fn get_blockchain_info(&self) -> BlockchainInfo {
        self.call_into("getblockchaininfo", &[]).await.unwrap()
    }

    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        let rpc = self.rpc.lock().await;
        let v_args: Vec<_> = args
            .iter()
            .map(serde_json::value::to_raw_value)
            .collect::<std::result::Result<_, serde_json::Error>>()?;
        let req = rpc.build_request(cmd, &v_args[..]);
        // if log_enabled!(Debug) {
        // 	debug!(target: "bitcoincore_rpc", "JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));
        // }

        let resp = rpc.send_request(req).await.map_err(Error::from);
        // log_response(cmd, &resp);
        Ok(resp.map_err(|e| anyhow!("RPC call failed: {:?}", e))?.result()?)
    }

    async fn call_into<T>(&self, cmd: &str, args: &[serde_json::Value]) -> Result<T>
    where
        JsonResponse: TryInto<T, Error = std::io::Error>,
    {
        let value: Value = self.call(cmd, args).await?;
        Ok(JsonResponse(value).try_into()?)
    }

    async fn on_new_block(&self, info: &BlockchainInfo) {
        let queue: Vec<Transaction> = { self.queued_transactions.lock().await.drain(..).collect() };
        info!("on_new_block height {} with {} queued txs", info.latest_height, queue.len());
        for tx in queue.iter() {
            self.broadcast_transactions(&[tx]);
        }
    }
}

impl FeeEstimator for BitcoindClient {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        self.fees
            .get(&confirmation_target)
            .unwrap_or_else(|| {
                panic!("there should be a fee estimate for  {:?}", &confirmation_target)
            })
            .load(Ordering::Acquire)
    }
}

impl BroadcasterInterface for BitcoindClient {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        for tx_ref in txs {
            let tx = (*tx_ref).clone();
            info!("before broadcast txid {}", tx.compute_txid());
            debug!("before broadcast tx {:?}", tx);
            let rpc = Arc::clone(&self.rpc);
            let queue = Arc::clone(&self.queued_transactions);
            let ser = hex::encode(serialize(&tx));
            tokio::spawn(async move {
                let result: Result<String, _> = {
                    let rpc = rpc.lock().await;
                    let raw_args = [serde_json::value::to_raw_value(&json![ser]).unwrap()];
                    let req = rpc.build_request("sendrawtransaction", &raw_args);
                    rpc.send_request(req).await.map_err(Error::from).unwrap().result()
                };

                match result {
                    Ok(txid) => {
                        info!("broadcast {}", txid);
                    }
                    Err(rpc_error::Error::Rpc(e)) =>
                        if e.code == -26 {
                            warn!("non-final {}, will retry, for {}", e.message, ser);
                            queue.lock().await.push(tx.clone());
                        } else {
                            error!("RPC error on broadcast: {:?} for {}", e, ser)
                        },
                    Err(e) => {
                        error!("could not broadcast: {} for {}", e, ser)
                    }
                }
            });
        }
    }
}

impl UtxoLookup for BitcoindClient {
    fn get_utxo(&self, _genesis_hash: &ChainHash, _short_channel_id: u64) -> UtxoResult {
        // apparently this is unused
        unimplemented!()
    }
}

impl BlockSource for BitcoindClient {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            Ok(self.call_into("getblockheader", &[json!(header_hash.to_string())]).await.unwrap())
        })
    }

    fn get_block<'a>(
        &'a self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, BlockData> {
        Box::pin(async move {
            Ok(BlockData::FullBlock(
                self.call_into("getblock", &[json!(header_hash.to_string()), json!(0)])
                    .await
                    .unwrap(),
            ))
        })
    }

    fn get_best_block(&self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async move {
            let info = self.get_blockchain_info().await;
            let mut latest_tip = self.latest_tip.lock().await;
            if info.latest_blockhash != *latest_tip {
                self.on_new_block(&info).await;
                *latest_tip = info.latest_blockhash;
            }
            Ok((info.latest_blockhash, Some(info.latest_height as u32)))
        })
    }
}
