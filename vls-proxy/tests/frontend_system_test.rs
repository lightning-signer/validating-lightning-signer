//! System test for the frontend.
//!
//! The default regtest version spins up bitcoind and runs an e2e test.
//!
//! You can also run it against testnet:
//!     cargo run --bin frontend-system-test --features system-test -- --network testnet --rpc http://user:pass@127.0.0.1:18332

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{All, Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::{BlockHash, Network};
use bitcoind_client::{BitcoindClient, BlockchainInfo};
use clap::Parser;
use core::result::Result as CoreResult;
use lightning_signer::bitcoin;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::node::{Heartbeat, SignedHeartbeat};
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::txoo::proof::TxoProof;
use lightning_signer::util::crypto_utils::sighash_from_heartbeat;
use lightning_signer::util::test_utils::MockListener;
use log::*;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use url::Url;
use vls_frontend::frontend::DummySourceFactory;
use vls_frontend::Frontend;
use vls_protocol::model;
use vls_protocol::msgs;
use vls_protocol::msgs::{
    AddBlockReply, ForwardWatchesReply, GetHeartbeatReply, Message, NodeInfoReply, SerBolt,
    TipInfoReply,
};
use vls_protocol::serde_bolt::{to_vec, Array, Octets, WireString};
use vls_protocol_client::{ClientResult, SignerPort};
use vls_proxy::config::CLAP_NETWORK_URL_MAPPING;
use vls_proxy::portfront::SignerPortFront;
use vls_proxy::util::{abort_on_panic, setup_logging};

struct State {
    height: u32,
    block_hash: BlockHash,
    tracker: ChainTracker<MockListener>,
}

#[derive(Clone)]
struct DummySignerPort {
    secp: Secp256k1<All>,
    node_id: PublicKey,
    xpriv: Xpriv,
    xpub: Xpub,
    state: Arc<Mutex<State>>,
}

const NODE_SECRET: [u8; 32] = [3u8; 32];

impl DummySignerPort {
    fn new(network: Network) -> Self {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&NODE_SECRET).unwrap();
        let node_id = PublicKey::from_secret_key(&secp, &secret_key);
        let xpriv = Xpriv::new_master(network, &[0; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let validator_factory = SimpleValidatorFactory::new();
        let tracker =
            ChainTracker::for_network(network, node_id, Arc::new(validator_factory), vec![]);
        let block_hash = tracker.tip().0.block_hash();
        let height = tracker.height;

        let state = State { height, block_hash, tracker };

        Self { secp, node_id, xpriv, xpub, state: Arc::new(Mutex::new(state)) }
    }

    fn assert_state(&self, height: u32, block_hash: BlockHash) -> bool {
        let state = self.state.lock().unwrap();
        state.height == height && state.block_hash == block_hash
    }

    fn height(&self) -> u32 {
        let state = self.state.lock().unwrap();
        state.height
    }
}

#[async_trait]
impl SignerPort for DummySignerPort {
    async fn handle_message(&self, message_bytes: Vec<u8>) -> ClientResult<Vec<u8>> {
        let message = msgs::from_vec(message_bytes).unwrap();
        match message {
            Message::NodeInfo(_) => {
                let reply = NodeInfoReply {
                    network_name: WireString("regtest".as_bytes().to_vec()),
                    node_id: model::PubKey(self.node_id.serialize()),
                    bip32: model::ExtKey(self.xpub.encode()),
                };
                Ok(reply.as_vec())
            }
            Message::TipInfo(_) => {
                let state = self.state.lock().unwrap();
                let reply = TipInfoReply { height: state.height, block_hash: state.block_hash };
                Ok(reply.as_vec())
            }
            Message::ForwardWatches(_) => {
                let reply = ForwardWatchesReply { txids: Array::new(), outpoints: Array::new() };
                Ok(reply.as_vec())
            }
            Message::AddBlock(add) => {
                let mut state = self.state.lock().unwrap();
                state.height += 1;
                let header: BlockHeader = deserialize(&add.header.0).unwrap();
                trace!("header {:?}", header);
                let proof: TxoProof = add.unspent_proof.unwrap().0;
                state.tracker.add_block(header, proof).expect("add block failed");
                state.block_hash = header.block_hash();
                let reply = AddBlockReply {};
                Ok(reply.as_vec())
            }
            Message::GetHeartbeat(_) => {
                let state = self.state.lock().unwrap();
                let heartbeat = Heartbeat {
                    chain_tip: state.block_hash,
                    chain_height: state.height,
                    chain_timestamp: 0,
                    current_timestamp: 0,
                };
                let kp = Keypair::from_secret_key(&self.secp, &self.xpriv.private_key);
                let ser_heartbeat = heartbeat.encode();
                let msg = sighash_from_heartbeat(&ser_heartbeat);
                let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &kp);
                let signed_heartbeat = SignedHeartbeat { signature: sig[..].to_vec(), heartbeat };

                let reply =
                    GetHeartbeatReply { heartbeat: Octets(to_vec(&signed_heartbeat).unwrap()) };
                Ok(reply.as_vec())
            }
            m => {
                panic!("unhandled {:?}", m);
            }
        }
    }

    fn is_ready(&self) -> bool {
        true
    }
}

async fn await_until<EF>(mut f: impl FnMut() -> bool, err_f: EF) -> Result<()>
where
    EF: FnOnce(),
{
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    while !f() {
        if start.elapsed() > timeout {
            err_f();
            return Err(anyhow!("await_until timeout"));
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[derive(Debug, Parser)]
#[clap()]
struct Args {
    #[clap(short, long, value_parser,
    value_name = "NETWORK",
    value_parser = Network::from_str,
    default_value = "regtest",
    )]
    pub network: Network,
    #[clap(
        long,
        value_parser,
        help = "block explorer/bitcoind RPC endpoint - used for broadcasting recovery transactions",
        default_value_ifs(CLAP_NETWORK_URL_MAPPING),
        value_name = "URL"
    )]
    pub rpc: Option<Url>,
    #[clap(long, help = "do not capture logs")]
    nocapture: bool,
}

#[tokio::test]
async fn frontend_system_test() -> Result<()> {
    abort_on_panic();
    let tmpdir = tempfile::tempdir()?;
    setup_logging(tmpdir.path().to_str().unwrap(), "system-test", "debug");
    let args = Args::parse();

    match args.network {
        Network::Regtest => run_regtest(tmpdir).await?,
        n => run_with_network(tmpdir, n, args.rpc.unwrap()).await?,
    }
    Ok(())
}

async fn run_with_network(tmpdir: TempDir, network: Network, url: Url) -> Result<()> {
    println!("running with network {} rpc {}", network, url);
    let (_shutdown_trigger, shutdown_signal) = triggered::trigger();
    let client = BitcoindClient::new(url.clone()).await;
    let info = get_info(&client).await?;
    let signer_port = Arc::new(DummySignerPort::new(network));
    let source_factory = Arc::new(DummySourceFactory::new(tmpdir.path(), network));
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port.clone(), network)),
        source_factory,
        url,
        shutdown_signal.clone(),
    );
    frontend.start();
    loop {
        sleep(Duration::from_millis(5000)).await;
        let height = signer_port.state.lock().unwrap().height;
        println!("at height {}", height);
        if height >= info.latest_height as u32 {
            break;
        }
    }
    Ok(())
}

async fn run_regtest(tmpdir: TempDir) -> Result<()> {
    let network = Network::Regtest;
    let url: Url = "http://user:pass@127.0.0.1:18443".parse()?;
    let client = BitcoindClient::new(url.clone()).await;
    let info = get_info(&client).await?;
    let mut height = info.latest_height as u32;

    // ignore error, might already exist
    let _: CoreResult<Value, _> = client.call("createwallet", &[json!("default")]).await;

    let address: String = client.call("getnewaddress", &[]).await?;

    info!("mine to {}", address);
    let block_hash = mine(&client, &address, 1).await?;
    height += 1;

    let (_shutdown_trigger, shutdown_signal) = triggered::trigger();
    let signer_port = Arc::new(DummySignerPort::new(network));
    let source_factory = Arc::new(DummySourceFactory::new(tmpdir.path(), network));
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port.clone(), network)),
        source_factory,
        url,
        shutdown_signal.clone(),
    );
    frontend.start();

    await_until(
        || signer_port.assert_state(height, block_hash),
        || error!("signer at height {} vs {}", signer_port.height(), height),
    )
    .await?;

    height += 1;
    info!("mine height {}", height);
    let block_hash = mine(&client, &address, 1).await?;

    await_until(
        || signer_port.assert_state(height, block_hash),
        || error!("signer at height {} vs {}", signer_port.height(), height),
    )
    .await?;
    Ok(())
}

async fn mine(client: &BitcoindClient, address: &str, blocks: u32) -> Result<BlockHash> {
    let hashes: Value = client.call("generatetoaddress", &[json!(blocks), json!(address)]).await?;
    Ok(BlockHash::from_str(&hashes[0].as_str().unwrap())?)
}

async fn get_info(client: &BitcoindClient) -> Result<BlockchainInfo> {
    let info = client.get_blockchain_info().await?;
    println!("{:?}", info);
    Ok(info)
}
