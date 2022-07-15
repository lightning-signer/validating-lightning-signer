use bitcoind_client::{BitcoindClient, BlockSource};
use clap::Clap;
use lightning_signer::bitcoin::util::merkleblock::PartialMerkleTree;
use lightning_signer::bitcoin::{Network, Transaction, Txid};
use lightning_signer::chain::tracker::{ChainTracker, Error as TrackerError};
use lightning_signer::monitor::ChainMonitor;
use rand::random;
use std::fmt::{self, Display, Formatter};
use url::Url;

#[derive(Debug)]
enum Error {
    ChainTrackerError(TrackerError),
}

impl From<TrackerError> for Error {
    fn from(e: TrackerError) -> Self {
        Error::ChainTrackerError(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(format!("{:?}", self).as_str())
    }
}

impl std::error::Error for Error {}

#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    /// Sets a custom config file. Could have been an Option<T> with no default too
    #[clap(short, long, default_value = "testnet")]
    network: Network,
    #[clap(short, long, about = "bitcoind RPC URL, must have http(s) schema")]
    rpc: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts: Opts = Opts::parse();
    let network = opts.network.clone();
    let rpc_s = opts.rpc.clone().unwrap_or_else(|| {
        match network {
            Network::Bitcoin => "http://user:pass@localhost:8332",
            Network::Testnet => "http://user:pass@localhost:18332",
            Network::Signet => "http://user:pass@localhost:38442",
            Network::Regtest => "http://user:pass@localhost:18332",
        }
        .to_owned()
    });

    let rpc = Url::parse(&rpc_s).expect("rpc url");

    run_test(network, rpc).await?;
    Ok(())
}

async fn run_test(network: Network, rpc: Url) -> anyhow::Result<()> {
    let client = BitcoindClient::new(
        rpc.host_str().expect("rpc host").to_owned(),
        rpc.port().expect("rpc port"),
        rpc.username().to_owned(),
        rpc.password().to_owned().expect("rpc password").to_owned(),
    ).await;
    let info = client.get_blockchain_info().await;
    println!("{:?}", info);
    let start_height = info.latest_height as u32 - 100000;
    let start_hash = client.get_block_hash(start_height).await?.expect("block disappeared");
    let tip = client.get_header(&start_hash, None).await?;
    assert_eq!(start_height, tip.height);
    let mut tracker: ChainTracker<ChainMonitor> =
        ChainTracker::new(network, start_height, tip.header).map_err(Error::from)?;
    loop {
        let height = tracker.height() + 1;
        let hash_opt = client.get_block_hash(height).await?;
        if let Some(hash) = hash_opt {
            let (txs, proof) = if random::<f32>() < 0.002 {
                let block = client.get_block(&hash).await?;
                let txs = block.txdata;
                let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
                let matches: Vec<bool> = txs.iter().map(|_| random::<f32>() < 0.01).collect();
                let matched_txs: Vec<Transaction> = txs
                    .into_iter()
                    .zip(matches.clone())
                    .filter(|(_, m)| *m)
                    .map(|(tx, _)| tx)
                    .collect();
                if matched_txs.is_empty() {
                    (vec![], None)
                } else {
                    let proof = PartialMerkleTree::from_txids(&txids, &matches);
                    println!("proof for {} txs", matched_txs.len());
                    (matched_txs, Some(proof))
                }
            } else {
                (vec![], None)
            };
            let data = client.get_header(&hash, None).await?;
            tracker.add_block(data.header, txs, proof).map_err(Error::from)?;
        } else {
            break;
        }
        if height % 2016 == 0 {
            println!("at {}", height)
        }
    }
    Ok(())
}
