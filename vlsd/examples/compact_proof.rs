use bitcoind_client::{bitcoind_client_from_url, BlockSource};
use lightning_signer::bitcoin::consensus::Encodable;
use lightning_signer::bitcoin::Network;
use lightning_signer::txoo::filter::BlockSpendFilter;
use log::*;
use std::env;
use url::Url;
use vlsd::util::setup_logging;

#[tokio::main]
async fn main() {
    setup_logging(".", "examples", "info");
    info!("starting...");
    let rpc_url =
        Url::parse(&env::var("BITCOIND_RPC_URL").unwrap_or("http://localhost:8332".to_string()))
            .unwrap();

    let client = bitcoind_client_from_url(rpc_url, Network::Bitcoin).await;
    let start_block = 800000;
    let mut max_size = 0;
    for height in start_block..start_block + 100 {
        let hash = client.get_block_hash(height).await.unwrap().unwrap();
        let block = client.get_block(&hash).await.unwrap();
        let filter = BlockSpendFilter::from_block(&block);
        // serialize the block
        let mut buf = Vec::new();
        block.consensus_encode(&mut buf).unwrap();
        info!("{}: block size {}, filter size {}", height, buf.len(), filter.content.len());
        max_size = max_size.max(filter.content.len());
    }
    info!("max filter size: {}", max_size);
}
