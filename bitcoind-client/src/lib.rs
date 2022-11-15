#![crate_name = "bitcoind_client"]

//! A bitcoind RPC client.

#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

/// Bitcoind RPC client
pub mod bitcoind_client;
mod convert;
/// Esplora RPC client
pub mod esplora_client;

pub use self::bitcoind_client::{BitcoindClient, BlockSource};
use async_trait::async_trait;
use core::fmt;
use lightning_signer::bitcoin::{Network, Transaction};
use lightning_signer::lightning::chain::transaction::OutPoint;
use log::info;
use std::env;
use std::fmt::{Display, Formatter};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use url::Url;

/// RPC errors
#[derive(Debug)]
pub enum Error {
    /// JSON RPC Error
    JsonRpc(jsonrpc_async::error::Error),
    /// JSON Error
    Json(serde_json::error::Error),
    /// IO Error
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(format!("{:?}", self).as_str())
    }
}

impl std::error::Error for Error {}

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

/// A trait for a generic block source
#[async_trait]
pub trait Explorer {
    /// Get whether an outpoint is unspent (will return Some(confirmations))
    async fn get_txout(&self, txout: &OutPoint) -> Result<Option<u64>, Error>;
    /// Broadcast transaction
    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), Error>;
}

/// The block explorer type
pub enum BlockExplorerType {
    /// A bitcoind RPC client "explorer"
    Bitcoind,
    /// The Blockstream Esplora block explorer
    Esplora,
}

/// Construct a block explorer client from an RPC URL, a network and a block explorer type
pub async fn explorer_from_url(
    network: Network,
    block_explorer_type: BlockExplorerType,
    url: Url,
) -> Option<Box<dyn Explorer>> {
    match block_explorer_type {
        BlockExplorerType::Bitcoind => {
            let explorer: Box<dyn Explorer> =
                Box::new(bitcoind_client_from_url(url, network).await);
            Some(explorer)
        }
        BlockExplorerType::Esplora => panic!("Esplora not supported yet"),
    }
}

fn bitcoin_network_path(base_path: PathBuf, network: Network) -> PathBuf {
    match network {
        Network::Bitcoin => base_path,
        Network::Testnet => base_path.join("testnet3"),
        Network::Signet => base_path.join("signet"),
        Network::Regtest => base_path.join("regtest"),
    }
}

fn bitcoin_rpc_cookie(network: Network) -> (String, String) {
    let home = env::var("HOME").expect("cannot get cookie file if HOME is not set");
    let bitcoin_path = Path::new(&home).join(".bitcoin");
    let bitcoin_net_path = bitcoin_network_path(bitcoin_path, network);
    let cookie_path = bitcoin_net_path.join("cookie");
    info!("auth to bitcoind via cookie {}", cookie_path.to_string_lossy());
    let cookie_contents = read_to_string(cookie_path).expect("cookie file read");
    let mut iter = cookie_contents.splitn(2, ":");
    (iter.next().expect("cookie user").to_string(), iter.next().expect("cookie pass").to_string())
}

/// Construct a client from an RPC URL and a network
pub async fn bitcoind_client_from_url(mut url: Url, network: Network) -> BitcoindClient {
    if url.username().is_empty() {
        // try to get from cookie file
        let (user, pass) = bitcoin_rpc_cookie(network);
        url.set_username(&user).expect("set user");
        url.set_password(Some(&pass)).expect("set pass");
    }
    BitcoindClient::new(url).await
}
