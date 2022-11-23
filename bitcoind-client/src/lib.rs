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
use crate::bitcoind_client::bitcoind_client_from_url;
use crate::esplora_client::EsploraClient;
use async_trait::async_trait;
use core::fmt;
use lightning_signer::bitcoin::{Network, Transaction};
use lightning_signer::lightning::chain::transaction::OutPoint;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
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
    /// Esplora Error
    Esplora(String),
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
    /// Get number of confirmations when an outpoint is confirmed and unspent
    /// Returns None if the outpoint is not confirmed or is spent
    async fn get_utxo_confirmations(&self, txout: &OutPoint) -> Result<Option<u64>, Error>;
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
) -> Box<dyn Explorer> {
    match block_explorer_type {
        BlockExplorerType::Bitcoind => Box::new(bitcoind_client_from_url(url, network).await),
        BlockExplorerType::Esplora => Box::new(EsploraClient::new(url).await),
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
