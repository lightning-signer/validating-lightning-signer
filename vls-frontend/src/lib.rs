#![crate_name = "vls_frontend"]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::secp256k1::PublicKey;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{BlockHash, BlockHeader, Network, OutPoint, Transaction, Txid};
use lightning_signer::bitcoin;

mod chain_follower;
pub mod frontend;

pub use self::frontend::Frontend;

/// Provides ChainTracks for nodes in a signer
#[async_trait]
pub trait ChainTrackDirectory: Sync + Send {
    /// Return a ChainTrack for a specific node
    fn tracker(&self, node_id: &PublicKey) -> Arc<dyn ChainTrack>;

    /// Return ChainTracks for all nodes
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>>;
}

/// ChainTracker interface
#[async_trait]
pub trait ChainTrack: Sync + Send {
    /// Identity string for the log
    fn log_prefix(&self) -> String;

    /// Returns the network
    fn network(&self) -> Network;

    /// Return the block height and hash of specified node's chaintracker tip
    async fn tip_info(&self) -> (u32, BlockHash);

    /// Returns all Txid and OutPoints to watch for in future blocks
    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>);

    /// Returns all Txid and OutPoint watches used for prior blocks (used when removing)
    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>);

    /// Add a block to the tracker
    async fn add_block(
        &self,
        header: BlockHeader,
        txs: Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    );

    /// Remove block at tip due to reorg
    async fn remove_block(&self, txs: Vec<Transaction>, txs_proof: Option<PartialMerkleTree>);
}
