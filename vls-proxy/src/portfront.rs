//! The SignerPortFront and NodePortFront provide a client RPC interface to the
//! core MultiSigner and Node objects via a communications link.

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::secp256k1::PublicKey;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{self, BlockHash, BlockHeader, Network, OutPoint, Txid};

use vls_frontend::{ChainTrack, ChainTrackDirectory};
use vls_protocol_client::SignerPort;

/// Implements ChainTrackDirectory using calls to remote MultiSigner
pub struct SignerPortFront {
    pub signer_port: Arc<dyn SignerPort>,
}

#[async_trait]
impl ChainTrackDirectory for SignerPortFront {
    fn tracker(&self, _node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        unimplemented!()
    }
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        unimplemented!()
    }
}

/// Implements ChainTrack using calls to inplace node
pub(crate) struct NodePortFront {}

#[async_trait]
impl ChainTrack for NodePortFront {
    fn log_prefix(&self) -> String {
        unimplemented!()
    }

    fn network(&self) -> Network {
        unimplemented!()
    }

    async fn tip_info(&self) -> (u32, BlockHash) {
        unimplemented!()
    }

    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        unimplemented!()
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        unimplemented!()
    }

    async fn add_block(
        &self,
        _header: BlockHeader,
        _txs: Vec<bitcoin::Transaction>,
        _txs_proof: Option<PartialMerkleTree>,
    ) {
        unimplemented!()
    }

    async fn remove_block(
        &self,
        _txs: Vec<bitcoin::Transaction>,
        _txs_proof: Option<PartialMerkleTree>,
    ) {
        unimplemented!()
    }
}
