//! The SignerFront and NodeFront provide a in-process call interface to the underlying MultiSigner
//! and Node objects for the ChainTrack traits.

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::secp256k1::PublicKey;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{BlockHash, BlockHeader, Network, OutPoint, Txid};

use lightning_signer::bitcoin;
use lightning_signer::node::Node;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::wallet::Wallet;

use vls_frontend::{ChainTrack, ChainTrackDirectory};

/// Implements ChainTrackDirectory using calls to inplace MultiSigner
pub struct SignerFront {
    /// The signer
    pub signer: Arc<MultiSigner>,
}

#[async_trait]
impl ChainTrackDirectory for SignerFront {
    fn tracker(&self, node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        let node = self.signer.get_node(node_id).unwrap();
        Arc::new(NodeFront { node })
    }
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        self.signer.get_node_ids().iter().map(|node_id| self.tracker(node_id)).collect()
    }
}

/// Implements ChainTrackDirectory using single inplace node
pub struct SingleFront {
    pub node: Arc<Node>,
}

#[async_trait]
impl ChainTrackDirectory for SingleFront {
    fn tracker(&self, _node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        // There are no additional added trackers for new nodes in the single case.
        unimplemented!();
    }
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        vec![Arc::new(NodeFront { node: Arc::clone(&self.node) })]
    }
}

/// Implements ChainTrack using calls to inplace node
pub(crate) struct NodeFront {
    node: Arc<Node>,
}

#[async_trait]
impl ChainTrack for NodeFront {
    fn log_prefix(&self) -> String {
        format!("tracker {}", self.node.log_prefix())
    }

    fn network(&self) -> Network {
        self.node.network()
    }

    async fn tip_info(&self) -> (u32, BlockHash) {
        let tracker = self.node.get_tracker();
        (tracker.height(), tracker.tip().block_hash())
    }

    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.node.get_tracker().get_all_forward_watches()
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.node.get_tracker().get_all_reverse_watches()
    }

    async fn add_block(
        &self,
        header: BlockHeader,
        txs: Vec<bitcoin::Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) {
        let mut tracker = self.node.get_tracker();
        tracker
            .add_block(header, txs, txs_proof)
            .unwrap_or_else(|e| panic!("{}: add_block failed: {:?}", self.node.log_prefix(), e));
        self.node.get_persister().update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(
            |e| panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e),
        );
    }

    async fn remove_block(
        &self,
        txs: Vec<bitcoin::Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) {
        let mut tracker = self.node.get_tracker();
        tracker
            .remove_block(txs, txs_proof)
            .unwrap_or_else(|e| panic!("{}: remove_block failed: {:?}", self.node.log_prefix(), e));
        self.node.get_persister().update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(
            |e| panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e),
        );
    }
}
