//! The SignerFront and NodeFront provide a in-process call interface to the underlying MultiSigner
//! and Node objects for the ChainTrack traits.

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, BlockHeader, Network, OutPoint, Txid};

use lightning_signer::bitcoin;
use lightning_signer::node::{Node, SignedHeartbeat};
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::txoo::proof::UnspentProof;
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
        Arc::new(NodeFront::new(node))
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
        vec![Arc::new(NodeFront::new(Arc::clone(&self.node)))]
    }
}

/// Implements ChainTrack using calls to inplace node
pub(crate) struct NodeFront {
    node: Arc<Node>,
    heartbeat_pubkey: PublicKey,
}

impl NodeFront {
    pub fn new(node: Arc<Node>) -> Self {
        let heartbeat_pubkey = node.get_account_extended_pubkey().public_key.clone();
        Self { node, heartbeat_pubkey }
    }
}

#[async_trait]
impl ChainTrack for NodeFront {
    fn log_prefix(&self) -> String {
        format!("tracker {}", self.node.log_prefix())
    }

    async fn id(&self) -> Vec<u8> {
        self.node.get_id().serialize().to_vec()
    }

    async fn heartbeat_pubkey(&self) -> PublicKey {
        self.heartbeat_pubkey.clone()
    }

    fn network(&self) -> Network {
        self.node.network()
    }

    async fn tip_info(&self) -> (u32, BlockHash) {
        let tracker = self.node.get_tracker();
        (tracker.height(), tracker.tip().0.block_hash())
    }

    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.node.get_tracker().get_all_forward_watches()
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.node.get_tracker().get_all_reverse_watches()
    }

    async fn add_block(&self, header: BlockHeader, proof: UnspentProof) {
        let mut tracker = self.node.get_tracker();
        tracker
            .add_block(header, proof)
            .unwrap_or_else(|e| panic!("{}: add_block failed: {:?}", self.node.log_prefix(), e));
        self.node.get_persister().update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(
            |e| panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e),
        );
    }

    async fn remove_block(&self, proof: UnspentProof) {
        let mut tracker = self.node.get_tracker();
        tracker
            .remove_block(proof)
            .unwrap_or_else(|e| panic!("{}: remove_block failed: {:?}", self.node.log_prefix(), e));
        self.node.get_persister().update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(
            |e| panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e),
        );
    }

    async fn beat(&self) -> SignedHeartbeat {
        self.node.get_heartbeat()
    }
}
