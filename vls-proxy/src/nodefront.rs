//! The SignerFront and NodeFront provide a in-process call interface to the underlying MultiSigner
//! and Node objects for the ChainTrack traits.

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Network, OutPoint, Txid};

use lightning_signer::bitcoin;
use lightning_signer::chain::tracker::{ChainTracker, Headers};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{Node, SignedHeartbeat};
use lightning_signer::persist::Persist;
use lightning_signer::signer::multi_signer::MultiSigner;
use lightning_signer::txoo::proof::TxoProof;
use lightning_signer::wallet::Wallet;
use vls_frontend::{ChainTrack, ChainTrackDirectory};
use vls_util::persist::ExternalPersistWithHelper;

/// Implements ChainTrackDirectory using calls to inplace MultiSigner
pub struct SignerFront {
    /// The signer
    pub signer: Arc<MultiSigner>,
    /// Optional external persister
    pub external_persist: Option<ExternalPersistWithHelper>,
}

#[async_trait]
impl ChainTrackDirectory for SignerFront {
    fn tracker(&self, node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        let node = self.signer.get_node(node_id).unwrap();
        Arc::new(NodeFront::new(node, self.external_persist.clone()))
    }
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        self.signer.get_node_ids().iter().map(|node_id| self.tracker(node_id)).collect()
    }
}

/// Implements ChainTrackDirectory using single inplace node
pub struct SingleFront {
    pub node: Arc<Node>,
    pub external_persist: Option<ExternalPersistWithHelper>,
}

#[async_trait]
impl ChainTrackDirectory for SingleFront {
    fn tracker(&self, _node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        // There are no additional added trackers for new nodes in the single case.
        unimplemented!();
    }
    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        vec![Arc::new(NodeFront::new(Arc::clone(&self.node), self.external_persist.clone()))]
    }
}

/// Implements ChainTrack using calls to inplace node
pub(crate) struct NodeFront {
    node: Arc<Node>,
    heartbeat_pubkey: PublicKey,
    external_persist: Option<ExternalPersistWithHelper>,
}

impl NodeFront {
    pub fn new(node: Arc<Node>, external_persist: Option<ExternalPersistWithHelper>) -> Self {
        let heartbeat_pubkey = node.get_account_extended_pubkey().public_key.clone();
        Self { node, heartbeat_pubkey, external_persist }
    }

    fn do_add_block(&self, header: BlockHeader, proof: TxoProof, persister: Arc<dyn Persist>) {
        let mut tracker = self.node.get_tracker();
        let proof = self.maybe_stream_block(&mut *tracker, proof);
        tracker
            .add_block(header, proof)
            .unwrap_or_else(|e| panic!("{}: add_block failed: {:?}", self.node.log_prefix(), e));
        persister.update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(|e| {
            panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
        });
    }

    fn do_remove_block(&self, proof: TxoProof, persister: Arc<dyn Persist>, prev_headers: Headers) {
        let mut tracker = self.node.get_tracker();
        let proof = self.maybe_stream_block(&mut *tracker, proof);
        tracker
            .remove_block(proof, prev_headers)
            .unwrap_or_else(|e| panic!("{}: remove_block failed: {:?}", self.node.log_prefix(), e));
        persister.update_tracker(&self.node.get_id(), &tracker).unwrap_or_else(|e| {
            panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
        });
    }

    fn maybe_stream_block(
        &self,
        tracker: &mut ChainTracker<ChainMonitor>,
        proof: TxoProof,
    ) -> TxoProof {
        // stream the block to the signer, if this is a false positive
        let (proof, block_opt) = proof.take_block();
        if let Some(block) = block_opt {
            let block_hash = block.block_hash();
            let bytes = serialize(&block);
            let mut offset = 0;
            // small prime chunk size to test streaming
            for chunk in bytes.chunks(23) {
                tracker.block_chunk(block_hash, offset, chunk).expect("block_chunk");
                offset += chunk.len() as u32;
            }
        }
        proof
    }

    fn do_beat(&self, _persister: Arc<dyn Persist>) -> SignedHeartbeat {
        self.node.get_heartbeat()
    }

    async fn with_persist_context<F>(
        external_persist: &ExternalPersistWithHelper,
        persister: Arc<dyn Persist>,
        f: F,
    ) where
        F: FnOnce(Arc<dyn Persist>),
    {
        // lock order: persist client, tracker
        let client = external_persist.persist_client.lock().await;

        persister.enter().expect("persister enter");
        f(persister.clone());
        let muts = persister.prepare();

        let helper = &external_persist.helper;
        let client_hmac = helper.client_hmac(&muts);
        let server_hmac = helper.server_hmac(&muts);
        let received_server_hmac =
            client.put(muts.clone(), &client_hmac).await.expect("persist failed");
        assert_eq!(received_server_hmac, server_hmac, "server hmac mismatch");

        persister.commit().expect("persister commit")
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

    async fn add_block(&self, header: BlockHeader, proof: TxoProof) {
        let persister = self.node.get_persister();
        if let Some(external_persist) = &self.external_persist {
            Self::with_persist_context(external_persist, persister, |persister| {
                self.do_add_block(header, proof, persister);
            })
            .await;
        } else {
            self.do_add_block(header, proof, persister);
        }
    }

    async fn remove_block(&self, proof: TxoProof, prev_headers: Headers) {
        let persister = self.node.get_persister();
        if let Some(external_persist) = &self.external_persist {
            Self::with_persist_context(external_persist, persister, |persister| {
                self.do_remove_block(proof, persister, prev_headers);
            })
            .await;
        } else {
            self.do_remove_block(proof, persister, prev_headers);
        }
    }

    async fn beat(&self) -> SignedHeartbeat {
        let persister = self.node.get_persister();
        let mut beat: Option<SignedHeartbeat> = None;
        if let Some(external_persist) = &self.external_persist {
            Self::with_persist_context(external_persist, persister, |persister| {
                beat = Some(self.do_beat(persister));
            })
            .await
        } else {
            beat = Some(self.do_beat(persister));
        }
        beat.unwrap()
    }
}
