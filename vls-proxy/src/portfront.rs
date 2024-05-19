//! The SignerPortFront and NodePortFront provide a client RPC interface to the
//! core MultiSigner and Node objects via a communications link.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use bitcoin::bip32::ExtendedPubKey;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Network, OutPoint, Txid};
use lightning_signer::bitcoin;

use vls_frontend::{ChainTrack, ChainTrackDirectory};
use vls_protocol::msgs::{self, DebugTxoProof, Message, SerBolt};
use vls_protocol::serde_bolt::{self, LargeOctets, Octets};
use vls_protocol_client::SignerPort;

use lightning_signer::chain::tracker::Headers;
use lightning_signer::node::SignedHeartbeat;
use lightning_signer::txoo::proof::TxoProof;
use log::*;

/// Implements ChainTrackDirectory using RPC to remote MultiSigner
pub struct SignerPortFront {
    pub signer_port: Arc<dyn SignerPort>,
    pub network: Network,
    pub trackers: Vec<Arc<dyn ChainTrack>>,
}

impl SignerPortFront {
    pub fn new(signer_port: Arc<dyn SignerPort>, network: Network) -> Self {
        let front = NodePortFront::new(signer_port.clone(), network);
        let trackers = vec![Arc::new(front) as Arc<dyn ChainTrack>];
        SignerPortFront { signer_port, network, trackers }
    }
}

#[async_trait]
impl ChainTrackDirectory for SignerPortFront {
    fn tracker(&self, _node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        unimplemented!()
    }

    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        self.trackers.clone()
    }
}

#[derive(Clone)]
struct NodeKeys {
    node_id: PublicKey,
    heartbeat_pubkey: PublicKey,
}

/// Implements ChainTrack using RPC to remote node
pub(crate) struct NodePortFront {
    signer_port: Arc<dyn SignerPort>,
    network: Network,
    node_keys: Mutex<Option<NodeKeys>>,
    block_chunk_size: usize,
}

const LOG_INTERVAL: u64 = 100;

// blocks will be streamed in chunks of this size
const BLOCK_CHUNK_SIZE: usize = 8192;

impl NodePortFront {
    fn new(signer_port: Arc<dyn SignerPort>, network: Network) -> Self {
        debug!("NodePortFront::new network: {}", network);
        let test_streaming = std::env::var("VLS_CHAINFOLLOWER_TEST_STREAMING")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        let block_chunk_size = if test_streaming {
            // create more chunks for better system testing
            1223
        } else {
            BLOCK_CHUNK_SIZE
        };

        Self { signer_port, network, node_keys: Mutex::new(None), block_chunk_size }
    }

    async fn wait_ready(&self) {
        let mut attempt: u64 = 0;
        while !self.signer_port.is_ready() {
            if attempt % LOG_INTERVAL == 0 {
                info!("waiting for signer_port to be ready");
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if attempt > 0 {
            info!("signer_port is now ready");
        }
    }

    async fn populate_keys(&self) -> NodeKeys {
        self.wait_ready().await;
        let reply = self
            .signer_port
            .handle_message(msgs::NodeInfo {}.as_vec())
            .await
            .expect("NodeInfo failed");
        if let Ok(Message::NodeInfoReply(m)) = msgs::from_vec(reply) {
            let xpubkey = ExtendedPubKey::decode(&m.bip32.0).expect("NodeInfoReply bip32 xpubkey");
            let heartbeat_pubkey = xpubkey.public_key;
            let node_id = PublicKey::from_slice(&m.node_id.0).expect("NodeInfoReply node_id");
            let mut lock = self.node_keys.lock().unwrap();
            let keys = NodeKeys { node_id, heartbeat_pubkey };
            *lock = Some(keys.clone());
            return keys;
        } else {
            panic!("unexpected NodeInfoReply");
        }
    }

    async fn maybe_stream_block(&self, proof: TxoProof) -> TxoProof {
        // stream the block to the signer, if this is a false positive
        let (proof, block_opt) = proof.take_block();
        if let Some(block) = block_opt {
            let block_hash = block.block_hash();
            let bytes = serialize(&block);
            let mut offset = 0;
            for chunk in bytes.chunks(self.block_chunk_size) {
                let req =
                    msgs::BlockChunk { hash: block_hash, offset, content: Octets(chunk.to_vec()) };
                let reply_bytes =
                    self.signer_port.handle_message(req.as_vec()).await.expect("BlockChunk failed");
                let result = msgs::from_vec(reply_bytes);
                match result {
                    Ok(Message::BlockChunkReply(_)) => {}
                    _ => panic!("unexpected {:?} when looking for BlockChunkReply", result),
                }
                offset += chunk.len() as u32;
            }
        }
        proof
    }
}

#[async_trait]
impl ChainTrack for NodePortFront {
    fn log_prefix(&self) -> String {
        let lock = self.node_keys.lock().unwrap();
        if let Some(nk) = lock.as_ref() {
            let id = nk.node_id.serialize().to_vec();
            format!("tracker {}", hex::encode(&id[0..4]))
        } else {
            format!("tracker")
        }
    }

    async fn id(&self) -> Vec<u8> {
        {
            let lock = self.node_keys.lock().unwrap();
            if let Some(nk) = lock.as_ref() {
                return nk.node_id.serialize().to_vec();
            }
        }
        let keys = self.populate_keys().await;
        let idvec = keys.node_id.serialize().to_vec();
        debug!("NodePortFront::id {}", hex::encode(&idvec));
        idvec
    }

    async fn heartbeat_pubkey(&self) -> PublicKey {
        {
            let lock = self.node_keys.lock().unwrap();
            if let Some(nk) = lock.as_ref() {
                return nk.heartbeat_pubkey.clone();
            }
        }
        let keys = self.populate_keys().await;
        let pubkey = keys.heartbeat_pubkey;
        debug!("NodePortFront::heartbeat_pubkey {}", pubkey);
        pubkey
    }

    fn network(&self) -> Network {
        self.network
    }

    async fn tip_info(&self) -> (u32, BlockHash) {
        self.wait_ready().await;
        let req = msgs::TipInfo {};
        let reply = self.signer_port.handle_message(req.as_vec()).await.expect("TipInfo failed");
        if let Ok(Message::TipInfoReply(m)) = msgs::from_vec(reply) {
            (m.height, m.block_hash)
        } else {
            panic!("unexpected TipInfoReply");
        }
    }

    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.wait_ready().await;
        let req = msgs::ForwardWatches {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("ForwardWatches failed");
        match msgs::from_vec(reply) {
            Ok(Message::ForwardWatchesReply(m)) => (m.txids.0, m.outpoints.0),
            Ok(m) => panic!("unexpected {:?}", m),
            Err(e) => panic!("unexpected error {:?}", e),
        }
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.wait_ready().await;
        let req = msgs::ReverseWatches {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("ReverseWatches failed");
        match msgs::from_vec(reply) {
            Ok(Message::ReverseWatchesReply(m)) => (m.txids.0, m.outpoints.0),
            Ok(m) => panic!("unexpected {:?}", m),
            Err(e) => panic!("unexpected error {:?}", e),
        }
    }

    async fn add_block(&self, header: BlockHeader, proof: TxoProof) {
        self.wait_ready().await;

        let proof = self.maybe_stream_block(proof).await;

        let req = msgs::AddBlock {
            header: Octets(serialize(&header)),
            unspent_proof: Some(DebugTxoProof(proof)),
        };
        let reply = self.signer_port.handle_message(req.as_vec()).await.expect("AddBlock failed");
        match msgs::from_vec(reply) {
            Ok(Message::AddBlockReply(_)) => return,
            Ok(Message::SignerError(msgs::SignerError { code, message })) => match code {
                msgs::CODE_ORPHAN_BLOCK => {
                    warn!("signer returned an OrphanBlock error: {:?}", message);
                    return;
                }
                _ => panic!("NodePortFront can't handle error code {}", code),
            },
            _ => panic!("unexpected AddBlockReply"),
        }
    }

    async fn remove_block(&self, proof: TxoProof, prev_headers: Headers) {
        self.wait_ready().await;

        let proof = self.maybe_stream_block(proof).await;

        let req = msgs::RemoveBlock {
            unspent_proof: Some(LargeOctets(serialize(&proof))),
            prev_block_header: prev_headers.0,
            prev_filter_header: prev_headers.1,
        };
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("RemoveBlock failed");
        if let Ok(Message::RemoveBlockReply(_)) = msgs::from_vec(reply) {
            return;
        } else {
            panic!("unexpected RemoveBlockReply");
        }
    }

    async fn beat(&self) -> SignedHeartbeat {
        self.wait_ready().await;
        let req = msgs::GetHeartbeat {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("GetHeartbeat failed");
        if let Ok(Message::GetHeartbeatReply(m)) = msgs::from_vec(reply) {
            let mut ser_hb = m.heartbeat.0;
            serde_bolt::from_vec(&mut ser_hb).expect("bad heartbeat")
        } else {
            panic!("unexpected GetHeartbeatReply");
        }
    }
}
