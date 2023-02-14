//! The SignerPortFront and NodePortFront provide a client RPC interface to the
//! core MultiSigner and Node objects via a communications link.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::{BlockHash, BlockHeader, Network, OutPoint, Txid};
use lightning_signer::bitcoin;

use vls_frontend::{ChainTrack, ChainTrackDirectory};
use vls_protocol::msgs::{self, Message, SerBolt};
use vls_protocol::serde_bolt::{LargeOctets, Octets};
use vls_protocol_client::SignerPort;

use lightning_signer::node::SignedHeartbeat;
use lightning_signer::txoo::proof::UnspentProof;
#[allow(unused_imports)]
use log::debug;

/// Implements ChainTrackDirectory using RPC to remote MultiSigner
pub struct SignerPortFront {
    pub signer_port: Box<dyn SignerPort>,
    pub network: Network,
    pub trackers: Vec<Arc<dyn ChainTrack>>,
}

impl SignerPortFront {
    pub fn new(signer_port: Box<dyn SignerPort>, network: Network) -> Self {
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
    signer_port: Box<dyn SignerPort>,
    network: Network,
    node_keys: Mutex<Option<NodeKeys>>,
}

impl NodePortFront {
    fn new(signer_port: Box<dyn SignerPort>, network: Network) -> Self {
        debug!("NodePortFront::new network: {}", network);
        Self { signer_port, network, node_keys: Mutex::new(None) }
    }

    async fn populate_keys(&self) -> NodeKeys {
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
}

#[async_trait]
impl ChainTrack for NodePortFront {
    fn log_prefix(&self) -> String {
        format!("tracker")
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
        let req = msgs::TipInfo {};
        let reply = self.signer_port.handle_message(req.as_vec()).await.expect("TipInfo failed");
        if let Ok(Message::TipInfoReply(m)) = msgs::from_vec(reply) {
            (m.height, BlockHash::from_slice(&m.block_hash.0).unwrap())
        } else {
            panic!("unexpected TipInfoReply");
        }
    }

    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        let req = msgs::ForwardWatches {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("ForwardWatches failed");
        if let Ok(Message::ForwardWatchesReply(m)) = msgs::from_vec(reply) {
            (
                m.txids.iter().map(|txid| Txid::from_slice(&txid.0).expect("bad txid")).collect(),
                m.outpoints
                    .iter()
                    .map(|op| {
                        OutPoint::new(
                            Txid::from_slice(&op.txid.0).expect("bad outpoint txid"),
                            op.vout,
                        )
                    })
                    .collect(),
            )
        } else {
            panic!("unexpected ForwardWatchesReply");
        }
    }

    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        let req = msgs::ReverseWatches {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("ReverseWatches failed");
        if let Ok(Message::ReverseWatchesReply(m)) = msgs::from_vec(reply) {
            (
                m.txids.iter().map(|txid| Txid::from_slice(&txid.0).expect("bad txid")).collect(),
                m.outpoints
                    .iter()
                    .map(|op| {
                        OutPoint::new(
                            Txid::from_slice(&op.txid.0).expect("bad outpoint txid"),
                            op.vout,
                        )
                    })
                    .collect(),
            )
        } else {
            panic!("unexpected ReverseWatchesReply");
        }
    }

    async fn add_block(&self, header: BlockHeader, proof: UnspentProof) {
        let req = msgs::AddBlock {
            header: Octets(serialize(&header)),
            unspent_proof: Some(LargeOctets(serialize(&proof))),
        };
        let reply = self.signer_port.handle_message(req.as_vec()).await.expect("AddBlock failed");
        if let Ok(Message::AddBlockReply(_)) = msgs::from_vec(reply) {
            return;
        } else {
            panic!("unexpected AddBlockReply");
        }
    }

    async fn remove_block(&self, proof: UnspentProof) {
        let req = msgs::RemoveBlock { unspent_proof: Some(LargeOctets(serialize(&proof))) };
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("RemoveBlock failed");
        if let Ok(Message::RemoveBlockReply(_)) = msgs::from_vec(reply) {
            return;
        } else {
            panic!("unexpected RemoveBlockReply");
        }
    }

    async fn beat(&self) -> SignedHeartbeat {
        let req = msgs::GetHeartbeat {};
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("GetHeartbeat failed");
        if let Ok(Message::GetHeartbeatReply(m)) = msgs::from_vec(reply) {
            let mut ser_hb = m.heartbeat.0;
            vls_protocol::serde_bolt::from_vec(&mut ser_hb).expect("bad heartbeat")
        } else {
            panic!("unexpected GetHeartbeatReply");
        }
    }
}
