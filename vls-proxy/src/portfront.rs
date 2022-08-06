//! The SignerPortFront and NodePortFront provide a client RPC interface to the
//! core MultiSigner and Node objects via a communications link.

use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{BlockHash, BlockHeader, Network, OutPoint, Txid};
use lightning_signer::bitcoin;

use vls_frontend::{ChainTrack, ChainTrackDirectory};
use vls_protocol::msgs::{self, Message, SerBolt};
use vls_protocol::serde_bolt::LargeBytes;
use vls_protocol_client::SignerPort;

#[allow(unused_imports)]
use log::debug;

/// Implements ChainTrackDirectory using RPC to remote MultiSigner
pub struct SignerPortFront {
    pub signer_port: Box<dyn SignerPort>,
    pub network: Network,
}

#[async_trait]
impl ChainTrackDirectory for SignerPortFront {
    fn tracker(&self, _node_id: &PublicKey) -> Arc<dyn ChainTrack> {
        unimplemented!()
    }

    async fn trackers(&self) -> Vec<Arc<dyn ChainTrack>> {
        vec![Arc::new(NodePortFront {
            signer_port: self.signer_port.clone(),
            network: self.network,
        }) as Arc<dyn ChainTrack>]
    }
}

/// Implements ChainTrack using RPC to remote node
pub(crate) struct NodePortFront {
    pub signer_port: Box<dyn SignerPort>,
    pub network: Network,
}

#[async_trait]
impl ChainTrack for NodePortFront {
    fn log_prefix(&self) -> String {
        format!("tracker")
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

    async fn add_block(
        &self,
        header: BlockHeader,
        txs: Vec<bitcoin::Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) {
        let req = msgs::AddBlock {
            header: LargeBytes(serialize(&header)),
            txs: txs.iter().map(|tx| LargeBytes(serialize(&tx))).collect(),
            txs_proof: txs_proof.map(|prf| LargeBytes(serialize(&prf))),
        };
        let reply = self.signer_port.handle_message(req.as_vec()).await.expect("AddBlock failed");
        if let Ok(Message::AddBlockReply(_)) = msgs::from_vec(reply) {
            return;
        } else {
            panic!("unexpected AddBlockReply");
        }
    }

    async fn remove_block(
        &self,
        txs: Vec<bitcoin::Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) {
        let req = msgs::RemoveBlock {
            txs: txs.iter().map(|tx| LargeBytes(serialize(&tx))).collect(),
            txs_proof: txs_proof.map(|prf| LargeBytes(serialize(&prf))),
        };
        let reply =
            self.signer_port.handle_message(req.as_vec()).await.expect("RemoveBlock failed");
        if let Ok(Message::RemoveBlockReply(_)) = msgs::from_vec(reply) {
            return;
        } else {
            panic!("unexpected RemoveBlockReply");
        }
    }
}
