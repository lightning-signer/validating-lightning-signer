use async_trait::async_trait;
use bitcoind_client::BlockSource;
use lightning_signer::bitcoin::util::merkleblock::PartialMerkleTree;
use lightning_signer::bitcoin::{Block, BlockHash, OutPoint, Transaction, Txid};
use lightning_signer::OrderedSet;
use std::iter::FromIterator;

/// A follower error
#[derive(Debug)]
pub enum Error {
    /// The block source is not available
    SourceError(String),
}

impl From<bitcoind_client::Error> for Error {
    fn from(e: bitcoind_client::Error) -> Error {
        Error::SourceError(e.to_string())
    }
}

/// The next action to take when following the chain
pub enum FollowAction {
    /// No action required, synced to chain tip
    None,
    /// A block has been added to the chain.
    /// Provides the new block.
    BlockAdded(Block),
    /// The current block has been reorganized out of the chain.
    /// Provides the block that was reorged out.
    BlockReorged(Block),
}

/// Follow the longest chain
#[async_trait]
pub trait Follower {
    async fn follow(&self, height: u32, hash: BlockHash) -> Result<FollowAction, Error>;
}

/// A follower for BlockSource
pub struct SourceFollower {
    source: Box<dyn BlockSource>,
}

impl SourceFollower {
    pub fn new(source: Box<dyn BlockSource>) -> Self {
        SourceFollower { source }
    }
}

#[async_trait]
impl Follower for SourceFollower {
    async fn follow(
        &self,
        current_height: u32,
        current_hash: BlockHash,
    ) -> Result<FollowAction, Error> {
        match self.source.get_block_hash(current_height + 1).await? {
            None => {
                // No new block, but check if the current block has been reorged
                match self.source.get_block_hash(current_height).await? {
                    None => {
                        // The current block has been reorged out of the chain
                        Ok(FollowAction::BlockReorged(self.source.get_block(&current_hash).await?))
                    }
                    Some(check_hash) => {
                        if check_hash == current_hash {
                            // No action required, synced to chain tip
                            Ok(FollowAction::None)
                        } else {
                            // The current block has been reorged out of the chain
                            Ok(FollowAction::BlockReorged(
                                self.source.get_block(&current_hash).await?,
                            ))
                        }
                    }
                }
            }
            Some(new_hash) => {
                let block = self.source.get_block(&new_hash).await?;
                if block.header.prev_blockhash == current_hash {
                    // A block has been added to the chain
                    Ok(FollowAction::BlockAdded(block))
                } else {
                    // The new block actually extends a different chain
                    Ok(FollowAction::BlockReorged(self.source.get_block(&current_hash).await?))
                }
            }
        }
    }
}

/// The next action to take when following the chain, with SPV proofs
pub enum FollowWithProofAction {
    /// No action required, synced to chain tip
    None,
    /// A block has been added to the chain.
    /// Provides the new block.
    BlockAdded(Block, (Vec<Transaction>, Option<PartialMerkleTree>)),
    /// The current block has been reorganized out of the chain.
    /// Provides the block that was reorged out.
    /// Note that the transactions should be "un-processed" in reverse order
    /// in case they have inter-dependencies.
    BlockReorged(Block, (Vec<Transaction>, Option<PartialMerkleTree>)),
}

#[async_trait]
pub trait Tracker {
    /// Returns all Txid and OutPoints to watch for in future blocks
    async fn forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>);

    /// Returns all Txid and OutPoint watches used for prior blocks.
    /// Used when removing blocks during reorg.
    async fn reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>);
}

/// A follower for BlockSource with SPV proofs
pub struct SourceWithProofFollower(SourceFollower);

impl SourceWithProofFollower {
    pub fn new(source: Box<dyn BlockSource>) -> Self {
        SourceWithProofFollower(SourceFollower::new(source))
    }

    pub async fn follow_with_proof(
        &self,
        current_height: u32,
        current_hash: BlockHash,
        tracker: &impl Tracker,
    ) -> Result<FollowWithProofAction, Error> {
        match self.0.follow(current_height, current_hash).await? {
            FollowAction::None => Ok(FollowWithProofAction::None),
            FollowAction::BlockAdded(block) => {
                let (txids, outpoints) = tracker.forward_watches().await;
                let proof = build_proof(&block, &txids, &outpoints);
                Ok(FollowWithProofAction::BlockAdded(block, proof))
            }
            FollowAction::BlockReorged(block) => {
                let (txids, outpoints) = tracker.reverse_watches().await;
                let proof = build_proof(&block, &txids, &outpoints);
                Ok(FollowWithProofAction::BlockReorged(block, proof))
            }
        }
    }
}

fn build_proof(
    block: &Block,
    txid_watches: &Vec<Txid>,
    outpoint_watches: &Vec<OutPoint>,
) -> (Vec<Transaction>, Option<PartialMerkleTree>) {
    let watched_txids = OrderedSet::from_iter(txid_watches.iter());
    let mut watched_outpoints = OrderedSet::from_iter(outpoint_watches.iter().cloned());
    let mut txids = vec![];
    let mut matches = vec![];
    let mut matched_txs = vec![];
    for tx in block.txdata.iter() {
        let txid = tx.txid();
        txids.push(txid);
        if watched_txids.contains(&txid)
            || tx.input.iter().any(|inp| watched_outpoints.contains(&inp.previous_output))
        {
            matches.push(true);
            matched_txs.push(tx.clone());
            // We need to watch the outputs of this transaction in case a subsequent
            // transaction in the block spends them.
            let additional_watches: Vec<OutPoint> = (0..tx.output.len() as u32)
                .into_iter()
                .map(|vout| OutPoint { txid, vout })
                .collect();
            watched_outpoints.extend(additional_watches.into_iter());
        } else {
            matches.push(false);
        }
    }

    if matched_txs.is_empty() {
        (vec![], None)
    } else {
        let proof = PartialMerkleTree::from_txids(&txids, &matches);
        (matched_txs, Some(proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use bitcoin::{Block, BlockHeader, OutPoint, TxIn, TxMerkleNode, TxOut};

    use crate::bitcoin::{PackedLockTime, Sequence, Witness};
    use bitcoin::hashes::Hash;
    use lightning_signer::bitcoin;
    use test_log::test;

    fn make_tx(previous_outputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: previous_outputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Default::default(),
                    sequence: Sequence::ZERO,
                    witness: Witness::default(),
                })
                .collect(),
            output: outputs,
        }
    }

    fn make_blockheader() -> BlockHeader {
        BlockHeader {
            version: 0,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_str(
                "0377d5ba2c6e0f7aeaebb3caa6cd05b8b9b8ba60d0554e53b7a327ffdaa7433a",
            )
            .unwrap(),
            time: 0,
            bits: 0,
            nonce: 0,
        }
    }

    fn make_block() -> Block {
        Block {
            header: make_blockheader(),
            txdata: vec![
                make_tx( // coinbase txid: 9310175d644aab7b9337ce806a4c7e27cdd815611085eab1a20c746a11742114
                         vec![OutPoint::from_str(
                             "0000000000000000000000000000000000000000000000000000000000000000:4294967295").unwrap()],
                         vec![
                             TxOut { value: 5000002055, script_pubkey: Default::default() }
                         ],
                ),
                make_tx( // watched by txid_watch txid: 71ce38d3be3f07ac707d1c348bfa976f6d8060c28dce533914bcdc6b7e38d091
                         vec![OutPoint::from_str(
                             "7b2c3d17a43ac15757cc2b768d602d1a9333269802b8ee9fab375ea25a0509c8:0").unwrap()],
                         vec![
                             TxOut { value: 9993618, script_pubkey: Default::default() },
                         ],
                ),
                make_tx( // watched by watch txid: ea2e897dbe842b0a3645d7297070579f42ce234cfb1da25f9195f4259496a1a6
                         vec![OutPoint::from_str(
                             "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1").unwrap()],
                         vec![
                             TxOut { value: 123456789, script_pubkey: Default::default() },
                         ],
                ),
                make_tx( // ignored txid: c8f94365a721c1637cacf44e734358d595dca8372a5d90e098482ed8f8d52cac
                         vec![OutPoint::from_str(
                             "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206:1").unwrap()],
                         vec![
                             TxOut { value: 1000000000, script_pubkey: Default::default() },
                         ],
                ),
                make_tx( // ignored txid: 96b6df8e0cbb9919414c96a56a9b52e7299c9e394b46533c7dea2d14843a457b
                         vec![OutPoint::from_str(
                             "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5:0").unwrap()],
                         vec![
                             TxOut { value: 2000000000, script_pubkey: Default::default() },
                         ],
                ),
                make_tx( // additional from watch txid: bfb031d4bb062a26561b828d686d0a30b2083d26463924060b638985348870cf
                         vec![OutPoint::from_str(
                             "ea2e897dbe842b0a3645d7297070579f42ce234cfb1da25f9195f4259496a1a6:0").unwrap()],
                         vec![
                             TxOut { value: 3000000000, script_pubkey: Default::default() },
                         ],
                ),
                make_tx( // additional from txid_watch txid: 17299ca25bd0dd92ef3e75f0aac5b04ad7477565e09e3bf4cc4fa2816f5d00d4
                         vec![OutPoint::from_str(
                             "71ce38d3be3f07ac707d1c348bfa976f6d8060c28dce533914bcdc6b7e38d091:0").unwrap()],
                         vec![
                             TxOut { value: 4000000000, script_pubkey: Default::default() },
                         ],
                ),
            ],
        }
    }

    #[test]
    fn build_proof_with_empty_block() {
        let block = Block { header: make_blockheader(), txdata: vec![] };
        assert_eq!(build_proof(&block, &vec![], &vec![]), (vec![], None));
    }

    #[test]
    fn build_proof_with_empty_watches() {
        assert_eq!(build_proof(&make_block(), &vec![], &vec![]), (vec![], None));
    }

    #[test]
    fn build_proof_with_txid_watch() {
        let block = make_block();
        let txid_watches = vec![block.txdata[1].txid()];
        let (txs, proof) = build_proof(&block, &txid_watches, &vec![]);
        assert_eq!(txs, vec![block.txdata[1].clone(), block.txdata[6].clone()]);
        assert!(proof.is_some());
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        let root = proof.unwrap().extract_matches(&mut matches, &mut indexes).unwrap();
        assert_eq!(root, block.header.merkle_root);
        assert_eq!(matches, vec![block.txdata[1].txid(), block.txdata[6].txid()]);
        assert_eq!(indexes, vec![1, 6]);
    }

    #[test]
    fn build_proof_with_outpoint_watch() {
        let block = make_block();
        let outpoint_watches = vec![block.txdata[2].input[0].previous_output];
        let (txs, proof) = build_proof(&block, &vec![], &outpoint_watches);
        assert_eq!(txs, vec![block.txdata[2].clone(), block.txdata[5].clone()]);
        assert!(proof.is_some());
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        let root = proof.unwrap().extract_matches(&mut matches, &mut indexes).unwrap();
        assert_eq!(root, block.header.merkle_root);
        assert_eq!(matches, vec![block.txdata[2].txid(), block.txdata[5].txid()]);
        assert_eq!(indexes, vec![2, 5]);
    }
}
