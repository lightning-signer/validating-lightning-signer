use crate::prelude::*;

use crate::bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use crate::bitcoin::util::merkleblock::PartialMerkleTree;
use crate::bitcoin::util::uint::Uint256;
use crate::bitcoin::{BlockHeader, Network, Transaction};
use alloc::collections::VecDeque;

/// Error
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Chain progression is invalid (e.g. invalid difficulty change)
    InvalidChain,
    /// Block is invalid (e.g. block hash not under target)
    InvalidBlock,
    /// Reorg size greater than [`ChainTracker::MAX_REORG_SIZE`]
    ReorgTooDeep,
    /// The SPV (merkle) proof was incorrect
    InvalidSpvProof,
}

/// Track chain, with basic validation
pub struct ChainTracker {
    headers: VecDeque<BlockHeader>,
    tip: BlockHeader,
    height: u32,
    network: Network,
}

impl ChainTracker {
    const MAX_REORG_SIZE: usize = 100;

    /// Create a new tracker
    pub fn new(network: Network, height: u32, tip: BlockHeader) -> Result<Self, Error> {
        tip.validate_pow(&tip.target())
            .map_err(|_| Error::InvalidBlock)?;
        let headers = VecDeque::new();
        Ok(ChainTracker {
            headers,
            tip,
            height,
            network,
        })
    }

    /// Current chain tip header
    pub fn tip(&self) -> BlockHeader {
        self.tip
    }

    /// Height of current chain tip
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Remove block at tip due to reorg
    pub fn remove_block(&mut self) -> Result<BlockHeader, Error> {
        if self.headers.is_empty() {
            return Err(Error::ReorgTooDeep);
        }
        let header = self.tip;
        self.tip = self.headers.pop_front().expect("already checked for empty");
        Ok(header)
    }

    /// Add a block, which becomes the new tip
    pub fn add_block(
        &mut self,
        header: BlockHeader,
        txs: Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) -> Result<(), Error> {
        // Check hash is correctly chained
        if header.prev_blockhash != self.tip.block_hash() {
            return Err(Error::InvalidChain);
        }
        // Ensure correctly mined (hash is under target)
        header
            .validate_pow(&header.target())
            .map_err(|_| Error::InvalidBlock)?;
        if (self.height + 1) % DIFFCHANGE_INTERVAL == 0 {
            let prev_target = self.tip.target();
            let target = header.target();
            let min = prev_target >> 2;
            let max = prev_target << 2;
            let chain_max = max_target(self.network);

            if target.gt(&chain_max) {
                return Err(Error::InvalidBlock);
            }
            if target.lt(&min) || target.gt(&max) {
                return Err(Error::InvalidChain);
            }
            // TODO do actual retargeting with timestamps, requires remembering start timestamp
        } else {
            if header.bits != self.tip.bits && self.network != Network::Testnet {
                return Err(Error::InvalidChain);
            }
        }

        // Check SPV proof
        if let Some(txs_proof) = txs_proof {
            let mut matches = Vec::new();
            let mut indexes = Vec::new();

            let root = txs_proof
                .extract_matches(&mut matches, &mut indexes)
                .map_err(|_| Error::InvalidSpvProof)?;
            if root != header.merkle_root {
                return Err(Error::InvalidSpvProof);
            }
            for (tx, txid) in txs.iter().zip(matches) {
                if tx.txid() != txid {
                    return Err(Error::InvalidSpvProof);
                }
            }
        } else {
            if !txs.is_empty() {
                return Err(Error::InvalidSpvProof);
            }
        }
        self.headers.truncate(Self::MAX_REORG_SIZE - 1);
        self.headers.push_front(self.tip);
        self.tip = header;
        self.height += 1;
        Ok(())
    }
}

/// The one in rust-bitcoin is incorrect for Regtest at least
pub fn max_target(network: Network) -> Uint256 {
    match network {
        Network::Regtest => Uint256::from_u64(0x7fffff).unwrap() << (256 - 24),
        _ => Uint256::from_u64(0xFFFF).unwrap() << 208,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::blockdata::constants::genesis_block;
    use crate::bitcoin::network::constants::Network;
    use crate::bitcoin::util::hash::bitcoin_merkle_root;
    use crate::bitcoin::{BlockHash, TxMerkleNode, Txid};

    #[test]
    fn test_add_remove() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        assert_eq!(tracker.height(), 0);
        assert_eq!(
            tracker.add_block(tracker.tip(), vec![], None).err(),
            Some(Error::InvalidChain)
        );
        let header = make_header(&tracker, Default::default());
        tracker.add_block(header, vec![], None)?;
        assert_eq!(tracker.height(), 1);

        // Difficulty can't change within the retarget period
        let bad_bits = header.bits - 1;
        // println!("{:x} {} {}", header.bits, BlockHeader::u256_from_compact_target(header.bits), BlockHeader::u256_from_compact_target(bad_bits));
        let header_bad_bits =
            mine_header_with_bits(tracker.tip.block_hash(), Default::default(), bad_bits);
        assert_eq!(
            tracker.add_block(header_bad_bits, vec![], None).err(),
            Some(Error::InvalidChain)
        );

        let header_removed = tracker.remove_block()?;
        assert_eq!(header, header_removed);
        assert_eq!(tracker.remove_block().err(), Some(Error::ReorgTooDeep));
        Ok(())
    }

    #[test]
    fn test_spv_proof() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        let txs = [Transaction {
            version: 0,
            lock_time: 0,
            input: vec![Default::default()],
            output: vec![Default::default()],
        }];
        let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
        let merkle_root = bitcoin_merkle_root(txids.iter().map(Txid::as_hash)).into();

        let header = make_header(&tracker, merkle_root);
        let proof = PartialMerkleTree::from_txids(txids.as_slice(), &[true]);

        // try providing txs without proof
        assert_eq!(
            tracker.add_block(header, txs.to_vec(), None).err(),
            Some(Error::InvalidSpvProof)
        );

        // try with a wrong root
        let bad_header = make_header(&tracker, Default::default());
        assert_eq!(
            tracker
                .add_block(bad_header, txs.to_vec(), Some(proof.clone()))
                .err(),
            Some(Error::InvalidSpvProof)
        );

        // try with a wrong txid
        let bad_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![Default::default()],
            output: vec![Default::default()],
        };

        assert_eq!(
            tracker
                .add_block(header, vec![bad_tx], Some(proof.clone()))
                .err(),
            Some(Error::InvalidSpvProof)
        );

        // but this works
        tracker.add_block(header, txs.to_vec(), Some(proof.clone()))?;

        Ok(())
    }

    #[test]
    fn test_retarget() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        for _ in 1..DIFFCHANGE_INTERVAL {
            let header = make_header(&tracker, Default::default());
            tracker.add_block(header, vec![], None)?;
        }
        assert_eq!(tracker.height, DIFFCHANGE_INTERVAL - 1);
        let target = tracker.tip().target();

        // Decrease difficulty by 2 fails because of chain max
        let bits = BlockHeader::compact_target_from_u256(&(target << 1));
        let header = mine_header_with_bits(tracker.tip().block_hash(), Default::default(), bits);
        assert_eq!(
            tracker.add_block(header, vec![], None).err(),
            Some(Error::InvalidBlock)
        );

        // Increase difficulty by 8 fails because of max retarget
        let bits = BlockHeader::compact_target_from_u256(&(target >> 3));
        let header = mine_header_with_bits(tracker.tip().block_hash(), Default::default(), bits);
        assert_eq!(
            tracker.add_block(header, vec![], None).err(),
            Some(Error::InvalidChain)
        );

        // Increase difficulty by 2
        let bits = BlockHeader::compact_target_from_u256(&(target >> 1));
        let header = mine_header_with_bits(tracker.tip().block_hash(), Default::default(), bits);
        tracker.add_block(header, vec![], None)?;
        Ok(())
    }

    fn make_tracker() -> Result<ChainTracker, Error> {
        let genesis = genesis_block(Network::Regtest);
        let tracker = ChainTracker::new(Network::Regtest, 0, genesis.header)?;
        Ok(tracker)
    }

    fn make_header(tracker: &ChainTracker, merkle_root: TxMerkleNode) -> BlockHeader {
        let tip = tracker.tip();
        let bits = tip.bits;
        mine_header_with_bits(tip.block_hash(), merkle_root, bits)
    }

    fn mine_header_with_bits(
        prev_hash: BlockHash,
        merkle_root: TxMerkleNode,
        bits: u32,
    ) -> BlockHeader {
        let mut nonce = 0;
        loop {
            let header = BlockHeader {
                version: 0,
                prev_blockhash: prev_hash,
                merkle_root,
                time: 0,
                bits,
                nonce,
            };
            if header.validate_pow(&header.target()).is_ok() {
                // println!("mined block with nonce {}", nonce);
                return header;
            }
            nonce += 1;
        }
    }
}
