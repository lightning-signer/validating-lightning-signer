use alloc::collections::VecDeque;
use crate::bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use crate::bitcoin::{BlockHeader, Network};
use crate::bitcoin::util::uint::Uint256;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidChain,
    InvalidBlock,
    ReorgTooDeep,
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

    pub fn tip(&self) -> BlockHeader {
        self.tip
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn remove_block(&mut self) -> Result<BlockHeader, Error> {
        if self.headers.is_empty() {
            return Err(Error::ReorgTooDeep)
        }
        let header = self.tip;
        self.tip = self.headers.pop_front()
            .expect("already checked for empty");
        Ok(header)
    }

    pub fn add_block(&mut self, header: BlockHeader) -> Result<(), Error> {
        // Check hash is correctly chained
        if header.prev_blockhash != self.tip.block_hash() {
            return Err(Error::InvalidChain);
        }
        // Ensure correctly mined (hash is under target)
        header.validate_pow(&header.target())
            .map_err(|_| Error::InvalidBlock)?;
        if (self.height + 1) % DIFFCHANGE_INTERVAL == 0 {
            let prev_target = self.tip.target();
            let target = header.target();
            let min = prev_target >> 2;
            let max = prev_target << 2;
            let chain_max = max_target(self.network);

            if target.ge(&chain_max) {
                return Err(Error::InvalidBlock);
            }
            if target.le(&min) || target.ge(&max) {
                return Err(Error::InvalidChain);
            }
            // TODO do actual retargeting with timestamps, requires remembering start timestamp
        } else {
            if header.bits != self.tip.bits {
                return Err(Error::InvalidChain);
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
        Network::Regtest => Uint256::from_u64(0x7fffff).unwrap() << (256-24),
        _ => Uint256::from_u64(0xFFFF).unwrap() << 208,
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::blockdata::constants::genesis_block;
    use crate::bitcoin::BlockHash;
    use crate::bitcoin::network::constants::Network;
    use super::*;

    #[test]
    pub fn test_add_remove() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        assert_eq!(tracker.height(), 0);
        assert_eq!(tracker.add_block(tracker.tip()).err(), Some(Error::InvalidChain));
        let header = make_header(&tracker);
        tracker.add_block(header)?;
        assert_eq!(tracker.height(), 1);

        // Difficulty can't change within the retarget period
        let bad_bits = header.bits - 1;
        // println!("{:x} {} {}", header.bits, BlockHeader::u256_from_compact_target(header.bits), BlockHeader::u256_from_compact_target(bad_bits));
        let header_bad_bits = mine_header_with_bits(tracker.tip.block_hash(), bad_bits);
        assert_eq!(tracker.add_block(header_bad_bits).err(), Some(Error::InvalidChain));

        let header_removed = tracker.remove_block()?;
        assert_eq!(header, header_removed);
        assert_eq!(tracker.remove_block().err(), Some(Error::ReorgTooDeep));
        Ok(())
    }

    #[test]
    pub fn test_retarget() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        for _ in 1..DIFFCHANGE_INTERVAL {
            let header = make_header(&tracker);
            tracker.add_block(header)?;
        }
        assert_eq!(tracker.height, DIFFCHANGE_INTERVAL - 1);
        let target = tracker.tip().target();

        // Decrease difficulty by 2 fails because of chain max
        let bits = BlockHeader::compact_target_from_u256(&(target << 1));
        let header = mine_header_with_bits(tracker.tip().block_hash(), bits);
        assert_eq!(tracker.add_block(header).err(), Some(Error::InvalidBlock));

        // Increase difficulty by 8 fails because of max retarget
        let bits = BlockHeader::compact_target_from_u256(&(target >> 3));
        let header = mine_header_with_bits(tracker.tip().block_hash(), bits);
        assert_eq!(tracker.add_block(header).err(), Some(Error::InvalidChain));

        // Increase difficulty by 2
        let bits = BlockHeader::compact_target_from_u256(&(target >> 1));
        let header = mine_header_with_bits(tracker.tip().block_hash(), bits);
        tracker.add_block(header)?;
        Ok(())
    }

    fn make_tracker() -> Result<ChainTracker, Error> {
        let genesis = genesis_block(Network::Regtest);
        let tracker = ChainTracker::new(Network::Regtest, 0, genesis.header)?;
        Ok(tracker)
    }

    fn make_header(tracker: &ChainTracker) -> BlockHeader {
        let tip = tracker.tip();
        let bits = tip.bits;
        mine_header_with_bits(tip.block_hash(), bits)
    }

    fn mine_header_with_bits(prev_hash: BlockHash, bits: u32) -> BlockHeader {
        let mut nonce = 0;
        loop {
            let header = BlockHeader {
                version: 0,
                prev_blockhash: prev_hash,
                merkle_root: Default::default(),
                time: 0,
                bits,
                nonce
            };
            if header.validate_pow(&header.target()).is_ok() {
                // println!("mined block with nonce {}", nonce);
                return header;
            }
            nonce += 1;
        }
    }
}
