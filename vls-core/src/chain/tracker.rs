use alloc::collections::VecDeque;

use bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::util::uint::Uint256;
use bitcoin::{BlockHeader, Network, OutPoint, Transaction, Txid};

#[allow(unused_imports)]
use log::{debug, error};

use crate::prelude::*;
use crate::short_function;

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

macro_rules! error_invalid_chain {
    ($($arg:tt)*) => {{
        error!("InvalidChain: {}", format!($($arg)*));
        Error::InvalidChain
    }};
}

macro_rules! error_invalid_block {
    ($($arg:tt)*) => {{
        error!("InvalidBlock: {}", format!($($arg)*));
        Error::InvalidBlock
    }};
}

macro_rules! error_invalid_spv_proof {
    ($($arg:tt)*) => {{
        error!("InvalidSpvProof: {}", format!($($arg)*));
        Error::InvalidSpvProof
    }};
}

/// A listener entry
#[derive(Debug, Clone)]
pub struct ListenSlot {
    /// watched transactions to be confirmed
    pub txid_watches: OrderedSet<Txid>,
    /// watched outpoints to be spent
    pub watches: OrderedSet<OutPoint>,
    /// outpoints we have already seen
    pub seen: OrderedSet<OutPoint>,
}

/// Track chain, with basic validation
pub struct ChainTracker<L: ChainListener + Ord> {
    /// headers past the tip
    pub headers: VecDeque<BlockHeader>,
    /// tip header
    pub tip: BlockHeader,
    /// height
    pub height: u32,
    /// The network
    pub network: Network,
    /// listeners
    pub listeners: OrderedMap<L, ListenSlot>,
}

impl<L: ChainListener + Ord> ChainTracker<L> {
    const MAX_REORG_SIZE: usize = 100;

    /// Create a new tracker
    pub fn new(network: Network, height: u32, tip: BlockHeader) -> Result<Self, Error> {
        tip.validate_pow(&tip.target())
            .map_err(|e| error_invalid_block!("validate pow {}: {}", tip.target(), e))?;
        let headers = VecDeque::new();
        let listeners = OrderedMap::new();
        Ok(ChainTracker { headers, tip, height, network, listeners })
    }

    /// Current chain tip header
    pub fn tip(&self) -> BlockHeader {
        self.tip
    }

    /// Headers past the tip
    pub fn headers(&self) -> &VecDeque<BlockHeader> {
        &self.headers
    }

    /// Height of current chain tip
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Remove block at tip due to reorg
    pub fn remove_block(
        &mut self,
        txs: Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) -> Result<BlockHeader, Error> {
        if self.headers.is_empty() {
            return Err(Error::ReorgTooDeep);
        }
        let header = self.tip;
        Self::validate_spv(&header, &txs, txs_proof)?;
        self.notify_listeners_remove(&txs);

        self.tip = self.headers.pop_front().expect("already checked for empty");
        self.height -= 1;
        Ok(header)
    }

    fn notify_listeners_remove(&mut self, txs: &Vec<Transaction>) {
        for (listener, slot) in self.listeners.iter_mut() {
            let mut matched = Vec::new();
            for tx in txs.iter().rev() {
                // Remove any outpoints that were seen as spent when we added this block
                let mut found = false;
                for inp in tx.input.iter().rev() {
                    if slot.seen.remove(&inp.previous_output) {
                        debug!(
                            "{}: unseeing previously seen outpoint {}",
                            short_function!(),
                            &inp.previous_output
                        );
                        found = true;
                        let inserted = slot.watches.insert(inp.previous_output);
                        assert!(inserted, "we failed to previously remove a watch");
                    }
                }

                let txid = tx.txid();
                if slot.txid_watches.contains(&txid) {
                    found = true;
                }

                // Remove any watches that match outputs which are being reorged-out.
                for (vout, _) in tx.output.iter().enumerate() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    if slot.watches.remove(&outpoint) {
                        debug!("{}: unwatching outpoint {}", short_function!(), &outpoint);
                        assert!(found, "a watch was previously added without any inputs matching");
                    }
                }

                if found {
                    matched.push(tx);
                }
            }
            listener.on_remove_block(matched);
        }
    }

    /// Add a block, which becomes the new tip
    pub fn add_block(
        &mut self,
        header: BlockHeader,
        txs: Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) -> Result<(), Error> {
        self.validate_block(&header, &txs, txs_proof)?;

        self.notify_listeners_add(&txs);

        self.headers.truncate(Self::MAX_REORG_SIZE - 1);
        self.headers.push_front(self.tip);
        self.tip = header;
        self.height += 1;
        Ok(())
    }

    fn notify_listeners_add(&mut self, txs: &Vec<Transaction>) {
        for (listener, slot) in self.listeners.iter_mut() {
            let mut matched = Vec::new();
            for tx in txs {
                let mut found = false;
                for inp in tx.input.iter() {
                    if slot.watches.remove(&inp.previous_output) {
                        found = true;
                        slot.seen.insert(inp.previous_output);
                    }
                }
                if slot.txid_watches.contains(&tx.txid()) {
                    found = true;
                }
                if found {
                    matched.push(tx);
                }
            }
            let new_watches = listener.on_add_block(matched);
            slot.watches.extend(new_watches);
        }
    }

    /// Add a listener and initialize the watched outpoint set
    pub fn add_listener(&mut self, listener: L, initial_txid_watches: OrderedSet<Txid>) {
        let slot = ListenSlot {
            txid_watches: initial_txid_watches,
            watches: OrderedSet::new(),
            seen: OrderedSet::new(),
        };
        self.listeners.insert(listener, slot);
    }

    /// Add more watches to a listener
    pub fn add_listener_watches(&mut self, listener: L, watches: OrderedSet<OutPoint>) {
        let slot = self
            .listeners
            .get_mut(&listener)
            .expect("trying to add watches to non-existent listener");
        slot.watches.extend(watches);
    }

    /// Return all Txid and OutPoint watches for future blocks.
    pub fn get_all_forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.get_all_watches(false)
    }

    /// Return all Txid and OutPoint watches for removing blocks.
    pub fn get_all_reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.get_all_watches(true)
    }

    fn get_all_watches(&self, include_reverse: bool) -> (Vec<Txid>, Vec<OutPoint>) {
        let mut txid_watches = OrderedSet::new();
        let mut outpoint_watches = OrderedSet::new();
        for slot in self.listeners.values() {
            txid_watches.extend(&slot.txid_watches);
            outpoint_watches.extend(&slot.watches);
            if include_reverse {
                outpoint_watches.extend(&slot.seen);
            }
        }
        (txid_watches.into_iter().collect(), outpoint_watches.into_iter().collect())
    }

    fn validate_block(
        &self,
        header: &BlockHeader,
        txs: &Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) -> Result<(), Error> {
        // Check hash is correctly chained
        if header.prev_blockhash != self.tip.block_hash() {
            return Err(error_invalid_chain!(
                "header.prev_blockhash {} != self.tip.block_hash {}",
                header.prev_blockhash.to_hex(),
                self.tip.block_hash().to_hex()
            ));
        }
        // Ensure correctly mined (hash is under target)
        header.validate_pow(&header.target()).map_err(|_| Error::InvalidBlock)?;
        if self.network == Network::Testnet
            && header.target() == max_target(self.network)
            && header.time > self.tip.time + 60 * 20
        {
            // special case for Testnet - 20 minute rule
        } else if (self.height + 1) % DIFFCHANGE_INTERVAL == 0 {
            let prev_target = self.tip.target();
            let target = header.target();
            let network = self.network;
            validate_retarget(prev_target, target, network)?;
        } else {
            if header.bits != self.tip.bits && self.network != Network::Testnet {
                return Err(error_invalid_chain!(
                    "header.bits {} != self.tip.bits {}",
                    header.bits,
                    self.tip.bits
                ));
            }
        }

        Self::validate_spv(header, txs, txs_proof)?;
        Ok(())
    }

    fn validate_spv(
        header: &BlockHeader,
        txs: &Vec<Transaction>,
        txs_proof: Option<PartialMerkleTree>,
    ) -> Result<(), Error> {
        // Check SPV proof
        if let Some(txs_proof) = txs_proof {
            let mut matches = Vec::new();
            let mut indexes = Vec::new();

            let root = txs_proof
                .extract_matches(&mut matches, &mut indexes)
                .map_err(|e| error_invalid_spv_proof!("extract matches failed: {:?}", e))?;
            if root != header.merkle_root {
                return Err(error_invalid_spv_proof!(
                    "root {} != header.merkle_root {}",
                    root,
                    header.merkle_root
                ));
            }
            for (tx, txid) in txs.iter().zip(matches) {
                if tx.txid() != txid {
                    return Err(error_invalid_spv_proof!("tx.txid {} != txid {}", tx.txid(), txid));
                }
            }
        } else {
            if !txs.is_empty() {
                return Err(error_invalid_spv_proof!("txs not empty"));
            }
        }
        Ok(())
    }
}

fn validate_retarget(prev_target: Uint256, target: Uint256, network: Network) -> Result<(), Error> {
    // TODO do actual retargeting with timestamps, requires remembering start timestamp

    // Round trip the target bounds, to simulate the way bitcoind checks them
    fn round_trip_target(prev_target: &Uint256) -> Uint256 {
        BlockHeader::u256_from_compact_target(BlockHeader::compact_target_from_u256(prev_target))
    }

    let min = round_trip_target(&(prev_target >> 2));
    let max = round_trip_target(&(prev_target << 2));
    let chain_max = max_target(network);

    if target.gt(&chain_max) {
        return Err(error_invalid_block!("target {} > chain_max {}", target, chain_max));
    }
    if target.lt(&min) {
        return Err(error_invalid_chain!("target {} < min {}", target, min));
    }
    if target.gt(&max) {
        return Err(error_invalid_chain!("target {} > max {}", target, max));
    }
    Ok(())
}

/// Listen to chain events
pub trait ChainListener: SendSync {
    /// A block was added, and zero or more transactions consume watched outpoints.
    /// The listener returns zero or more new outpoints to watch.
    fn on_add_block(&self, txs: Vec<&Transaction>) -> Vec<OutPoint>;
    /// A block was deleted.
    /// The tracker will revert any changes to the watched outpoints set.
    fn on_remove_block(&self, txs: Vec<&Transaction>);
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
    use bitcoin::hashes::Hash;
    use bitcoin::{PackedLockTime, Sequence, TxMerkleNode, Witness};
    use core::iter::FromIterator;

    use crate::bitcoin::blockdata::constants::genesis_block;
    use crate::bitcoin::hashes::_export::_core::cmp::Ordering;
    use crate::bitcoin::network::constants::Network;
    use crate::bitcoin::util::hash::bitcoin_merkle_root;
    use crate::bitcoin::{TxIn, Txid};
    use crate::util::test_utils::*;

    use super::*;

    use test_log::test;

    #[test]
    fn test_add_remove() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        assert_eq!(tracker.height(), 0);
        assert_eq!(tracker.add_block(tracker.tip(), vec![], None).err(), Some(Error::InvalidChain));
        let header = make_header(tracker.tip(), TxMerkleNode::all_zeros());
        tracker.add_block(header, vec![], None)?;
        assert_eq!(tracker.height(), 1);

        // Difficulty can't change within the retarget period
        let bad_bits = header.bits - 1;
        // println!("{:x} {} {}", header.bits, BlockHeader::u256_from_compact_target(header.bits), BlockHeader::u256_from_compact_target(bad_bits));
        let header_bad_bits =
            mine_header_with_bits(tracker.tip.block_hash(), TxMerkleNode::all_zeros(), bad_bits);
        assert_eq!(
            tracker.add_block(header_bad_bits, vec![], None).err(),
            Some(Error::InvalidChain)
        );

        let header_removed = tracker.remove_block(vec![], None)?;
        assert_eq!(header, header_removed);
        assert_eq!(tracker.remove_block(vec![], None).err(), Some(Error::ReorgTooDeep));
        Ok(())
    }

    struct MockListener {
        watch: OutPoint,
        watched: Mutex<bool>,
    }

    impl SendSync for MockListener {}

    impl PartialEq<Self> for MockListener {
        fn eq(&self, other: &Self) -> bool {
            self.watch.eq(&other.watch)
        }
    }

    impl PartialOrd for MockListener {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            self.watch.partial_cmp(&other.watch)
        }
    }

    impl Eq for MockListener {}

    impl Ord for MockListener {
        fn cmp(&self, other: &Self) -> Ordering {
            self.watch.cmp(&other.watch)
        }
    }

    impl Clone for MockListener {
        fn clone(&self) -> Self {
            // We just need this to have the right `Ord` semantics
            // the value of `watched` doesn't matter
            Self { watch: self.watch, watched: Mutex::new(false) }
        }
    }

    impl ChainListener for MockListener {
        fn on_add_block(&self, _txs: Vec<&Transaction>) -> Vec<OutPoint> {
            let mut watched = self.watched.lock().unwrap();
            if *watched {
                vec![]
            } else {
                *watched = true;
                vec![self.watch]
            }
        }

        fn on_remove_block(&self, _txs: Vec<&Transaction>) {}
    }

    impl MockListener {
        fn new(watch: OutPoint) -> Self {
            MockListener { watch, watched: Mutex::new(false) }
        }
    }

    #[test]
    fn test_listeners() -> Result<(), Error> {
        let mut tracker = make_tracker()?;

        let header = make_header(tracker.tip(), TxMerkleNode::all_zeros());
        tracker.add_block(header, vec![], None)?;

        let tx = make_tx(vec![make_txin(1)]);
        let initial_watch = make_outpoint(1);
        let second_watch = OutPoint::new(tx.txid(), 0);
        let listener = MockListener::new(second_watch);

        tracker.add_listener(listener.clone(), OrderedSet::new());

        tracker.add_listener_watches(listener.clone(), OrderedSet::from_iter(vec![initial_watch]));

        assert_eq!(tracker.listeners.len(), 1);
        assert_eq!(
            tracker.listeners.get(&listener).unwrap().watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        add_block(&mut tracker, tx.clone())?;

        assert_eq!(
            tracker.listeners.get(&listener).unwrap().watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        let tx2 = make_tx(vec![TxIn {
            previous_output: second_watch,
            script_sig: Default::default(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        }]);

        add_block(&mut tracker, tx2.clone())?;

        assert_eq!(tracker.listeners.get(&listener).unwrap().watches, OrderedSet::new());

        remove_block(&mut tracker, tx2.clone())?;

        assert_eq!(
            tracker.listeners.get(&listener).unwrap().watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        remove_block(&mut tracker, tx.clone())?;

        assert_eq!(
            tracker.listeners.get(&listener).unwrap().watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        Ok(())
    }

    fn add_block(tracker: &mut ChainTracker<MockListener>, tx: Transaction) -> Result<(), Error> {
        let txids = [tx.txid()];
        let proof = PartialMerkleTree::from_txids(&txids, &[true]);

        // unwrap is OK, because we have non-empty txids
        let merkle_root = bitcoin_merkle_root(txids.iter().map(Txid::as_hash)).unwrap().into();

        tracker.add_block(make_header(tracker.tip(), merkle_root), vec![tx], Some(proof))
    }

    fn remove_block(
        tracker: &mut ChainTracker<MockListener>,
        tx: Transaction,
    ) -> Result<(), Error> {
        let txids = [tx.txid()];
        let proof = PartialMerkleTree::from_txids(&txids, &[true]);

        tracker.remove_block(vec![tx], Some(proof))?;
        Ok(())
    }

    #[test]
    fn test_spv_proof() -> Result<(), Error> {
        let mut tracker = make_tracker()?;
        let txs = [Transaction {
            version: 0,
            lock_time: PackedLockTime::ZERO,
            input: vec![Default::default()],
            output: vec![Default::default()],
        }];
        let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();
        // unwrap is OK, because we have non-empty txids
        let merkle_root = bitcoin_merkle_root(txids.iter().map(Txid::as_hash)).unwrap().into();

        let header = make_header(tracker.tip(), merkle_root);
        let proof = PartialMerkleTree::from_txids(txids.as_slice(), &[true]);

        // try providing txs without proof
        assert_eq!(
            tracker.add_block(header, txs.to_vec(), None).err(),
            Some(Error::InvalidSpvProof)
        );

        // try with a wrong root
        let bad_header = make_header(tracker.tip(), TxMerkleNode::all_zeros());
        assert_eq!(
            tracker.add_block(bad_header, txs.to_vec(), Some(proof.clone())).err(),
            Some(Error::InvalidSpvProof)
        );

        // try with a wrong txid
        let bad_tx = Transaction {
            version: 1,
            lock_time: PackedLockTime::ZERO,
            input: vec![Default::default()],
            output: vec![Default::default()],
        };

        assert_eq!(
            tracker.add_block(header, vec![bad_tx], Some(proof.clone())).err(),
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
            let header = make_header(tracker.tip(), TxMerkleNode::all_zeros());
            tracker.add_block(header, vec![], None)?;
        }
        assert_eq!(tracker.height, DIFFCHANGE_INTERVAL - 1);
        let target = tracker.tip().target();

        // Decrease difficulty by 2 fails because of chain max
        let bits = BlockHeader::compact_target_from_u256(&(target << 1));
        let header =
            mine_header_with_bits(tracker.tip().block_hash(), TxMerkleNode::all_zeros(), bits);
        assert_eq!(tracker.add_block(header, vec![], None).err(), Some(Error::InvalidBlock));

        // Increase difficulty by 8 fails because of max retarget
        let bits = BlockHeader::compact_target_from_u256(&(target >> 3));
        let header =
            mine_header_with_bits(tracker.tip().block_hash(), TxMerkleNode::all_zeros(), bits);
        assert_eq!(tracker.add_block(header, vec![], None).err(), Some(Error::InvalidChain));

        // Increase difficulty by 2
        let bits = BlockHeader::compact_target_from_u256(&(target >> 1));
        let header =
            mine_header_with_bits(tracker.tip().block_hash(), TxMerkleNode::all_zeros(), bits);
        tracker.add_block(header, vec![], None)?;
        Ok(())
    }

    #[test]
    fn test_retarget_rounding() -> Result<(), Error> {
        validate_retarget(
            BlockHeader::u256_from_compact_target(0x1c063051),
            BlockHeader::u256_from_compact_target(0x1c018c14),
            Network::Testnet,
        )?;
        Ok(())
    }

    fn make_tracker() -> Result<ChainTracker<MockListener>, Error> {
        let genesis = genesis_block(Network::Regtest);
        let tracker = ChainTracker::new(Network::Regtest, 0, genesis.header)?;
        Ok(tracker)
    }
}
