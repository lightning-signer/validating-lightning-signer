use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::mem;

use bitcoin::blockdata::constants::{genesis_block, DIFFCHANGE_INTERVAL};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::uint::Uint256;
use bitcoin::{BlockHeader, FilterHeader, Network, OutPoint, Transaction, Txid};

use crate::policy::validator::ValidatorFactory;
#[allow(unused_imports)]
use log::{debug, error};
use serde_derive::{Deserialize, Serialize};
use serde_with::serde_as;
use txoo::filter::BlockSpendFilter;
use txoo::get_latest_checkpoint;
use txoo::proof::{ProofType, TxoProof};

use crate::prelude::*;
use crate::short_function;
use crate::util::ser_util::{OutPointDef, TxidDef};

/// Error
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Chain progression is invalid (e.g. invalid difficulty change)
    InvalidChain,
    /// Block is invalid (e.g. block hash not under target)
    InvalidBlock,
    /// Reorg size greater than [`ChainTracker::MAX_REORG_SIZE`]
    ReorgTooDeep,
    /// The TXOO proof was incorrect
    InvalidProof,
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

macro_rules! error_invalid_proof {
    ($($arg:tt)*) => {{
        error!("InvalidProof: {}", format!($($arg)*));
        Error::InvalidProof
    }};
}

/// A listener entry
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenSlot {
    /// watched transactions to be confirmed
    #[serde_as(as = "OrderedSet<TxidDef>")]
    pub txid_watches: OrderedSet<Txid>,
    /// watched outpoints to be spent
    #[serde_as(as = "OrderedSet<OutPointDef>")]
    pub watches: OrderedSet<OutPoint>,
    /// outpoints we have already seen
    #[serde_as(as = "OrderedSet<OutPointDef>")]
    pub seen: OrderedSet<OutPoint>,
}

/// Block headers, including the usual bitcoin block header
/// and the filter header
#[derive(Clone)]
pub struct Headers(pub BlockHeader, pub FilterHeader);

impl Encodable for Headers {
    fn consensus_encode<S: crate::io::Write + ?Sized>(
        &self,
        s: &mut S,
    ) -> Result<usize, crate::io::Error> {
        let mut len = 0;
        len += self.0.consensus_encode(s)?;
        len += self.1.consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for Headers {
    fn consensus_decode<D: crate::io::Read + ?Sized>(
        d: &mut D,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let header = BlockHeader::consensus_decode(d)?;
        let filter_header = FilterHeader::consensus_decode(d)?;
        Ok(Headers(header, filter_header))
    }
}

/// Track chain, with basic validation
pub struct ChainTracker<L: ChainListener> {
    /// headers past the tip
    pub headers: VecDeque<Headers>,
    /// tip header
    pub tip: Headers,
    /// height
    pub height: u32,
    /// The network
    pub network: Network,
    /// listeners
    pub listeners: OrderedMap<L::Key, (L, ListenSlot)>,
    node_id: PublicKey,
    validator_factory: Arc<dyn ValidatorFactory>,
}

impl<L: ChainListener> ChainTracker<L> {
    // # issue #187
    #[cfg(feature = "tracker_size_workaround")]
    /// Maximum reorg size that we will accept
    pub const MAX_REORG_SIZE: usize = 16;
    #[cfg(not(feature = "tracker_size_workaround"))]
    /// Maximum reorg size that we will accept
    pub const MAX_REORG_SIZE: usize = 100;

    /// Create a new tracker
    pub fn new(
        network: Network,
        height: u32,
        tip: Headers,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<Self, Error> {
        let header = tip.0;
        header
            .validate_pow(&header.target())
            .map_err(|e| error_invalid_block!("validate pow {}: {}", header.target(), e))?;
        let headers = VecDeque::new();
        let listeners = OrderedMap::new();
        Ok(ChainTracker { headers, tip, height, network, listeners, node_id, validator_factory })
    }

    /// Restore a tracker
    pub fn restore(
        headers: VecDeque<Headers>,
        tip: Headers,
        height: u32,
        network: Network,
        listeners: OrderedMap<L::Key, (L, ListenSlot)>,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Self {
        ChainTracker { headers, tip, height, network, listeners, node_id, validator_factory }
    }

    /// Create a tracker at genesis
    pub fn from_genesis(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Self {
        let height = 0;
        let genesis = genesis_block(network);
        let filter = BlockSpendFilter::from_block(&genesis);
        let filter_header = filter.filter_header(&FilterHeader::all_zeros());
        Self::from_checkpoint(
            network,
            node_id,
            validator_factory,
            &genesis.header,
            &filter_header,
            height,
        )
    }

    fn from_checkpoint(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
        header: &BlockHeader,
        filter_header: &FilterHeader,
        height: u32,
    ) -> Self {
        let tip = Headers(*header, *filter_header);

        Self::new(network, height, tip, node_id, validator_factory)
            .expect("genesis block / checkpoint is expected to be valid")
    }

    /// Create a tracker for a network, from a checkpoint if exists or from genesis otherwise
    pub fn for_network(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Self {
        if let Some((height, _hash, filter_header, header)) = get_latest_checkpoint(network) {
            Self::from_checkpoint(
                network,
                node_id,
                validator_factory,
                &header,
                &filter_header,
                height,
            )
        } else {
            Self::from_genesis(network, node_id, validator_factory)
        }
    }

    /// Current chain tip header
    pub fn tip(&self) -> &Headers {
        &self.tip
    }

    /// Headers past the tip
    pub fn headers(&self) -> &VecDeque<Headers> {
        &self.headers
    }

    /// Height of current chain tip
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Remove block at tip due to reorg
    pub fn remove_block(&mut self, proof: TxoProof) -> Result<BlockHeader, Error> {
        if self.headers.is_empty() {
            return Err(Error::ReorgTooDeep);
        }
        let prev_headers = &self.headers[0];

        self.validate_block(self.height - 1, prev_headers, &self.tip, &proof, true)?;
        let txs = match proof.proof {
            ProofType::Filter(_, spv_proof) => spv_proof.txs,
            ProofType::Block(b) => b.txdata,
            ProofType::ExternalBlock() => panic!("ExternalBlock"),
        };
        self.notify_listeners_remove(&txs);

        let mut headers = self.headers.pop_front().expect("already checked");
        mem::swap(&mut self.tip, &mut headers);
        self.height -= 1;
        Ok(headers.0)
    }

    fn notify_listeners_remove(&mut self, txs: &[Transaction]) {
        for (listener, slot) in self.listeners.values_mut() {
            for tx in txs.iter().rev() {
                // Remove any outpoints that were seen as spent when we added this block
                for inp in tx.input.iter().rev() {
                    if slot.seen.remove(&inp.previous_output) {
                        debug!(
                            "{}: unseeing previously seen outpoint {}",
                            short_function!(),
                            &inp.previous_output
                        );
                        let inserted = slot.watches.insert(inp.previous_output);
                        assert!(inserted, "we failed to previously remove a watch");
                    }
                }

                let txid = tx.txid();

                // Remove any watches that match outputs which are being reorged-out.
                for (vout, _) in tx.output.iter().enumerate() {
                    let outpoint = OutPoint::new(txid, vout as u32);
                    if slot.watches.remove(&outpoint) {
                        debug!("{}: unwatching outpoint {}", short_function!(), &outpoint);
                    }
                }
            }

            listener.on_remove_block(txs);
        }
    }

    /// Add a block, which becomes the new tip
    pub fn add_block(&mut self, header: BlockHeader, proof: TxoProof) -> Result<(), Error> {
        let filter_header = proof.filter_header();
        let headers = Headers(header, filter_header);
        self.validate_block(self.height, &self.tip, &headers, &proof, false)?;
        let txs = match proof.proof {
            ProofType::Filter(_, spv_proof) => spv_proof.txs,
            ProofType::Block(b) => b.txdata,
            ProofType::ExternalBlock() => panic!("ExternalBlock"),
        };

        self.notify_listeners_add(&txs);

        self.headers.truncate(Self::MAX_REORG_SIZE - 1);
        self.headers.push_front(self.tip.clone());
        self.tip = Headers(header, filter_header);
        self.height += 1;
        Ok(())
    }

    fn notify_listeners_add(&mut self, txs: &[Transaction]) {
        for (listener, slot) in self.listeners.values_mut() {
            for tx in txs {
                for inp in tx.input.iter() {
                    if slot.watches.remove(&inp.previous_output) {
                        debug!("{}: matched input {:?}", short_function!(), &inp.previous_output);
                        slot.seen.insert(inp.previous_output);
                    }
                }
                if slot.txid_watches.contains(&tx.txid()) {
                    debug!("{}: matched txid {}", short_function!(), &tx.txid());
                }
            }

            // we provide all txs regardless of whether they matched or not,
            // because streaming block parsing will not be able to filter
            // unmatched txs ahead of time
            let new_watches = listener.on_add_block(txs);
            debug!("{}: adding {:?} watches", short_function!(), new_watches);
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
        debug!("{}: adding listener with txid watches {:?}", short_function!(), slot.txid_watches);
        self.listeners.insert(listener.key().clone(), (listener, slot));
    }

    /// Add more watches to a listener
    pub fn add_listener_watches(&mut self, key: &L::Key, watches: OrderedSet<OutPoint>) {
        let (_, slot) =
            self.listeners.get_mut(key).expect("trying to add watches to non-existent listener");
        debug!("{}: adding watches {:?}", short_function!(), watches);
        slot.watches.extend(watches);
    }

    /// Return all Txid and OutPoint watches for future blocks.
    pub fn get_all_forward_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.get_all_watches(false)
    }

    /// Return all Txid and OutPoint watches for removing blocks.
    /// This is a superset of the forward watches, and also includes
    /// watches for outpoints which were seen as spent in previous blocks.
    pub fn get_all_reverse_watches(&self) -> (Vec<Txid>, Vec<OutPoint>) {
        self.get_all_watches(true)
    }

    fn get_all_watches(&self, include_reverse: bool) -> (Vec<Txid>, Vec<OutPoint>) {
        let mut txid_watches = OrderedSet::new();
        let mut outpoint_watches = OrderedSet::new();
        for (_, slot) in self.listeners.values() {
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
        height: u32,
        prev_headers: &Headers,
        headers: &Headers,
        proof: &TxoProof,
        is_remove: bool,
    ) -> Result<(), Error> {
        let header = &headers.0;
        let prev_header = &prev_headers.0;
        // Check hash is correctly chained
        if header.prev_blockhash != prev_header.block_hash() {
            return Err(error_invalid_chain!(
                "header.prev_blockhash {} != self.tip.block_hash {}",
                header.prev_blockhash.to_hex(),
                prev_header.block_hash().to_hex()
            ));
        }
        // Ensure correctly mined (hash is under target)
        header.validate_pow(&header.target()).map_err(|_| Error::InvalidBlock)?;
        if self.network == Network::Testnet
            && header.target() == max_target(self.network)
            && header.time > prev_header.time + 60 * 20
        {
            // special case for Testnet - 20 minute rule
        } else if (height + 1) % DIFFCHANGE_INTERVAL == 0 {
            let prev_target = prev_header.target();
            let target = header.target();
            let network = self.network;
            validate_retarget(prev_target, target, network)?;
        } else {
            if header.bits != prev_header.bits && self.network != Network::Testnet {
                return Err(error_invalid_chain!(
                    "header.bits {} != self.tip.bits {}",
                    header.bits,
                    prev_header.bits
                ));
            }
        }

        let (_, outpoint_watches) =
            if is_remove { self.get_all_reverse_watches() } else { self.get_all_forward_watches() };

        let validator = self.validator_factory.make_validator(self.network, self.node_id, None);
        let prev_filter_header = &prev_headers.1;

        if prev_filter_header.iter().all(|x| *x == 0) {
            // This allows us to upgrade old signers that didn't have filter headers.
            // It is safe, because it's vanishingly unlikely that the filter header is
            // all zeros, so the only way this can be triggered is if the filter header
            // was missing on restore.
            log::warn!("bypassing filter validation because prev_filter_header is all zeroes");
        } else {
            validator
                .validate_block(proof, height + 1, header, prev_filter_header, &outpoint_watches)
                .map_err(|e| error_invalid_proof!("{:?}", e))?;
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
    /// The key type
    type Key: Ord + Clone;

    /// The key
    fn key(&self) -> &Self::Key;

    /// A block was added, and zero or more transactions consume watched outpoints.
    /// The listener returns zero or more new outpoints to watch.
    fn on_add_block(&self, txs: &[Transaction]) -> Vec<OutPoint>;

    /// A block was deleted.
    /// The tracker will revert any changes to the watched outpoints set.
    fn on_remove_block(&self, txs: &[Transaction]);
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
    use crate::util::test_utils::*;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::network::constants::Network;
    use bitcoin::util::hash::bitcoin_merkle_root;
    use bitcoin::{Block, TxIn};
    use bitcoin::{PackedLockTime, Sequence, TxMerkleNode, Witness};
    use bitcoind_client::dummy::DummyTxooSource;
    use core::iter::FromIterator;

    use super::*;

    use crate::util::mocks::MockValidatorFactory;
    use test_log::test;
    use txoo::source::Source;

    #[tokio::test]
    async fn test_add_remove() -> Result<(), Error> {
        let genesis = genesis_block(Network::Regtest);
        let source = make_source().await;
        let (mut tracker, _) = make_tracker()?;
        let header0 = tracker.tip().0.clone();
        assert_eq!(tracker.height(), 0);
        let header1 = add_block(&mut tracker, &source, &[]).await?;
        assert_eq!(tracker.height(), 1);

        // difficulty can't change within the retarget period
        let bad_bits = header1.bits - 1;
        let header_bad_bits =
            mine_header_with_bits(tracker.tip.0.block_hash(), TxMerkleNode::all_zeros(), bad_bits);
        let dummy_proof =
            TxoProof::prove_unchecked(&genesis, &FilterHeader::all_zeros(), tracker.height() + 1);
        assert_eq!(
            tracker.add_block(header_bad_bits, dummy_proof).err(),
            Some(Error::InvalidChain)
        );

        let header_removed = remove_block(&mut tracker, &source, &[], &header0).await?;
        assert_eq!(header1, header_removed);

        // can't go back before the first block that the tracker saw
        let (_, filter_header) = source.get(0, &genesis).await.unwrap();
        let proof = TxoProof::prove_unchecked(&genesis, &filter_header, 0);

        assert_eq!(tracker.remove_block(proof).err(), Some(Error::ReorgTooDeep));
        Ok(())
    }

    async fn make_source() -> DummyTxooSource {
        let source = DummyTxooSource::new();
        source.on_new_block(0, &genesis_block(Network::Regtest)).await;
        source
    }

    #[tokio::test]
    async fn test_listeners() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, validator_factory) = make_tracker()?;

        let header1 = add_block(&mut tracker, &source, &[]).await?;

        let tx = make_tx(vec![make_txin(1)]);
        let initial_watch = make_outpoint(1);
        let second_watch = OutPoint::new(tx.txid(), 0);
        let listener = MockListener::new(second_watch);

        tracker.add_listener(listener.clone(), OrderedSet::new());

        tracker.add_listener_watches(&second_watch, OrderedSet::from_iter(vec![initial_watch]));

        assert_eq!(tracker.listeners.len(), 1);
        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        let header2 = add_block(&mut tracker, &source, &[tx.clone()]).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        let tx2 = make_tx(vec![TxIn {
            previous_output: second_watch,
            script_sig: Default::default(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        }]);

        let _header3 = add_block(&mut tracker, &source, &[tx2.clone()]).await?;

        assert_eq!(tracker.listeners.get(listener.key()).unwrap().1.watches, OrderedSet::new());

        // validation included forward watches
        assert_eq!(
            *validator_factory.validator().last_validated_watches.lock().unwrap(),
            vec![second_watch]
        );

        remove_block(&mut tracker, &source, &[tx2], &header2).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        // validation should have included reverse watches
        assert_eq!(
            *validator_factory.validator().last_validated_watches.lock().unwrap(),
            vec![initial_watch, second_watch]
        );

        remove_block(&mut tracker, &source, &[tx], &header1).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        // validation should still include reverse watches, because those are
        // currently not pruned
        assert_eq!(
            *validator_factory.validator().last_validated_watches.lock().unwrap(),
            vec![initial_watch, second_watch]
        );

        Ok(())
    }

    // returns the new block's header
    async fn add_block(
        tracker: &mut ChainTracker<MockListener>,
        source: &DummyTxooSource,
        txs: &[Transaction],
    ) -> Result<BlockHeader, Error> {
        let txs = txs_with_coinbase(txs);

        let block = make_block(tracker.tip().0, txs);
        let height = tracker.height() + 1;
        source.on_new_block(height, &block).await;
        let (_attestation, filter_header) = source.get(height, &block).await.unwrap();
        let proof = TxoProof::prove_unchecked(&block, &filter_header, height);

        tracker.add_block(block.header.clone(), proof)?;
        Ok(block.header)
    }

    // returns the new block's header
    async fn add_block_with_bits(
        tracker: &mut ChainTracker<MockListener>,
        source: &DummyTxooSource,
        bits: u32,
        do_add: bool,
    ) -> Result<BlockHeader, Error> {
        let txs = txs_with_coinbase(&[]);
        let txids: Vec<Txid> = txs.iter().map(|tx| tx.txid()).collect();

        let merkle_root = bitcoin_merkle_root(txids.iter().map(Txid::as_hash)).unwrap().into();
        let header = mine_header_with_bits(tracker.tip().0.block_hash(), merkle_root, bits);

        let block = Block { header, txdata: txs };
        let height = tracker.height() + 1;

        let filter_header = if do_add {
            source.on_new_block(height, &block).await;
            let (_attestation, filter_header) = source.get(height, &block).await.unwrap();
            filter_header
        } else {
            FilterHeader::all_zeros()
        };
        let proof = TxoProof::prove_unchecked(&block, &filter_header, height);

        tracker.add_block(block.header.clone(), proof)?;
        Ok(block.header)
    }

    // returns the removed block's header
    async fn remove_block(
        tracker: &mut ChainTracker<MockListener>,
        source: &DummyTxooSource,
        txs: &[Transaction],
        prev_header: &BlockHeader,
    ) -> Result<BlockHeader, Error> {
        let txs = txs_with_coinbase(txs);
        let block = make_block(*prev_header, txs);
        let height = tracker.height();
        let (_attestation, filter_header) = source.get(height, &block).await.unwrap();
        let proof = TxoProof::prove_unchecked(&block, &filter_header, height);

        let header = tracker.remove_block(proof)?;
        Ok(header)
    }

    fn txs_with_coinbase(txs: &[Transaction]) -> Vec<Transaction> {
        let mut txs = txs.to_vec();
        txs.insert(
            0,
            Transaction { version: 0, lock_time: PackedLockTime(0), input: vec![], output: vec![] },
        );
        txs
    }

    #[tokio::test]
    async fn test_retarget() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, _) = make_tracker()?;
        for _ in 1..DIFFCHANGE_INTERVAL {
            add_block(&mut tracker, &source, &[]).await?;
        }
        assert_eq!(tracker.height, DIFFCHANGE_INTERVAL - 1);
        let target = tracker.tip().0.target();

        // Decrease difficulty by 2 fails because of chain max
        let bits = BlockHeader::compact_target_from_u256(&(target << 1));
        assert_eq!(
            add_block_with_bits(&mut tracker, &source, bits, false).await.err(),
            Some(Error::InvalidBlock)
        );

        // Increase difficulty by 8 fails because of max retarget
        let bits = BlockHeader::compact_target_from_u256(&(target >> 3));
        assert_eq!(
            add_block_with_bits(&mut tracker, &source, bits, false).await.err(),
            Some(Error::InvalidChain)
        );

        // Increase difficulty by 2
        let bits = BlockHeader::compact_target_from_u256(&(target >> 1));
        add_block_with_bits(&mut tracker, &source, bits, true).await?;
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

    fn make_tracker() -> Result<(ChainTracker<MockListener>, Arc<MockValidatorFactory>), Error> {
        let genesis = genesis_block(Network::Regtest);
        let validator_factory = Arc::new(MockValidatorFactory::new());
        let (node_id, _, _) = make_node();
        let tip = Headers(genesis.header, FilterHeader::all_zeros());
        let tracker =
            ChainTracker::new(Network::Regtest, 0, tip, node_id, validator_factory.clone())?;
        Ok((tracker, validator_factory))
    }
}
