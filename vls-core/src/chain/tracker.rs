use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::mem;
#[cfg(feature = "timeless_workaround")]
use core::time::Duration;

use bitcoin::blockdata::constants::{genesis_block, DIFFCHANGE_INTERVAL};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::uint::Uint256;
use bitcoin::{
    BlockHash, BlockHeader, FilterHeader, Network, OutPoint, PackedLockTime, Transaction, TxIn,
    TxOut, Txid,
};

use crate::policy::validator::ValidatorFactory;
#[allow(unused_imports)]
use log::{debug, error, info, warn};
use push_decoder::{BlockDecoder, Listener as PushListener};
use serde_derive::{Deserialize, Serialize};
use serde_with::{serde_as, IfIsHumanReadable};
use txoo::filter::BlockSpendFilter;
use txoo::get_latest_checkpoint;
use txoo::proof::{ProofType, TxoProof};

use crate::prelude::*;
use crate::short_function;
use crate::util::ser_util::{OutPointReversedDef, TxIdReversedDef};

/// Error
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Chain progression is invalid (e.g. invalid difficulty change)
    InvalidChain,
    /// Previous blockhash of new block header doesn't match the current tip
    OrphanBlock(String),
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

macro_rules! error_orphan_block {
    ($($arg:tt)*) => {{
        let message = format!($($arg)*);
        warn!("OrphanBlock: {}", message);
        Error::OrphanBlock(message)
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
    #[serde_as(as = "IfIsHumanReadable<OrderedSet<TxIdReversedDef>>")]
    pub txid_watches: OrderedSet<Txid>,
    /// watched outpoints to be spent
    #[serde_as(as = "IfIsHumanReadable<OrderedSet<OutPointReversedDef>>")]
    pub watches: OrderedSet<OutPoint>,
    /// outpoints we have already seen
    #[serde_as(as = "IfIsHumanReadable<OrderedSet<OutPointReversedDef>>")]
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

// the decode state while we are receiving a block
struct BlockDecodeState {
    decoder: BlockDecoder,
    offset: u32,
    block_hash: BlockHash,
}

impl BlockDecodeState {
    fn new(block_hash: BlockHash) -> Self {
        BlockDecodeState { decoder: BlockDecoder::new(), offset: 0, block_hash }
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
    // Block decoder, only while streaming a block is in progress
    decode_state: Option<RefCell<BlockDecodeState>>,
    /// public keys of trusted TXO oracle
    pub trusted_oracle_pubkeys: Vec<PublicKey>,
    allow_deep_reorgs: bool,
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
        trusted_oracle_pubkeys: Vec<PublicKey>,
    ) -> Result<Self, Error> {
        let header = tip.0;
        header
            .validate_pow(&header.target())
            .map_err(|e| error_invalid_block!("validate pow {}: {}", header.target(), e))?;
        let headers = VecDeque::new();
        let listeners = OrderedMap::new();
        Ok(ChainTracker {
            headers,
            tip,
            height,
            network,
            listeners,
            node_id,
            validator_factory,
            decode_state: None,
            trusted_oracle_pubkeys,
            allow_deep_reorgs: false,
        })
    }

    /// Set whether deep reorgs are allowed
    pub fn set_allow_deep_reorgs(&mut self, allow: bool) {
        self.allow_deep_reorgs = allow;
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
        trusted_oracle_pubkeys: Vec<PublicKey>,
    ) -> Self {
        ChainTracker {
            headers,
            tip,
            height,
            network,
            listeners,
            node_id,
            validator_factory,
            decode_state: None,
            trusted_oracle_pubkeys,
            allow_deep_reorgs: false,
        }
    }

    /// Create a tracker at genesis
    pub fn from_genesis(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
        trusted_oracle_pubkeys: Vec<PublicKey>,
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
            trusted_oracle_pubkeys,
        )
    }

    fn from_checkpoint(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
        header: &BlockHeader,
        filter_header: &FilterHeader,
        height: u32,
        trusted_oracle_pubkeys: Vec<PublicKey>,
    ) -> Self {
        let tip = Headers(*header, *filter_header);

        Self::new(network, height, tip, node_id, validator_factory, trusted_oracle_pubkeys)
            .expect("genesis block / checkpoint is expected to be valid")
    }

    /// Create a tracker for a network, from a checkpoint if exists or from genesis otherwise
    pub fn for_network(
        network: Network,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
        trusted_oracle_pubkeys: Vec<PublicKey>,
    ) -> Self {
        if let Some((height, _hash, filter_header, header)) = get_latest_checkpoint(network) {
            Self::from_checkpoint(
                network,
                node_id,
                validator_factory,
                &header,
                &filter_header,
                height,
                trusted_oracle_pubkeys,
            )
        } else {
            Self::from_genesis(network, node_id, validator_factory, trusted_oracle_pubkeys)
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

    #[cfg(feature = "timeless_workaround")]
    // WORKAROUND for #206, #339, #235 - If our implementation has no clock use the
    // latest BlockHeader timestamp.
    /// Header timestamp of current chain tip
    pub fn tip_time(&self) -> Duration {
        Duration::from_secs(if self.headers.is_empty() { 0 } else { self.headers[0].0.time as u64 })
    }

    /// Remove block at tip due to reorg
    ///
    /// The previous block and filter headers are provided in case the reorg
    /// is too deep for our local memory of headers.  However, this should
    /// only be used on testnet, since a deep reorg may be incompatible
    /// with the Lightning security model.
    pub fn remove_block(
        &mut self,
        proof: TxoProof,
        supplied_prev_headers: Headers,
    ) -> Result<BlockHeader, Error> {
        // there are four block hashes in play here:
        // - the block hash in the BlockChunk messages
        // - our idea of the tip's block hash (`tip_block_hash`)
        // - the hash of the block that was actually streamed (`external_block_hash`)
        // - the hash in the proof
        //
        // we need to make sure they are all the same:
        // - `maybe_finish_decoding_block` here checks 1 vs 2
        // - `ChainTrackerPushListener` checks 1 vs 3
        // - `validate_block` checks 2 vs 4

        if self.headers.is_empty() {
            if self.allow_deep_reorgs {
                warn!("reorg too deep, but allowed by flag");
            } else {
                return Err(Error::ReorgTooDeep);
            }
        }

        // If we have headers (i.e. not a deep reorg), check the prev header
        // matches what we were given as an argument and pop it off.  Otherwise,
        // we assume the prev header is correct and use it.
        if !self.headers.is_empty() {
            if supplied_prev_headers.0 != self.headers[0].0 {
                return Err(error_invalid_chain!(
                    "supplied prev block header {:?} != self.headers {:?}",
                    supplied_prev_headers.0,
                    self.headers[0].0
                ));
            }
            if supplied_prev_headers.1 != self.headers[0].1 {
                return Err(error_invalid_chain!(
                    "supplied prev filter header {} != self.headers[0].1 {} for prev block hash {}",
                    supplied_prev_headers.1.to_hex(),
                    self.headers[0].1.to_hex(),
                    supplied_prev_headers.0.block_hash().to_hex()
                ));
            }
            self.headers.pop_front();
        };

        let mut prev_headers = supplied_prev_headers;

        let tip_block_hash = prev_headers.0.block_hash();
        self.maybe_finish_decoding_block(&proof, &tip_block_hash);

        // we assume here that the external block hash and the tip block hash are the same
        // this is actually validated below in notify_listeners_remove
        let expected_external_block_hash =
            if proof.proof.is_external() { Some(&tip_block_hash) } else { None };
        self.validate_block(
            self.height - 1,
            expected_external_block_hash,
            &prev_headers,
            &self.tip,
            &proof,
            true,
        )?;
        match proof.proof {
            ProofType::Filter(_, spv_proof) =>
                self.notify_listeners_remove(Some(spv_proof.txs.as_slice()), tip_block_hash),
            ProofType::Block(b) => panic!("non-streamed block not supported {}", b.block_hash()),
            ProofType::ExternalBlock() => self.notify_listeners_remove(None, tip_block_hash),
        };

        info!("removed block {}: {}", self.height, &self.tip.0.block_hash());
        mem::swap(&mut self.tip, &mut prev_headers);
        self.height -= 1;
        Ok(prev_headers.0)
    }

    /// Restore a listener
    pub fn restore_listener(&mut self, outpoint: L::Key, listener: L, slot: ListenSlot) {
        self.listeners.insert(outpoint, (listener, slot));
    }

    // Notify listeners of a block remove.
    // If txs is None, this is a streamed block, and the transactions were already
    // provided as push events.
    fn notify_listeners_remove(&mut self, txs: Option<&[Transaction]>, block_hash: BlockHash) {
        for (listener, slot) in self.listeners.values_mut() {
            let (adds, removes) = if let Some(txs) = txs {
                listener.on_remove_block(txs, &block_hash)
            } else {
                listener.on_remove_streamed_block_end(&block_hash)
            };

            debug!("{}: REVERT adding {:?}, removing {:?}", short_function!(), adds, removes);

            // these are going to be re-added to the watches,
            // so we need to remove them from the seen set
            for outpoint in removes.iter() {
                slot.seen.remove(outpoint);
            }

            // revert what we did to the watches in the forward direction
            slot.watches.extend(removes);
            // remove after adding, in case there were intra-block spends
            for outpoint in adds.iter() {
                slot.watches.remove(outpoint);
            }
        }
    }

    /// Handle a streamed block
    pub fn block_chunk(&mut self, hash: BlockHash, offset: u32, chunk: &[u8]) -> Result<(), Error> {
        if offset == 0 {
            assert!(self.decode_state.is_none(), "already decoding, and got chunk at offset 0");
            self.decode_state = Some(RefCell::new(BlockDecodeState::new(hash)));
        }

        // we jump through some hoops here to prevent the borrow checker from complaining
        if let Some(decode_state_cell) = self.decode_state.as_ref() {
            let mut decode_state = decode_state_cell.borrow_mut();
            assert_eq!(
                decode_state.block_hash, hash,
                "got chunk for wrong block {} != {}",
                hash, decode_state.block_hash
            );
            assert_eq!(
                decode_state.offset, offset,
                "got chunk for wrong offset {} != {}",
                offset, decode_state.offset
            );
            let decoder = &mut decode_state.decoder;
            let mut listener = ChainTrackerPushListener(self, hash);
            decoder.decode_next(chunk, &mut listener).expect("decode failure");
            decode_state.offset += chunk.len() as u32;
        } else {
            panic!("got chunk at offset {} without decoder", offset);
        }
        Ok(())
    }

    /// Add a block, which becomes the new tip
    pub fn add_block(&mut self, header: BlockHeader, proof: TxoProof) -> Result<(), Error> {
        // there are four block hashes in play here:
        // - the block hash in the BlockChunk messages
        // - the block hash of the AddBlock message's header (`message_block_hash`)
        // - the hash of the block that was actually streamed (`external_block_hash`)
        // - the hash in the proof
        //
        // we need to make sure they are all the same:
        // - `maybe_finish_decoding_block` here checks 1 vs 2
        // - `ChainTrackerPushListener` checks 1 vs 3
        // - `validate_block` checks 2 vs 4

        let message_block_hash = header.block_hash();
        self.maybe_finish_decoding_block(&proof, &message_block_hash);

        let filter_header = proof.filter_header();
        let headers = Headers(header, filter_header);

        // we assume here that the external block hash and the message block hash are the same
        // this is actually validated below in notify_listeners_remove
        let expected_external_block_hash =
            if proof.proof.is_external() { Some(&message_block_hash) } else { None };
        self.validate_block(
            self.height,
            expected_external_block_hash,
            &self.tip,
            &headers,
            &proof,
            false,
        )?;
        match proof.proof {
            ProofType::Filter(_, spv_proof) =>
                self.notify_listeners_add(Some(spv_proof.txs.as_slice()), message_block_hash),
            ProofType::Block(b) => panic!("non-streamed block not supported {}", b.block_hash()),
            ProofType::ExternalBlock() => self.notify_listeners_add(None, message_block_hash),
        };

        self.headers.truncate(Self::MAX_REORG_SIZE - 1);
        self.headers.push_front(self.tip.clone());
        self.tip = Headers(header, filter_header);
        self.height += 1;
        info!("added block {}: {}", self.height, &self.tip.0.block_hash());
        Ok(())
    }

    // if we're decoding a block, tell the decoder we are done.
    // will panic if the proof is external and we are not decoding or vice versa.
    fn maybe_finish_decoding_block(&mut self, proof: &TxoProof, expected_block_hash: &BlockHash) {
        assert_eq!(
            proof.proof.is_external(),
            self.decode_state.is_some(),
            "is_external != decode_state"
        );
        if let Some(decode_state_cell) = self.decode_state.take() {
            let decode_state = decode_state_cell.into_inner();
            decode_state.decoder.finish().expect("decode finish failure");
            assert_eq!(
                decode_state.block_hash, *expected_block_hash,
                "wrong block was sent {} != {}",
                decode_state.block_hash, expected_block_hash
            );
        }
    }

    // Notify listeners of a block add.
    // If txs is None, this is a streamed block, and the transactions were already
    // provided as push events.
    fn notify_listeners_add(&mut self, txs: Option<&[Transaction]>, block_hash: BlockHash) {
        for (listener, slot) in self.listeners.values_mut() {
            let (adds, removes) = if let Some(txs) = txs {
                listener.on_add_block(txs, &block_hash)
            } else {
                listener.on_add_streamed_block_end(&block_hash)
            };
            debug!("{}: adding {:?}, removing {:?}", short_function!(), adds, removes);

            slot.watches.extend(adds);
            // remove after adding, in case there were intra-block spends
            for outpoint in removes.iter() {
                slot.watches.remove(outpoint);
            }

            // keep track of what we removed, so we can watch reorgs for it
            slot.seen.extend(removes);
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

    /// Remove a listener
    pub fn remove_listener(&mut self, key: &L::Key) {
        debug!("{}: removing listener", short_function!());
        self.listeners.remove(&key);
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
        external_block_hash: Option<&BlockHash>,
        prev_headers: &Headers,
        headers: &Headers,
        proof: &TxoProof,
        is_remove: bool,
    ) -> Result<(), Error> {
        let header = &headers.0;
        let prev_header = &prev_headers.0;
        // Check hash is correctly chained
        if header.prev_blockhash != prev_header.block_hash() {
            return Err(error_orphan_block!(
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
                .validate_block(
                    proof,
                    height + 1,
                    header,
                    external_block_hash,
                    prev_filter_header,
                    &outpoint_watches,
                    &self.trusted_oracle_pubkeys,
                )
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

// work around unecessary mutable borrow tripping us up
struct ChainTrackerPushListener<'a, L: ChainListener>(&'a ChainTracker<L>, BlockHash);

impl<'a, L: ChainListener> ChainTrackerPushListener<'a, L> {
    // broadcast push events to all listeners
    fn do_push<F: FnMut(&mut dyn PushListener)>(&mut self, mut f: F) {
        for (listener, _) in self.0.listeners.values() {
            listener.on_push(&mut f)
        }
    }
}

impl<'a, L: ChainListener> PushListener for ChainTrackerPushListener<'a, L> {
    fn on_block_start(&mut self, header: &BlockHeader) {
        // ensure that the block hash in the BlockChunk message
        // matches the streamed block header
        assert_eq!(
            header.block_hash(),
            self.1,
            "streamed block hash does not match header {} != {}",
            header.block_hash(),
            self.1
        );
        self.do_push(|pl| pl.on_block_start(header));
    }

    fn on_block_end(&mut self) {
        self.do_push(|pl| pl.on_block_end());
    }

    fn on_transaction_start(&mut self, version: i32) {
        self.do_push(|pl| pl.on_transaction_start(version));
    }

    fn on_transaction_end(&mut self, locktime: PackedLockTime, txid: Txid) {
        self.do_push(|pl| pl.on_transaction_end(locktime, txid));
    }

    fn on_transaction_input(&mut self, txin: &TxIn) {
        self.do_push(|pl| pl.on_transaction_input(txin));
    }

    fn on_transaction_output(&mut self, txout: &TxOut) {
        self.do_push(|pl| pl.on_transaction_output(txout));
    }
}

/// Listen to chain events
pub trait ChainListener: SendSync {
    /// The key type
    type Key: Ord + Clone;

    /// The key
    fn key(&self) -> &Self::Key;

    /// A block was added via a compact proof.
    /// The listener returns outpoints to watch in the future, and outpoints to stop watching.
    fn on_add_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>);

    /// A block was added via streaming (see `on_block_chunk`).
    /// The listener returns outpoints to watch in the future, and outpoints to stop watching.
    /// The decoded block hash is also returned.
    fn on_add_streamed_block_end(&self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>);

    /// A block was deleted via a compact proof.
    /// The listener returns the same thing as on_add_block, so that the changes can be reverted.
    /// The decoded block hash is also returned.
    fn on_remove_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>);

    /// A block was deleted via streaming (see `on_block_chunk`).
    /// The listener returns the same thing as on_add_block, so that the changes can be reverted.
    fn on_remove_streamed_block_end(
        &self,
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>);

    /// Get the block push decoder listener
    fn on_push<F>(&self, f: F)
    where
        F: FnOnce(&mut dyn PushListener);
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
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::network::constants::Network;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
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
    async fn test_add_valid_proof() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, _) = make_tracker()?;
        assert_eq!(tracker.height(), 0);

        let public_key = source.oracle_setup().await.public_key;
        tracker.trusted_oracle_pubkeys = vec![public_key];

        add_block(&mut tracker, &source, &[]).await?;
        add_block(&mut tracker, &source, &[]).await?;
        assert_eq!(tracker.height(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_add_invalid_proof() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, _) = make_tracker()?;
        assert_eq!(tracker.height(), 0);

        let random_secret = [0x11; 32];
        let public_key = get_txoo_public_key(&random_secret);
        tracker.trusted_oracle_pubkeys = vec![public_key];

        add_block(&mut tracker, &source, &[]).await?;
        let result = add_block(&mut tracker, &source, &[]).await;
        assert!(result.is_err());

        Ok(())
    }

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

        let prev_headers = Headers(header0, FilterHeader::all_zeros());
        assert_eq!(tracker.remove_block(proof, prev_headers).err(), Some(Error::ReorgTooDeep));
        Ok(())
    }

    #[tokio::test]
    async fn test_listeners() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, _validator_factory) = make_tracker()?;

        let header1 = add_block(&mut tracker, &source, &[]).await?;

        let tx = make_tx(vec![make_txin(1)]);
        let initial_watch = make_outpoint(1);
        let second_watch = OutPoint::new(tx.txid(), 0);
        let listener = MockListener::new(initial_watch);

        tracker.add_listener(listener.clone(), OrderedSet::new());

        tracker.add_listener_watches(&initial_watch, OrderedSet::from_iter(vec![initial_watch]));

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

        remove_block(&mut tracker, &source, &[tx2], &header2).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        remove_block(&mut tracker, &source, &[tx], &header1).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_streamed() -> Result<(), Error> {
        let source = make_source().await;
        let (mut tracker, _validator_factory) = make_tracker()?;

        let _header1 = add_block(&mut tracker, &source, &[]).await?;

        let tx = make_tx(vec![make_txin(1)]);
        let initial_watch = make_outpoint(1);
        let second_watch = OutPoint::new(tx.txid(), 0);
        let listener = MockListener::new(initial_watch);

        tracker.add_listener(listener.clone(), OrderedSet::new());

        tracker.add_listener_watches(&initial_watch, OrderedSet::from_iter(vec![initial_watch]));

        assert_eq!(tracker.listeners.len(), 1);
        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![initial_watch])
        );

        let _header2 = add_streamed_block(&mut tracker, &source, &[tx.clone()]).await?;

        assert_eq!(
            tracker.listeners.get(listener.key()).unwrap().1.watches,
            OrderedSet::from_iter(vec![second_watch])
        );

        Ok(())
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
        let tracker = ChainTracker::new(
            Network::Regtest,
            0,
            tip,
            node_id,
            validator_factory.clone(),
            vec![],
        )?;
        Ok((tracker, validator_factory))
    }

    async fn make_source() -> DummyTxooSource {
        let source = DummyTxooSource::new();
        source.on_new_block(0, &genesis_block(Network::Regtest)).await;
        source
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
        let (attestation, filter_header) = source.get(height, &block).await.unwrap();
        let pubkey = source.oracle_setup().await.public_key;
        let txid_watches: Vec<_> = block.txdata.iter().map(|tx| tx.txid()).collect();
        let proof = TxoProof::prove(
            vec![(pubkey, attestation)],
            &filter_header,
            &block,
            height,
            &[],
            &txid_watches,
        );

        tracker.add_block(block.header.clone(), proof)?;
        Ok(block.header)
    }

    // returns the new block's header
    async fn add_streamed_block(
        tracker: &mut ChainTracker<MockListener>,
        source: &DummyTxooSource,
        txs: &[Transaction],
    ) -> Result<BlockHeader, Error> {
        let txs = txs_with_coinbase(txs);

        let block = make_block(tracker.tip().0, txs);
        let height = tracker.height() + 1;
        source.on_new_block(height, &block).await;
        let (attestation, filter_header) = source.get(height, &block).await.unwrap();
        let pubkey = source.oracle_setup().await.public_key;
        let txid_watches: Vec<_> = block.txdata.iter().map(|tx| tx.txid()).collect();
        let proof = TxoProof::prove(
            vec![(pubkey, attestation)],
            &filter_header,
            &block,
            height,
            &[],
            &txid_watches,
        );

        let proof =
            TxoProof { attestations: proof.attestations, proof: ProofType::ExternalBlock() };

        let bytes = serialize(&block);
        tracker.block_chunk(block.block_hash(), 0, &bytes)?;
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

        let proof: TxoProof;
        if do_add {
            source.on_new_block(height, &block).await;
            let public_key = source.oracle_setup().await.public_key;
            let (attestation, filter_header) = source.get(height, &block).await.unwrap();
            proof = TxoProof::prove(
                vec![(public_key, attestation)],
                &filter_header,
                &block,
                height,
                &vec![],
                &txids,
            );
        } else {
            let filter_header = FilterHeader::all_zeros();
            proof = TxoProof::prove_unchecked(&block, &filter_header, height);
        }

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
        let (attestation, filter_header) = source.get(height, &block).await.unwrap();
        let pubkey = source.oracle_setup().await.public_key;
        let txid_watches: Vec<_> = block.txdata.iter().map(|tx| tx.txid()).collect();
        let proof = TxoProof::prove(
            vec![(pubkey, attestation)],
            &filter_header,
            &block,
            height,
            &[],
            &txid_watches,
        );

        let prev_filter_header = tracker.headers[0].1;
        let prev_headers = Headers(*prev_header, prev_filter_header);
        let removed_header = tracker.remove_block(proof, prev_headers)?;
        Ok(removed_header)
    }

    fn txs_with_coinbase(txs: &[Transaction]) -> Vec<Transaction> {
        let mut txs = txs.to_vec();
        txs.insert(
            0,
            Transaction {
                version: 0,
                lock_time: PackedLockTime(0),
                input: vec![],
                output: vec![Default::default()],
            },
        );
        txs
    }

    fn get_txoo_public_key(secret_key: &[u8]) -> PublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&secret_key).expect("32 bytes, within curve order");
        PublicKey::from_secret_key(&secp, &secret_key)
    }
}
