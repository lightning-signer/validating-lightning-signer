use alloc::collections::BTreeSet as Set;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, BlockHeader, OutPoint, PackedLockTime, Transaction, TxIn, TxOut, Txid};
use log::*;
use push_decoder::{self, Listener as _};
use serde_derive::{Deserialize, Serialize};

use crate::chain::tracker::ChainListener;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::util::transaction_utils::{decode_commitment_number, decode_commitment_tx};
use crate::{Arc, CommitmentPointProvider};

// the depth at which we consider a channel to be done
const MIN_DEPTH: u32 = 100;

// the maximum depth we will watch for HTLC sweeps on closed channels
const MAX_CLOSING_DEPTH: u32 = 2016;

// Keep track of closing transaction outpoints.
// These include the to-us output (if it exists) and all HTLC outputs.
// For each output, we keep track of whether it has been spent yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClosingOutpoints {
    txid: Txid,
    our_output: Option<(u32, bool)>,
    htlc_outputs: Vec<u32>,
    htlc_spents: Vec<bool>,
}

impl ClosingOutpoints {
    // construct a new ClosingOutpoints with all spent flags false
    fn new(txid: Txid, our_output_index: Option<u32>, htlc_output_indexes: Vec<u32>) -> Self {
        let v = vec![false; htlc_output_indexes.len()];
        ClosingOutpoints {
            txid,
            our_output: our_output_index.map(|i| (i, false)),
            htlc_outputs: htlc_output_indexes,
            htlc_spents: v,
        }
    }

    // does this closing tx's to-us output match this outpoint?
    fn includes_our_output(&self, outpoint: &OutPoint) -> bool {
        self.txid == outpoint.txid && self.our_output.map(|(i, _)| i) == Some(outpoint.vout)
    }

    // does this closing tx include an HTLC outpoint that matches?
    fn includes_htlc_output(&self, outpoint: &OutPoint) -> bool {
        self.txid == outpoint.txid && self.htlc_outputs.contains(&(outpoint.vout))
    }

    fn set_our_output_spent(&mut self, vout: u32, spent: bool) {
        let p = self.our_output.as_mut().unwrap();
        assert_eq!(p.0, vout);
        p.1 = spent;
    }

    fn set_htlc_output_spent(&mut self, vout: u32, spent: bool) {
        let i = self.htlc_outputs.iter().position(|&x| x == vout).unwrap();
        self.htlc_spents[i] = spent;
    }

    // are all outputs spent?
    fn is_all_spent(&self) -> bool {
        self.our_output.as_ref().map(|(_, b)| *b).unwrap_or(true)
            && self.htlc_spents.iter().all(|b| *b)
    }
}

/// State
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    // Chain height
    height: u32,
    // funding txids
    funding_txids: Vec<Txid>,
    // the funding output index for each funding tx
    funding_vouts: Vec<u32>,
    // inputs derived from funding_txs for convenience
    funding_inputs: Set<OutPoint>,
    // The height where the funding transaction was confirmed
    funding_height: Option<u32>,
    // The actual funding outpoint on-chain
    funding_outpoint: Option<OutPoint>,
    // The height of a transaction that double-spends a funding input
    funding_double_spent_height: Option<u32>,
    // The height of a mutual-close transaction
    mutual_closing_height: Option<u32>,
    // The height of a unilateral-close transaction
    unilateral_closing_height: Option<u32>,
    // Unilateral closing transaction outpoints to watch
    closing_outpoints: Option<ClosingOutpoints>,
    // Unilateral closing transaction swept height
    closing_swept_height: Option<u32>,
    // Our commitment transaction output swept height
    our_output_swept_height: Option<u32>,
    // Whether we saw a block yet - used for sanity check
    #[serde(default)]
    saw_block: bool,
}

// A push decoder listener.
// We need this temporary struct so that the commitment point provider
// is easily accessible during push event handling.
struct PushListener<'a> {
    commitment_point_provider: &'a dyn CommitmentPointProvider,
    decode_state: &'a mut BlockDecodeState,
    saw_block: bool,
}

// A state change detected in a block, to be applied to the monitor `State`.
#[derive(Clone, Debug, Serialize, Deserialize)]
enum StateChange {
    // A funding transaction was confirmed.  The funding outpoint is provided.
    FundingConfirmed(OutPoint),
    // A funding input was spent, either by the actual funding transaction
    // or by a double-spend.  The output is provided.
    FundingInputSpent(OutPoint),
    // A unilateral closing transaction was confirmed.
    // The funding outpoint, our output index and HTLC output indexes are provided
    UnilateralCloseConfirmed(Txid, OutPoint, Option<u32>, Vec<u32>),
    // A mutual close transaction was confirmed.
    MutualCloseConfirmed(Txid, OutPoint),
    /// Our commitment output was spent
    OurOutputSpent(u32),
    /// An HTLC commitment output was spent
    HTLCOutputSpent(u32),
}

// Keep track of the state of a block push-decoder parse state
#[derive(Clone, Debug)]
struct BlockDecodeState {
    // The changes detected in the current block
    changes: Vec<StateChange>,
    // The version of the current transaction
    version: i32,
    // The input number in the current transaction
    input_num: u32,
    // The output number in the current transaction
    output_num: u32,
    // The closing transaction, if we detect one
    closing_tx: Option<Transaction>,
    // The block hash
    block_hash: Option<BlockHash>,
    // A temporary copy of the current state, for keeping track
    // of state changes intra-block, without changing the actual state
    state: State,
}

impl BlockDecodeState {
    fn new(state: &State) -> Self {
        BlockDecodeState {
            changes: Vec::new(),
            version: 0,
            input_num: 0,
            output_num: 0,
            closing_tx: None,
            block_hash: None,
            state: state.clone(),
        }
    }

    fn new_with_block_hash(state: &State, block_hash: &BlockHash) -> Self {
        BlockDecodeState {
            changes: Vec::new(),
            version: 0,
            input_num: 0,
            output_num: 0,
            closing_tx: None,
            block_hash: Some(*block_hash),
            state: state.clone(),
        }
    }

    // Add a state change for the current block.
    // This also updates the temporary monitor state, so that intra-block
    // processing can be done.  For example, this is needed if a closing transaction
    // is confirmed, and then swept in the same block.
    fn add_change(&mut self, change: StateChange) {
        self.changes.push(change.clone());
        let mut adds = Vec::new();
        let mut removes = Vec::new();
        self.state.apply_forward_change(&mut adds, &mut removes, change);
    }
}

const MAX_COMMITMENT_OUTPUTS: u32 = 600;

impl<'a> PushListener<'a> {
    // Check if we ever saw the beginning of a block.  If not, we might get
    // a partial set of push events from a block right after we got created,
    // which we must ignore.
    fn is_not_ready_for_push(&self) -> bool {
        if self.saw_block {
            // if we ever saw a block, then we must have seen the block start
            // for the current block
            assert!(self.decode_state.block_hash.is_some(), "saw block but no decode state");
            false
        } else {
            // if we never saw a block, then we must not have seen the block start
            assert!(
                self.decode_state.block_hash.is_none(),
                "never saw a block but decode state is present"
            );
            true
        }
    }
}

impl<'a> push_decoder::Listener for PushListener<'a> {
    fn on_block_start(&mut self, header: &BlockHeader) {
        // we shouldn't get more than one block start per decode state lifetime
        // (which is the lifetime of a block stream)
        assert!(self.decode_state.block_hash.is_none(), "saw more than one on_block_start");
        self.decode_state.block_hash = Some(header.block_hash());
        self.saw_block = true;
    }

    fn on_transaction_start(&mut self, version: i32) {
        if self.is_not_ready_for_push() {
            return;
        }
        let state = &mut self.decode_state;
        state.version = version;
        state.input_num = 0;
        state.output_num = 0;
        state.closing_tx = None;
    }

    fn on_transaction_input(&mut self, input: &TxIn) {
        if self.is_not_ready_for_push() {
            return;
        }

        let decode_state = &mut self.decode_state;

        if decode_state.state.funding_inputs.contains(&input.previous_output) {
            // A funding input was spent
            decode_state.add_change(StateChange::FundingInputSpent(input.previous_output));
        }

        if Some(input.previous_output) == decode_state.state.funding_outpoint {
            // The funding outpoint was spent - this is a closing transaction.
            // Starting gathering it.  It will be processed in on_transaction_end.
            // It may be either mutual or unilateral.
            let tx = Transaction {
                version: decode_state.version,
                lock_time: PackedLockTime::ZERO,
                input: vec![input.clone()],
                output: vec![],
            };
            decode_state.closing_tx = Some(tx);
        }

        // Check if an output of a unilateral closing transaction was spent.
        // split into two blocks for borrow checker
        let closing_change = if let Some(ref c) = decode_state.state.closing_outpoints {
            if c.includes_our_output(&input.previous_output) {
                // We spent our output of a closing transaction
                Some(StateChange::OurOutputSpent(input.previous_output.vout))
            } else if c.includes_htlc_output(&input.previous_output) {
                // We spent an HTLC output of a closing transaction
                Some(StateChange::HTLCOutputSpent(input.previous_output.vout))
            } else {
                None
            }
        } else {
            None
        };

        closing_change.map(|c| decode_state.add_change(c));

        if decode_state.closing_tx.is_some() {
            assert_eq!(decode_state.input_num, 0, "closing tx must have only one input");
        }
        decode_state.input_num += 1;
    }

    fn on_transaction_output(&mut self, output: &TxOut) {
        if self.is_not_ready_for_push() {
            return;
        }

        let decode_state = &mut self.decode_state;
        if let Some(closing_tx) = &mut decode_state.closing_tx {
            closing_tx.output.push(output.clone());
            assert!(
                decode_state.output_num < MAX_COMMITMENT_OUTPUTS,
                "more than {} commitment outputs",
                MAX_COMMITMENT_OUTPUTS
            );
        }

        decode_state.output_num += 1;
    }

    fn on_transaction_end(&mut self, lock_time: PackedLockTime, txid: Txid) {
        if self.is_not_ready_for_push() {
            return;
        }

        let decode_state = &mut self.decode_state;

        if let Some(ind) = decode_state.state.funding_txids.iter().position(|i| *i == txid) {
            let vout = decode_state.state.funding_vouts[ind];
            // This was a funding transaction, which just confirmed
            assert!(
                vout < decode_state.output_num,
                "tx {} doesn't have funding output index {}",
                txid,
                vout
            );
            let outpoint = OutPoint { txid: txid.clone(), vout };
            decode_state.add_change(StateChange::FundingConfirmed(outpoint));
        }

        // complete handling of closing tx, if this was one
        if let Some(mut closing_tx) = decode_state.closing_tx.take() {
            closing_tx.lock_time = lock_time;
            // closing tx
            assert_eq!(closing_tx.input.len(), 1);
            let provider = self.commitment_point_provider;
            let parameters = provider.get_transaction_parameters();

            // check that the closing tx is a commitment tx, otherwise it was a mutual close
            let commitment_number_opt = decode_commitment_number(&closing_tx, &parameters);
            if let Some(commitment_number) = commitment_number_opt {
                let secp_ctx = Secp256k1::new();
                info!("unilateral close {} at commitment {} confirmed", txid, commitment_number);
                let holder_per_commitment = provider.get_holder_commitment_point(commitment_number);
                let cp_per_commitment =
                    provider.get_counterparty_commitment_point(commitment_number);
                let (our_output_index, htlc_indices) = decode_commitment_tx(
                    &closing_tx,
                    &holder_per_commitment,
                    &cp_per_commitment,
                    &parameters,
                    &secp_ctx,
                );
                info!("our_output_index: {:?}, htlc_indices: {:?}", our_output_index, htlc_indices);
                decode_state.add_change(StateChange::UnilateralCloseConfirmed(
                    txid,
                    closing_tx.input[0].previous_output,
                    our_output_index,
                    htlc_indices,
                ));
            } else {
                decode_state.add_change(StateChange::MutualCloseConfirmed(
                    txid,
                    closing_tx.input[0].previous_output,
                ));
                info!("mutual close {} confirmed", txid);
            }
        }
    }

    fn on_block_end(&mut self) {
        // we need to wait until we get the following `AddBlock` or `RemoveBlock`
        // message before actually updating ourselves
    }
}

impl State {
    fn depth_of(&self, other_height: Option<u32>) -> u32 {
        (self.height + 1).saturating_sub(other_height.unwrap_or(self.height + 1))
    }

    fn is_done(&self) -> bool {
        // we are done if:
        // - funding was double spent
        // - mutual closed
        // - unilateral closed, and our output, as well as all HTLCs were swept
        // and, the last confirmation is buried
        //
        // TODO: check 2nd level HTLCs
        // TODO: disregard received HTLCs that we can't claim (we don't have the preimage)

        if self.depth_of(self.funding_double_spent_height) >= MIN_DEPTH {
            return true;
        }
        if self.depth_of(self.mutual_closing_height) >= MIN_DEPTH {
            return true;
        }
        if self.depth_of(self.closing_swept_height) >= MIN_DEPTH {
            return true;
        }
        // since we don't yet have the logic to tell which HTLCs we can claim,
        // time out watching them after MAX_CLOSING_DEPTH
        if self.depth_of(self.our_output_swept_height) >= MAX_CLOSING_DEPTH {
            {
                warn!("considering monitor done, because unilateral closing tx confirmed at height {} and our main output was swept",
                    self.unilateral_closing_height.unwrap_or(0));
                return true;
            }
        }
        return false;
    }

    fn on_add_block_end(
        &mut self,
        block_hash: &BlockHash,
        decode_state: &mut BlockDecodeState,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        assert_eq!(decode_state.block_hash.as_ref(), Some(block_hash));

        self.saw_block = true;
        self.height += 1;

        let closing_was_swept = self.is_closing_swept();
        let our_output_was_swept = self.is_our_output_swept();

        let mut adds = Vec::new();
        let mut removes = Vec::new();

        let changed = !decode_state.changes.is_empty();

        if changed {
            debug!("detected add-changes at height {}: {:?}", self.height, decode_state.changes);
        }

        // apply changes
        for change in decode_state.changes.drain(..) {
            self.apply_forward_change(&mut adds, &mut removes, change);
        }

        let closing_is_swept = self.is_closing_swept();
        let our_output_is_swept = self.is_our_output_swept();

        if !closing_was_swept && closing_is_swept {
            info!("closing tx was swept at height {}", self.height);
            self.closing_swept_height = Some(self.height);
        }

        if !our_output_was_swept && our_output_is_swept {
            info!("our output was swept at height {}", self.height);
            self.our_output_swept_height = Some(self.height);
        }

        if self.is_done() {
            info!("done at height {}", self.height);
        }

        if changed {
            info!("on_add_block_end state changed: {:#?}", self);
        }

        (adds, removes)
    }

    fn on_remove_block_end(
        &mut self,
        block_hash: &BlockHash,
        decode_state: &mut BlockDecodeState,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        assert_eq!(decode_state.block_hash.as_ref(), Some(block_hash));

        let closing_was_swept = self.is_closing_swept();
        let our_output_was_swept = self.is_our_output_swept();

        let mut adds = Vec::new();
        let mut removes = Vec::new();

        let changed = !decode_state.changes.is_empty();

        if changed {
            debug!("detected remove-changes at height {}: {:?}", self.height, decode_state.changes);
        }

        for change in decode_state.changes.drain(..) {
            self.apply_backward_change(&mut adds, &mut removes, change);
        }

        let closing_is_swept = self.is_closing_swept();
        let our_output_is_swept = self.is_our_output_swept();

        if closing_was_swept && !closing_is_swept {
            info!("closing tx was un-swept at height {}", self.height);
            self.closing_swept_height = None;
        }

        if our_output_was_swept && !our_output_is_swept {
            info!("our output was un-swept at height {}", self.height);
            self.our_output_swept_height = None;
        }

        self.height -= 1;

        if changed {
            info!("on_remove_block_end state changed: {:#?}", self);
        }

        // note that the caller will remove the adds and add the removes
        (adds, removes)
    }

    // whether the unilateral closing tx was fully swept
    fn is_closing_swept(&self) -> bool {
        self.closing_outpoints.as_ref().map(|o| o.is_all_spent()).unwrap_or(false)
    }

    // whether our output was swept, or does not exist
    fn is_our_output_swept(&self) -> bool {
        self.closing_outpoints
            .as_ref()
            .map(|o| o.our_output.map(|(_, s)| s).unwrap_or(true))
            .unwrap_or(false)
    }

    fn apply_forward_change(
        &mut self,
        adds: &mut Vec<OutPoint>,
        removes: &mut Vec<OutPoint>,
        change: StateChange,
    ) {
        match change {
            StateChange::FundingConfirmed(outpoint) => {
                self.funding_height = Some(self.height);
                self.funding_outpoint = Some(outpoint);
                // we may have thought we had a double-spend, but now we know we don't
                self.funding_double_spent_height = None;
                adds.push(outpoint);
            }
            StateChange::FundingInputSpent(outpoint) => {
                // A funding input was double-spent, or funding was confirmed
                // (in which case we'll see FundingConfirmed later on in this
                // change list).
                // we may have seen some other funding input double-spent, so
                // don't overwrite the depth if it exists
                self.funding_double_spent_height.get_or_insert(self.height);
                // no matter whether funding, or double-spend, we want to stop watching this outpoint
                removes.push(outpoint);
            }
            StateChange::UnilateralCloseConfirmed(
                txid,
                funding_outpoint,
                our_output_index,
                htlcs_indices,
            ) => {
                self.unilateral_closing_height = Some(self.height);
                removes.push(funding_outpoint);
                our_output_index.map(|i| adds.push(OutPoint { txid: txid.clone(), vout: i }));
                for i in htlcs_indices.iter() {
                    adds.push(OutPoint { txid: txid.clone(), vout: *i });
                }
                self.closing_outpoints =
                    Some(ClosingOutpoints::new(txid, our_output_index, htlcs_indices));
            }
            StateChange::OurOutputSpent(vout) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_our_output_spent(vout, true);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                removes.push(outpoint);
            }
            StateChange::HTLCOutputSpent(vout) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_htlc_output_spent(vout, true);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                removes.push(outpoint);
            }
            StateChange::MutualCloseConfirmed(_txid, funding_outpoint) => {
                self.mutual_closing_height = Some(self.height);
                removes.push(funding_outpoint);
            }
        }
    }

    // Note that in the logic below, we are mimicking the logic of
    // apply_forward_change, but the caller will remove the adds and add the
    // removes.
    fn apply_backward_change(
        &mut self,
        adds: &mut Vec<OutPoint>,
        removes: &mut Vec<OutPoint>,
        change: StateChange,
    ) {
        match change {
            StateChange::FundingConfirmed(outpoint) => {
                // A funding tx was reorged-out
                assert_eq!(self.funding_height, Some(self.height));
                self.funding_height = None;
                self.funding_outpoint = None;
                adds.push(outpoint);
            }
            StateChange::FundingInputSpent(outpoint) => {
                // A funding double-spent was reorged-out, or funding confirmation
                // was reorged-out (in which case we'll see FundingConfirmed later
                // on in this change list).
                // We may have seen some other funding input double-spent, so
                // clear out the height only if it is the current height.
                if self.funding_double_spent_height == Some(self.height) {
                    self.funding_double_spent_height = None
                }
                // no matter whether funding, or double-spend, we want to re-start watching this outpoint
                removes.push(outpoint);
            }
            StateChange::UnilateralCloseConfirmed(
                txid,
                funding_outpoint,
                our_output_index,
                htlcs_indices,
            ) => {
                // A closing tx was reorged-out
                assert_eq!(self.unilateral_closing_height, Some(self.height));
                self.unilateral_closing_height = None;
                self.closing_outpoints = None;
                our_output_index.map(|i| adds.push(OutPoint { txid: txid.clone(), vout: i }));
                for i in htlcs_indices {
                    adds.push(OutPoint { txid: txid.clone(), vout: i });
                }
                removes.push(funding_outpoint)
            }
            StateChange::OurOutputSpent(vout) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_our_output_spent(vout, false);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                removes.push(outpoint);
            }
            StateChange::HTLCOutputSpent(vout) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_htlc_output_spent(vout, false);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                removes.push(outpoint);
            }
            StateChange::MutualCloseConfirmed(_txid, funding_outpoint) => {
                self.mutual_closing_height = None;
                removes.push(funding_outpoint);
            }
        }
    }
}

/// This is a pre-cursor to [`ChainMonitor`], before the [`CommitmentPointProvider`] is available.
#[derive(Clone)]
pub struct ChainMonitorBase {
    // the first funding outpoint, used to identify the channel / channel monitor
    pub(crate) funding_outpoint: OutPoint,
    // the monitor state
    state: Arc<Mutex<State>>,
}

impl ChainMonitorBase {
    /// Create a new chain monitor.
    /// Use add_funding to really start monitoring.
    pub fn new(funding_outpoint: OutPoint, height: u32) -> Self {
        let state = State {
            height,
            funding_txids: Vec::new(),
            funding_vouts: Vec::new(),
            funding_inputs: OrderedSet::new(),
            funding_height: None,
            funding_outpoint: None,
            funding_double_spent_height: None,
            mutual_closing_height: None,
            unilateral_closing_height: None,
            closing_outpoints: None,
            closing_swept_height: None,
            our_output_swept_height: None,
            saw_block: false,
        };

        Self { funding_outpoint, state: Arc::new(Mutex::new(state)) }
    }

    /// recreate this monitor after restoring from persistence
    pub fn new_from_persistence(funding_outpoint: OutPoint, state: State) -> Self {
        Self { funding_outpoint, state: Arc::new(Mutex::new(state)) }
    }

    /// Get the ChainMonitor
    pub fn as_monitor(
        &self,
        commitment_point_provider: Box<dyn CommitmentPointProvider>,
    ) -> ChainMonitor {
        ChainMonitor {
            funding_outpoint: self.funding_outpoint,
            state: self.state.clone(),
            decode_state: Arc::new(Mutex::new(None)),
            commitment_point_provider,
        }
    }

    /// Add a funding transaction to keep track of
    /// For single-funding
    pub fn add_funding_outpoint(&self, outpoint: &OutPoint) {
        let mut state = self.state.lock().expect("lock");
        assert!(state.funding_txids.is_empty(), "only a single funding tx currently supported");
        assert_eq!(state.funding_txids.len(), state.funding_vouts.len());
        state.funding_txids.push(outpoint.txid);
        state.funding_vouts.push(outpoint.vout);
    }

    /// Add a funding input
    /// For single-funding
    pub fn add_funding_inputs(&self, tx: &Transaction) {
        let mut state = self.state.lock().expect("lock");
        state.funding_inputs.extend(tx.input.iter().map(|i| i.previous_output));
    }

    /// Convert to a ChainState, to be used for validation
    pub fn as_chain_state(&self) -> ChainState {
        let state = self.state.lock().expect("lock");
        ChainState {
            current_height: state.height,
            funding_depth: state.funding_height.map(|h| state.height + 1 - h).unwrap_or(0),
            funding_double_spent_depth: state
                .funding_double_spent_height
                .map(|h| state.height + 1 - h)
                .unwrap_or(0),
            closing_depth: state
                .mutual_closing_height
                .or(state.unilateral_closing_height)
                .map(|h| state.height + 1 - h)
                .unwrap_or(0),
        }
    }

    /// Whether this channel can be forgotten
    pub fn is_done(&self) -> bool {
        let state = self.state.lock().expect("lock");
        state.is_done()
    }
}

/// Keep track of channel on-chain events.
/// Note that this object has refcounted state, so is lightweight to clone.
#[derive(Clone)]
pub struct ChainMonitor {
    /// the first funding outpoint, used to identify the channel / channel monitor
    pub funding_outpoint: OutPoint,
    /// the monitor state
    pub state: Arc<Mutex<State>>,
    // Block decode state, only while in progress
    // Lock order: after `self.state`
    decode_state: Arc<Mutex<Option<BlockDecodeState>>>,
    // the commitment point provider, helps with decoding transactions
    commitment_point_provider: Box<dyn CommitmentPointProvider>,
}

impl ChainMonitor {
    /// Get the base
    pub fn as_base(&self) -> ChainMonitorBase {
        ChainMonitorBase { funding_outpoint: self.funding_outpoint, state: self.state.clone() }
    }

    /// Get the locked state
    pub fn get_state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("lock")
    }

    /// Add a funding transaction to keep track of
    /// For dual-funding
    pub fn add_funding(&self, tx: &Transaction, vout: u32) {
        let mut state = self.state.lock().expect("lock");
        assert!(state.funding_txids.is_empty(), "only a single funding tx currently supported");
        assert_eq!(state.funding_txids.len(), state.funding_vouts.len());
        state.funding_txids.push(tx.txid());
        state.funding_vouts.push(vout);
        state.funding_inputs.extend(tx.input.iter().map(|i| i.previous_output));
    }

    /// Returns the number of confirmations of the funding transaction, or zero
    /// if it wasn't confirmed yet.
    pub fn funding_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        state.depth_of(state.funding_height)
    }

    /// Returns the number of confirmations of a double-spend of the funding transaction
    /// or zero if it wasn't double-spent.
    pub fn funding_double_spent_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        state.depth_of(state.funding_double_spent_height)
    }

    /// Returns the number of confirmations of the closing transaction, or zero
    pub fn closing_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        let closing_height = state.unilateral_closing_height.or(state.mutual_closing_height);
        state.depth_of(closing_height)
    }

    /// Whether this channel can be forgotten:
    /// - mutual close is confirmed
    /// - unilateral close is swept
    /// - funding transaction is double-spent
    /// and enough confirmations have passed
    pub fn is_done(&self) -> bool {
        let state = self.state.lock().expect("lock");
        state.is_done()
    }

    // push compact proof transactions through, simulating a streamed block
    fn push_transactions(&self, block_hash: &BlockHash, txs: &[Transaction]) -> BlockDecodeState {
        let mut state = self.state.lock().expect("lock");

        // we are synced if we see a compact proof
        state.saw_block = true;

        let mut decode_state = BlockDecodeState::new_with_block_hash(&*state, block_hash);

        let mut listener = PushListener {
            commitment_point_provider: &*self.commitment_point_provider,
            decode_state: &mut decode_state,
            saw_block: true,
        };

        // stream the transactions to the state
        for tx in txs {
            listener.on_transaction_start(tx.version);
            for input in tx.input.iter() {
                listener.on_transaction_input(input);
            }

            for output in tx.output.iter() {
                listener.on_transaction_output(output);
            }
            listener.on_transaction_end(tx.lock_time, tx.txid());
        }

        decode_state
    }
}

impl ChainListener for ChainMonitor {
    type Key = OutPoint;

    fn key(&self) -> &Self::Key {
        &self.funding_outpoint
    }

    fn on_add_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        debug!("on_add_block for {}", self.funding_outpoint);
        let mut decode_state = self.push_transactions(block_hash, txs);

        let mut state = self.state.lock().expect("lock");
        state.on_add_block_end(block_hash, &mut decode_state)
    }

    fn on_add_streamed_block_end(&self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.state.lock().expect("lock");
        let mut decode_state = self.decode_state.lock().expect("lock").take();
        if !state.saw_block {
            // not ready yet, bail
            return (Vec::new(), Vec::new());
        }
        state.on_add_block_end(block_hash, decode_state.as_mut().unwrap())
    }

    fn on_remove_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        debug!("on_remove_block for {}", self.funding_outpoint);
        let mut decode_state = self.push_transactions(block_hash, txs);

        let mut state = self.state.lock().expect("lock");
        state.on_remove_block_end(block_hash, &mut decode_state)
    }

    fn on_remove_streamed_block_end(
        &self,
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.state.lock().expect("lock");
        let mut decode_state = self.decode_state.lock().expect("lock").take();
        if !state.saw_block {
            // not ready yet, bail
            return (Vec::new(), Vec::new());
        }
        state.on_remove_block_end(block_hash, decode_state.as_mut().unwrap())
    }

    fn on_push<F>(&self, f: F)
    where
        F: FnOnce(&mut dyn push_decoder::Listener),
    {
        let mut state = self.state.lock().expect("lock");
        let saw_block = state.saw_block;

        let mut decode_state_lock = self.decode_state.lock().expect("lock");

        let decode_state = decode_state_lock.get_or_insert_with(|| BlockDecodeState::new(&*state));

        let mut listener = PushListener {
            commitment_point_provider: &*self.commitment_point_provider,
            decode_state,
            saw_block,
        };
        f(&mut listener);

        // update the saw_block flag, in case the listener saw a block start event
        state.saw_block = listener.saw_block;
    }
}

impl SendSync for ChainMonitor {}

#[cfg(test)]
mod tests {
    use crate::channel::{
        ChannelBase, ChannelCommitmentPointProvider, ChannelId, ChannelSetup, CommitmentType,
    };
    use crate::node::Node;
    use crate::util::test_utils::key::{make_test_counterparty_points, make_test_pubkey};
    use crate::util::test_utils::*;
    use bitcoin::hashes::Hash;
    use bitcoin::TxMerkleNode;
    use lightning::ln::chan_utils::HTLCOutputInCommitment;
    use lightning::ln::PaymentHash;
    use test_log::test;

    use super::*;

    #[test]
    fn test_funding() {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let outpoint = OutPoint::new(tx.txid(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let monitor = ChainMonitorBase::new(outpoint, 0).as_monitor(cpp);
        let block_hash = BlockHash::all_zeros();
        monitor.add_funding(&tx, 0);
        monitor.on_add_block(&[], &block_hash);
        monitor.on_add_block(&[tx.clone()], &block_hash);
        assert_eq!(monitor.funding_depth(), 1);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
        monitor.on_add_block(&[], &block_hash);
        assert_eq!(monitor.funding_depth(), 2);
        monitor.on_remove_block(&[], &block_hash);
        assert_eq!(monitor.funding_depth(), 1);
        monitor.on_remove_block(&[tx], &block_hash);
        assert_eq!(monitor.funding_depth(), 0);
        monitor.on_remove_block(&[], &block_hash);
        assert_eq!(monitor.funding_depth(), 0);
    }

    #[test]
    fn test_funding_double_spent() {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let tx2 = make_tx(vec![make_txin(2)]);
        let outpoint = OutPoint::new(tx.txid(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let monitor = ChainMonitorBase::new(outpoint, 0).as_monitor(cpp);
        let block_hash = BlockHash::all_zeros();
        monitor.add_funding(&tx, 0);
        monitor.on_add_block(&[], &block_hash);
        monitor.on_add_block(&[tx2.clone()], &block_hash);
        assert_eq!(monitor.funding_depth(), 0);
        assert_eq!(monitor.funding_double_spent_depth(), 1);
        monitor.on_add_block(&[], &block_hash);
        assert_eq!(monitor.funding_depth(), 0);
        assert_eq!(monitor.funding_double_spent_depth(), 2);
        monitor.on_remove_block(&[], &block_hash);
        assert_eq!(monitor.funding_double_spent_depth(), 1);
        monitor.on_remove_block(&[tx2], &block_hash);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
        monitor.on_remove_block(&[], &block_hash);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
    }

    #[test]
    fn test_stream() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let monitor = ChainMonitorBase::new(outpoint, 0).as_monitor(cpp);
        let header = BlockHeader {
            version: 0,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: 0,
            nonce: 0,
        };
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);

        // test a push when not ready (simulates creation during a stream)
        monitor.on_push(|listener| {
            listener.on_transaction_input(&tx.input[1]);
            listener.on_transaction_output(&tx.output[0]);
            listener.on_transaction_end(tx.lock_time, tx.txid());
            listener.on_block_end();
        });

        assert!(!monitor.state.lock().unwrap().saw_block);

        // test a block push
        monitor.on_push(|listener| {
            listener.on_block_start(&header);
            listener.on_transaction_start(2);
            listener.on_transaction_input(&tx.input[0]);
            listener.on_transaction_input(&tx.input[1]);
            listener.on_transaction_output(&tx.output[0]);
            listener.on_transaction_end(tx.lock_time, tx.txid());
            listener.on_block_end();
        });
        monitor.on_add_streamed_block_end(&header.block_hash());

        assert!(monitor.state.lock().unwrap().saw_block);

        // test another block push to ensure the state is reset
        monitor.on_push(|listener| {
            listener.on_block_start(&header);
            listener.on_transaction_start(2);
            listener.on_transaction_input(&tx.input[0]);
            listener.on_transaction_input(&tx.input[1]);
            listener.on_transaction_output(&tx.output[0]);
            listener.on_transaction_end(tx.lock_time, tx.txid());
            listener.on_block_end();
        });
        monitor.on_add_streamed_block_end(&header.block_hash());

        assert!(monitor.state.lock().unwrap().saw_block);
    }

    #[test]
    fn test_mutual_close() {
        let block_hash = BlockHash::all_zeros();
        let (node, channel_id, monitor, funding_txid) = setup_funded_channel();

        // channel should exist after a heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_ok());
        assert_eq!(node.get_tracker().listeners.len(), 1);

        let close_tx = make_tx(vec![TxIn {
            previous_output: OutPoint::new(funding_txid, 0),
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }]);
        monitor.on_add_block(&[close_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        assert!(!monitor.is_done());

        // channel should exist after a heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_ok());
        assert_eq!(node.get_tracker().listeners.len(), 1);

        for _ in 1..MIN_DEPTH - 1 {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        monitor.on_add_block(&[], &block_hash);
        assert!(monitor.is_done());

        // channel should be pruned after a heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_err());
        assert_eq!(node.get_tracker().listeners.len(), 0);
    }

    #[test]
    fn test_unilateral_holder_close() {
        let block_hash = BlockHash::all_zeros();
        let (node, channel_id, monitor, _funding_txid) = setup_funded_channel();

        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;
        let htlcs = Vec::new();
        let closing_commitment_tx = node
            .with_channel(&channel_id, |chan| {
                chan.set_next_holder_commit_num_for_testing(commit_num);
                let per_commitment_point = chan.get_per_commitment_point(commit_num)?;
                let txkeys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

                Ok(chan.make_holder_commitment_tx(
                    commit_num,
                    &txkeys,
                    feerate_per_kw,
                    to_holder,
                    to_cp,
                    htlcs.clone(),
                ))
            })
            .expect("make_holder_commitment_tx failed");
        let closing_tx = closing_commitment_tx.trust().built_transaction().transaction.clone();
        let closing_txid = closing_tx.txid();
        let holder_output_index =
            closing_tx.output.iter().position(|out| out.value == to_holder).unwrap() as u32;
        monitor.on_add_block(&[closing_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        assert!(!monitor.is_done());
        // we never forget the channel if we didn't sweep our output
        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        let sweep_cp_tx = make_tx(vec![make_txin2(closing_txid, 1 - holder_output_index)]);
        monitor.on_add_block(&[sweep_cp_tx], &block_hash);
        // we still never forget the channel
        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        let sweep_holder_tx = make_tx(vec![make_txin2(closing_txid, holder_output_index)]);
        monitor.on_add_block(&[sweep_holder_tx], &block_hash);
        // once we sweep our output, we forget the channel
        for _ in 1..MIN_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(monitor.is_done());
    }

    #[test]
    fn test_unilateral_cp_and_htlcs_close() {
        let block_hash = BlockHash::all_zeros();
        let (node, channel_id, monitor, _funding_txid) = setup_funded_channel();

        let commit_num = 23;
        let feerate_per_kw = 1000;
        let to_holder = 100000;
        let to_cp = 200000;
        let htlcs = vec![HTLCOutputInCommitment {
            offered: false,
            amount_msat: 10000,
            cltv_expiry: 0,
            payment_hash: PaymentHash([0; 32]),
            transaction_output_index: None,
        }];
        let closing_commitment_tx = node
            .with_channel(&channel_id, |chan| {
                let per_commitment_point = make_test_pubkey(12);
                chan.set_next_counterparty_commit_num_for_testing(
                    commit_num,
                    per_commitment_point.clone(),
                );
                Ok(chan.make_counterparty_commitment_tx(
                    &per_commitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_holder,
                    to_cp,
                    htlcs.clone(),
                ))
            })
            .expect("make_holder_commitment_tx failed");
        let closing_tx = closing_commitment_tx.trust().built_transaction().transaction.clone();
        let closing_txid = closing_tx.txid();
        let holder_output_index =
            closing_tx.output.iter().position(|out| out.value == to_holder).unwrap() as u32;
        let cp_output_index =
            closing_tx.output.iter().position(|out| out.value == to_cp).unwrap() as u32;
        let htlc_output_index = closing_tx
            .output
            .iter()
            .position(|out| out.value == htlcs[0].amount_msat / 1000)
            .unwrap() as u32;
        monitor.on_add_block(&[closing_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        assert!(!monitor.is_done());
        // we never forget the channel if we didn't sweep our output
        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        let sweep_cp_tx = make_tx(vec![make_txin2(closing_txid, cp_output_index)]);
        monitor.on_add_block(&[sweep_cp_tx], &block_hash);
        // we still never forget the channel
        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        let sweep_holder_tx = make_tx(vec![make_txin2(closing_txid, holder_output_index)]);
        monitor.on_add_block(&[sweep_holder_tx], &block_hash);

        let monitor1 = monitor.clone();

        // TIMELINE 1 - HTLC output not swept
        // we forget the channel once we sweep our output and MAX_CLOSING_DEPTH blocks have passed
        for _ in 1..MAX_CLOSING_DEPTH - 1 {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        monitor.on_add_block(&[], &block_hash);
        assert!(monitor.is_done());
        // drop so we don't refer to it by mistake below
        drop(monitor);

        // TIMELINE 2 - HTLC output swept
        let sweep_htlc_tx = make_tx(vec![make_txin2(closing_txid, htlc_output_index)]);
        monitor1.on_add_block(&[sweep_htlc_tx], &block_hash);

        for _ in 1..MIN_DEPTH {
            monitor1.on_add_block(&[], &block_hash);
        }
        assert!(monitor1.is_done());
    }

    fn setup_funded_channel() -> (Arc<Node>, ChannelId, ChainMonitor, Txid) {
        let funding_tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let setup = make_channel_setup(funding_outpoint);

        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let channel = node.get_channel(&channel_id).unwrap();
        let cpp = Box::new(ChannelCommitmentPointProvider::new(channel.clone()));
        let monitor = node
            .with_channel(&channel_id, |chan| Ok(chan.monitor.clone().as_monitor(cpp.clone())))
            .unwrap();
        let block_hash = BlockHash::all_zeros();
        monitor.on_add_block(&[], &block_hash);
        monitor.on_add_block(&[funding_tx.clone()], &block_hash);
        assert_eq!(monitor.funding_depth(), 1);
        (node, channel_id, monitor, funding_tx.txid())
    }

    fn make_txin2(prev_txid: Txid, prevout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(prev_txid, prevout),
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }
    }

    fn make_channel_setup(funding_outpoint: OutPoint) -> ChannelSetup {
        ChannelSetup {
            is_outbound: true,
            channel_value_sat: 3_000_000,
            push_value_msat: 0,
            funding_outpoint,
            holder_selected_contest_delay: 6,
            holder_shutdown_script: None,
            counterparty_points: make_test_counterparty_points(),
            counterparty_selected_contest_delay: 7,
            counterparty_shutdown_script: None,
            commitment_type: CommitmentType::StaticRemoteKey,
        }
    }
}
