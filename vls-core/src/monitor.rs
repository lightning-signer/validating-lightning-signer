use alloc::collections::BTreeSet as Set;

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::Version;
use bitcoin::{BlockHash, OutPoint, Transaction, TxIn, TxOut, Txid};
use log::*;
use push_decoder::Listener as _;
use serde_derive::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::chain::tracker::ChainListener;
use crate::channel::ChannelId;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::util::transaction_utils::{decode_commitment_number, decode_commitment_tx};
use crate::{Arc, CommitmentPointProvider};

// the depth at which we consider a channel to be done
const MIN_DEPTH: u32 = 100;

// the maximum depth we will watch for HTLC sweeps on closed channels
const MAX_CLOSING_DEPTH: u32 = 2016;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecondLevelHTLCOutput {
    outpoint: OutPoint,
    spent: bool,
}

impl SecondLevelHTLCOutput {
    fn new(outpoint: OutPoint) -> Self {
        Self { outpoint, spent: false }
    }

    fn set_spent(&mut self, spent: bool) {
        self.spent = spent;
    }

    fn is_spent(&self) -> bool {
        self.spent
    }

    fn matches_outpoint(&self, outpoint: &OutPoint) -> bool {
        self.outpoint == *outpoint
    }
}

// Keep track of closing transaction outpoints.
// These include the to-us output (if it exists), all HTLC outputs, and second-level HTLC outputs.
// For each output, we keep track of whether it has been spent yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClosingOutpoints {
    txid: Txid,
    our_output: Option<(u32, bool)>,
    htlc_outputs: Vec<u32>,
    htlc_spents: Vec<bool>,
    second_level_htlc_outputs: Vec<SecondLevelHTLCOutput>,
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
            second_level_htlc_outputs: Vec::new(),
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
        // safe due to PushListener logic
        let p = self.our_output.as_mut().unwrap();
        assert_eq!(p.0, vout);
        p.1 = spent;
    }

    fn set_htlc_output_spent(&mut self, vout: u32, spent: bool) {
        // safe due to PushListener logic
        let i = self.htlc_outputs.iter().position(|&x| x == vout).unwrap();
        self.htlc_spents[i] = spent;
    }

    /// Returns true if all relevant outputs are considered spent.
    /// This includes:
    /// - our main output
    /// - first-level HTLC outputs
    /// - second-level HTLC outputs
    fn is_all_spent(&self) -> bool {
        let our_output_spent = self.our_output.as_ref().map(|(_, b)| *b).unwrap_or(true);
        let htlc_outputs_spent = self.htlc_spents.iter().all(|b| *b);
        let second_level_htlcs_spent = self.second_level_htlc_outputs.iter().all(|h| h.is_spent());

        our_output_spent && htlc_outputs_spent && second_level_htlcs_spent
    }

    fn add_second_level_htlc_output(&mut self, outpoint: OutPoint) {
        self.second_level_htlc_outputs.push(SecondLevelHTLCOutput::new(outpoint));
    }

    fn includes_second_level_htlc_output(&self, outpoint: &OutPoint) -> bool {
        self.second_level_htlc_outputs.iter().any(|h| h.matches_outpoint(outpoint))
    }

    fn set_second_level_htlc_spent(&mut self, outpoint: OutPoint, spent: bool) {
        let htlc_outpoint = self
            .second_level_htlc_outputs
            .iter_mut()
            .find(|h| h.matches_outpoint(&outpoint))
            .expect("second-level HTLC outpoint");
        htlc_outpoint.set_spent(spent);
    }

    fn remove_second_level_htlc_output(&mut self, outpoint: &OutPoint) {
        self.second_level_htlc_outputs.retain(|h| !h.matches_outpoint(outpoint));
    }
}

/// State
#[serde_as]
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
    // Whether the node has forgotten this channel
    #[serde(default)]
    saw_forget_channel: bool,
    // The associated channel_id for logging and debugging.
    // Not persisted, but explicitly populated by new_from_persistence
    #[serde(skip)]
    channel_id: Option<ChannelId>,
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
    // An HTLC commitment output was spent
    // The htlc output index and the second-level HTLC outpoint are provided
    HTLCOutputSpent(u32, OutPoint),
    /// A second-level HTLC output was spent
    SecondLevelHTLCOutputSpent(OutPoint),
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
    // Tracks which HTLC outputs (vouts) were spent and where
    // Format: [(htlc_vout, spending_input_index)]
    spent_htlc_outputs: Vec<(u32, u32)>,
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
            spent_htlc_outputs: Vec::new(),
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
            spent_htlc_outputs: Vec::new(),
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
        state.spent_htlc_outputs = Vec::new();
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
                version: Version(decode_state.version),
                lock_time: LockTime::ZERO,
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
                // Track vout and input index for second-level HTLC creation in on_transaction_end
                decode_state
                    .spent_htlc_outputs
                    .push((input.previous_output.vout, decode_state.input_num));
                None
            } else if c.includes_second_level_htlc_output(&input.previous_output) {
                Some(StateChange::SecondLevelHTLCOutputSpent(input.previous_output))
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

    fn on_transaction_end(&mut self, lock_time: LockTime, txid: Txid) {
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
            let outpoint = OutPoint { txid, vout };
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

        let htlc_changes: Vec<StateChange> = decode_state
            .spent_htlc_outputs
            .drain(..)
            .map(|(spent_vout, input_index)| {
                let second_level_outpoint = OutPoint { txid, vout: input_index };
                StateChange::HTLCOutputSpent(spent_vout, second_level_outpoint)
            })
            .collect();

        for change in htlc_changes {
            decode_state.add_change(change);
        }
    }

    fn on_block_end(&mut self) {
        // we need to wait until we get the following `AddBlock` or `RemoveBlock`
        // message before actually updating ourselves
    }
}

impl State {
    fn channel_id(&self) -> &ChannelId {
        // safe because populated by new_from_persistence
        self.channel_id.as_ref().expect("missing associated channel_id in monitor::State")
    }

    fn depth_of(&self, other_height: Option<u32>) -> u32 {
        (self.height + 1).saturating_sub(other_height.unwrap_or(self.height + 1))
    }

    fn deep_enough_and_saw_node_forget(&self, other_height: Option<u32>, limit: u32) -> bool {
        // If the event depth is less than MIN_DEPTH we never prune.
        // If the event depth is greater we prune if saw_forget_channel is true.
        let depth = self.depth_of(other_height);
        if depth < limit {
            // Not deep enough, we aren't done
            false
        } else if self.saw_forget_channel {
            // Deep enough and the node thinks it's done too
            true
        } else {
            // Deep enough, but we haven't heard from the node
            warn!(
                "expected forget_channel for {} overdue by {} blocks",
                self.channel_id(),
                depth - limit
            );
            false
        }
    }

    fn diagnostic(&self, is_closed: bool) -> String {
        if self.funding_height.is_none() {
            format!("UNCOMFIRMED hold till funding doublespent + {}", MIN_DEPTH)
        } else if let Some(height) = self.funding_double_spent_height {
            format!("AGING_FUNDING_DOUBLESPENT at {} until {}", height, height + MIN_DEPTH)
        } else if let Some(height) = self.mutual_closing_height {
            format!("AGING_MUTUALLY_CLOSED at {} until {}", height, height + MIN_DEPTH)
        } else if let Some(height) = self.closing_swept_height {
            format!("AGING_CLOSING_SWEPT at {} until {}", height, height + MIN_DEPTH)
        } else if let Some(height) = self.our_output_swept_height {
            format!("AGING_OUR_OUTPUT_SWEPT at {} until {}", height, height + MAX_CLOSING_DEPTH)
        } else if is_closed {
            "CLOSING".into()
        } else {
            "ACTIVE".into()
        }
    }

    fn is_done(&self) -> bool {
        // we are done if:
        // - funding was double spent
        // - mutual closed
        // - unilateral closed, and our output, as well as all HTLCs were swept
        // and, the last confirmation is buried
        //
        // TODO(472) disregard received HTLCs that we can't claim (we don't have the preimage)

        if self.deep_enough_and_saw_node_forget(self.funding_double_spent_height, MIN_DEPTH) {
            debug!(
                "{} is_done because funding double spent {} blocks ago",
                self.channel_id(),
                MIN_DEPTH
            );
            return true;
        }

        if self.deep_enough_and_saw_node_forget(self.mutual_closing_height, MIN_DEPTH) {
            debug!("{} is_done because mutual closed {} blocks ago", self.channel_id(), MIN_DEPTH);
            return true;
        }

        if self.deep_enough_and_saw_node_forget(self.closing_swept_height, MIN_DEPTH) {
            debug!("{} is_done because closing swept {} blocks ago", self.channel_id(), MIN_DEPTH);
            return true;
        }

        // since we don't yet have the logic to tell which HTLCs we can claim,
        // time out watching them after MAX_CLOSING_DEPTH
        if self.deep_enough_and_saw_node_forget(self.our_output_swept_height, MAX_CLOSING_DEPTH) {
            debug!(
                "{} is_done because closing output swept {} blocks ago",
                self.channel_id(),
                MAX_CLOSING_DEPTH
            );
            return true;
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
            debug!(
                "{} detected add-changes at height {}: {:?}",
                self.channel_id(),
                self.height,
                decode_state.changes
            );
        }

        // apply changes
        for change in decode_state.changes.drain(..) {
            self.apply_forward_change(&mut adds, &mut removes, change);
        }

        let closing_is_swept = self.is_closing_swept();
        let our_output_is_swept = self.is_our_output_swept();

        if !closing_was_swept && closing_is_swept {
            info!("{} closing tx was swept at height {}", self.channel_id(), self.height);
            self.closing_swept_height = Some(self.height);
        }

        if !our_output_was_swept && our_output_is_swept {
            info!("{} our output was swept at height {}", self.channel_id(), self.height);
            self.our_output_swept_height = Some(self.height);
        }

        if self.is_done() {
            info!("{} done at height {}", self.channel_id(), self.height);
        }

        if changed {
            #[cfg(not(feature = "log_pretty_print"))]
            info!("on_add_block_end state changed: {:?}", self);
            #[cfg(feature = "log_pretty_print")]
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
            debug!(
                "{} detected remove-changes at height {}: {:?}",
                self.channel_id(),
                self.height,
                decode_state.changes
            );
        }

        for change in decode_state.changes.drain(..) {
            self.apply_backward_change(&mut adds, &mut removes, change);
        }

        let closing_is_swept = self.is_closing_swept();
        let our_output_is_swept = self.is_our_output_swept();

        if closing_was_swept && !closing_is_swept {
            info!("{} closing tx was un-swept at height {}", self.channel_id(), self.height);
            self.closing_swept_height = None;
        }

        if our_output_was_swept && !our_output_is_swept {
            info!("{} our output was un-swept at height {}", self.channel_id(), self.height);
            self.our_output_swept_height = None;
        }

        self.height -= 1;

        if changed {
            #[cfg(not(feature = "log_pretty_print"))]
            info!("on_remove_block_end state changed: {:?}", self);
            #[cfg(feature = "log_pretty_print")]
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
        // unwraps below on self.closing_outpoints are safe due to PushListener logic
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
                our_output_index.map(|i| adds.push(OutPoint { txid, vout: i }));
                for i in htlcs_indices.iter() {
                    adds.push(OutPoint { txid, vout: *i });
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
            StateChange::HTLCOutputSpent(vout, second_level_htlc_outpoint) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_htlc_output_spent(vout, true);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                outpoints.add_second_level_htlc_output(second_level_htlc_outpoint);
                removes.push(outpoint);
                adds.push(second_level_htlc_outpoint);
            }
            StateChange::SecondLevelHTLCOutputSpent(outpoint) => {
                let closing_outpoints = self.closing_outpoints.as_mut().unwrap();
                closing_outpoints.set_second_level_htlc_spent(outpoint, true);
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
                our_output_index.map(|i| adds.push(OutPoint { txid, vout: i }));
                for i in htlcs_indices {
                    adds.push(OutPoint { txid, vout: i });
                }
                removes.push(funding_outpoint)
            }
            StateChange::OurOutputSpent(vout) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_our_output_spent(vout, false);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                removes.push(outpoint);
            }
            StateChange::HTLCOutputSpent(vout, second_level_htlc_outpoint) => {
                let outpoints = self.closing_outpoints.as_mut().unwrap();
                outpoints.set_htlc_output_spent(vout, false);
                let outpoint = OutPoint { txid: outpoints.txid, vout };
                outpoints.remove_second_level_htlc_output(&second_level_htlc_outpoint);
                adds.push(outpoint);
                removes.push(second_level_htlc_outpoint);
            }
            StateChange::SecondLevelHTLCOutputSpent(outpoint) => {
                let closing_outpoints = self.closing_outpoints.as_mut().unwrap();
                closing_outpoints.set_second_level_htlc_spent(outpoint, false);
                adds.push(outpoint);
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
    pub fn new(funding_outpoint: OutPoint, height: u32, chan_id: &ChannelId) -> Self {
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
            saw_forget_channel: false,
            channel_id: Some(chan_id.clone()),
        };

        Self { funding_outpoint, state: Arc::new(Mutex::new(state)) }
    }

    /// recreate this monitor after restoring from persistence
    pub fn new_from_persistence(
        funding_outpoint: OutPoint,
        state: State,
        channel_id: &ChannelId,
    ) -> Self {
        let state = Arc::new(Mutex::new(state));
        state.lock().unwrap().channel_id = Some(channel_id.clone());
        Self { funding_outpoint, state }
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
        let mut state = self.get_state();
        assert!(state.funding_txids.is_empty(), "only a single funding tx currently supported");
        assert_eq!(state.funding_txids.len(), state.funding_vouts.len());
        state.funding_txids.push(outpoint.txid);
        state.funding_vouts.push(outpoint.vout);
    }

    /// Add a funding input
    /// For single-funding
    pub fn add_funding_inputs(&self, tx: &Transaction) {
        let mut state = self.get_state();
        state.funding_inputs.extend(tx.input.iter().map(|i| i.previous_output));
    }

    /// Convert to a ChainState, to be used for validation
    pub fn as_chain_state(&self) -> ChainState {
        let state = self.get_state();
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
        self.get_state().is_done()
    }

    /// Called when the node tells us it forgot the channel
    pub fn forget_channel(&self) {
        let mut state = self.get_state();
        state.saw_forget_channel = true;
    }

    /// Returns the actual funding outpoint on-chain
    pub fn funding_outpoint(&self) -> Option<OutPoint> {
        self.get_state().funding_outpoint
    }

    /// Return whether forget_channel was seen
    pub fn forget_seen(&self) -> bool {
        self.get_state().saw_forget_channel
    }

    /// Return string describing the state
    pub fn diagnostic(&self, is_closed: bool) -> String {
        self.get_state().diagnostic(is_closed)
    }

    // Add this getter method
    fn get_state(&self) -> MutexGuard<State> {
        self.state.lock().expect("lock")
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
    pub fn get_state(&self) -> MutexGuard<State> {
        self.state.lock().expect("lock")
    }

    /// Add a funding transaction to keep track of
    /// For dual-funding
    pub fn add_funding(&self, tx: &Transaction, vout: u32) {
        let mut state = self.get_state();
        assert!(state.funding_txids.is_empty(), "only a single funding tx currently supported");
        assert_eq!(state.funding_txids.len(), state.funding_vouts.len());
        state.funding_txids.push(tx.compute_txid());
        state.funding_vouts.push(vout);
        state.funding_inputs.extend(tx.input.iter().map(|i| i.previous_output));
    }

    /// Returns the number of confirmations of the funding transaction, or zero
    /// if it wasn't confirmed yet.
    pub fn funding_depth(&self) -> u32 {
        let state = self.get_state();
        state.depth_of(state.funding_height)
    }

    /// Returns the number of confirmations of a double-spend of the funding transaction
    /// or zero if it wasn't double-spent.
    pub fn funding_double_spent_depth(&self) -> u32 {
        let state = self.get_state();
        state.depth_of(state.funding_double_spent_height)
    }

    /// Returns the number of confirmations of the closing transaction, or zero
    pub fn closing_depth(&self) -> u32 {
        let state = self.get_state();
        let closing_height = state.unilateral_closing_height.or(state.mutual_closing_height);
        state.depth_of(closing_height)
    }

    /// Whether this channel can be forgotten:
    /// - mutual close is confirmed
    /// - unilateral close is swept
    /// - funding transaction is double-spent
    /// and enough confirmations have passed
    pub fn is_done(&self) -> bool {
        self.get_state().is_done()
    }

    // push compact proof transactions through, simulating a streamed block
    fn push_transactions(&self, block_hash: &BlockHash, txs: &[Transaction]) -> BlockDecodeState {
        let mut state = self.get_state();

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
            listener.on_transaction_start(tx.version.0);
            for input in tx.input.iter() {
                listener.on_transaction_input(input);
            }

            for output in tx.output.iter() {
                listener.on_transaction_output(output);
            }
            listener.on_transaction_end(tx.lock_time, tx.compute_txid());
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

        let mut state = self.get_state();
        state.on_add_block_end(block_hash, &mut decode_state)
    }

    fn on_add_streamed_block_end(&self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.get_state();
        let mut decode_state = self.decode_state.lock().expect("lock").take();
        if !state.saw_block {
            // not ready yet, bail
            return (Vec::new(), Vec::new());
        }
        // safe because `on_push` must have been called first
        state.on_add_block_end(block_hash, decode_state.as_mut().unwrap())
    }

    fn on_remove_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        debug!("on_remove_block for {}", self.funding_outpoint);
        let mut decode_state = self.push_transactions(block_hash, txs);

        let mut state = self.get_state();
        state.on_remove_block_end(block_hash, &mut decode_state)
    }

    fn on_remove_streamed_block_end(
        &self,
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.get_state();
        let mut decode_state = self.decode_state.lock().expect("lock").take();
        if !state.saw_block {
            // not ready yet, bail
            return (Vec::new(), Vec::new());
        }
        // safe because `on_push` must have been called first
        state.on_remove_block_end(block_hash, decode_state.as_mut().unwrap())
    }

    fn on_push<F>(&self, f: F)
    where
        F: FnOnce(&mut dyn push_decoder::Listener),
    {
        let mut state = self.get_state();
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
    use bitcoin::block::Version;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::hashes::Hash;
    use bitcoin::CompactTarget;
    use lightning::ln::chan_utils::HTLCOutputInCommitment;
    use lightning::types::payment::PaymentHash;
    use test_log::test;

    use super::*;

    #[test]
    fn test_funding() {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let outpoint = OutPoint::new(tx.compute_txid(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let chan_id = ChannelId::new(&[33u8; 32]);
        let monitor = ChainMonitorBase::new(outpoint, 0, &chan_id).as_monitor(cpp);
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
        let outpoint = OutPoint::new(tx.compute_txid(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let chan_id = ChannelId::new(&[33u8; 32]);
        let monitor = ChainMonitorBase::new(outpoint, 0, &chan_id).as_monitor(cpp);
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
        let chan_id = ChannelId::new(&[33u8; 32]);
        let monitor = ChainMonitorBase::new(outpoint, 0, &chan_id).as_monitor(cpp);
        let header = BlockHeader {
            version: Version::from_consensus(0),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);

        // test a push when not ready (simulates creation during a stream)
        monitor.on_push(|listener| {
            listener.on_transaction_input(&tx.input[1]);
            listener.on_transaction_output(&tx.output[0]);
            listener.on_transaction_end(tx.lock_time, tx.compute_txid());
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
            listener.on_transaction_end(tx.lock_time, tx.compute_txid());
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
            listener.on_transaction_end(tx.lock_time, tx.compute_txid());
            listener.on_block_end();
        });
        monitor.on_add_streamed_block_end(&header.block_hash());

        assert!(monitor.state.lock().unwrap().saw_block);
    }

    #[test]
    fn test_streamed_block_operations() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let cpp = Box::new(DummyCommitmentPointProvider {});
        let chan_id = ChannelId::new(&[33u8; 32]);
        let monitor = ChainMonitorBase::new(outpoint, 0, &chan_id).as_monitor(cpp);
        let block_hash = BlockHash::all_zeros();

        // Test when not ready (saw_block = false)
        let (adds, removes) = monitor.on_add_streamed_block_end(&block_hash);
        assert!(adds.is_empty());
        assert!(removes.is_empty());

        let (adds, removes) = monitor.on_remove_streamed_block_end(&block_hash);
        assert!(adds.is_empty());
        assert!(removes.is_empty());

        let funding_tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let funding_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
        let monitor2 = ChainMonitorBase::new(funding_outpoint, 0, &chan_id)
            .as_monitor(Box::new(DummyCommitmentPointProvider {}));
        monitor2.add_funding(&funding_tx, 0);

        let header = BlockHeader {
            version: Version::from_consensus(0),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let header_block_hash = header.block_hash();

        monitor2.on_push(|listener| {
            listener.on_block_start(&header);
            listener.on_transaction_start(funding_tx.version.0);

            for input in &funding_tx.input {
                listener.on_transaction_input(input);
            }

            for output in &funding_tx.output {
                listener.on_transaction_output(output);
            }

            listener.on_transaction_end(funding_tx.lock_time, funding_tx.compute_txid());
            listener.on_block_end();
        });

        let (adds, _) = monitor2.on_add_streamed_block_end(&header_block_hash);
        assert!(!adds.is_empty());

        monitor2.on_push(|listener| {
            listener.on_block_start(&header);
            listener.on_transaction_start(funding_tx.version.0);

            for input in &funding_tx.input {
                listener.on_transaction_input(input);
            }

            for output in &funding_tx.output {
                listener.on_transaction_output(output);
            }

            listener.on_transaction_end(funding_tx.lock_time, funding_tx.compute_txid());
            listener.on_block_end();
        });

        let (adds, _) = monitor2.on_remove_streamed_block_end(&header_block_hash);
        assert!(!adds.is_empty());
    }

    #[test]
    fn test_chain_monitor_conversions_and_getters() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let chan_id = ChannelId::new(&[33u8; 32]);
        let base = ChainMonitorBase::new(outpoint, 0, &chan_id);

        let cpp = Box::new(DummyCommitmentPointProvider {});
        let monitor = base.as_monitor(cpp);
        let base2 = monitor.as_base();
        assert_eq!(base2.funding_outpoint, outpoint);

        assert_eq!(base.funding_outpoint(), None);
        assert!(!base.forget_seen());

        base.forget_channel();
        assert!(base.forget_seen());
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
        node.forget_channel(&channel_id).unwrap();
        monitor.on_add_block(&[], &block_hash);
        assert!(monitor.is_done());

        // channel should still be there until the heartbeat
        assert!(node.get_channel(&channel_id).is_ok());

        // channel should be pruned after a heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_err());
        assert_eq!(node.get_tracker().listeners.len(), 0);
    }

    #[test]
    fn test_mutual_close_with_forget_channel() {
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
        assert!(!monitor.is_done());

        // channel should still be there until the forget_channel
        assert!(node.get_channel(&channel_id).is_ok());
        node.forget_channel(&channel_id).unwrap();

        // need a heartbeat to do the pruning
        assert!(node.get_channel(&channel_id).is_ok());
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_err());
        assert_eq!(node.get_tracker().listeners.len(), 0);
    }

    #[test]
    fn test_mutual_close_with_missing_forget_channel() {
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

        // we're not done because no forget_channel seen
        assert!(!monitor.is_done());
        assert!(node.get_channel(&channel_id).is_ok());

        // channel should still be there after heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_ok());

        // wait a long time
        for _ in 0..2016 - 1 {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());

        // we still don't forget the channel if the node hasn't said forget
        monitor.on_add_block(&[], &block_hash);
        assert!(!monitor.is_done());

        // channel should still be there
        assert!(node.get_channel(&channel_id).is_ok());

        // channel should not be pruned after a heartbeat
        node.get_heartbeat();
        assert!(node.get_channel(&channel_id).is_ok());
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
                let txkeys = chan.make_holder_tx_keys(&per_commitment_point);

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
        let closing_txid = closing_tx.compute_txid();
        let holder_output_index =
            closing_tx.output.iter().position(|out| out.value.to_sat() == to_holder).unwrap()
                as u32;
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
        node.forget_channel(&channel_id).unwrap();
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
                    commit_num + 1,
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
        let closing_txid = closing_tx.compute_txid();
        let holder_output_index =
            closing_tx.output.iter().position(|out| out.value.to_sat() == to_holder).unwrap()
                as u32;
        let cp_output_index =
            closing_tx.output.iter().position(|out| out.value.to_sat() == to_cp).unwrap() as u32;
        let htlc_output_index = closing_tx
            .output
            .iter()
            .position(|out| out.value.to_sat() == htlcs[0].amount_msat / 1000)
            .unwrap() as u32;

        assert_eq!(monitor.closing_depth(), 0);
        assert!(!monitor.is_done());

        monitor.on_add_block(&[closing_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        assert!(!monitor.is_done());

        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();

        assert!(!closing_outpoints.is_all_spent());

        let holder_outpoint = OutPoint { txid: closing_txid, vout: holder_output_index };
        let cp_outpoint = OutPoint { txid: closing_txid, vout: cp_output_index };
        let htlc_outpoint = OutPoint { txid: closing_txid, vout: htlc_output_index };

        assert!(closing_outpoints.includes_our_output(&holder_outpoint));
        assert!(!closing_outpoints.includes_our_output(&cp_outpoint));
        assert!(closing_outpoints.includes_htlc_output(&htlc_outpoint));
        assert!(!closing_outpoints.includes_htlc_output(&holder_outpoint));

        assert!(!closing_outpoints.includes_second_level_htlc_output(&htlc_outpoint));

        drop(state);

        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());

        let sweep_cp_tx = make_tx(vec![make_txin2(closing_txid, cp_output_index)]);
        monitor.on_add_block(&[sweep_cp_tx], &block_hash);

        // Still not done because our output isn't swept
        for _ in 1..MAX_CLOSING_DEPTH {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());

        let sweep_holder_tx = make_tx(vec![make_txin2(closing_txid, holder_output_index)]);
        monitor.on_add_block(&[sweep_holder_tx], &block_hash);

        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        // Our output should be marked as spent, but HTLCs not yet
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        let monitor1 = monitor.clone();

        // TIMELINE 1 - HTLC output not swept
        for _ in 1..MAX_CLOSING_DEPTH - 1 {
            monitor.on_add_block(&[], &block_hash);
        }
        assert!(!monitor.is_done());
        monitor.on_add_block(&[], &block_hash);
        assert!(!monitor.is_done());

        // TIMELINE 2 - HTLC output swept
        let sweep_htlc_tx = make_tx(vec![make_txin2(closing_txid, htlc_output_index)]);
        let sweep_htlc_txid = sweep_htlc_tx.compute_txid();
        monitor1.on_add_block(&[sweep_htlc_tx], &block_hash);

        let state = monitor1.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        let second_level_outpoint = OutPoint { txid: sweep_htlc_txid, vout: 0 };
        assert!(closing_outpoints.includes_second_level_htlc_output(&second_level_outpoint));
        // Second-level not swept yet
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        for _ in 1..MAX_CLOSING_DEPTH {
            monitor1.on_add_block(&[], &block_hash);
        }
        assert!(!monitor1.is_done());

        let sweep_second_level_tx = make_tx(vec![make_txin2(sweep_htlc_txid, 0)]);
        monitor1.on_add_block(&[sweep_second_level_tx], &block_hash);

        let state = monitor1.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        // Now all outputs should be spent
        assert!(closing_outpoints.is_all_spent());
        drop(state);

        for _ in 1..MAX_CLOSING_DEPTH {
            monitor1.on_add_block(&[], &block_hash);
        }
        // still not done, need forget from node
        assert!(!monitor1.is_done());

        // once the node forgets we can forget all of the above
        node.forget_channel(&channel_id).unwrap();
        assert!(monitor.is_done());
        assert!(monitor1.is_done());
    }

    #[test]
    fn test_unilateral_cp_and_htlcs_backward_change() {
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
                    commit_num + 1,
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
            .expect("make_counterparty_commitment_tx failed");

        let closing_tx = closing_commitment_tx.trust().built_transaction().transaction.clone();
        let closing_txid = closing_tx.compute_txid();
        let holder_output_index =
            closing_tx.output.iter().position(|out| out.value.to_sat() == to_holder).unwrap()
                as u32;
        let htlc_output_index = closing_tx
            .output
            .iter()
            .position(|out| out.value.to_sat() == htlcs[0].amount_msat / 1000)
            .unwrap() as u32;

        monitor.on_add_block(&[closing_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        let htlc_outpoint = OutPoint { txid: closing_txid, vout: htlc_output_index };
        assert!(closing_outpoints.includes_htlc_output(&htlc_outpoint));
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        let sweep_holder_tx = make_tx(vec![make_txin2(closing_txid, holder_output_index)]);
        monitor.on_add_block(&[sweep_holder_tx.clone()], &block_hash);

        let sweep_htlc_tx = make_tx(vec![make_txin2(closing_txid, htlc_output_index)]);
        let sweep_htlc_txid = sweep_htlc_tx.compute_txid();
        monitor.on_add_block(&[sweep_htlc_tx.clone()], &block_hash);

        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        let second_level_outpoint = OutPoint { txid: sweep_htlc_txid, vout: 0 };
        assert!(closing_outpoints.includes_second_level_htlc_output(&second_level_outpoint));
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        let sweep_second_level_tx = make_tx(vec![make_txin2(sweep_htlc_txid, 0)]);
        monitor.on_add_block(&[sweep_second_level_tx.clone()], &block_hash);

        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        assert!(closing_outpoints.is_all_spent());
        drop(state);

        // Roll back second-level HTLC spend
        monitor.on_remove_block(&[sweep_second_level_tx], &block_hash);
        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        // Roll back first-level HTLC spend
        monitor.on_remove_block(&[sweep_htlc_tx], &block_hash);
        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        assert!(!closing_outpoints.includes_second_level_htlc_output(&second_level_outpoint));
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        // Roll back holder output spend
        monitor.on_remove_block(&[sweep_holder_tx], &block_hash);
        let state = monitor.get_state();
        let closing_outpoints = state.closing_outpoints.as_ref().unwrap();
        let holder_outpoint = OutPoint { txid: closing_txid, vout: holder_output_index };
        assert!(closing_outpoints.includes_our_output(&holder_outpoint));
        assert!(!closing_outpoints.is_all_spent());
        drop(state);

        // Roll back unilateral close
        monitor.on_remove_block(&[closing_tx], &block_hash);
        let state = monitor.get_state();
        assert!(state.closing_outpoints.is_none());
        assert_eq!(state.unilateral_closing_height, None);
    }

    #[test]
    fn test_apply_backward_change_funding_confirmed() {
        let funding_tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let funding_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
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
        assert!(monitor.get_state().funding_outpoint.is_some());

        monitor.on_remove_block(&[funding_tx], &block_hash);
        assert_eq!(monitor.funding_depth(), 0);
        assert!(monitor.get_state().funding_outpoint.is_none());
    }

    #[test]
    fn test_apply_backward_change_mutual_close() {
        let block_hash = BlockHash::all_zeros();
        let (_, _, monitor, funding_txid) = setup_funded_channel();

        let close_tx = make_tx(vec![TxIn {
            previous_output: OutPoint::new(funding_txid, 0),
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }]);

        monitor.on_add_block(&[close_tx.clone()], &block_hash);
        assert_eq!(monitor.closing_depth(), 1);
        assert!(monitor.get_state().mutual_closing_height.is_some());

        monitor.on_remove_block(&[close_tx], &block_hash);
        assert_eq!(monitor.closing_depth(), 0);
        assert!(monitor.get_state().mutual_closing_height.is_none());
    }

    #[test]
    fn test_closing_outpoints_is_all_spent_logic() {
        let txid = Txid::all_zeros();
        let mut closing_outpoints = ClosingOutpoints::new(txid, Some(0), vec![1, 2]);

        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_our_output_spent(0, true);
        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_htlc_output_spent(1, true);
        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_htlc_output_spent(2, true);
        // All first-level spent, no second-level
        assert!(closing_outpoints.is_all_spent());

        let second_level_outpoint = OutPoint { txid, vout: 10 };
        closing_outpoints.add_second_level_htlc_output(second_level_outpoint);
        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_second_level_htlc_spent(second_level_outpoint, true);
        assert!(closing_outpoints.is_all_spent());
    }

    #[test]
    fn test_closing_outpoints_without_our_output() {
        let txid = Txid::all_zeros();
        let mut closing_outpoints = ClosingOutpoints::new(txid, None, vec![1]);

        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_htlc_output_spent(1, true);
        assert!(closing_outpoints.is_all_spent());
    }

    #[test]
    fn test_closing_outpoints_boolean_logic_edge_cases() {
        let txid = Txid::all_zeros();

        let closing_outpoints = ClosingOutpoints::new(txid, None, vec![]);
        assert!(closing_outpoints.is_all_spent());

        let mut closing_outpoints = ClosingOutpoints::new(txid, Some(0), vec![1]);

        closing_outpoints.set_our_output_spent(0, false);
        closing_outpoints.set_htlc_output_spent(1, false);
        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_our_output_spent(0, true);
        closing_outpoints.set_htlc_output_spent(1, false);
        assert!(!closing_outpoints.is_all_spent());
    }

    #[test]
    fn test_closing_outpoints_second_level_management() {
        let txid = Txid::all_zeros();
        let mut closing_outpoints = ClosingOutpoints::new(txid, None, vec![]);

        let outpoint1 = OutPoint { txid, vout: 10 };
        let outpoint2 = OutPoint { txid, vout: 11 };

        closing_outpoints.add_second_level_htlc_output(outpoint1);
        closing_outpoints.add_second_level_htlc_output(outpoint2);

        assert!(closing_outpoints.includes_second_level_htlc_output(&outpoint1));
        assert!(closing_outpoints.includes_second_level_htlc_output(&outpoint2));

        closing_outpoints.set_second_level_htlc_spent(outpoint1, true);
        assert!(!closing_outpoints.is_all_spent());

        closing_outpoints.set_second_level_htlc_spent(outpoint2, true);
        assert!(closing_outpoints.is_all_spent());

        closing_outpoints.remove_second_level_htlc_output(&outpoint1);
        assert!(!closing_outpoints.includes_second_level_htlc_output(&outpoint1));
        assert!(closing_outpoints.includes_second_level_htlc_output(&outpoint2));
        assert!(closing_outpoints.is_all_spent());
    }

    #[test]
    fn test_second_level_htlc_output_methods() {
        let outpoint = OutPoint { txid: Txid::all_zeros(), vout: 0 };
        let mut htlc_output = SecondLevelHTLCOutput::new(outpoint);

        assert!(!htlc_output.is_spent());
        assert!(htlc_output.matches_outpoint(&outpoint));

        let different_outpoint = OutPoint { txid: Txid::all_zeros(), vout: 1 };
        assert!(!htlc_output.matches_outpoint(&different_outpoint));

        htlc_output.set_spent(true);
        assert!(htlc_output.is_spent());

        htlc_output.set_spent(false);
        assert!(!htlc_output.is_spent());
    }

    #[test]
    fn test_transaction_state_isolation() {
        let block_hash = BlockHash::all_zeros();
        let (_, _, monitor, funding_txid) = setup_funded_channel();
        let funding_outpoint = OutPoint::new(funding_txid, 0);

        let closing_tx = make_tx(vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }]);
        let closing_txid = closing_tx.compute_txid();

        let unrelated_tx = make_tx(vec![make_txin2(Txid::all_zeros(), 0)]);

        let mut decode_state =
            BlockDecodeState::new_with_block_hash(&monitor.get_state(), &block_hash);
        let mut listener = PushListener {
            commitment_point_provider: &*monitor.commitment_point_provider,
            decode_state: &mut decode_state,
            saw_block: true,
        };

        listener.on_transaction_start(closing_tx.version.0);
        listener.on_transaction_input(&closing_tx.input[0]);
        listener.on_transaction_output(&closing_tx.output[0]);
        listener.on_transaction_end(closing_tx.lock_time, closing_txid);

        assert!(listener.decode_state.closing_tx.is_none());

        listener.on_transaction_start(unrelated_tx.version.0);

        assert_eq!(listener.decode_state.version, unrelated_tx.version.0);
        assert_eq!(listener.decode_state.input_num, 0);
        assert_eq!(listener.decode_state.output_num, 0);
        assert!(listener.decode_state.closing_tx.is_none());
        assert!(listener.decode_state.spent_htlc_outputs.is_empty());
    }

    #[test]
    fn test_is_done_conditions() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let chan_id = ChannelId::new(&[33u8; 32]);

        let base1 = ChainMonitorBase::new(outpoint, MIN_DEPTH + 10, &chan_id);
        {
            let mut state = base1.get_state();
            state.funding_double_spent_height = Some(10);
            state.saw_forget_channel = true;
        }
        assert!(base1.is_done());

        let base2 = ChainMonitorBase::new(outpoint, MAX_CLOSING_DEPTH + 10, &chan_id);
        {
            let mut state = base2.get_state();
            state.our_output_swept_height = Some(10);
            state.saw_forget_channel = true;
        }
        assert!(base2.is_done());
    }

    #[test]
    fn test_diagnostic_all_states() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let chan_id = ChannelId::new(&[33u8; 32]);
        let base = ChainMonitorBase::new(outpoint, 100, &chan_id);

        let diagnostic = base.diagnostic(false);
        assert_eq!(
            diagnostic,
            format!("UNCOMFIRMED hold till funding doublespent + {}", MIN_DEPTH)
        );

        {
            let mut state = base.get_state();
            state.funding_height = Some(90);
        }
        assert_eq!(base.diagnostic(false), "ACTIVE");
        assert_eq!(base.diagnostic(true), "CLOSING");

        // Test all aging states
        let test_cases = vec![
            ("funding_double_spent_height", 95, MIN_DEPTH, "AGING_FUNDING_DOUBLESPENT"),
            ("mutual_closing_height", 98, MIN_DEPTH, "AGING_MUTUALLY_CLOSED"),
            ("closing_swept_height", 99, MIN_DEPTH, "AGING_CLOSING_SWEPT"),
            ("our_output_swept_height", 97, MAX_CLOSING_DEPTH, "AGING_OUR_OUTPUT_SWEPT"),
        ];

        for (field, height, depth_limit, expected_prefix) in test_cases {
            {
                let mut state = base.get_state();
                state.funding_height = Some(90);
                state.funding_double_spent_height = None;
                state.mutual_closing_height = None;
                state.closing_swept_height = None;
                state.our_output_swept_height = None;

                match field {
                    "funding_double_spent_height" =>
                        state.funding_double_spent_height = Some(height),
                    "mutual_closing_height" => state.mutual_closing_height = Some(height),
                    "closing_swept_height" => state.closing_swept_height = Some(height),
                    "our_output_swept_height" => state.our_output_swept_height = Some(height),
                    _ => unreachable!(),
                }
            }

            let diagnostic = base.diagnostic(false);
            let expected =
                format!("{} at {} until {}", expected_prefix, height, height + depth_limit);
            assert_eq!(diagnostic, expected);
        }
    }

    fn setup_funded_channel() -> (Arc<Node>, ChannelId, ChainMonitor, Txid) {
        let funding_tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let funding_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);
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
        (node, channel_id, monitor, funding_tx.compute_txid())
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
