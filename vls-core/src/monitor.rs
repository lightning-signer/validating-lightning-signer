use alloc::collections::BTreeSet as Set;
use core::ops::{Deref, DerefMut};

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, BlockHeader, OutPoint, PackedLockTime, Transaction, TxIn, TxOut, Txid};
use log::*;
use push_decoder::{self, Listener as _};
use serde_derive::{Deserialize, Serialize};

use crate::chain::tracker::ChainListener;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::util::transaction_utils::{decode_commitment_number, parse_closing_tx};
use crate::{Arc, CommitmentPointProvider};

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
    // Number of confirmations of the funding transaction
    funding_height: Option<u32>,
    // The actual funding outpoint on-chain
    funding_outpoint: Option<OutPoint>,
    // Number of confirmations of a transaction that double-spends
    // a funding input
    funding_double_spent_height: Option<u32>,
    // Number of confirmations of the closing transaction
    closing_height: Option<u32>,
    // Whether we saw a block yet - used for sanity check
    #[serde(default)]
    saw_block: bool,
    // Block decode state, only while in progress
    #[serde(skip)]
    decode_state: Option<BlockDecodeState>,
}

struct PushListener<'a>(&'a mut State, &'a CommitmentPointProvider);

impl Deref for PushListener<'_> {
    type Target = State;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for PushListener<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

// A state change detected in a block, to be applied to the monitor state
#[derive(Clone, Debug, Serialize, Deserialize)]
enum StateChange {
    // A funding transaction was confirmed.  The funding outpoint is provided.
    FundingConfirmed(OutPoint),
    // A funding transaction was double spent, the double-spent funding input is provided
    FundingDoubleSpent(OutPoint),
    // A closing transaction was confirmed.
    // The funding outpoint, our output index and HTLC output indexes are provided
    ClosingConfirmed(Txid, OutPoint, Option<u32>, Vec<u32>),
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
    block_hash: BlockHash,
}

const MAX_COMMITMENT_OUTPUTS: u32 = 600;

impl<'a> push_decoder::Listener for PushListener<'a> {
    fn on_block_start(&mut self, header: &BlockHeader) {
        let block_hash = header.block_hash();
        self.0.on_block_start(block_hash);
    }

    fn on_transaction_start(&mut self, version: i32) {
        if self.is_not_ready_for_push() {
            return;
        }
        let state = self.decode_state.as_mut().expect("decode state");
        state.version = version;
        state.input_num = 0;
        state.output_num = 0;
        state.closing_tx = None;
    }

    fn on_transaction_input(&mut self, input: &TxIn) {
        if self.is_not_ready_for_push() {
            return;
        }

        if self.funding_inputs.contains(&input.previous_output) {
            // A funding input was spent
            let state = self.decode_state.as_mut().expect("decode state");
            state.changes.push(StateChange::FundingDoubleSpent(input.previous_output));
        }

        if Some(input.previous_output) == self.funding_outpoint {
            let state = self.decode_state.as_mut().expect("decode state");
            let tx = Transaction {
                version: state.version,
                lock_time: PackedLockTime::ZERO,
                input: vec![input.clone()],
                output: vec![],
            };
            state.closing_tx = Some(tx);
        }

        let state = self.decode_state.as_mut().expect("decode state");
        if state.closing_tx.is_some() {
            assert_eq!(state.input_num, 0, "closing tx must have only one input");
        }
        state.input_num += 1;
    }

    fn on_transaction_output(&mut self, output: &TxOut) {
        if self.is_not_ready_for_push() {
            return;
        }
        let state = self.decode_state.as_mut().expect("decode state");
        if let Some(closing_tx) = &mut state.closing_tx {
            closing_tx.output.push(output.clone());
            assert!(
                state.output_num < MAX_COMMITMENT_OUTPUTS,
                "more than {} commitment outputs",
                MAX_COMMITMENT_OUTPUTS
            );
        }

        state.output_num += 1;
    }

    fn on_transaction_end(&mut self, lock_time: PackedLockTime, txid: Txid) {
        if self.is_not_ready_for_push() {
            return;
        }

        if let Some(ind) = self.funding_txids.iter().position(|i| *i == txid) {
            let vout = self.funding_vouts[ind];
            let state = self.decode_state.as_mut().expect("decode state");
            // This was a funding transaction, which just confirmed
            assert!(
                vout < state.output_num,
                "tx {} doesn't have funding output index {}",
                txid,
                vout
            );
            let outpoint = OutPoint { txid: txid.clone(), vout };
            state.changes.push(StateChange::FundingConfirmed(outpoint));
        }

        let state = self.decode_state.as_mut().expect("decode state");
        let closing_tx = state.closing_tx.take().map(|mut tx| {
            tx.lock_time = lock_time;
            tx
        });

        // separate block because of borrow checker
        if let Some(closing_tx) = closing_tx {
            // closing tx
            assert_eq!(closing_tx.input.len(), 1);
            let provider = self.1;
            let parameters = provider.get_transaction_parameters();

            let commitment_number_opt = decode_commitment_number(&closing_tx, &parameters);
            if let Some(commitment_number) = commitment_number_opt {
                let secp_ctx = Secp256k1::new();
                info!("unilateral close at commitment {} confirmed", commitment_number);
                let holder_per_commitment = provider.get_holder_commitment_point(commitment_number);
                let cp_per_commitment =
                    provider.get_counterparty_commitment_point(commitment_number);
                let (our_output_index, htlc_indices) = parse_closing_tx(
                    &closing_tx,
                    &holder_per_commitment,
                    &cp_per_commitment,
                    &parameters,
                    &secp_ctx,
                );
                info!("our_output_index: {:?}, htlc_indices: {:?}", our_output_index, htlc_indices);
                let state = self.decode_state.as_mut().expect("decode state");
                state.changes.push(StateChange::ClosingConfirmed(
                    txid,
                    closing_tx.input[0].previous_output,
                    our_output_index,
                    htlc_indices,
                ));
            } else {
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
    fn on_add_block_end(&mut self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>) {
        if self.is_not_ready_for_push() {
            return (vec![], vec![]);
        }

        let state = self.decode_state.take().expect("decode state");
        assert_eq!(state.block_hash, *block_hash);

        // if we have funding confirmed, ignore any detected double-spends (we didn't
        // know the txid at the point where we saw the spend)
        let have_funding_confirmed = state.changes.iter().any(|c| match c {
            StateChange::FundingConfirmed(_) => true,
            _ => false,
        });

        self.saw_block = true;
        self.height += 1;

        debug!("detected add-changes at height {}: {:?}", self.height, state.changes);

        let mut adds = Vec::new();
        let mut removes = Vec::new();

        // apply changes
        for change in state.changes {
            match change {
                StateChange::FundingConfirmed(outpoint) => {
                    assert!(self.funding_double_spent_height.is_none());
                    self.funding_height = Some(self.height);
                    self.funding_outpoint = Some(outpoint);
                    adds.push(outpoint);
                }
                StateChange::FundingDoubleSpent(outpoint) => {
                    if !have_funding_confirmed {
                        // A funding input was spent, but no funding tx was confirmed,
                        // so we have a double spend on funding
                        assert!(self.funding_height.is_none());
                        // we may have seen some other funding input double-spent, so
                        // don't overwrite the depth if it exists
                        self.funding_double_spent_height.get_or_insert(self.height);
                    }
                    // no matter whether funding, or double-spend, we want to stop watching these outputs
                    removes.push(outpoint);
                }
                StateChange::ClosingConfirmed(
                    txid,
                    funding_outpoint,
                    our_output_index,
                    htlcs_indices,
                ) => {
                    self.closing_height = Some(self.height);
                    removes.push(funding_outpoint);
                    our_output_index.map(|i| adds.push(OutPoint { txid: txid.clone(), vout: i }));
                    for i in htlcs_indices {
                        adds.push(OutPoint { txid: txid.clone(), vout: i });
                    }
                }
            }
        }

        (adds, removes)
    }

    fn on_remove_block_end(&mut self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>) {
        if self.is_not_ready_for_push() {
            return (vec![], vec![]);
        }

        let state = self.decode_state.take().expect("decode state");
        assert_eq!(state.block_hash, *block_hash);

        // if we have funding confirmed, ignore any detected double-spends (we didn't
        // know the txid at the point where we saw the spend)
        let have_funding_confirmed = state.changes.iter().any(|c| match c {
            StateChange::FundingConfirmed(_) => true,
            _ => false,
        });

        debug!("detected remove-changes at height {}: {:?}", self.height, state.changes);

        let mut adds = Vec::new();
        let mut removes = Vec::new();

        for change in state.changes {
            match change {
                StateChange::FundingConfirmed(outpoint) => {
                    // A funding tx was reorged-out
                    assert_eq!(self.funding_height, Some(self.height));
                    self.funding_height = None;
                    self.funding_outpoint = None;
                    adds.push(outpoint);
                }
                StateChange::FundingDoubleSpent(outpoint) => {
                    if !have_funding_confirmed {
                        // A funding double-spent was reorged-out
                        // we may have seen some other funding input double-spent, so
                        // don't overwrite the depth if it's non-zero, and don't assume
                        // it is 1
                        assert!(self.funding_double_spent_height.is_some());
                        if self.funding_double_spent_height == Some(self.height) {
                            self.funding_double_spent_height = None
                        }
                    }
                    // no matter whether funding, or double-spend, we want to stop watching these outputs
                    removes.push(outpoint);
                }
                StateChange::ClosingConfirmed(
                    txid,
                    funding_outpoint,
                    our_output_index,
                    htlcs_indices,
                ) => {
                    // A closing tx was reorged-out
                    assert_eq!(self.closing_height, Some(self.height));
                    self.closing_height = None;
                    our_output_index.map(|i| adds.push(OutPoint { txid: txid.clone(), vout: i }));
                    for i in htlcs_indices {
                        adds.push(OutPoint { txid: txid.clone(), vout: i });
                    }
                    removes.push(funding_outpoint)
                }
            }
        }
        self.height -= 1;

        // note that the caller will remove the adds and add the removes
        (adds, removes)
    }

    fn on_block_start(&mut self, block_hash: BlockHash) {
        self.saw_block = true;
        self.decode_state = Some(BlockDecodeState {
            changes: Vec::new(),
            version: 0,
            input_num: 0,
            output_num: 0,
            closing_tx: None,
            block_hash,
        });
    }

    // Check if we ever saw the beginning of a block.  If not, we might get
    // push events from a block right after we got created, so we need to
    // ignore them.
    fn is_not_ready_for_push(&self) -> bool {
        self.decode_state.is_none() && !self.saw_block
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
            closing_height: None,
            saw_block: false,
            decode_state: None,
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
            closing_depth: state.closing_height.map(|h| state.height + 1 - h).unwrap_or(0),
        }
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
    /// the commitment point provider, helps with decoding transactions
    pub commitment_point_provider: Box<dyn CommitmentPointProvider>,
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
        state.funding_height.map(|h| state.height + 1 - h).unwrap_or(0)
    }

    /// Returns the number of confirmations of a double-spend of the funding transaction
    /// or zero if it wasn't double-spent.
    pub fn funding_double_spent_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        state.funding_double_spent_height.map(|h| state.height + 1 - h).unwrap_or(0)
    }

    fn push_transactions(&self, block_hash: &BlockHash, txs: &[Transaction]) {
        let mut state = self.state.lock().expect("lock");
        state.on_block_start(*block_hash);

        let mut listener = PushListener(&mut state, &*self.commitment_point_provider);

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
        self.push_transactions(block_hash, txs);

        let mut state = self.state.lock().expect("lock");
        state.on_add_block_end(block_hash)
    }

    fn on_add_streamed_block_end(&self, block_hash: &BlockHash) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.state.lock().expect("lock");
        state.on_add_block_end(block_hash)
    }

    fn on_remove_block(
        &self,
        txs: &[Transaction],
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        debug!("on_remove_block for {}", self.funding_outpoint);
        self.push_transactions(block_hash, txs);

        let mut state = self.state.lock().expect("lock");
        state.on_remove_block_end(block_hash)
    }

    fn on_remove_streamed_block_end(
        &self,
        block_hash: &BlockHash,
    ) -> (Vec<OutPoint>, Vec<OutPoint>) {
        let mut state = self.state.lock().expect("lock");
        state.on_remove_block_end(block_hash)
    }

    fn on_push<F>(&self, f: F)
    where
        F: FnOnce(&mut dyn push_decoder::Listener),
    {
        let mut state = self.state.lock().expect("lock");
        let mut listener = PushListener(&mut *state, &*self.commitment_point_provider);
        f(&mut listener);
    }
}

impl SendSync for ChainMonitor {}

#[cfg(test)]
mod tests {
    use crate::util::test_utils::*;
    use bitcoin::hashes::Hash;
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
}
