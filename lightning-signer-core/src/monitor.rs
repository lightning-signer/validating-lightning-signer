use alloc::collections::BTreeSet as Set;

use bitcoin::{OutPoint, Transaction, Txid};

use crate::bitcoin::hashes::_export::_core::cmp::Ordering;
use crate::chain::tracker::ChainListener;
use crate::policy::validator::ChainState;
use crate::prelude::*;
use crate::Arc;

/// State
#[derive(Clone, Debug)]
pub struct State {
    /// Chain height
    pub height: u32,
    /// funding txids
    pub funding_txids: Vec<Txid>,
    /// the funding output index for each funding tx
    pub funding_vouts: Vec<u32>,
    /// inputs derived from funding_txs for convenience
    pub funding_inputs: Set<OutPoint>,
    /// Number of confirmations of the funding transaction
    pub funding_height: Option<u32>,
    /// The actual funding outpoint on-chain
    pub funding_outpoint: Option<OutPoint>,
    /// Number of confirmations of a transaction that double-spends
    /// a funding input
    pub funding_double_spent_height: Option<u32>,
    /// Number of confirmations of the closing transaction
    pub closing_height: Option<u32>,
}

/// Keep track of channel on-chain events.
/// Note that this object has refcounted state, so is lightweight to clone.
#[derive(Clone)]
pub struct ChainMonitor {
    /// the first funding outpoint, used to identify the channel / channel monitor
    pub funding_outpoint: OutPoint,
    /// the monitor state
    pub state: Arc<Mutex<State>>,
}

impl Eq for ChainMonitor {}

impl PartialEq<Self> for ChainMonitor {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(&other) == Ordering::Equal
    }
}

impl PartialOrd<Self> for ChainMonitor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for ChainMonitor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.funding_outpoint.cmp(&other.funding_outpoint)
    }
}

impl ChainMonitor {
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
        };

        Self { funding_outpoint, state: Arc::new(Mutex::new(state)) }
    }

    /// recreate this monitor after restoring from persistence
    pub fn new_from_persistence(funding_outpoint: OutPoint, state: State) -> Self {
        Self { funding_outpoint, state: Arc::new(Mutex::new(state)) }
    }

    /// Get the locked state
    pub fn get_state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("lock")
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

impl ChainListener for ChainMonitor {
    fn on_add_block(&self, txs: Vec<&Transaction>) -> Vec<OutPoint> {
        let mut state = self.state.lock().expect("lock");
        let mut outpoints = vec![];

        state.height += 1;
        for tx in txs {
            let spent: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
            let txid = tx.txid();
            if let Some(ind) = state.funding_txids.iter().position(|i| *i == txid) {
                // A funding tx was confirmed
                assert!(state.funding_double_spent_height.is_none());
                let outpoint = OutPoint::new(txid, state.funding_vouts[ind]);
                assert!(
                    outpoint.vout < tx.output.len() as u32,
                    "tx doesn't have funding output index"
                );
                state.funding_height = Some(state.height);
                state.funding_outpoint = Some(outpoint);
                outpoints.push(outpoint);
            } else if spent.iter().any(|i| state.funding_inputs.contains(&i)) {
                // A funding input was spent, but no funding tx was confirmed,
                // so we have a double spend on funding
                assert!(state.funding_height.is_none());
                // we may have seen some other funding input double-spent, so
                // don't overwrite the depth if it exists
                if state.funding_double_spent_height.is_none() {
                    state.funding_double_spent_height = Some(state.height);
                }
            } else if spent.iter().any(|i| Some(*i) == state.funding_outpoint) {
                // Closed on-chain
                state.closing_height = Some(state.height);
            } else {
                panic!("unknown tx confirmed")
            }
        }

        outpoints
    }

    fn on_remove_block(&self, txs: Vec<&Transaction>) {
        let mut state = self.state.lock().expect("lock");
        for tx in txs {
            let spent: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
            let txid = tx.txid();
            if let Some(_) = state.funding_txids.iter().position(|i| *i == txid) {
                // A funding tx was reorged-out
                assert_eq!(state.funding_height, Some(state.height));
                state.funding_height = None;
                state.funding_outpoint = None;
            } else if spent.iter().any(|i| state.funding_inputs.contains(&i)) {
                // A funding double-spent was reorged-out
                // we may have seen some other funding input double-spent, so
                // don't overwrite the depth if it's non-zero, and don't assume
                // it is 1
                assert!(state.funding_double_spent_height.is_some());
                if state.funding_double_spent_height == Some(state.height) {
                    state.funding_double_spent_height = None
                }
            } else if spent.iter().any(|i| Some(*i) == state.funding_outpoint) {
                // A closing tx was reorged-out
                assert_eq!(state.closing_height, Some(state.height));
                state.closing_height = None;
            } else {
                panic!("unknown reorged tx");
            }
        }
        state.height -= 1;
    }
}

impl SendSync for ChainMonitor {}

#[cfg(test)]
mod tests {
    use crate::util::test_utils::*;

    use super::*;

    #[test]
    fn test_funding() {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let outpoint = OutPoint::new(tx.txid(), 0);
        let monitor = ChainMonitor::new(outpoint, 0);
        monitor.add_funding(&tx, 0);
        monitor.on_add_block(vec![]);
        monitor.on_add_block(vec![&tx]);
        assert_eq!(monitor.funding_depth(), 1);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
        monitor.on_add_block(vec![]);
        assert_eq!(monitor.funding_depth(), 2);
        monitor.on_remove_block(vec![]);
        assert_eq!(monitor.funding_depth(), 1);
        monitor.on_remove_block(vec![&tx]);
        assert_eq!(monitor.funding_depth(), 0);
        monitor.on_remove_block(vec![]);
        assert_eq!(monitor.funding_depth(), 0);
    }

    #[test]
    fn test_funding_double_spent() {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let tx2 = make_tx(vec![make_txin(2)]);
        let outpoint = OutPoint::new(tx.txid(), 0);
        let monitor = ChainMonitor::new(outpoint, 0);
        monitor.add_funding(&tx, 0);
        monitor.on_add_block(vec![]);
        monitor.on_add_block(vec![&tx2]);
        assert_eq!(monitor.funding_depth(), 0);
        assert_eq!(monitor.funding_double_spent_depth(), 1);
        monitor.on_add_block(vec![]);
        assert_eq!(monitor.funding_depth(), 0);
        assert_eq!(monitor.funding_double_spent_depth(), 2);
        monitor.on_remove_block(vec![]);
        assert_eq!(monitor.funding_double_spent_depth(), 1);
        monitor.on_remove_block(vec![&tx2]);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
        monitor.on_remove_block(vec![]);
        assert_eq!(monitor.funding_double_spent_depth(), 0);
    }
}
