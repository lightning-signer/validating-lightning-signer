use alloc::collections::BTreeSet as Set;

use bitcoin::{OutPoint, Transaction, Txid};

use crate::bitcoin::hashes::_export::_core::cmp::Ordering;
use crate::chain::tracker::ChainListener;
use crate::prelude::*;
use crate::Arc;

struct State {
    // funding txids
    funding_txids: Vec<Txid>,
    // the funding output index for each funding tx
    funding_vouts: Vec<u32>,
    // inputs derived from funding_txs for convenience
    funding_inputs: Set<OutPoint>,
    // Number of confirmations of the funding transaction
    funding_depth: Option<u32>,
    // Number of confirmations of a transaction that double-spends
    // a funding input
    funding_double_spent_depth: Option<u32>,
}

/// Keep track of channel on-chain events.
/// Note that this object has refcounted state, so is lightweight to clone.
#[derive(Clone)]
pub struct ChainMonitor {
    funding_outpoint: OutPoint,
    state: Arc<Mutex<State>>,
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
    pub fn new(funding_outpoint: OutPoint) -> Self {
        let state = State {
            funding_txids: Vec::new(),
            funding_vouts: Vec::new(),
            funding_inputs: Set::new(),
            funding_depth: None,
            funding_double_spent_depth: None,
        };

        Self {
            funding_outpoint,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Add a funding transaction to keep track of
    pub fn add_funding(&self, tx: &Transaction, vout: u32) {
        let mut state = self.state.lock().expect("lock");
        assert!(
            state.funding_txids.is_empty(),
            "only a single funding tx currently supported"
        );
        assert_eq!(state.funding_txids.len(), state.funding_vouts.len());
        state.funding_txids.push(tx.txid());
        state.funding_vouts.push(vout);
        state
            .funding_inputs
            .extend(tx.input.iter().map(|i| i.previous_output));
    }

    /// Returns the number of confirmations of the funding transaction, or zero
    /// if it wasn't confirmed yet.
    pub fn funding_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        state.funding_depth.unwrap_or(0)
    }

    /// Returns the number of confirmations of a double-spend of the funding transaction
    /// or zero if it wasn't double-spent.
    pub fn funding_double_spent_depth(&self) -> u32 {
        let state = self.state.lock().expect("lock");
        state.funding_double_spent_depth.unwrap_or(0)
    }
}

impl ChainListener for ChainMonitor {
    fn on_add_block(&self, txs: Vec<&Transaction>) -> Vec<OutPoint> {
        let mut state = self.state.lock().expect("lock");
        for tx in txs {
            if let Some(ind) = state.funding_txids.iter().position(|i| *i == tx.txid()) {
                assert!(state.funding_double_spent_depth.is_none());
                let outpoint = OutPoint::new(tx.txid(), state.funding_vouts[ind]);
                assert!(
                    outpoint.vout < tx.output.len() as u32,
                    "tx doesn't have funding output index"
                );
                state.funding_depth = Some(1);
                return vec![outpoint];
            } else if tx
                .input
                .iter()
                .any(|i| state.funding_inputs.contains(&i.previous_output))
            {
                assert!(state.funding_depth.is_none());
                // we may have seen some other funding input double-spent, so
                // don't overwrite the depth if it exists
                if state.funding_double_spent_depth.is_none() {
                    state.funding_double_spent_depth = Some(0);
                }
            } else {
                panic!("unexpected tx provided to ChainMonitor.on_add_block");
            }
        }
        state.funding_depth = state.funding_depth.map(|d| d + 1);
        state.funding_double_spent_depth = state.funding_double_spent_depth.map(|d| d + 1);
        vec![]
    }

    fn on_remove_block(&self, txs: Vec<&Transaction>) {
        let mut state = self.state.lock().expect("lock");
        for tx in txs {
            if let Some(_) = state.funding_txids.iter().position(|i| *i == tx.txid()) {
                assert_eq!(state.funding_depth, Some(1));
                state.funding_depth = None
            } else if tx
                .input
                .iter()
                .any(|i| state.funding_inputs.contains(&i.previous_output))
            {
                // we may have seen some other funding input double-spent, so
                // don't overwrite the depth if it's non-zero, and don't assume
                // it is 1
                assert!(state.funding_double_spent_depth.is_some());
                if state.funding_double_spent_depth == Some(1) {
                    state.funding_double_spent_depth = None
                }
            } else {
                panic!("unknown reorged tx");
            }
        }
        state.funding_depth = state.funding_depth.map(|d| d - 1);
        state.funding_double_spent_depth = state.funding_double_spent_depth.map(|d| d - 1);
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
        let monitor = ChainMonitor::new(outpoint);
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
        let monitor = ChainMonitor::new(outpoint);
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
