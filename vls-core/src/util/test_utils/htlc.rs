use lightning::types::payment::PaymentHash;

use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};

pub fn make_htlc(payment_hash: PaymentHash, value_sat: u64, cltv_expiry: u32) -> HTLCInfo2 {
    HTLCInfo2 { value_sat, payment_hash, cltv_expiry }
}

pub fn make_commit_info_with_htlcs(
    offered_htlcs: Vec<HTLCInfo2>,
    received_htlcs: Vec<HTLCInfo2>,
) -> CommitmentInfo2 {
    CommitmentInfo2::new(false, 2_000_000, 3_000_000, offered_htlcs, received_htlcs, 7500)
}

/// Create a counterparty commitment info for testing (is_counterparty_broadcaster = true)
/// For counterparty commitments:
/// - offered_htlcs = HTLCs the counterparty offers = INCOMING for us
/// - received_htlcs = HTLCs the counterparty receives = OUTGOING for us
pub fn make_counterparty_commit_info_with_htlcs(
    offered_htlcs: Vec<HTLCInfo2>,
    received_htlcs: Vec<HTLCInfo2>,
) -> CommitmentInfo2 {
    CommitmentInfo2::new(true, 2_000_000, 3_000_000, offered_htlcs, received_htlcs, 7500)
}
