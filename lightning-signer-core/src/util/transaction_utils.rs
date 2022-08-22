use crate::io_extras::sink;
use bitcoin::consensus::Encodable;
use bitcoin::{Script, Transaction, TxOut, VarInt};

/// The maximum value of an input or output in milli satoshi
pub const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

/// The minimum value of the dust limit in satoshis.
// FIXME - this is copied from `lightning::ln::channel, lobby to increase visibility.
pub const MIN_DUST_LIMIT_SATOSHIS: u64 = 330;

/// The expected weight of a commitment transaction
pub(crate) fn expected_commitment_tx_weight(opt_anchors: bool, num_untrimmed_htlc: usize) -> usize {
    /// FIXME - these are copied from `lightning::ln:channel, lobby to increase visibility.
    const COMMITMENT_TX_BASE_WEIGHT: usize = 724;
    const COMMITMENT_TX_BASE_ANCHOR_WEIGHT: usize = 1124;
    const COMMITMENT_TX_WEIGHT_PER_HTLC: usize = 172;
    let base_weight =
        if opt_anchors { COMMITMENT_TX_BASE_ANCHOR_WEIGHT } else { COMMITMENT_TX_BASE_WEIGHT };
    base_weight + num_untrimmed_htlc * COMMITMENT_TX_WEIGHT_PER_HTLC
}

/// The weight of a mutual close transaction.
pub(crate) fn mutual_close_tx_weight(unsigned_tx: &Transaction) -> usize {
    const EXPECTED_MUTUAL_CLOSE_WITNESS_WEIGHT: usize = //
        2 + 1 + 4 + // witness-marker-and-flag witness-element-count 4-element-lengths
        72 + 72 + // <signature_for_pubkey1> <signature_for_pubkey2>
        1 + 1 + 33 + 1 + 33 + 1 + 1; // 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG
    unsigned_tx.weight() + EXPECTED_MUTUAL_CLOSE_WITNESS_WEIGHT
}

/// Possibly adds a change output to the given transaction, always doing so if there are excess
/// funds available beyond the requested feerate.
/// Assumes at least one input will have a witness (ie spends a segwit output).
/// Returns an Err(()) if the requested feerate cannot be met.
pub fn maybe_add_change_output(
    tx: &mut Transaction,
    input_value: u64,
    witness_max_weight: usize,
    feerate_sat_per_1000_weight: u32,
    change_destination_script: Script,
) -> Result<(), ()> {
    if input_value > MAX_VALUE_MSAT / 1000 {
        //bail!("Input value is greater than max satoshis");
        return Err(());
    }

    let mut output_value = 0;
    for output in tx.output.iter() {
        output_value += output.value;
        if output_value >= input_value {
            // bail!("Ouput value equals or exceeds input value");
            return Err(());
        }
    }

    let dust_value = change_destination_script.dust_value();
    let mut change_output = TxOut { script_pubkey: change_destination_script, value: 0 };
    let change_len = change_output.consensus_encode(&mut sink()).map_err(|_| ())?;
    let mut weight_with_change: i64 =
        tx.weight() as i64 + 2 + witness_max_weight as i64 + change_len as i64 * 4;
    // Include any extra bytes required to push an extra output.
    weight_with_change += (VarInt(tx.output.len() as u64 + 1).len()
        - VarInt(tx.output.len() as u64).len()) as i64
        * 4;
    // When calculating weight, add two for the flag bytes
    let change_value: i64 = (input_value - output_value) as i64
        - weight_with_change * feerate_sat_per_1000_weight as i64 / 1000;
    if change_value >= dust_value.to_sat() as i64 {
        change_output.value = change_value as u64;
        tx.output.push(change_output);
    } else if (input_value - output_value) as i64
        - (tx.weight() as i64 + 2 + witness_max_weight as i64) * feerate_sat_per_1000_weight as i64
            / 1000
        < 0
    {
        // bail!("Requested fee rate cannot be met");
        return Err(());
    }

    Ok(())
}

/// Estimate the feerate for an HTLC transaction
pub(crate) fn estimate_feerate_per_kw(total_fee: u64, weight: u64) -> u32 {
    // we want the highest feerate that can give rise to this total fee
    (((total_fee * 1000) + 999) / weight) as u32
}

#[cfg(test)]
mod tests {
    use lightning::ln::chan_utils::{htlc_success_tx_weight, htlc_timeout_tx_weight};

    #[test]
    fn test_estimate_feerate() {
        let weights = vec![
            htlc_timeout_tx_weight(false),
            htlc_timeout_tx_weight(true),
            htlc_success_tx_weight(false),
            htlc_success_tx_weight(true),
        ];

        // make sure the feerate is not lower than 253 at the low end,
        // so as not to fail policy check
        let feerate = 253;
        for weight in &weights {
            let total_fee = (feerate as u64 * *weight) / 1000;
            let estimated_feerate = super::estimate_feerate_per_kw(total_fee, *weight);
            assert!(estimated_feerate >= 253);
        }

        // make sure that the total tx fee stays the same after estimating the rate and recomputing the fee
        // so as to recreate an identical transaction
        for feerate in (300..5000).step_by(10) {
            for weight in &weights {
                let total_fee = (feerate as u64 * *weight) / 1000;
                let estimated_feerate = super::estimate_feerate_per_kw(total_fee, *weight);
                let recovered_total_fee = (estimated_feerate as u64 * *weight) / 1000;
                assert_eq!(total_fee, recovered_total_fee);
            }
        }
    }
}
