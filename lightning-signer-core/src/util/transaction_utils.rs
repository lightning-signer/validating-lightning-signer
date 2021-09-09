use crate::io_extras::sink;
use bitcoin::consensus::Encodable;
use bitcoin::{Script, Transaction, TxOut, VarInt};

/// The maximum value of an input or output in milli satoshi
pub const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

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
    let mut change_output = TxOut {
        script_pubkey: change_destination_script,
        value: 0,
    };
    let change_len = change_output
        .consensus_encode(&mut sink())
        .map_err(|_| ())?;
    let mut weight_with_change: i64 =
        tx.get_weight() as i64 + 2 + witness_max_weight as i64 + change_len as i64 * 4;
    // Include any extra bytes required to push an extra output.
    weight_with_change += (VarInt(tx.output.len() as u64 + 1).len()
        - VarInt(tx.output.len() as u64).len()) as i64
        * 4;
    // When calculating weight, add two for the flag bytes
    let change_value: i64 = (input_value - output_value) as i64
        - weight_with_change * feerate_sat_per_1000_weight as i64 / 1000;
    if change_value >= dust_value.as_sat() as i64 {
        change_output.value = change_value as u64;
        tx.output.push(change_output);
    } else if (input_value - output_value) as i64
        - (tx.get_weight() as i64 + 2 + witness_max_weight as i64)
            * feerate_sat_per_1000_weight as i64
            / 1000
        < 0
    {
        // bail!("Requested fee rate cannot be met");
        return Err(());
    }

    Ok(())
}
