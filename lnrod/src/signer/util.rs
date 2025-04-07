use anyhow::{anyhow, Result};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use lightning::sign::{DelayedPaymentOutputDescriptor, SpendableOutputDescriptor};
use lightning_signer::bitcoin::transaction::Version;
use lightning_signer::bitcoin::Amount;
use lightning_signer::util::transaction_utils;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;
use lightning_signer::{bitcoin, lightning};
use std::collections::HashSet;

pub fn create_spending_transaction(
    descriptors: &[&SpendableOutputDescriptor],
    outputs: Vec<TxOut>,
    change_destination_script: ScriptBuf,
    feerate_sat_per_1000_weight: u32,
) -> Result<Transaction> {
    let mut input = Vec::new();
    let mut input_value = Amount::ZERO;
    let mut witness_weight = 0;
    let mut output_set = HashSet::with_capacity(descriptors.len());
    for outp in descriptors {
        match outp {
            SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                input.push(TxIn {
                    previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::default(),
                });
                witness_weight += descriptor.max_witness_length();
                input_value += descriptor.output.value;
                if !output_set.insert(descriptor.outpoint) {
                    return Err(anyhow!("duplicate"));
                }
            }
            SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                input.push(TxIn {
                    previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(descriptor.to_self_delay as u32),
                    witness: Witness::default(),
                });
                witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
                input_value += descriptor.output.value;
                if !output_set.insert(descriptor.outpoint) {
                    return Err(anyhow!("duplicate"));
                }
            }
            SpendableOutputDescriptor::StaticOutput {
                ref outpoint,
                ref output,
                channel_keys_id: _,
            } => {
                input.push(TxIn {
                    previous_output: outpoint.into_bitcoin_outpoint(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::default(),
                });
                witness_weight += 1 + 73 + 34;
                input_value += output.value;
                if !output_set.insert(*outpoint) {
                    return Err(anyhow!("duplicate"));
                }
            }
        }
        if input_value > Amount::from_sat(MAX_VALUE_MSAT / 1000) {
            return Err(anyhow!("overflow"));
        }
    }
    let mut spend_tx =
        Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input, output: outputs };
    transaction_utils::maybe_add_change_output(
        &mut spend_tx,
        input_value.to_sat(),
        witness_weight,
        feerate_sat_per_1000_weight,
        change_destination_script,
    )
    .map_err(|()| anyhow!("could not add change"))?;
    Ok(spend_tx)
}
