use anyhow::{anyhow, Result};
use lightning_signer::bitcoin::{PackedLockTime, Script, Sequence, Transaction, TxIn, Witness};
use lightning_signer::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning_signer::util::transaction_utils;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;
use std::collections::HashSet;

pub fn create_spending_transaction(
    descriptors: &[DelayedPaymentOutputDescriptor],
    output_script: Script,
    feerate_sat_per_1000_weight: u32,
) -> Result<Transaction> {
    let mut input = Vec::new();
    let mut input_value = 0;
    let mut witness_weight = 0;
    let mut output_set = HashSet::with_capacity(descriptors.len());
    for descriptor in descriptors {
        input.push(TxIn {
            previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
            script_sig: Script::new(),
            sequence: Sequence(descriptor.to_self_delay as u32),
            witness: Witness::default(),
        });
        witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
        input_value += descriptor.output.value;
        if !output_set.insert(descriptor.outpoint) {
            return Err(anyhow!("duplicate"));
        }
        if input_value > MAX_VALUE_MSAT / 1000 {
            return Err(anyhow!("overflow"));
        }
    }
    let mut spend_tx =
        Transaction { version: 2, lock_time: PackedLockTime(0), input, output: vec![] };
    transaction_utils::maybe_add_change_output(
        &mut spend_tx,
        input_value,
        witness_weight,
        feerate_sat_per_1000_weight,
        output_script,
    )
    .map_err(|()| anyhow!("could not add change"))?;
    Ok(spend_tx)
}
