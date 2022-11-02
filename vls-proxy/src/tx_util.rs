use anyhow::{anyhow, Result};
use lightning_signer::bitcoin::secp256k1::SecretKey;
use lightning_signer::bitcoin::{PackedLockTime, Script, Sequence, Transaction, TxIn, Witness};
use lightning_signer::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor;
use lightning_signer::node::{Node, SpendType};
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

pub fn spend_delayed_outputs(
    node: &Node,
    descriptors: &[DelayedPaymentOutputDescriptor],
    unilateral_close_key: (SecretKey, Vec<Vec<u8>>),
    output_script: Script,
    opath: Vec<u32>,
    feerate_sat_per_1000_weight: u32,
) -> Transaction {
    let mut tx =
        create_spending_transaction(descriptors, output_script, feerate_sat_per_1000_weight)
            .expect("create_spending_transaction");
    let spendtypes = descriptors.iter().map(|_| SpendType::P2wsh).collect();
    let values_sat = descriptors.iter().map(|d| d.output.value).collect();
    let ipaths = descriptors.iter().map(|_| vec![]).collect();
    let uniclosekeys = descriptors.iter().map(|_| Some(unilateral_close_key.clone())).collect();
    let witnesses = node
        .sign_onchain_tx(&tx, &ipaths, &values_sat, &spendtypes, uniclosekeys, &vec![opath])
        .expect("sign");
    assert_eq!(witnesses.len(), tx.input.len());
    for (idx, w) in witnesses.into_iter().enumerate() {
        tx.input[idx].witness = Witness::from_vec(w);
    }
    tx
}
