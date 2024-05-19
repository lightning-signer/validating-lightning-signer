use crate::io_extras::sink;
use crate::prelude::*;
use bitcoin::address::Payload;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{PublicKey as BitcoinPublicKey, ScriptBuf};
use bitcoin::{Transaction, TxOut, VarInt};
use lightning::ln::chan_utils::{
    get_commitment_transaction_number_obscure_factor, get_revokeable_redeemscript,
    make_funding_redeemscript, ChannelTransactionParameters, TxCreationKeys,
};

use crate::tx::script::{
    get_to_countersignatory_with_anchors_redeemscript, ANCHOR_OUTPUT_VALUE_SATOSHI,
};

/// The maximum value of an input or output in milli satoshi
pub const MAX_VALUE_MSAT: u64 = 21_000_000_0000_0000_000;

/// The minimum value of the dust limit in satoshis - for p2wsh outputs
/// (such as anchors)
// FIXME - this is copied from `lightning::ln::channel, lobby to increase visibility.
pub const MIN_DUST_LIMIT_SATOSHIS: u64 = 330;
/// The minimum value of the dust limit in satoshis - for segwit in general
/// This is also the minimum negotiated dust limit
// FIXME - this is copied from `lightning::ln::channel, lobby to increase visibility.
pub const MIN_CHAN_DUST_LIMIT_SATOSHIS: u64 = 354;

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
    // NOTE related to issue 165 - we use 72 here because we might as well assume low-S
    // for the signature, and some node implementations use that.
    // However, nodes may use 73 to be consistent with BOLT-3.
    // That's OK because we will be more lenient on the fee.
    const EXPECTED_MUTUAL_CLOSE_WITNESS_WEIGHT: usize = //
        2 + 1 + 4 + // witness-marker-and-flag witness-element-count 4-element-lengths
        72 + 72 + // <signature_for_pubkey1> <signature_for_pubkey2>
        1 + 1 + 33 + 1 + 33 + 1 + 1; // 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG
    unsigned_tx.weight().to_wu() as usize + EXPECTED_MUTUAL_CLOSE_WITNESS_WEIGHT
}

/// Possibly adds a change output to the given transaction, always doing so if there are excess
/// funds available beyond the requested feerate.
/// Assumes at least one input will have a witness (ie spends a segwit output).
/// Returns an Err(()) if the requested feerate cannot be met.
pub fn maybe_add_change_output(
    tx: &mut Transaction,
    input_value: u64,
    witness_max_weight: u64,
    feerate_sat_per_1000_weight: u32,
    change_destination_script: ScriptBuf,
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
        tx.weight().to_wu() as i64 + 2 + witness_max_weight as i64 + change_len as i64 * 4;
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
        - (tx.weight().to_wu() as i64 + 2 + witness_max_weight as i64)
            * feerate_sat_per_1000_weight as i64
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

pub(crate) fn add_holder_sig(
    tx: &mut Transaction,
    holder_sig: Signature,
    counterparty_sig: Signature,
    holder_funding_key: &PublicKey,
    counterparty_funding_key: &PublicKey,
) {
    let funding_redeemscript =
        make_funding_redeemscript(&holder_funding_key, &counterparty_funding_key);

    tx.input[0].witness.push(Vec::new());
    let mut ser_holder_sig = holder_sig.serialize_der().to_vec();
    ser_holder_sig.push(EcdsaSighashType::All as u8);
    let mut ser_cp_sig = counterparty_sig.serialize_der().to_vec();
    ser_cp_sig.push(EcdsaSighashType::All as u8);

    let holder_sig_first =
        holder_funding_key.serialize()[..] < counterparty_funding_key.serialize()[..];

    if holder_sig_first {
        tx.input[0].witness.push(ser_holder_sig);
        tx.input[0].witness.push(ser_cp_sig);
    } else {
        tx.input[0].witness.push(ser_cp_sig);
        tx.input[0].witness.push(ser_holder_sig);
    }

    tx.input[0].witness.push(funding_redeemscript.as_bytes().to_vec());
}

pub(crate) fn is_tx_non_malleable(tx: &Transaction, segwit_flags: &[bool]) -> bool {
    assert_eq!(tx.input.len(), segwit_flags.len(), "tx and segwit_flags must have same length");
    segwit_flags.iter().all(|flag| *flag)
}

/// Decode a commitment transaction and return the outputs that we need to watch.
/// Our main output index and any HTLC output indexes are returned.
///
/// `cp_per_commitment_point` is filled in if known, otherwise None.  It might
/// not be known if the signer is old, before we started collecting counterparty secrets.
/// If it is None, then we won't be able to tell the difference between a counterparty
/// to-self output and an HTLC output.
pub fn decode_commitment_tx(
    tx: &Transaction,
    holder_per_commitment_point: &PublicKey,
    cp_per_commitment_point: &Option<PublicKey>,
    params: &ChannelTransactionParameters,
    secp_ctx: &Secp256k1<All>,
) -> (Option<u32>, Vec<u32>) {
    let cp_params = params.counterparty_parameters.as_ref().unwrap();

    let opt_anchors = params.channel_type_features.supports_anchors_nonzero_fee_htlc_tx()
        || params.channel_type_features.supports_anchors_zero_fee_htlc_tx();
    let holder_pubkeys = &params.holder_pubkeys;
    let cp_pubkeys = &cp_params.pubkeys;

    let holder_non_delayed_script = if opt_anchors {
        get_to_countersignatory_with_anchors_redeemscript(&holder_pubkeys.payment_point)
            .to_v0_p2wsh()
    } else {
        Payload::p2wpkh(&BitcoinPublicKey::new(holder_pubkeys.payment_point))
            .unwrap()
            .script_pubkey()
    };

    // compute the transaction keys we would have used if this is a holder commitment
    let holder_tx_keys = TxCreationKeys::derive_new(
        secp_ctx,
        &holder_per_commitment_point,
        &holder_pubkeys.delayed_payment_basepoint,
        &holder_pubkeys.htlc_basepoint,
        &cp_pubkeys.revocation_basepoint,
        &cp_pubkeys.htlc_basepoint,
    );

    let holder_delayed_redeem_script = get_revokeable_redeemscript(
        &holder_tx_keys.revocation_key,
        cp_params.selected_contest_delay,
        &holder_tx_keys.broadcaster_delayed_payment_key,
    );

    let holder_delayed_script = holder_delayed_redeem_script.to_v0_p2wsh();

    let cp_delayed_script = if let Some(cp_per_commitment_point) = cp_per_commitment_point {
        // compute the transaction keys we would have used if this is a holder commitment
        let cp_tx_keys = TxCreationKeys::derive_new(
            secp_ctx,
            &cp_per_commitment_point,
            &cp_pubkeys.delayed_payment_basepoint,
            &cp_pubkeys.htlc_basepoint,
            &holder_pubkeys.revocation_basepoint,
            &holder_pubkeys.htlc_basepoint,
        );

        let cp_delayed_redeem_script = get_revokeable_redeemscript(
            &cp_tx_keys.revocation_key,
            params.holder_selected_contest_delay,
            &cp_tx_keys.broadcaster_delayed_payment_key,
        );

        Some(cp_delayed_redeem_script.to_v0_p2wsh())
    } else {
        None
    };

    let mut htlcs = Vec::new();
    let mut main_output_index = None;

    // find the output that pays to us, if any
    for (idx, output) in tx.output.iter().enumerate() {
        // we don't track anchors
        if output.value == ANCHOR_OUTPUT_VALUE_SATOSHI {
            continue;
        }

        if Some(&output.script_pubkey) == cp_delayed_script.as_ref() {
            continue;
        }

        // look for our main output, either when broadcast by us or by our counterparty
        if output.script_pubkey == holder_non_delayed_script
            || output.script_pubkey == holder_delayed_script
        {
            main_output_index = Some(idx as u32);
        } else if output.script_pubkey.is_v0_p2wsh() {
            htlcs.push(idx as u32);
        }
    }

    (main_output_index, htlcs)
}

/// Decode a commitment transaction and return the commitment number if it is a commitment tx
pub fn decode_commitment_number(
    tx: &Transaction,
    params: &ChannelTransactionParameters,
) -> Option<u64> {
    let holder_pubkeys = &params.holder_pubkeys;
    let cp_params = params.counterparty_parameters.as_ref().unwrap();
    let cp_pubkeys = &cp_params.pubkeys;

    let obscure_factor = get_commitment_transaction_number_obscure_factor(
        &holder_pubkeys.payment_point,
        &cp_pubkeys.payment_point,
        params.is_outbound_from_holder,
    );

    // if the tx has more than one input, it's not a standard closing tx,
    // so we bail
    if tx.input.len() != 1 {
        return None;
    }

    // check if the input sequence and locktime are set to standard commitment tx values
    if (tx.input[0].sequence.0 >> 8 * 3) as u8 != 0x80
        || (tx.lock_time.to_consensus_u32() >> 8 * 3) as u8 != 0x20
    {
        return None;
    }

    // forward counting
    let commitment_number = (((tx.input[0].sequence.0 as u64 & 0xffffff) << 3 * 8)
        | (tx.lock_time.to_consensus_u32() as u64 & 0xffffff))
        ^ obscure_factor;
    Some(commitment_number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelBase;
    use crate::util::test_utils::{
        init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
    };
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::Transaction;
    use lightning::ln::chan_utils::{htlc_success_tx_weight, htlc_timeout_tx_weight};
    use lightning::ln::features::ChannelTypeFeatures;

    #[test]
    fn test_parse_closing_tx_holder() {
        let secp_ctx = Secp256k1::new();
        let commitment_number = 0;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[0], make_test_channel_setup());
        let params = node
            .with_channel(&channel_id, |channel| Ok(channel.make_channel_parameters()))
            .unwrap();

        let (holder_commitment, per_commitment_point) = node
            .with_channel(&channel_id, |channel| {
                let per_commitment_point =
                    channel.get_per_commitment_point(commitment_number).unwrap();
                let keys = channel.make_holder_tx_keys(&per_commitment_point).unwrap();
                let per_commitment_point = channel.get_per_commitment_point(commitment_number)?;
                Ok((
                    channel.make_holder_commitment_tx(
                        commitment_number,
                        &keys,
                        123,
                        1000,
                        100,
                        Vec::new(),
                    ),
                    per_commitment_point,
                ))
            })
            .unwrap();
        let holder_tx = holder_commitment.trust().built_transaction().transaction.clone();
        let parsed_commitment_number = decode_commitment_number(&holder_tx, &params).unwrap();
        assert_eq!(parsed_commitment_number, commitment_number);
        let (parsed_main, htlcs) =
            decode_commitment_tx(&holder_tx, &per_commitment_point, &None, &params, &secp_ctx);
        let our_main =
            holder_tx.output.iter().position(|txout| txout.script_pubkey.is_v0_p2wsh()).unwrap();
        assert_eq!(parsed_main, Some(our_main as u32));
        assert!(htlcs.is_empty());
    }

    #[test]
    fn test_parse_closing_tx_counterparty() {
        let secp_ctx = Secp256k1::new();
        let commitment_number = 0;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[0], make_test_channel_setup());
        let params = node
            .with_channel(&channel_id, |channel| Ok(channel.make_channel_parameters()))
            .unwrap();

        let cp_per_commitment_secret = SecretKey::from_slice(&[2; 32]).unwrap();
        let cp_per_commitment_point =
            PublicKey::from_secret_key(&secp_ctx, &cp_per_commitment_secret);
        let (cp_commitment, holder_per_commitment_point) = node
            .with_channel(&channel_id, |channel| {
                // this is not used in the test because we are parsing a counterparty commitment,
                // but we need to set it to something different than the counterparty one
                let holder_per_commitment_point =
                    channel.get_per_commitment_point(commitment_number)?;
                Ok((
                    channel.make_counterparty_commitment_tx(
                        &cp_per_commitment_point,
                        commitment_number,
                        123,
                        1000,
                        100,
                        Vec::new(),
                    ),
                    holder_per_commitment_point,
                ))
            })
            .unwrap();
        let cp_tx = cp_commitment.trust().built_transaction().transaction.clone();
        let parsed_commit_number = decode_commitment_number(&cp_tx, &params).unwrap();
        assert_eq!(parsed_commit_number, commitment_number);
        let (parsed_main, htlcs) = decode_commitment_tx(
            &cp_tx,
            &holder_per_commitment_point,
            &Some(cp_per_commitment_point),
            &params,
            &secp_ctx,
        );
        let our_main =
            cp_tx.output.iter().position(|txout| txout.script_pubkey.is_v0_p2wpkh()).unwrap();
        assert_eq!(parsed_main, Some(our_main as u32));
        println!("htlcs: {:?}", htlcs);
        assert!(htlcs.is_empty());
    }

    #[test]
    fn test_estimate_feerate() {
        let non_anchor_features = ChannelTypeFeatures::empty();
        let mut anchor_features = ChannelTypeFeatures::empty();
        anchor_features.set_anchors_zero_fee_htlc_tx_optional();
        let weights = vec![
            htlc_timeout_tx_weight(&non_anchor_features),
            htlc_timeout_tx_weight(&anchor_features),
            htlc_success_tx_weight(&non_anchor_features),
            htlc_success_tx_weight(&anchor_features),
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

    #[test]
    fn test_issue_165() {
        let tx: Transaction = deserialize(&Vec::from_hex("0200000001b78e0523c17f8ac709eec54654cc849529c05584bfda6e04c92a3b670476f2a20000000000ffffffff017d4417000000000016001476168b09afc66bd3956efb25cd8b83650bda0c5f00000000").unwrap()).unwrap();
        let tx_weight = tx.weight();
        let spk = tx.output[0].script_pubkey.len();
        let weight = super::mutual_close_tx_weight(&tx);
        let fee = 1524999 - tx.output[0].value;
        let estimated_feerate = super::estimate_feerate_per_kw(fee, weight as u64);
        let expected_tx_weight = (4 +                                           // version
            1 +                                           // input count
            36 +                                          // prevout
            1 +                                           // script length (0)
            4 +                                           // sequence
            1 +                                           // output count
            4                                             // lock time
        )*4 +                                         // * 4 for non-witness parts
            ((8+1) +                            // output values and script length
                spk as u64) * 4; // scriptpubkey and witness multiplier
        assert_eq!(expected_tx_weight, tx_weight.to_wu());
        // CLN was actually missing the pubkey length byte, so the feerate is genuinely too low
        assert_eq!(estimated_feerate, 252);
    }
}
