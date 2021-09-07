#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{self, Transaction};
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_htlc_redeemscript, get_revokeable_redeemscript,
        ChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use test_env_log::test;

    use crate::channel::{ChannelBase, ChannelSetup, CommitmentType};
    use crate::util::crypto_utils::{
        derive_public_key, derive_revocation_pubkey, signature_to_bitcoin_vec,
    };
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn sign_local_htlc_tx_static_test() {
        let setup = make_test_channel_setup();
        sign_local_htlc_tx_test(&setup);
    }

    #[test]
    fn sign_local_htlc_tx_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_local_htlc_tx_test(&setup);
    }

    fn sign_local_htlc_tx_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let htlc_amount_sat = 10 * 1000;

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: htlc_amount_sat * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let n: u64 = 1;

        let (per_commitment_point, txkeys, to_self_delay) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(n);
                let per_commitment_point = chan.get_per_commitment_point(n).expect("point");
                let txkeys = chan
                    .make_holder_tx_keys(&per_commitment_point)
                    .expect("failed to make txkeys");
                let to_self_delay = chan
                    .make_channel_parameters()
                    .as_holder_broadcastable()
                    .contest_delay();
                Ok((per_commitment_point, txkeys, to_self_delay))
            })
            .expect("point");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &txkeys.broadcaster_delayed_payment_key,
            &txkeys.revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &txkeys);

        let output_witscript = get_revokeable_redeemscript(
            &txkeys.revocation_key,
            to_self_delay,
            &txkeys.broadcaster_delayed_payment_key,
        );

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        let sigvec = node
            .with_ready_channel(&channel_id, |chan| {
                let sig = chan
                    .sign_holder_htlc_tx(
                        &htlc_tx,
                        n,
                        None,
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            })
            .unwrap();

        check_signature(
            &htlc_tx,
            0,
            sigvec,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        let sigvec1 = node
            .with_ready_channel(&channel_id, |chan| {
                let sig = chan
                    .sign_holder_htlc_tx(
                        &htlc_tx,
                        999,
                        Some(per_commitment_point),
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            })
            .unwrap();

        check_signature(
            &htlc_tx,
            0,
            sigvec1,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );
    }

    fn sign_counterparty_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChannelTransactionParameters),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut Transaction),
    {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let remote_per_commitment_point = make_test_pubkey(10);
        let htlc_amount_sat = 1_000_000;

        let (sig, htlc_tx, htlc_redeemscript) = node.with_ready_channel(&channel_id, |chan| {
            let mut channel_parameters = chan.make_channel_parameters();

            // Mutate the channel parameters
            chanparammut(&mut channel_parameters);

            let mut keys = chan.make_counterparty_tx_keys(&remote_per_commitment_point)?;

            // Mutate the tx creation keys.
            keysmut(&mut keys);

            let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
            let feerate_per_kw = 1000;
            let to_self_delay = channel_parameters
                .as_counterparty_broadcastable()
                .contest_delay();

            let htlc = HTLCOutputInCommitment {
                offered: is_offered,
                amount_msat: htlc_amount_sat * 1000,
                cltv_expiry: if is_offered { 2 << 16 } else { 0 },
                payment_hash: PaymentHash([1; 32]),
                transaction_output_index: Some(0),
            };

            let mut htlc_tx = build_htlc_transaction(
                &commitment_txid,
                feerate_per_kw,
                to_self_delay,
                &htlc,
                &keys.broadcaster_delayed_payment_key,
                &keys.revocation_key,
            );

            // Mutate the transaction.
            txmut(&mut htlc_tx);

            let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

            let output_witscript = get_revokeable_redeemscript(
                &keys.revocation_key,
                to_self_delay,
                &keys.broadcaster_delayed_payment_key,
            );

            let sig = chan.sign_counterparty_htlc_tx(
                &htlc_tx,
                &remote_per_commitment_point,
                &htlc_redeemscript,
                htlc_amount_sat,
                &output_witscript,
            )?;
            Ok((sig, htlc_tx, htlc_redeemscript))
        })?;

        if is_offered {
            assert_eq!(
                htlc_tx.txid().to_hex(),
                "66a108d7722fdb160206ba075a49c03c9e0174421c0c845cddd4a5b931fa5ab5"
            );
        } else {
            assert_eq!(
                htlc_tx.txid().to_hex(),
                "a052c48d7cba8eb1107d72b15741292267d4f4af754a7136168de50d4359b714"
            );
        }

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &remote_per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            signature_to_bitcoin_vec(sig),
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        Ok(())
    }

    fn sign_holder_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChannelTransactionParameters),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut Transaction),
    {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let commit_num = 23;
        let htlc_amount_sat = 1_000_000;

        let (sig, per_commitment_point, htlc_tx, htlc_redeemscript) =
            node.with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(commit_num);
                let mut channel_parameters = chan.make_channel_parameters();

                // Mutate the channel parameters
                chanparammut(&mut channel_parameters);

                let per_commitment_point =
                    chan.get_per_commitment_point(commit_num).expect("point");
                let mut keys = chan.make_holder_tx_keys(&per_commitment_point)?;

                // Mutate the tx creation keys.
                keysmut(&mut keys);

                let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
                let feerate_per_kw = 1000;
                let to_self_delay = channel_parameters.as_holder_broadcastable().contest_delay();

                let htlc = HTLCOutputInCommitment {
                    offered: is_offered,
                    amount_msat: htlc_amount_sat * 1000,
                    cltv_expiry: if is_offered { 2 << 16 } else { 0 },
                    payment_hash: PaymentHash([1; 32]),
                    transaction_output_index: Some(0),
                };

                let mut htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    feerate_per_kw,
                    to_self_delay,
                    &htlc,
                    &keys.broadcaster_delayed_payment_key,
                    &keys.revocation_key,
                );

                // Mutate the transaction.
                txmut(&mut htlc_tx);

                let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

                let output_witscript = get_revokeable_redeemscript(
                    &keys.revocation_key,
                    to_self_delay,
                    &keys.broadcaster_delayed_payment_key,
                );

                let sig = chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    commit_num,
                    Some(per_commitment_point),
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok((sig, per_commitment_point, htlc_tx, htlc_redeemscript))
            })?;

        if is_offered {
            assert_eq!(
                htlc_tx.txid().to_hex(),
                "783ca2bb360dc712301d43daef0dbae2e15a8f06dcc73062b24e1d86cb918e5c"
            );
        } else {
            assert_eq!(
                htlc_tx.txid().to_hex(),
                "89cf05ddaef231827291e32cc67d17810b867614bbb8e1a39c001f62f57421ab"
            );
        }

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            signature_to_bitcoin_vec(sig),
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        Ok(())
    }

    macro_rules! sign_counterparty_offered_htlc_tx_with_mutators {
        ($pm: expr, $km: expr, $tm: expr) => {
            sign_counterparty_htlc_tx_with_mutators(true, $pm, $km, $tm)
        };
    }

    macro_rules! sign_counterparty_received_htlc_tx_with_mutators {
        ($pm: expr, $km: expr, $tm: expr) => {
            sign_counterparty_htlc_tx_with_mutators(false, $pm, $km, $tm)
        };
    }

    macro_rules! sign_holder_offered_htlc_tx_with_mutators {
        ($pm: expr, $km: expr, $tm: expr) => {
            sign_holder_htlc_tx_with_mutators(true, $pm, $km, $tm)
        };
    }

    macro_rules! sign_holder_received_htlc_tx_with_mutators {
        ($pm: expr, $km: expr, $tm: expr) => {
            sign_holder_htlc_tx_with_mutators(false, $pm, $km, $tm)
        };
    }

    #[test]
    fn sign_counterparty_offered_htlc_tx_with_no_mut_test() {
        let status = sign_counterparty_offered_htlc_tx_with_mutators!(
            |_param| {
                // don't mutate the channel parameters, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tx| {
                // don't mutate the tx, should pass
            }
        );
        assert!(status.is_ok());
    }

    #[test]
    fn sign_counterparty_received_htlc_tx_with_no_mut_test() {
        let status = sign_counterparty_received_htlc_tx_with_mutators!(
            |_param| {
                // don't mutate the channel parameters, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tx| {
                // don't mutate the tx, should pass
            }
        );
        assert!(status.is_ok());
    }

    #[test]
    fn sign_holder_offered_htlc_tx_with_no_mut_test() {
        let status = sign_holder_offered_htlc_tx_with_mutators!(
            |_param| {
                // don't mutate the channel parameters, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tx| {
                // don't mutate the tx, should pass
            }
        );
        assert!(status.is_ok());
    }

    #[test]
    fn sign_holder_received_htlc_tx_with_no_mut_test() {
        let status = sign_holder_received_htlc_tx_with_mutators!(
            |_param| {
                // don't mutate the channel parameters, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tx| {
                // don't mutate the tx, should pass
            }
        );
        assert!(status.is_ok());
    }

    // policy-htlc-version
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_version_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.version = 3 // only version 2 allowed
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-version
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_version_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.version = 3 // only version 2 allowed
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-version
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_version_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.version = 3 // only version 2 allowed
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-version
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_version_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.version = 3 // only version 2 allowed
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-locktime
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_locktime_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.lock_time = 0 // offered must have non-zero locktime
            ),
            "policy failure: validate_htlc_tx: offered lock_time must be non-zero"
        );
    }

    // policy-htlc-locktime
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_locktime_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.lock_time = 42 // received must have zero locktime
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-locktime
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_locktime_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.lock_time = 0 // offered must have non-zero locktime
            ),
            "policy failure: validate_htlc_tx: offered lock_time must be non-zero"
        );
    }

    // policy-htlc-locktime
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_locktime_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.lock_time = 42 // received must have zero locktime
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-sequence
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_sequence_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.input[0].sequence = 42 // sequence must be per BOLT#3
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-sequence
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_sequence_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.input[0].sequence = 42 // sequence must be per BOLT#3
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-sequence
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_sequence_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.input[0].sequence = 42 // sequence must be per BOLT#3
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-sequence
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_sequence_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.input[0].sequence = 42 // sequence must be per BOLT#3
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-to-self-delay
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_to_self_delay_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |param| param.holder_selected_contest_delay = 42,
                |_keys| {},
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-to-self-delay
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_to_self_delay_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |param| param.holder_selected_contest_delay = 42,
                |_keys| {},
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-to-self-delay
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_to_self_delay_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |param| {
                    let mut cptp = param.counterparty_parameters.as_ref().unwrap().clone();
                    cptp.selected_contest_delay = 42;
                    param.counterparty_parameters = Some(cptp);
                },
                |_keys| {},
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-to-self-delay
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_to_self_delay_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |param| {
                    let mut cptp = param.counterparty_parameters.as_ref().unwrap().clone();
                    cptp.selected_contest_delay = 42;
                    param.counterparty_parameters = Some(cptp);
                },
                |_keys| {},
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-revocation-pubkey
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_revpubkey_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.revocation_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-revocation-pubkey
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_revpubkey_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.revocation_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-revocation-pubkey
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_revpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.revocation_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-revocation-pubkey
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_revpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.revocation_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-delayed-pubkey
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_bad_delayedpubkey_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-delayed-pubkey
    #[test]
    fn sign_counterparty_received_htlc_tx_with_bad_delayedpubkey_test() {
        assert_failed_precondition_err!(
            sign_counterparty_received_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-delayed-pubkey
    #[test]
    fn sign_holder_offered_htlc_tx_with_bad_delayedpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_offered_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-delayed-pubkey
    #[test]
    fn sign_holder_received_htlc_tx_with_bad_delayedpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |keys| keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
                |_tx| {}
            ),
            "policy failure: sighash mismatch"
        );
    }

    // policy-htlc-fee-range
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_low_feerate_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.output[0].value = 999_900 // htlc_amount_sat is 1_000_000
            ),
            "policy failure: validate_htlc_tx: \
             feerate_per_kw of 151 is smaller than the minimum of 500"
        );
    }

    // policy-htlc-fee-range
    #[test]
    fn sign_counterparty_offered_htlc_tx_with_high_feerate_test() {
        assert_failed_precondition_err!(
            sign_counterparty_offered_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.output[0].value = 980_000 // htlc_amount_sat is 1_000_000
            ),
            "policy failure: validate_htlc_tx: \
             feerate_per_kw of 30166 is larger than the maximum of 16000"
        );
    }

    // policy-htlc-fee-range
    #[test]
    fn sign_holder_received_htlc_tx_with_low_feerate_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.output[0].value = 999_900 // htlc_amount_sat is 1_000_000
            ),
            "policy failure: validate_htlc_tx: \
             feerate_per_kw of 143 is smaller than the minimum of 500"
        );
    }

    // policy-htlc-fee-range
    #[test]
    fn sign_holder_received_htlc_tx_with_high_feerate_test() {
        assert_failed_precondition_err!(
            sign_holder_received_htlc_tx_with_mutators!(
                |_param| {},
                |_keys| {},
                |tx| tx.output[0].value = 980_000 // htlc_amount_sat is 1_000_000
            ),
            "policy failure: validate_htlc_tx: \
             feerate_per_kw of 28450 is larger than the maximum of 16000"
        );
    }

    #[test]
    #[ignore] // we don't support anchors yet
    fn sign_remote_htlc_tx_with_anchors_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let htlc_amount_sat = 10 * 1000;

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: htlc_amount_sat * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::derive_new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_revocation_pubkey(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let output_witscript =
            get_revokeable_redeemscript(&revocation_key, to_self_delay, &a_delayed_payment_key);

        let ser_signature = node
            .with_ready_channel(&channel_id, |chan| {
                let sig = chan
                    .sign_counterparty_htlc_tx(
                        &htlc_tx,
                        &remote_per_commitment_point,
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(signature_to_bitcoin_vec(sig))
            })
            .unwrap();

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &remote_per_commitment_point);

        check_signature_with_setup(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
            &setup,
        );
    }
}
