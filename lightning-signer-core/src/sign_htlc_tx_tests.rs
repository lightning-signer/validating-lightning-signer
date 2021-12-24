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
    use crate::policy::validator::ChainState;
    use crate::util::crypto_utils::{derive_public_key, derive_revocation_pubkey};
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    use paste::paste;

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
                chan.enforcement_state.set_next_holder_commit_num_for_testing(n);
                let per_commitment_point = chan.get_per_commitment_point(n).expect("point");
                let txkeys =
                    chan.make_holder_tx_keys(&per_commitment_point).expect("failed to make txkeys");
                let to_self_delay =
                    chan.make_channel_parameters().as_holder_broadcastable().contest_delay();
                Ok((per_commitment_point, txkeys, to_self_delay))
            })
            .expect("point");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            setup.option_anchor_outputs(),
            &txkeys.broadcaster_delayed_payment_key,
            &txkeys.revocation_key,
        );

        let htlc_redeemscript =
            get_htlc_redeemscript(&htlc, setup.option_anchor_outputs(), &txkeys);

        let output_witscript = get_revokeable_redeemscript(
            &txkeys.revocation_key,
            to_self_delay,
            &txkeys.broadcaster_delayed_payment_key,
        );

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        let sigvec = node
            .with_ready_channel(&channel_id, |chan| {
                let typedsig = chan
                    .sign_holder_htlc_tx(
                        &htlc_tx,
                        n,
                        None,
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(typedsig.serialize())
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sigvec, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);

        let sigvec1 = node
            .with_ready_channel(&channel_id, |chan| {
                let typedsig = chan
                    .sign_holder_htlc_tx(
                        &htlc_tx,
                        999,
                        Some(per_commitment_point),
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(typedsig.serialize())
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sigvec1, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);
    }

    #[allow(dead_code)]
    struct ChanParamMutationState<'a> {
        is_counterparty: bool,
        param: &'a mut ChannelTransactionParameters,
    }

    #[allow(dead_code)]
    struct KeysMutationState<'a> {
        keys: &'a mut TxCreationKeys,
    }

    #[allow(dead_code)]
    struct TxMutationState<'a> {
        is_offered: bool,
        cstate: &'a mut ChainState,
        tx: &'a mut Transaction,
    }

    fn sign_counterparty_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let setup = make_test_channel_setup();
        let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup);

        let remote_per_commitment_point = make_test_pubkey(10);
        let htlc_amount_sat = 1_000_000;

        let (typedsig, htlc_tx, htlc_redeemscript) =
            node.with_ready_channel(&channel_id, |chan| {
                let mut channel_parameters = chan.make_channel_parameters();

                // Mutate the channel parameters
                chanparammut(&mut ChanParamMutationState {
                    is_counterparty: true,
                    param: &mut channel_parameters,
                });

                let mut keys = chan.make_counterparty_tx_keys(&remote_per_commitment_point)?;

                // Mutate the tx creation keys.
                keysmut(&mut KeysMutationState { keys: &mut keys });

                let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
                let feerate_per_kw = 1000;
                let to_self_delay =
                    channel_parameters.as_counterparty_broadcastable().contest_delay();

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
                    channel_parameters.opt_anchors.is_some(),
                    &keys.broadcaster_delayed_payment_key,
                    &keys.revocation_key,
                );

                let mut cstate = make_test_chain_state();

                // Mutate the transaction.
                txmut(&mut TxMutationState {
                    is_offered: is_offered,
                    cstate: &mut cstate,
                    tx: &mut htlc_tx,
                });

                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, channel_parameters.opt_anchors.is_some(), &keys);

                let output_witscript = get_revokeable_redeemscript(
                    &keys.revocation_key,
                    to_self_delay,
                    &keys.broadcaster_delayed_payment_key,
                );

                let typedsig = chan.sign_counterparty_htlc_tx(
                    &htlc_tx,
                    &remote_per_commitment_point,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok((typedsig, htlc_tx, htlc_redeemscript))
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
            typedsig.serialize(),
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
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let setup = make_test_channel_setup();
        let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup);

        let commit_num = 23;
        let htlc_amount_sat = 1_000_000;

        let (typedsig, per_commitment_point, htlc_tx, htlc_redeemscript) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);
                let mut channel_parameters = chan.make_channel_parameters();

                // Mutate the channel parameters
                chanparammut(&mut ChanParamMutationState {
                    is_counterparty: false,
                    param: &mut channel_parameters,
                });

                let per_commitment_point =
                    chan.get_per_commitment_point(commit_num).expect("point");
                let mut keys = chan.make_holder_tx_keys(&per_commitment_point)?;

                // Mutate the tx creation keys.
                keysmut(&mut KeysMutationState { keys: &mut keys });

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
                    channel_parameters.opt_anchors.is_some(),
                    &keys.broadcaster_delayed_payment_key,
                    &keys.revocation_key,
                );

                let mut cstate = make_test_chain_state();

                // Mutate the transaction.
                txmut(&mut TxMutationState {
                    is_offered: is_offered,
                    cstate: &mut cstate,
                    tx: &mut htlc_tx,
                });

                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, channel_parameters.opt_anchors.is_some(), &keys);

                let output_witscript = get_revokeable_redeemscript(
                    &keys.revocation_key,
                    to_self_delay,
                    &keys.broadcaster_delayed_payment_key,
                );

                let typedsig = chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    commit_num,
                    Some(per_commitment_point),
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok((typedsig, per_commitment_point, htlc_tx, htlc_redeemscript))
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
            typedsig.serialize(),
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        Ok(())
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, $pm, $km, $tm)
                    );
                }
            }
        };
    }

    generate_status_ok_variations!(success, |_| {}, |_| {}, |_| {});

    #[allow(dead_code)]
    struct ErrMsgContext {
        is_counterparty: bool,
        is_offered: bool,
        opt_anchors: bool,
    }

    const ERR_MSG_CONTEXT_HOLDER_RECEIVED_STATIC: ErrMsgContext =
        ErrMsgContext { is_counterparty: false, is_offered: false, opt_anchors: false };
    const ERR_MSG_CONTEXT_HOLDER_OFFERED_STATIC: ErrMsgContext =
        ErrMsgContext { is_counterparty: false, is_offered: true, opt_anchors: false };
    const ERR_MSG_CONTEXT_CPARTY_RECEIVED_STATIC: ErrMsgContext =
        ErrMsgContext { is_counterparty: true, is_offered: false, opt_anchors: false };
    const ERR_MSG_CONTEXT_CPARTY_OFFERED_STATIC: ErrMsgContext =
        ErrMsgContext { is_counterparty: true, is_offered: true, opt_anchors: false };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_STATIC)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_param {
        ($name: ident, $pm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, $pm, |_| {}, |_| {}, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_keys {
        ($name: ident, $km: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, |_| {}, $km, |_| {}, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_tx {
        ($name: ident, $tm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, |_| {}, |_| {}, $tm, $errmsg);
        };
    }

    // policy-htlc-version
    generate_failed_precondition_error_with_mutated_tx!(
        bad_version,
        |tms| tms.tx.version = 3, // only version 2 allowed
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-locktime
    generate_failed_precondition_error_with_mutated_tx!(
        bad_locktime,
        |tms| {
            // offered must have non-zero, received must have zero
            tms.tx.lock_time = if tms.is_offered { 0 } else { 42 };
        },
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                "policy failure: validate_htlc_tx: offered lock_time must be non-zero"
            } else {
                "policy failure: sighash mismatch"
            }
        }
    );

    // policy-htlc-sequence
    generate_failed_precondition_error_with_mutated_tx!(
        bad_sequence,
        |tms| tms.tx.input[0].sequence = 42, // sequence must be per BOLT#3
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-to-self-delay
    generate_failed_precondition_error_with_mutated_param!(
        bad_to_self_delay,
        |pms| {
            if pms.is_counterparty {
                pms.param.holder_selected_contest_delay = 42;
            } else {
                let mut cptp = pms.param.counterparty_parameters.as_ref().unwrap().clone();
                cptp.selected_contest_delay = 42;
                pms.param.counterparty_parameters = Some(cptp);
            }
        },
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-revocation-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_revpubkey,
        |kms| kms.keys.revocation_key = make_test_pubkey(42),
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-delayed-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_delayedpubkey,
        |kms| kms.keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-fee-range
    generate_failed_precondition_error_with_mutated_tx!(
        low_feerate,
        |tms| tms.tx.output[0].value = 999_900, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                "policy failure: validate_htlc_tx: \
                 feerate_per_kw of 151 is smaller than the minimum of 500"
            } else {
                "policy failure: validate_htlc_tx: \
                 feerate_per_kw of 143 is smaller than the minimum of 500"
            }
        }
    );

    // policy-htlc-fee-range
    generate_failed_precondition_error_with_mutated_tx!(
        high_feerate,
        |tms| tms.tx.output[0].value = 980_000, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                "policy failure: validate_htlc_tx: \
                 feerate_per_kw of 30166 is larger than the maximum of 16000"
            } else {
                "policy failure: validate_htlc_tx: \
                 feerate_per_kw of 28450 is larger than the maximum of 16000"
            }
        }
    );

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
            setup.option_anchor_outputs(),
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, setup.option_anchor_outputs(), &keys);

        let output_witscript =
            get_revokeable_redeemscript(&revocation_key, to_self_delay, &a_delayed_payment_key);

        let ser_signature = node
            .with_ready_channel(&channel_id, |chan| {
                let typedsig = chan
                    .sign_counterparty_htlc_tx(
                        &htlc_tx,
                        &remote_per_commitment_point,
                        &htlc_redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                    .unwrap();
                Ok(typedsig.serialize())
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
