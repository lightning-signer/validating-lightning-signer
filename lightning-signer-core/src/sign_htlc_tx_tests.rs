#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::{self, Transaction};
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_htlc_redeemscript, get_revokeable_redeemscript,
        ChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use test_env_log::test;

    use crate::channel::{ChannelBase, ChannelSetup, CommitmentType};
    use crate::policy::validator::ChainState;
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

        let sig = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    n,
                    None,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sig, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);

        let sig1 = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    999,
                    Some(per_commitment_point),
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sig1, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);
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
        commitment_type: CommitmentType,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

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

        let expected_txid = if commitment_type == CommitmentType::StaticRemoteKey {
            if is_offered {
                "66a108d7722fdb160206ba075a49c03c9e0174421c0c845cddd4a5b931fa5ab5"
            } else {
                "a052c48d7cba8eb1107d72b15741292267d4f4af754a7136168de50d4359b714"
            }
        } else {
            if is_offered {
                "81688eca802d9676c24ed8ec444fd5f47991d44f18d8096cede1915ce4a907cb"
            } else {
                "944edd4d2bdc576a9275a920c61c720c7487e8a908d05a7381216047d762c281"
            }
        };
        assert_eq!(htlc_tx.txid().to_hex(), expected_txid);

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &remote_per_commitment_point);

        check_counterparty_htlc_signature(
            &htlc_tx,
            0,
            typedsig,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
            setup.option_anchor_outputs(),
        );

        Ok(())
    }

    fn sign_holder_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        commitment_type: CommitmentType,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

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

        let expected_txid = if commitment_type == CommitmentType::StaticRemoteKey {
            if is_offered {
                "783ca2bb360dc712301d43daef0dbae2e15a8f06dcc73062b24e1d86cb918e5c"
            } else {
                "89cf05ddaef231827291e32cc67d17810b867614bbb8e1a39c001f62f57421ab"
            }
        } else {
            if is_offered {
                "f108967616fc7d97c672d66c4885bcf02a78eabd5c38239ce548922cdb16bbe0"
            } else {
                "41c6974ee15c8c5de8f23c64942061a0dad581442218afff28fb84ddce713866"
            }
        };
        assert_eq!(htlc_tx.txid().to_hex(), expected_txid);

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        check_signature(&htlc_tx, 0, typedsig, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);

        Ok(())
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_anchors>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_anchors>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_anchors>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_anchors>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm)
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
    const ERR_MSG_CONTEXT_HOLDER_RECEIVED_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_counterparty: false, is_offered: false, opt_anchors: true };
    const ERR_MSG_CONTEXT_HOLDER_OFFERED_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_counterparty: false, is_offered: true, opt_anchors: true };
    const ERR_MSG_CONTEXT_CPARTY_RECEIVED_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_counterparty: true, is_offered: false, opt_anchors: true };
    const ERR_MSG_CONTEXT_CPARTY_OFFERED_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_counterparty: true, is_offered: true, opt_anchors: true };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_ANCHORS)
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
        |tms| tms.tx.output[0].value = 999_800, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                format!(
                    "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is smaller than the minimum of 500",
                    if ectx.opt_anchors { 301 } else { 302 }
                )
            } else {
                format!(
                    "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is smaller than the minimum of 500",
                    if ectx.opt_anchors { 284 } else { 285 }
                )
            }
        }
    );

    // policy-htlc-fee-range
    generate_failed_precondition_error_with_mutated_tx!(
        high_feerate,
        |tms| tms.tx.output[0].value = 980_000, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                format!(
                    "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is larger than the maximum of 16000",
                    if ectx.opt_anchors { 30031 } else { 30166 }
                )
            } else {
                format!(
                    "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is larger than the maximum of 16000",
                    if ectx.opt_anchors { 28329 } else { 28450 }
                )
            }
        }
    );
}
