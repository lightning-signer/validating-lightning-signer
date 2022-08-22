#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{self, Transaction};
    use lightning::chain::keysinterface::BaseSign;
    use lightning::ln::chan_utils::TxCreationKeys;
    use lightning::ln::PaymentHash;

    use test_log::test;

    use crate::channel::{Channel, ChannelBase, CommitmentType};
    use crate::policy::error::policy_error;
    use crate::policy::validator::ChainState;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    use paste::paste;

    #[test]
    fn validate_holder_commitment_with_htlcs() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);

        let offered_htlcs = vec![
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([1; 32]),
                cltv_expiry: 1 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([2; 32]),
                cltv_expiry: 2 << 16,
            },
        ];
        let received_htlcs = vec![
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([3; 32]),
                cltv_expiry: 3 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([4; 32]),
                cltv_expiry: 4 << 16,
            },
            HTLCInfo2 {
                value_sat: 10_000,
                payment_hash: PaymentHash([5; 32]),
                cltv_expiry: 5 << 16,
            },
        ];
        let sum_htlc = 50_000;

        let commit_num = 1;
        let feerate_per_kw = 1100;
        let fees = 20_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - sum_htlc - fees;

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");
    }

    // policy-revoke-new-commitment-signed
    #[test]
    fn validate_holder_commitment_with_bad_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let commit_num = 2;
        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        // Force the channel to commit_num 2 to build the bogus commitment ...
        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, commit_num);

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, 1);

        assert_failed_precondition_err!(
            validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs,),
            "policy failure: set_next_holder_commit_num: invalid progression: 1 to 3"
        );
    }

    // policy-commitment-holder-not-revoked
    #[test]
    fn validate_holder_commitment_with_revoked_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        // Start by validating holder commitment #10 (which revokes #9)
        let commit_num = 10;
        set_next_holder_commit_num_for_testing(&node_ctx, &chan_ctx, commit_num);

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs.clone(),
            received_htlcs.clone(),
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let revoked_commit_num = commit_num - 1;

        // Now attempt to holder sign holder commitment #9
        let commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            revoked_commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );

        assert_failed_precondition_err!(
            sign_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 10 != 11"
        );
    }

    #[test]
    fn validate_holder_commitment_with_same_commit_num() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let commit_num = 1;
        let feerate_per_kw = 1100;
        let fees = 10_000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fees;

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_num,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        // You can do it again w/ same commit num.
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");
    }

    const HOLD_COMMIT_NUM: u64 = 43;

    #[allow(dead_code)]
    struct TxBuilderMutationState<'a> {
        commit_tx_ctx: &'a mut TestCommitmentTxContext,
    }

    #[allow(dead_code)]
    struct KeysMutationState<'a> {
        keys: &'a mut TxCreationKeys,
    }

    #[allow(dead_code)]
    struct ValidationMutationState<'a> {
        opt_anchors: bool,
        chan: &'a mut Channel,
        cstate: &'a mut ChainState,
        commit_tx_ctx: &'a mut TestCommitmentTxContext,
        tx: &'a mut Transaction,
        witscripts: &'a mut Vec<Vec<u8>>,
        commit_sig: &'a mut Signature,
        htlc_sigs: &'a mut Vec<Signature>,
    }

    #[allow(dead_code)]
    struct ValidationState<'a> {
        chan: &'a Channel,
    }

    fn validate_holder_commitment_with_mutators_common<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let to_broadcaster = 1_979_997;
        let to_countersignatory = 1_000_000;
        let feerate_per_kw = 1200;
        let htlc1 =
            HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

        let htlc2 =
            HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

        let htlc3 = HTLCInfo2 {
            value_sat: 10_003,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
        };
        let offered_htlcs = vec![htlc1];
        let received_htlcs = vec![htlc2, htlc3];

        let mut commit_tx_ctx0 = TestCommitmentTxContext {
            commit_num: HOLD_COMMIT_NUM,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs: offered_htlcs.clone(),
            received_htlcs: received_htlcs.clone(),
            tx: None,
        };

        mutate_tx_builder(&mut TxBuilderMutationState { commit_tx_ctx: &mut commit_tx_ctx0 });

        commit_tx_ctx0 = channel_commitment(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx0.commit_num,
            commit_tx_ctx0.feerate_per_kw,
            commit_tx_ctx0.to_broadcaster,
            commit_tx_ctx0.to_countersignatory,
            commit_tx_ctx0.offered_htlcs.clone(),
            commit_tx_ctx0.received_htlcs.clone(),
        );

        let (commit_sig0, htlc_sigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx0);

        node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
            let mut commit_tx_ctx = commit_tx_ctx0.clone();
            let mut commit_sig = commit_sig0.clone();
            let mut htlc_sigs = htlc_sigs0.clone();

            let channel_parameters = chan.make_channel_parameters();
            let parameters = channel_parameters.as_holder_broadcastable();
            let per_commitment_point = chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;

            let mut keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

            mutate_keys(&mut KeysMutationState { keys: &mut keys });

            let htlcs = Channel::htlcs_info2_to_oic(
                commit_tx_ctx.offered_htlcs.clone(),
                commit_tx_ctx.received_htlcs.clone(),
            );
            let redeem_scripts = build_tx_scripts(
                &keys,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                &htlcs,
                &parameters,
                &chan.keys.pubkeys().funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
            )
            .expect("scripts");
            let mut output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let mut tx =
                commit_tx_ctx.tx.as_ref().unwrap().trust().built_transaction().transaction.clone();

            let mut cstate = make_test_chain_state();

            mutate_validation_input(&mut ValidationMutationState {
                opt_anchors: commitment_type == CommitmentType::Anchors,
                chan: chan,
                cstate: &mut cstate,
                commit_tx_ctx: &mut commit_tx_ctx,
                tx: &mut tx,
                witscripts: &mut output_witscripts,
                commit_sig: &mut commit_sig,
                htlc_sigs: &mut htlc_sigs,
            });

            // Validate the holder_commitment, but defer error returns till after we've had
            // a chance to validate the channel state for side-effects
            let deferred_rv = chan.validate_holder_commitment_tx(
                &tx,
                &output_witscripts,
                commit_tx_ctx.commit_num,
                commit_tx_ctx.feerate_per_kw,
                commit_tx_ctx.offered_htlcs.clone(),
                commit_tx_ctx.received_htlcs.clone(),
                &commit_sig,
                &htlc_sigs,
            );
            validate_channel_state(&ValidationState { chan });
            deferred_rv?;
            Ok(())
        })
    }

    fn validate_holder_commitment_with_mutators<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node_ctx, chan_ctx) = setup_funded_channel_with_setup(
            setup,
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    fn validate_holder_commitment_retry_with_mutators<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        commitment_type: CommitmentType,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TxBuilderMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        ValidationMutator: Fn(&mut ValidationMutationState),
        ChannelStateValidator: Fn(&ValidationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node_ctx, chan_ctx) = setup_funded_channel_with_setup(
            setup,
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        // Start with successful validation w/o mutations
        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            |_tms| {},
            |_kms| {},
            |_vms| {},
            |vs| {
                // Channel state should advance.
                assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            },
        )?;

        // Retry with mutations
        validate_holder_commitment_with_mutators_common(
            commitment_type,
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_status_ok!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_status_ok!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::Anchors, $tms, $kms, $vms, $vs)
                    );
                }
            }
        };
    }

    macro_rules! generate_status_ok_retry_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_status_ok!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_status_ok!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::Anchors, $tms, $kms, $vms, $vs)
                    );
                }
            }
        };
    }

    #[allow(dead_code)]
    struct ErrMsgContext {
        opt_anchors: bool,
    }

    const ERR_MSG_CONTEXT_STATIC: ErrMsgContext = ErrMsgContext { opt_anchors: false };
    const ERR_MSG_CONTEXT_ANCHORS: ErrMsgContext = ErrMsgContext { opt_anchors: true };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_with_mutators(
                            CommitmentType::Anchors, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_retry_variations {
        ($name: ident, $tms: expr, $kms: expr, $vms: expr, $vs: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _anchors>]() {
                    assert_failed_precondition_err!(
                        validate_holder_commitment_retry_with_mutators(
                            CommitmentType::Anchors, $tms, $kms, $vms, $vs),
                        ($errcls)(ERR_MSG_CONTEXT_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_retry_with_mutated_tx {
        ($name: ident, $tms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_retry_variations!(
                $name,
                $tms,
                |_| {},
                |_| {},
                $vs,
                $errmsg
            );
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_keys {
        ($name: ident, $kms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!(
                $name,
                |_| {},
                $kms,
                |_| {},
                $vs,
                $errmsg
            );
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_validation_input {
        ($name: ident, $vms: expr, $vs: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!(
                $name,
                |_| {},
                |_| {},
                $vms,
                $vs,
                $errmsg
            );
        };
    }

    generate_status_ok_variations!(success, |_tms| {}, |_kms| {}, |_vms| {}, |vs| {
        // Channel state should advance.
        assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
    });

    // policy-commitment-retry-same
    generate_status_ok_retry_variations!(can_retry, |_tms| {}, |_kms| {}, |_vms| {}, |vs| {
        // Channel state should advance.
        assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
    });

    // policy-revoke-not-closed
    // It's ok to retry a validate_holder_commitment after it has been signed.
    generate_status_ok_retry_variations!(
        can_retry_after_signed,
        |_tms| {},
        |_kms| {},
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should stay advanced
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        }
    );

    // policy-revoke-not-closed
    // It's not ok to advance after a prior has been signed
    generate_failed_precondition_error_with_mutated_validation_input!(
        not_after_signed,
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: channel is closing"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_to_holder,
        |tms| {
            tms.commit_tx_ctx.to_broadcaster -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_to_counterparty,
        |tms| {
            tms.commit_tx_ctx.to_countersignatory -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_offered_htlc,
        |tms| {
            tms.commit_tx_ctx.offered_htlcs[0].value_sat -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutated_tx!(
        bad_received_htlc,
        |tms| {
            tms.commit_tx_ctx.received_htlcs[0].value_sat -= 1;
        },
        |vs| {
            // Channel state should stay where we advanced it initially.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_commit_sig,
        |vms| {
            *vms.commit_sig = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: commit sig verify failed: signature failed verification"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_htlc_sig,
        |vms| {
            vms.htlc_sigs[0] = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: \
             commit sig verify failed for htlc 0: signature failed verification"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        not_ahead,
        |vms| {
            // Set the channel's next_holder_commit_num ahead two, past the retry ...
            vms.chan.enforcement_state.set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM + 2);
        },
        |vs| {
            // Channel state should stay where we advanced it.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 2);
        },
        |_| "policy failure: validate_holder_commitment_tx: \
             can't sign revoked commitment_number 43, next_holder_commit_num is 45"
    );

    generate_failed_precondition_error_with_mutated_validation_input!(
        not_behind,
        |vms| {
            // Set the channel's next_holder_commit_num ahead two behind 1, in the past ...
            vms.chan.enforcement_state.set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM - 1);
        },
        |vs| {
            // Channel state should stay where we set it.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM - 1);
        },
        |_| "policy failure: set_next_holder_commit_num: invalid progression: 42 to 44"
    );

    // policy-revoke-not-closed
    generate_failed_precondition_error_with_mutated_validation_input!(
        not_closed,
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: channel is closing"
    );

    // policy-revoke-not-closed
    generate_status_ok_retry_variations!(
        // It's ok to validate existing when closed (ie: retry after mutual close)
        closed_ok_on_previous,
        |_tms| {},
        |_kms| {},
        |vms| {
            vms.chan.enforcement_state.channel_closed = true;
        },
        |vs| {
            // Channel state should advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
        }
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-version
    generate_failed_precondition_error_with_mutated_validation_input!(
        bad_version,
        |vms| {
            vms.tx.version = 3;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: decode_commitment_tx: bad commitment version: 3"
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-broadcaster-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_delayed_pubkey,
        |kms| {
            kms.keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: script pubkey doesn't match inner script",
            if ectx.opt_anchors { 6 } else { 4 }
        )
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-holder
    generate_failed_precondition_error_with_mutated_validation_input!(
        multiple_to_holder,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let ndx = basendx + 4;
            vms.tx.output.push(vms.tx.output[ndx].clone());
            vms.witscripts.push(vms.witscripts[ndx].clone());
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: more than one to_broadcaster output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
    );

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-counterparty
    generate_failed_precondition_error_with_mutated_validation_input!(
        multiple_to_counterparty,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let ndx = basendx + 3;
            vms.tx.output.push(vms.tx.output[ndx].clone());
            vms.witscripts.push(vms.witscripts[ndx].clone());
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
             tx output[{}]: more than one to_countersigner output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_to_holder,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let delta = 1_979_900;
            vms.tx.output[basendx + 3].value += delta;
            vms.tx.output[basendx + 4].value -= delta;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_broadcaster_value_sat 97 less than dust limit 330"
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_to_counterparty,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            let delta = 999_900;
            vms.tx.output[basendx + 3].value -= delta;
            vms.tx.output[basendx + 4].value += delta;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |_| "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_countersigner_value_sat 100 less than dust limit 330"
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_offered_htlc,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            vms.commit_tx_ctx.offered_htlcs[0].value_sat = 1000;
            vms.tx.output[basendx].value = 1000;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             offered htlc.value_sat 1000 less than dust limit {}",
            if ectx.opt_anchors { 1129 } else { 1125 }
        )
    );

    // policy-commitment-outputs-trimmed
    generate_failed_precondition_error_with_mutated_validation_input!(
        dust_received_htlc,
        |vms| {
            let basendx = if vms.opt_anchors { 2 } else { 0 };
            vms.commit_tx_ctx.received_htlcs[0].value_sat = 1000;
            vms.tx.output[basendx + 1].value = 1000;
        },
        |vs| {
            // Channel state should not advance.
            assert_eq!(vs.chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
        },
        |ectx: ErrMsgContext| format!(
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             received htlc.value_sat 1000 less than dust limit {}",
            if ectx.opt_anchors { 1177 } else { 1173 }
        )
    );

    #[test]
    fn channel_state_counterparty_commit_and_revoke_test() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 3_000_000);
        synthesize_ready_channel(
            &node_ctx,
            &mut chan_ctx,
            bitcoin::OutPoint { txid: Txid::from_slice(&[2u8; 32]).unwrap(), vout: 0 },
            HOLD_COMMIT_NUM,
        );
        node_ctx
            .node
            .with_ready_channel(&chan_ctx.channel_id, |chan| {
                let validator = chan.validator();
                let state = &mut chan.enforcement_state;

                // We'll need a placeholder; actual values not checked here ...
                let commit_info = make_test_commitment_info();

                // confirm initial state
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 0);
                // commit 0: unitialized <- next_revoke, <- next_commit

                // can't set next_commit to 0 (what would current point be?)
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        0,
                        make_test_pubkey(0x08),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_commit_num, 0);

                // can't set next_revoke to 0 either
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 1
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);
                // commit 0: current <- next_revoke
                // commit 1: next    <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);

                // can't skip next_commit forward
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 3 too large \
                     relative to next_counterparty_revoke_num 0"
                );
                assert_eq!(state.next_counterparty_commit_num, 1);

                // can't skip next_revoke forward
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 1),
                    "set_next_counterparty_revoke_num: \
                     1 too large relative to next_counterparty_commit_num 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 2
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    2,
                    make_test_pubkey(0x12),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: unrevoked <- next_revoke
                // commit 1: current
                // commit 2: next    <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    2,
                    make_test_pubkey(0x12),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't commit old thing
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        1,
                        make_test_pubkey(0x10),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't advance commit again
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 3 too large \
                     relative to next_counterparty_revoke_num 0"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't (ever) set next_revoke to 0
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 2),
                    "set_next_counterparty_revoke_num: 2 too large relative to \
                     next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // REVOKE commit 0
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: revoked
                // commit 1: current   <- next_revoke
                // commit 2: next      <- next_commit

                // retries are ok
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't retry the previous commit anymore
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 2 too small relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't skip commit ahead
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        4,
                        make_test_pubkey(0x16),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 4 too large relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't revoke backwards
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 2),
                    "set_next_counterparty_revoke_num: 2 too large \
                     relative to next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // ADVANCE next_commit to 3
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    3,
                    make_test_pubkey(0x14),
                    commit_info.clone()
                ));
                // commit 0: revoked
                // commit 1: unrevoked <- next_revoke
                // commit 2: current
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // retries ok
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    3,
                    make_test_pubkey(0x14),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can still retry the old revoke (they may not have seen our commit).
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can't skip revoke ahead
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 3),
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't commit ahead until revoke catches up
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        4,
                        make_test_pubkey(0x16),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 4 too large relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't commit behind
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 2 too small relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // REVOKE commit 1
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 2));
                // commit 1: revoked
                // commit 2: current   <- next_revoke
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // revoke retries ok
                assert_validation_ok!(validator.set_next_counterparty_revoke_num(state, 2));
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't revoke backwards
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 1),
                    "set_next_counterparty_revoke_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // can't revoke ahead until next commit
                assert_policy_err!(
                    validator.set_next_counterparty_revoke_num(state, 3),
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // commit retry not ok anymore
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 3 too small relative to \
                     next_counterparty_revoke_num 2"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't skip commit ahead
                assert_policy_err!(
                    validator.set_next_counterparty_commit_num(
                        state,
                        5,
                        make_test_pubkey(0x18),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 5 too large relative to \
                     next_counterparty_revoke_num 2"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // ADVANCE next_commit to 4
                assert_validation_ok!(validator.set_next_counterparty_commit_num(
                    state,
                    4,
                    make_test_pubkey(0x16),
                    commit_info.clone()
                ));
                // commit 2: unrevoked <- next_revoke
                // commit 3: current
                // commit 4: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 4);

                Ok(())
            })
            .expect("success");
    }
}
