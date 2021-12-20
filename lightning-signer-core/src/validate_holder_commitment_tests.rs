#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Signature;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{self, Transaction};
    use lightning::chain::keysinterface::BaseSign;
    use lightning::ln::chan_utils::TxCreationKeys;
    use lightning::ln::PaymentHash;

    use test_env_log::test;

    use crate::channel::{Channel, ChannelBase};
    use crate::policy::error::policy_error;
    use crate::policy::validator::ChainState;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

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
        let fees = 20_000;
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
        let fees = 20_000;
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
        let fees = 20_000;
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

    fn validate_holder_commitment_with_mutator_common<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        KeysMutator: Fn(&mut TxCreationKeys),
        ValidationMutator: Fn(
            &mut Channel,
            &mut ChainState,
            &mut TestCommitmentTxContext,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut Signature,
            &mut Vec<Signature>,
        ),
        ChannelStateValidator: Fn(&Channel),
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

        mutate_tx_builder(&mut commit_tx_ctx0);

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

            mutate_keys(&mut keys);

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

            mutate_validation_input(
                chan,
                &mut cstate,
                &mut commit_tx_ctx,
                &mut tx,
                &mut output_witscripts,
                &mut commit_sig,
                &mut htlc_sigs,
            );

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
            validate_channel_state(chan);
            deferred_rv?;
            Ok(())
        })
    }

    fn validate_holder_commitment_with_mutator<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        KeysMutator: Fn(&mut TxCreationKeys),
        ValidationMutator: Fn(
            &mut Channel,
            &mut ChainState,
            &mut TestCommitmentTxContext,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut Signature,
            &mut Vec<Signature>,
        ),
        ChannelStateValidator: Fn(&Channel),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let (node_ctx, chan_ctx) = setup_funded_channel(
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        validate_holder_commitment_with_mutator_common(
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    fn validate_holder_commitment_retry_with_mutator<
        TxBuilderMutator,
        KeysMutator,
        ValidationMutator,
        ChannelStateValidator,
    >(
        mutate_tx_builder: TxBuilderMutator,
        mutate_keys: KeysMutator,
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        KeysMutator: Fn(&mut TxCreationKeys),
        ValidationMutator: Fn(
            &mut Channel,
            &mut ChainState,
            &mut TestCommitmentTxContext,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut Signature,
            &mut Vec<Signature>,
        ),
        ChannelStateValidator: Fn(&Channel),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let (node_ctx, chan_ctx) = setup_funded_channel(
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
        );

        // Start with successful validation w/o mutations
        validate_holder_commitment_with_mutator_common(
            &node_ctx,
            &chan_ctx,
            |_commit_tx_ctx| {},
            |_keys| {},
            |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
            |chan| {
                // Channel state should advance.
                assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            },
        )?;

        // Retry with mutations
        validate_holder_commitment_with_mutator_common(
            &node_ctx,
            &chan_ctx,
            mutate_tx_builder,
            mutate_keys,
            mutate_validation_input,
            validate_channel_state,
        )
    }

    #[test]
    fn validate_holder_commitment_success() {
        assert_status_ok!(validate_holder_commitment_with_mutator(
            |_commit_tx_ctx| {},
            |_keys| {},
            |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel state should advance.
                assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            }
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn validate_holder_commitment_can_retry() {
        assert_status_ok!(validate_holder_commitment_retry_with_mutator(
            |_commit_tx_ctx| {},
            |_keys| {},
            |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
            |chan| {
                // Channel state should stay where we advanced it initially.
                assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            }
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn validate_holder_commitment_retry_with_bad_to_holder() {
        assert_failed_precondition_err!(
            validate_holder_commitment_retry_with_mutator(
                |commit_tx_ctx| {
                    commit_tx_ctx.to_broadcaster -= 1;
                },
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
                |chan| {
                    // Channel state should stay where we advanced it initially.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
                }
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn validate_holder_commitment_retry_with_bad_to_counterparty() {
        assert_failed_precondition_err!(
            validate_holder_commitment_retry_with_mutator(
                |commit_tx_ctx| {
                    commit_tx_ctx.to_countersignatory -= 1;
                },
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
                |chan| {
                    // Channel state should stay where we advanced it initially.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
                }
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn validate_holder_commitment_retry_with_bad_offered_htlc() {
        assert_failed_precondition_err!(
            validate_holder_commitment_retry_with_mutator(
                |commit_tx_ctx| {
                    commit_tx_ctx.offered_htlcs[0].value_sat -= 1;
                },
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
                |chan| {
                    // Channel state should stay where we advanced it initially.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
                }
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn validate_holder_commitment_retry_with_bad_received_htlc() {
        assert_failed_precondition_err!(
            validate_holder_commitment_retry_with_mutator(
                |commit_tx_ctx| {
                    commit_tx_ctx.received_htlcs[0].value_sat -= 1;
                },
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
                |chan| {
                    // Channel state should stay where we advanced it initially.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
                }
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 43 with changed info"
        );
    }

    #[test]
    fn validate_holder_commitment_with_bad_commit_sig() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, commit_sig, _htlc_sigs| {
                    *commit_sig = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: commit sig verify failed: secp: signature failed verification"
        );
    }

    #[test]
    fn validate_holder_commitment_with_bad_htlc_sig() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, htlc_sigs| {
                    htlc_sigs[0] = Signature::from_str("30450221009338316aef0f17f75127a24d60ae8a980fee5e2b4605dc96fba2d5407e77fcee022029e311ff22df5b515e4a2fbe412d32ed49e93cabbb31b067ad3318ac22441cd2").expect("sig");
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: \
             commit sig verify failed for htlc 0: secp: signature failed verification"
        );
    }

    #[test]
    fn validate_holder_commitment_not_ahead() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    // Set the channel's next_holder_commit_num ahead two, past the retry ...
                    chan.enforcement_state
                        .set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM + 2);
                },
                |chan| {
                    // Channel state should stay where we advanced it.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 2);
                }
            ),
            "policy failure: validate_holder_commitment_tx: \
             can't sign revoked commitment_number 43, next_holder_commit_num is 45"
        );
    }

    #[test]
    fn validate_holder_commitment_not_behind() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    // Set the channel's next_holder_commit_num ahead two behind 1, in the past ...
                    chan.enforcement_state
                        .set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM - 1);
                },
                |chan| {
                    // Channel state should stay where we set it.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM - 1);
                }
            ),
            "policy failure: set_next_holder_commit_num: invalid progression: 42 to 44"
        );
    }

    // policy-revoke-not-closed
    #[test]
    fn validate_holder_commitment_not_closed() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    chan.enforcement_state.mutual_close_signed = true;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: validate_holder_commitment_tx: mutual close already signed"
        );
    }

    // policy-revoke-not-closed
    #[test]
    fn validate_holder_commitment_closed_ok_on_previous() {
        // It's ok to validate existing when closed (ie: retry after mutual close)
        assert_status_ok!(validate_holder_commitment_retry_with_mutator(
            |_commit_tx_ctx| {},
            |_keys| {},
            |chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                chan.enforcement_state.mutual_close_signed = true;
            },
            |chan| {
                // Channel state should stay where it was
                assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM + 1);
            }
        ));
    }

    // policy-revoke-new-commitment-valid
    // policy-commitment-version
    #[test]
    fn validate_holder_commitment_bad_version() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, tx, _witscripts, _commit_sig, _htlc_sigs| {
                    tx.version = 3;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: decode_commitment_tx: bad commitment version: 3"
        );
    }

    // policy-revoke-new-commitment-valid
    // policy-commitment-broadcaster-pubkey
    #[test]
    fn validate_holder_commitment_bad_delayed_pubkey() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |keys| {
                    keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
                },
                |_chan, _cstate, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {},
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "transaction format: decode_commitment_tx: \
             tx output[4]: script pubkey doesn't match inner script"
        );
    }

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-holder
    #[test]
    fn validate_holder_commitment_with_multiple_to_holder() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, tx, witscripts, _commit_sig, _htlc_sigs| {
                    let ndx = 4;
                    tx.output.push(tx.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "transaction format: decode_commitment_tx: \
             tx output[5]: more than one to_broadcaster output"
        );
    }

    // policy-revoke-new-commitment-valid
    // policy-commitment-singular-to-counterparty
    #[test]
    fn validate_holder_commitment_with_multiple_to_counterparty() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, tx, witscripts, _commit_sig, _htlc_sigs| {
                    let ndx = 3;
                    tx.output.push(tx.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "transaction format: decode_commitment_tx: \
             tx output[5]: more than one to_countersigner output"
        );
    }

    // policy-commitment-outputs-trimmed
    #[test]
    fn validate_holder_commitment_with_dust_to_holder() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, tx, _witscripts, _commit_sig, _htlc_sigs| {
                    let delta = 1_979_900;
                    tx.output[3].value += delta;
                    tx.output[4].value -= delta;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_broadcaster_value_sat 97 less than dust limit 330"
        );
    }

    // policy-commitment-outputs-trimmed
    #[test]
    fn validate_holder_commitment_with_dust_to_counterparty() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, _commit_tx_ctx, tx, _witscripts, _commit_sig, _htlc_sigs| {
                    let delta = 999_900;
                    tx.output[3].value -= delta;
                    tx.output[4].value += delta;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             to_countersigner_value_sat 100 less than dust limit 330"
        );
    }

    // policy-commitment-outputs-trimmed
    #[test]
    fn validate_holder_commitment_with_dust_offered_htlc() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, commit_tx_ctx, tx, _witscripts, _commit_sig, _htlc_sigs| {
                    commit_tx_ctx.offered_htlcs[0].value_sat = 1000;
                    tx.output[0].value = 1000;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             offered htlc.value_sat 1000 less than dust limit 2319"
        );
    }

    // policy-commitment-outputs-trimmed
    #[test]
    fn validate_holder_commitment_with_dust_received_htlc() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |_commit_tx_ctx| {},
                |_keys| {},
                |_chan, _cstate, commit_tx_ctx, tx, _witscripts, _commit_sig, _htlc_sigs| {
                    commit_tx_ctx.received_htlcs[0].value_sat = 1000;
                    tx.output[1].value = 1000;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(chan.enforcement_state.next_holder_commit_num, HOLD_COMMIT_NUM);
                }
            ),
            "policy failure: validate_holder_commitment_tx: validate_commitment_tx: \
             received htlc.value_sat 1000 less than dust limit 2439"
        );
    }

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
                let state = &mut chan.enforcement_state;

                // We'll need a placeholder; actual values not checked here ...
                let commit_info = make_test_commitment_info();

                // confirm initial state
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 0);
                // commit 0: unitialized <- next_revoke, <- next_commit

                // can't set next_commit to 0 (what would current point be?)
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
                        0,
                        make_test_pubkey(0x08),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_commit_num, 0);

                // can't set next_revoke to 0 either
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 1
                assert_validation_ok!(state.set_next_counterparty_commit_num(
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);
                // commit 0: current <- next_revoke
                // commit 1: next    <- next_commit

                // retries are ok
                assert_validation_ok!(state.set_next_counterparty_commit_num(
                    1,
                    make_test_pubkey(0x10),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);

                // can't skip next_commit forward
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_revoke_num(1),
                    "set_next_counterparty_revoke_num: \
                     1 too large relative to next_counterparty_commit_num 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // ADVANCE next_commit to 2
                assert_validation_ok!(state.set_next_counterparty_commit_num(
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
                assert_validation_ok!(state.set_next_counterparty_commit_num(
                    2,
                    make_test_pubkey(0x12),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't commit old thing
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
                        1,
                        make_test_pubkey(0x10),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't advance commit again
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_revoke_num(0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // can't skip revoke ahead
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(2),
                    "set_next_counterparty_revoke_num: 2 too large relative to \
                     next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 0);

                // REVOKE commit 0
                assert_validation_ok!(state.set_next_counterparty_revoke_num(1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: revoked
                // commit 1: current   <- next_revoke
                // commit 2: next      <- next_commit

                // retries are ok
                assert_validation_ok!(state.set_next_counterparty_revoke_num(1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);

                // can't retry the previous commit anymore
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_revoke_num(0),
                    "set_next_counterparty_revoke_num: can\'t set next to 0"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't skip revoke ahead
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(2),
                    "set_next_counterparty_revoke_num: 2 too large \
                     relative to next_counterparty_commit_num 2"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // ADVANCE next_commit to 3
                assert_validation_ok!(state.set_next_counterparty_commit_num(
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
                assert_validation_ok!(state.set_next_counterparty_commit_num(
                    3,
                    make_test_pubkey(0x14),
                    commit_info.clone()
                ));
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can still retry the old revoke (they may not have seen our commit).
                assert_validation_ok!(state.set_next_counterparty_revoke_num(1));
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can't skip revoke ahead
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(3),
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 1);

                // can't commit ahead until revoke catches up
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_commit_num(
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 2 too small relative to \
                     next_counterparty_revoke_num 1"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // REVOKE commit 1
                assert_validation_ok!(state.set_next_counterparty_revoke_num(2));
                // commit 1: revoked
                // commit 2: current   <- next_revoke
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // revoke retries ok
                assert_validation_ok!(state.set_next_counterparty_revoke_num(2));
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // can't revoke backwards
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(1),
                    "set_next_counterparty_revoke_num: invalid progression: 2 to 1"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // can't revoke ahead until next commit
                assert_policy_err!(
                    state.set_next_counterparty_revoke_num(3),
                    "set_next_counterparty_revoke_num: 3 too large relative to \
                     next_counterparty_commit_num 3"
                );
                assert_eq!(state.next_counterparty_revoke_num, 2);

                // commit retry not ok anymore
                assert_policy_err!(
                    state.set_next_counterparty_commit_num(
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
                    state.set_next_counterparty_commit_num(
                        5,
                        make_test_pubkey(0x18),
                        commit_info.clone()
                    ),
                    "set_next_counterparty_commit_num: 5 too large relative to \
                     next_counterparty_revoke_num 2"
                );
                assert_eq!(state.next_counterparty_commit_num, 3);

                // ADVANCE next_commit to 4
                assert_validation_ok!(state.set_next_counterparty_commit_num(
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
