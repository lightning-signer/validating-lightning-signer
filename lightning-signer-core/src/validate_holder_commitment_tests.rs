#[cfg(test)]
mod tests {
    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Signature;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{self, Transaction};
    use lightning::ln::PaymentHash;

    use test_env_log::test;

    use crate::channel::{Channel, ChannelBase};
    use crate::policy::error::policy_error;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn validate_holder_commitment_with_htlcs() {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;
        let chan_ctx = fund_test_channel(&node_ctx, channel_amount);

        let offered_htlcs = vec![
            HTLCInfo2 {
                value_sat: 1000,
                payment_hash: PaymentHash([1; 32]),
                cltv_expiry: 1 << 16,
            },
            HTLCInfo2 {
                value_sat: 1000,
                payment_hash: PaymentHash([2; 32]),
                cltv_expiry: 2 << 16,
            },
        ];
        let received_htlcs = vec![
            HTLCInfo2 {
                value_sat: 1000,
                payment_hash: PaymentHash([3; 32]),
                cltv_expiry: 3 << 16,
            },
            HTLCInfo2 {
                value_sat: 1000,
                payment_hash: PaymentHash([4; 32]),
                cltv_expiry: 4 << 16,
            },
            HTLCInfo2 {
                value_sat: 1000,
                payment_hash: PaymentHash([5; 32]),
                cltv_expiry: 5 << 16,
            },
        ];
        let sum_htlc = 5000;

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
            "policy failure: get_per_commitment_point: \
                commitment_number 2 invalid when next_holder_commit_num is 1"
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
            "policy failure: validate_sign_holder_commitment_tx: \
             can't sign revoked commitment_number 9, next_holder_commit_num is 11"
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

    fn validate_holder_commitment_with_mutator<ValidationMutator, ChannelStateValidator>(
        mutate_validation_input: ValidationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        ValidationMutator: Fn(
            &mut Channel,
            &mut TestCommitmentTxContext,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut Signature,
            &mut Vec<Signature>,
        ),
        ChannelStateValidator: Fn(&Channel),
    {
        let node_ctx = test_node_ctx(1);

        let channel_amount = 3_000_000;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);

        // Pretend we funded the channel and ran for a while ...
        synthesize_ready_channel(
            &node_ctx,
            &mut chan_ctx,
            bitcoin::OutPoint {
                txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                vout: 0,
            },
            HOLD_COMMIT_NUM,
        );

        let fee = 1000;
        let to_broadcaster = 1_000_000;
        let to_countersignatory = channel_amount - to_broadcaster - fee;
        let offered_htlcs = vec![];
        let received_htlcs = vec![];

        let feerate_per_kw = 1200;

        let mut commit_tx_ctx0 = channel_commitment(
            &node_ctx,
            &chan_ctx,
            HOLD_COMMIT_NUM,
            feerate_per_kw,
            to_broadcaster,
            to_countersignatory,
            offered_htlcs.clone(),
            received_htlcs.clone(),
        );

        let (commit_sig0, htlc_sigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx0);

        node_ctx
            .node
            .with_ready_channel(&chan_ctx.channel_id, |chan| {
                let mut commit_tx_ctx = commit_tx_ctx0.clone();
                let mut commit_sig = commit_sig0.clone();
                let mut htlc_sigs = htlc_sigs0.clone();

                let htlcs = Channel::htlcs_info2_to_oic(
                    commit_tx_ctx.offered_htlcs.clone(),
                    commit_tx_ctx.received_htlcs.clone(),
                );
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_holder_broadcastable();
                let per_commitment_point =
                    chan.get_per_commitment_point(commit_tx_ctx.commit_num)?;
                let keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    commit_tx_ctx.to_broadcaster,
                    commit_tx_ctx.to_countersignatory,
                    &htlcs,
                    &parameters,
                )
                .expect("scripts");
                let mut output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

                let mut tx = commit_tx_ctx
                    .tx
                    .as_ref()
                    .unwrap()
                    .trust()
                    .built_transaction()
                    .transaction
                    .clone();

                mutate_validation_input(
                    chan,
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

    #[test]
    fn validate_holder_commitment_success() {
        assert!(validate_holder_commitment_with_mutator(
            |_chan, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel state should advance.
                assert_eq!(
                    chan.enforcement_state.next_holder_commit_num,
                    HOLD_COMMIT_NUM + 1
                );
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_holder_commitment_can_retry() {
        assert!(validate_holder_commitment_with_mutator(
            |chan, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                // Set the channel's next_holder_commit_num ahead one;
                // pretend we've already seen it ...
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM + 1);
            },
            |chan| {
                // Channel state should stay where we advanced it.
                assert_eq!(
                    chan.enforcement_state.next_holder_commit_num,
                    HOLD_COMMIT_NUM + 1
                );
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_holder_commitment_not_ahead() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |chan, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    // Set the channel's next_holder_commit_num ahead two, past the retry ...
                    chan.enforcement_state
                        .set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM + 2);
                },
                |chan| {
                    // Channel state should stay where we advanced it.
                    assert_eq!(
                        chan.enforcement_state.next_holder_commit_num,
                        HOLD_COMMIT_NUM + 2
                    );
                }
            ),
            "policy failure: set_next_holder_commit_num: invalid progression: 45 to 44"
        );
    }

    #[test]
    fn validate_holder_commitment_not_behind() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |chan, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    // Set the channel's next_holder_commit_num ahead two behind 1, in the past ...
                    chan.enforcement_state
                        .set_next_holder_commit_num_for_testing(HOLD_COMMIT_NUM - 1);
                },
                |chan| {
                    // Channel state should stay where we set it.
                    assert_eq!(
                        chan.enforcement_state.next_holder_commit_num,
                        HOLD_COMMIT_NUM - 1
                    );
                }
            ),
            "policy failure: get_per_commitment_point: \
             commitment_number 43 invalid when next_holder_commit_num is 42"
        );
    }

    // policy-revoke-not-closed
    #[test]
    fn validate_holder_commitment_not_closed() {
        assert_failed_precondition_err!(
            validate_holder_commitment_with_mutator(
                |chan, _commit_tx_ctx, _tx, _witscripts, _commit_sig, _htlc_sigs| {
                    chan.enforcement_state.mutual_close_signed = true;
                },
                |chan| {
                    // Channel state should not advance.
                    assert_eq!(
                        chan.enforcement_state.next_holder_commit_num,
                        HOLD_COMMIT_NUM
                    );
                }
            ),
            "policy failure: validate_holder_commitment_state: mutual close already signed"
        );
    }

    #[test]
    fn channel_state_counterparty_commit_and_revoke_test() {
        let node_ctx = test_node_ctx(1);
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, 3_000_000);
        synthesize_ready_channel(
            &node_ctx,
            &mut chan_ctx,
            bitcoin::OutPoint {
                txid: Txid::from_slice(&[2u8; 32]).unwrap(),
                vout: 0,
            },
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
                assert!(state
                    .set_next_counterparty_commit_num(
                        1,
                        make_test_pubkey(0x10),
                        commit_info.clone()
                    )
                    .is_ok());
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 1);
                // commit 0: current <- next_revoke
                // commit 1: next    <- next_commit

                // retries are ok
                assert!(state
                    .set_next_counterparty_commit_num(
                        1,
                        make_test_pubkey(0x10),
                        commit_info.clone()
                    )
                    .is_ok());
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
                assert!(state
                    .set_next_counterparty_commit_num(
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone()
                    )
                    .is_ok());
                assert_eq!(state.next_counterparty_revoke_num, 0);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: unrevoked <- next_revoke
                // commit 1: current
                // commit 2: next    <- next_commit

                // retries are ok
                assert!(state
                    .set_next_counterparty_commit_num(
                        2,
                        make_test_pubkey(0x12),
                        commit_info.clone()
                    )
                    .is_ok());
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
                assert!(state.set_next_counterparty_revoke_num(1).is_ok());
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 2);
                // commit 0: revoked
                // commit 1: current   <- next_revoke
                // commit 2: next      <- next_commit

                // retries are ok
                assert!(state.set_next_counterparty_revoke_num(1).is_ok());
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
                assert!(state
                    .set_next_counterparty_commit_num(
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone()
                    )
                    .is_ok());
                // commit 0: revoked
                // commit 1: unrevoked <- next_revoke
                // commit 2: current
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 1);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // retries ok
                assert!(state
                    .set_next_counterparty_commit_num(
                        3,
                        make_test_pubkey(0x14),
                        commit_info.clone()
                    )
                    .is_ok());
                assert_eq!(state.next_counterparty_commit_num, 3);

                // Can still retry the old revoke (they may not have seen our commit).
                assert!(state.set_next_counterparty_revoke_num(1).is_ok());
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
                assert!(state.set_next_counterparty_revoke_num(2).is_ok());
                // commit 1: revoked
                // commit 2: current   <- next_revoke
                // commit 3: next      <- next_commit
                assert_eq!(state.next_counterparty_revoke_num, 2);
                assert_eq!(state.next_counterparty_commit_num, 3);

                // revoke retries ok
                assert!(state.set_next_counterparty_revoke_num(2).is_ok());
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
                assert!(state
                    .set_next_counterparty_commit_num(
                        4,
                        make_test_pubkey(0x16),
                        commit_info.clone()
                    )
                    .is_ok());
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
