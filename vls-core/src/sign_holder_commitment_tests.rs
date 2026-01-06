#[cfg(test)]
mod tests {
    use bitcoin::bip32::DerivationPath;
    use bitcoin::{self, Amount, OutPoint, ScriptBuf, Transaction};
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_htlc_redeemscript, make_funding_redeemscript,
    };

    use test_log::test;

    use crate::channel::{
        Channel, ChannelBase, ChannelSetup, CommitmentType, InputUtxo, TypedSignature,
    };
    use crate::node::NodeMonitor;
    use crate::policy::validator::{ChainState, EnforcementState};
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;
    use crate::util::transaction_utils::expected_commitment_tx_weight;

    use paste::paste;

    #[test]
    fn success_redundant_static() {
        let setup = make_test_channel_setup();
        test_redundant(&setup);
    }

    #[test]
    fn success_redundant_anchors() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::AnchorsZeroFeeHtlc;
        test_redundant(&setup);
    }

    fn test_redundant(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let commit_num = 23;
        let to_holder_value_sat = 1_000_000;
        let to_counterparty_value_sat = 1_999_000;
        let tx = node
            .with_channel(&channel_id, |chan| {
                chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);
                let per_commitment_point = chan.get_per_commitment_point(commit_num)?;
                let txkeys = chan.make_holder_tx_keys(&per_commitment_point);
                let commitment_tx = chan.make_holder_commitment_tx(
                    commit_num,
                    &txkeys,
                    0,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                );
                Ok(commitment_tx.trust().built_transaction().transaction.clone())
            })
            .expect("build");
        let signature = node
            .with_channel(&channel_id, |chan| {
                chan.sign_holder_commitment_tx_phase2_redundant(
                    commit_num,
                    0, // feerate not used
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                    vec![],
                )
            })
            .expect("sign");
        assert_eq!(
            tx.compute_txid().to_string(),
            if setup.commitment_type == CommitmentType::AnchorsZeroFeeHtlc {
                "35d42554e19cc82267c29b813d8a9465b762c730a1958b31f147080d302b6fbd"
            } else {
                "ae3b1c99071772622e336cf674c6f26bf5ef8860b6487b7cdf82e7d86cf23a42"
            }
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            TypedSignature::all(signature),
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    const HOLD_COMMIT_NUM: u64 = 23;

    #[allow(dead_code)]
    struct SignMutationState<'a> {
        cstate: &'a mut ChainState,
        estate: &'a mut EnforcementState,
        commit_num: &'a mut u64,
        chan_ctx: &'a TestChannelContext,
        num_htlcs: usize,
        tx: &'a Transaction,
    }

    fn sign_holder_commitment_tx_with_mutators<SignInputMutator>(
        commitment_type: CommitmentType,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        SignInputMutator: Fn(&mut SignMutationState),
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

        let commit_tx_ctx = setup_validated_holder_commitment(
            &node_ctx,
            &chan_ctx,
            HOLD_COMMIT_NUM,
            |_commit_tx_ctx| {},
            |_keys| {},
        )?;

        sign_holder_commitment_tx_with_mutators_common(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx,
            mutate_sign_inputs,
        )
    }

    fn sign_holder_commitment_tx_retry_with_mutators<SignInputMutator>(
        commitment_type: CommitmentType,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        SignInputMutator: Fn(&mut SignMutationState),
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

        let commit_tx_ctx = setup_validated_holder_commitment(
            &node_ctx,
            &chan_ctx,
            HOLD_COMMIT_NUM,
            |_commit_tx_ctx| {},
            |_keys| {},
        )?;

        // Sign the holder commitment w/o mutators the first time.
        sign_holder_commitment_tx_with_mutators_common(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx.clone(),
            |_sms| {},
        )?;

        // Retry the signature with mutators.
        sign_holder_commitment_tx_with_mutators_common(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx,
            mutate_sign_inputs,
        )
    }

    fn sign_holder_commitment_tx_with_mutators_common<SignInputMutator>(
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        commit_tx_ctx0: TestCommitmentTxContext,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        SignInputMutator: Fn(&mut SignMutationState),
    {
        let (sig, tx) = node_ctx.node.with_channel(&chan_ctx.channel_id, |chan| {
            let mut commit_tx_ctx = commit_tx_ctx0.clone();

            let per_commitment_point =
                chan.get_per_commitment_point(commit_tx_ctx.commit_num).expect("point");
            let txkeys = chan.make_holder_tx_keys(&per_commitment_point);

            let htlcs = Channel::htlcs_info2_to_oic(
                &commit_tx_ctx.offered_htlcs,
                &commit_tx_ctx.received_htlcs,
            );

            let commitment_tx = chan.make_holder_commitment_tx(
                commit_tx_ctx.commit_num,
                &txkeys,
                commit_tx_ctx.feerate_per_kw,
                commit_tx_ctx.to_broadcaster,
                commit_tx_ctx.to_countersignatory,
                htlcs.clone(),
            );
            // rebuild to get the scripts
            let trusted_tx = commitment_tx.trust();
            let tx = trusted_tx.built_transaction().clone();

            let mut cstate = make_test_chain_state();

            // Mutate the signing inputs.
            mutate_sign_inputs(&mut SignMutationState {
                cstate: &mut cstate,
                estate: &mut chan.enforcement_state,
                commit_num: &mut commit_tx_ctx.commit_num,
                chan_ctx: chan_ctx,
                num_htlcs: commit_tx_ctx.offered_htlcs.len() + commit_tx_ctx.received_htlcs.len(),
                tx: &tx.transaction,
            });

            let sig = chan.sign_holder_commitment_tx_phase2(commit_tx_ctx.commit_num)?;

            let build_feerate =
                if chan_ctx.setup.is_zero_fee_htlc() { 0 } else { commit_tx_ctx.feerate_per_kw };

            let _htlc_txs = trusted_tx
                .htlcs()
                .iter()
                .map(|htlc| {
                    build_htlc_transaction(
                        &tx.transaction.compute_txid(),
                        build_feerate,
                        chan_ctx.setup.counterparty_selected_contest_delay,
                        &htlc,
                        &chan_ctx.setup.features(),
                        &txkeys.broadcaster_delayed_payment_key,
                        &txkeys.revocation_key,
                    )
                })
                .collect::<Vec<Transaction>>();

            let _htlc_redeemscripts = htlcs
                .iter()
                .map(|htlc| get_htlc_redeemscript(&htlc, &chan_ctx.setup.features(), &txkeys))
                .collect::<Vec<ScriptBuf>>();

            assert_eq!(chan.enforcement_state.channel_closed, true);

            let (tx_r, _htlc_txs_r, _revocable_script_r, _uck_r, _revocation_pubkey_r) = chan
                .sign_holder_commitment_tx_for_recovery(
                    commit_tx_ctx.feerate_per_kw as u32,
                    &[InputUtxo {
                        outpoint: OutPoint::new(tx.transaction.compute_txid(), 0),
                        value: Amount::from_sat(commit_tx_ctx.to_countersignatory),
                        derivation_path: DerivationPath::master(),
                    }],
                )?;
            assert_eq!(tx_r.compute_txid(), tx.transaction.compute_txid());
            // TODO(303) HTLC recovery is not implemented yet

            Ok((sig, tx.transaction.clone()))
        })?;

        // no counterparty commitment, balance is "opening"
        assert_eq!(node_ctx.node.channel_balance(), ChannelBalanceBuilder::new().build());

        assert_eq!(
            tx.compute_txid().to_string(),
            if chan_ctx.setup.commitment_type == CommitmentType::StaticRemoteKey {
                "54cb4849bc8cb6474bc0209665ad88519121a1a2c35b0ac59aa1c0f0e42a772e"
            } else {
                "dd2ace31bff26915c6a1e30b44918a0743b09d08e35eff56c8bc00c09b70498a"
            }
        );

        let funding_pubkey = get_channel_funding_pubkey(&node_ctx.node, &chan_ctx.channel_id);
        let channel_funding_redeemscript = make_funding_redeemscript(
            &funding_pubkey,
            &chan_ctx.setup.counterparty_points.funding_pubkey,
        );

        check_signature(
            &tx,
            0,
            TypedSignature::all(sig),
            &funding_pubkey,
            chan_ctx.setup.channel_value_sat,
            &channel_funding_redeemscript,
        );

        Ok(())
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $sms: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_status_ok!(
                        sign_holder_commitment_tx_with_mutators(
                            CommitmentType::StaticRemoteKey, $sms)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _zerofee>]() {
                    assert_status_ok!(
                        sign_holder_commitment_tx_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $sms)
                    );
                }
            }
        };
    }

    macro_rules! generate_status_ok_retry_variations {
        ($name: ident, $sms: expr) => {
            paste! {
                #[test]
                fn [<$name _retry_static>]() {
                    assert_status_ok!(
                        sign_holder_commitment_tx_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $sms)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _retry_zerofee>]() {
                    assert_status_ok!(
                        sign_holder_commitment_tx_retry_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $sms)
                    );
                }
            }
        };
    }

    generate_status_ok_variations!(success, |_| {});

    generate_status_ok_variations!(ok_after_mutual_close, |sms| {
        sms.estate.channel_closed = true;
    });

    generate_status_ok_retry_variations!(success, |_| {});

    generate_status_ok_retry_variations!(ok_after_mutual_close, |sms| {
        sms.estate.channel_closed = true;
    });

    generate_status_ok_variations!(check_expected_tx_weight, |sms| {
        assert_eq!(
            expected_commitment_tx_weight(sms.chan_ctx.setup.is_anchors(), sms.num_htlcs),
            if sms.chan_ctx.setup.is_anchors() { 1640 } else { 1240 }
        );
        const WITNESS_WEIGHT: usize = //
            2 + // witness-header
            1 + // witness-element-count
            1 + // nil-length
            1 + 73 + // len sig_alice
            1 + 73 + // len sig_bob
            1 + 1 + 1 + 33 + 1 + 33 + 1 + 1; // len 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG

        // The discrepency between estimated commitment weight for anchors and actual is the
        // `count_tx_out` field which is estimated at 3 bytes, but is actually 1 byte for small
        // numbers of outputs (htlcs).  This 2 byte difference is multiplied by 4 due to the segwit
        // weight multipier.
        assert_eq!(
            sms.tx.weight().to_wu() + WITNESS_WEIGHT as u64,
            if sms.chan_ctx.setup.is_anchors() { 1632 } else { 1240 }
        );
    });

    #[allow(dead_code)]
    struct ErrMsgContext {
        opt_anchors: bool,
    }

    const ERR_MSG_CONTEXT_STATIC: ErrMsgContext = ErrMsgContext { opt_anchors: false };
    const ERR_MSG_CONTEXT_ANCHORS: ErrMsgContext = ErrMsgContext { opt_anchors: true };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $sms: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_commitment_tx_with_mutators(
                            CommitmentType::StaticRemoteKey, $sms),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _zero_fee>]() {
                    assert_failed_precondition_err!(
                        sign_holder_commitment_tx_with_mutators(
                            CommitmentType::AnchorsZeroFeeHtlc, $sms),
                        ($errcls)(ERR_MSG_CONTEXT_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_retry_variations {
        ($name: ident, $sms: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _retry_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_commitment_tx_retry_with_mutators(
                            CommitmentType::StaticRemoteKey, $sms),
                        ($errcls)(ERR_MSG_CONTEXT_STATIC)
                    );
                }
            }
        };
    }

    generate_failed_precondition_error_variations!(
        bad_prior_commit_num,
        |sms| *sms.commit_num -= 1,
        |_| "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 23 != 24"
    );

    generate_failed_precondition_error_variations!(
        bad_later_commit_num,
        |sms| *sms.commit_num += 1,
        |_| "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 25 != 24"
    );

    generate_failed_precondition_error_retry_variations!(
        bad_prior_commit_num,
        |sms| *sms.commit_num -= 1,
        |_| "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 23 != 24"
    );

    generate_failed_precondition_error_retry_variations!(
        bad_later_commit_num,
        |sms| *sms.commit_num += 1,
        |_| "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 25 != 24"
    );
}
