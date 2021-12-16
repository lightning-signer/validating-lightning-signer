#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use lightning::ln::chan_utils::make_funding_redeemscript;

    use test_env_log::test;

    use crate::channel::{Channel, ChannelBase, ChannelSetup, CommitmentType};
    use crate::policy::validator::{ChainState, EnforcementState};
    use crate::util::crypto_utils::signature_to_bitcoin_vec;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn sign_holder_commitment_tx_phase2_static_test() {
        let setup = make_test_channel_setup();
        sign_holder_commitment_tx_phase2_test(&setup);
    }

    #[test]
    fn sign_holder_commitment_tx_phase2_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_holder_commitment_tx_phase2_test(&setup);
    }

    fn sign_holder_commitment_tx_phase2_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let commit_num = 23;
        let to_holder_value_sat = 1_000_000;
        let to_counterparty_value_sat = 1_999_000;
        let tx = node
            .with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);

                let commitment_tx = chan
                    .make_holder_commitment_tx(
                        commit_num,
                        0,
                        to_holder_value_sat,
                        to_counterparty_value_sat,
                        vec![],
                    )
                    .expect("holder_commitment_tx");
                Ok(commitment_tx.trust().built_transaction().transaction.clone())
            })
            .expect("build");
        let (ser_signature, _) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_holder_commitment_tx_phase2(
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
            tx.txid().to_hex(),
            "991422f2c0d308b9319f9aec28ccef4bffedf5d36965ec7346155537b8800844"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
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
    }

    fn sign_holder_commitment_tx_with_mutators<SignInputMutator>(
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        SignInputMutator: Fn(&mut SignMutationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let (node_ctx, chan_ctx) = setup_funded_channel(
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
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        SignInputMutator: Fn(&mut SignMutationState),
    {
        let next_holder_commit_num = HOLD_COMMIT_NUM;
        let next_counterparty_commit_num = HOLD_COMMIT_NUM + 1;
        let next_counterparty_revoke_num = next_counterparty_commit_num - 1;
        let (node_ctx, chan_ctx) = setup_funded_channel(
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
        let (sig, tx) = node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
            let mut commit_tx_ctx = commit_tx_ctx0.clone();

            let per_commitment_point =
                chan.get_per_commitment_point(commit_tx_ctx.commit_num).expect("point");
            let keys = chan.make_holder_tx_keys(&per_commitment_point)?;

            let htlcs = Channel::htlcs_info2_to_oic(
                commit_tx_ctx.offered_htlcs.clone(),
                commit_tx_ctx.received_htlcs.clone(),
            );

            let commitment_tx = chan.make_holder_commitment_tx_with_keys(
                keys,
                commit_tx_ctx.commit_num,
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
            });

            let sig = chan.sign_holder_commitment_tx(commit_tx_ctx.commit_num)?;

            Ok((sig, tx.transaction.clone()))
        })?;

        assert_eq!(
            tx.txid().to_hex(),
            "d236f61c3e0fb3221fab61f97696077df3514e3d602561a6d2050d79777eb362"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node_ctx.node, &chan_ctx.channel_id);
        let channel_funding_redeemscript = make_funding_redeemscript(
            &funding_pubkey,
            &chan_ctx.setup.counterparty_points.funding_pubkey,
        );

        check_signature(
            &tx,
            0,
            signature_to_bitcoin_vec(sig),
            &funding_pubkey,
            chan_ctx.setup.channel_value_sat,
            &channel_funding_redeemscript,
        );

        Ok(())
    }

    #[test]
    fn success_phase1() {
        assert_status_ok!(sign_holder_commitment_tx_with_mutators(|_sms| {
            // don't mutate the state, should pass
        },));
    }

    #[test]
    fn ok_after_mutual_close_phase1() {
        assert_status_ok!(sign_holder_commitment_tx_with_mutators(|sms| {
            // Set the mutual_close_signed flag
            sms.estate.mutual_close_signed = true;
        }));
    }

    #[test]
    fn bad_prior_commit_num_phase1() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(|sms| {
                *sms.commit_num -= 1;
            }),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 23 != 24"
        );
    }

    #[test]
    fn bad_following_commit_num_phase1() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(|sms| {
                *sms.commit_num += 1;
            }),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 25 != 24"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn retry_success_phase1() {
        assert_status_ok!(sign_holder_commitment_tx_retry_with_mutators(|_sms| {
            // don't mutate the state, should pass
        },));
    }

    #[test]
    fn retry_bad_prior_commit_num_phase1() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(|sms| {
                *sms.commit_num -= 1;
            }),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 23 != 24"
        );
    }

    #[test]
    fn retry_bad_following_commit_num_phase1() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(|sms| {
                *sms.commit_num += 1;
            }),
            "policy failure: get_current_holder_commitment_info: \
             invalid next holder commitment number: 25 != 24"
        );
    }
}
