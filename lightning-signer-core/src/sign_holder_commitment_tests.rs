#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{self, Transaction};
    use lightning::ln::chan_utils::{make_funding_redeemscript, TxCreationKeys};

    use test_env_log::test;

    use crate::channel::{Channel, ChannelBase, ChannelSetup, CommitmentType};
    use crate::policy::validator::{ChainState, EnforcementState};
    use crate::tx::tx::HTLCInfo2;
    use crate::util::crypto_utils::signature_to_bitcoin_vec;
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn sign_holder_commitment_tx_test() {
        let setup = make_test_channel_setup();
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let commit_num = 23;
                let feerate_per_kw = 0;
                let to_broadcaster = 1_999_000;
                let to_countersignatory = 1_000_000;
                let offered_htlcs = vec![];
                let received_htlcs = vec![];
                let mut htlcs =
                    Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(commit_num);

                let parameters = channel_parameters.as_holder_broadcastable();

                let per_commitment_point =
                    chan.get_per_commitment_point(commit_num).expect("point");
                let keys = chan.make_holder_tx_keys(&per_commitment_point).unwrap();

                let redeem_scripts = build_tx_scripts(
                    &keys,
                    to_broadcaster,
                    to_countersignatory,
                    &mut htlcs,
                    &parameters,
                )
                .expect("scripts");
                let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

                let commitment_tx = chan
                    .make_holder_commitment_tx(
                        commit_num,
                        feerate_per_kw,
                        to_broadcaster,
                        to_countersignatory,
                        htlcs.clone(),
                    )
                    .expect("holder_commitment_tx");

                // rebuild to get the scripts
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();

                let cstate = make_test_chain_state();

                let sig = chan
                    .sign_holder_commitment_tx(
                        &cstate,
                        &tx.transaction,
                        &output_witscripts,
                        commit_num,
                        feerate_per_kw,
                        offered_htlcs,
                        received_htlcs,
                    )
                    .expect("sign");
                Ok((sig, tx.transaction.clone()))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            tx.txid().to_hex(),
            "17e696b2d7135e3b4df5ea7ab3f0bbb7cf22b37fa700c81075d5ec11e82fd1fc"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            signature_to_bitcoin_vec(sig),
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

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
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(commit_num);

                let commitment_tx = chan
                    .make_holder_commitment_tx(
                        commit_num,
                        0,
                        to_holder_value_sat,
                        to_counterparty_value_sat,
                        vec![],
                    )
                    .expect("holder_commitment_tx");
                Ok(commitment_tx
                    .trust()
                    .built_transaction()
                    .transaction
                    .clone())
            })
            .expect("build");
        let (ser_signature, _) = node
            .with_ready_channel(&channel_id, |chan| {
                let cstate = make_test_chain_state();
                chan.sign_holder_commitment_tx_phase2(
                    &cstate,
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

    fn sign_holder_commitment_tx_with_mutators<
        TxBuilderMutator,
        StateMutator,
        KeysMutator,
        SignInputMutator,
    >(
        mutate_tx_builder: TxBuilderMutator,
        mutate_channel_state: StateMutator,
        mutate_keys: KeysMutator,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        SignInputMutator: Fn(
            &mut ChainState,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut u64,
            &mut u32,
            &mut Vec<HTLCInfo2>,
            &mut Vec<HTLCInfo2>,
        ),
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
            mutate_tx_builder,
            mutate_channel_state,
            mutate_keys,
            mutate_sign_inputs,
        )
    }

    fn sign_holder_commitment_tx_retry_with_mutators<
        TxBuilderMutator,
        StateMutator,
        KeysMutator,
        SignInputMutator,
    >(
        mutate_tx_builder: TxBuilderMutator,
        mutate_channel_state: StateMutator,
        mutate_keys: KeysMutator,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        SignInputMutator: Fn(
            &mut ChainState,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut u64,
            &mut u32,
            &mut Vec<HTLCInfo2>,
            &mut Vec<HTLCInfo2>,
        ),
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
            |_commit_tx_ctx| {},
            |_chan| {},
            |_keys| {},
            |_cstate,
             _tx,
             _witscripts,
             _commit_num,
             _feerate_per_kw,
             _offered_htlcs,
             _received_htlcs| {},
        )?;

        // Retry the signature with mutators.
        sign_holder_commitment_tx_with_mutators_common(
            &node_ctx,
            &chan_ctx,
            commit_tx_ctx,
            mutate_tx_builder,
            mutate_channel_state,
            mutate_keys,
            mutate_sign_inputs,
        )
    }

    fn sign_holder_commitment_tx_with_mutators_common<
        TxBuilderMutator,
        StateMutator,
        KeysMutator,
        SignInputMutator,
    >(
        node_ctx: &TestNodeContext,
        chan_ctx: &TestChannelContext,
        mut commit_tx_ctx0: TestCommitmentTxContext,
        mutate_tx_builder: TxBuilderMutator,
        mutate_channel_state: StateMutator,
        mutate_keys: KeysMutator,
        mutate_sign_inputs: SignInputMutator,
    ) -> Result<(), Status>
    where
        TxBuilderMutator: Fn(&mut TestCommitmentTxContext),
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        SignInputMutator: Fn(
            &mut ChainState,
            &mut Transaction,
            &mut Vec<Vec<u8>>,
            &mut u64,
            &mut u32,
            &mut Vec<HTLCInfo2>,
            &mut Vec<HTLCInfo2>,
        ),
    {
        mutate_tx_builder(&mut commit_tx_ctx0);

        let (sig, tx) = node_ctx
            .node
            .with_ready_channel(&chan_ctx.channel_id, |chan| {
                let mut commit_tx_ctx = commit_tx_ctx0.clone();

                let channel_parameters = chan.make_channel_parameters();

                // Mutate the signer state.
                mutate_channel_state(&mut chan.enforcement_state);

                let parameters = channel_parameters.as_holder_broadcastable();
                let per_commitment_point = chan
                    .get_per_commitment_point(commit_tx_ctx.commit_num)
                    .expect("point");
                let mut keys = chan.make_holder_tx_keys(&per_commitment_point)?;

                // Mutate the tx creation keys.
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
                )
                .expect("scripts");
                let mut output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

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
                let mut tx = trusted_tx.built_transaction().clone();

                let mut cstate = make_test_chain_state();

                // Mutate the signing inputs.
                mutate_sign_inputs(
                    &mut cstate,
                    &mut tx.transaction,
                    &mut output_witscripts,
                    &mut commit_tx_ctx.commit_num,
                    &mut commit_tx_ctx.feerate_per_kw,
                    &mut commit_tx_ctx.offered_htlcs,
                    &mut commit_tx_ctx.received_htlcs,
                );

                let sig = chan.sign_holder_commitment_tx(
                    &cstate,
                    &tx.transaction,
                    &output_witscripts,
                    commit_tx_ctx.commit_num,
                    commit_tx_ctx.feerate_per_kw,
                    commit_tx_ctx.offered_htlcs.clone(),
                    commit_tx_ctx.received_htlcs.clone(),
                )?;

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
    fn sign_holder_commitment_tx_with_no_mut_test() {
        assert_status_ok!(sign_holder_commitment_tx_with_mutators(
            |_commit_tx_ctx| {},
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
        ));
    }

    // policy-commitment-version
    #[test]
    fn sign_holder_commitment_tx_with_bad_version_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    tx.version = 3;
                },
            ),
            "policy failure: decode_commitment_tx: bad commitment version: 3"
        );
    }

    // policy-commitment-locktime
    #[test]
    fn sign_holder_commitment_tx_with_bad_locktime_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    tx.lock_time = 42;
                },
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-sequence
    #[test]
    fn sign_holder_commitment_tx_with_bad_sequence_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    tx.input[0].sequence = 42;
                },
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-input-single
    #[test]
    fn sign_holder_commitment_tx_with_bad_numinputs_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    let mut inp2 = tx.input[0].clone();
                    inp2.previous_output.txid = bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
                    tx.input.push(inp2);
                },
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-input-match-funding
    #[test]
    fn sign_holder_commitment_tx_with_input_mismatch_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    tx.input[0].previous_output.txid =
                        bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
                },
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-revocation-pubkey
    #[test]
    fn sign_holder_commitment_tx_with_bad_revpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |keys| {
                    keys.revocation_key = make_test_pubkey(42);
                },
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-htlc-counterparty-htlc-pubkey`
    #[test]
    fn sign_holder_commitment_tx_with_bad_htlcpubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |keys| {
                    keys.countersignatory_htlc_key = make_test_pubkey(42);
                },
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    // policy-commitment-broadcaster-pubkey
    #[test]
    fn sign_holder_commitment_tx_with_bad_delayed_pubkey_test() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |keys| {
                    keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
                },
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: recomposed tx mismatch"
        );
    }

    #[test]
    fn sign_holder_commitment_tx_after_mutual_close() {
        assert_status_ok!(sign_holder_commitment_tx_with_mutators(
            |_commit_tx_ctx| {},
            |state| state.mutual_close_signed = true,
            |_keys| {},
            |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
        ));
    }

    // policy-commitment-singular-to-holder
    #[test]
    fn sign_holder_commitment_tx_with_multiple_to_holder() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    // Duplicate the to_holder output
                    let ndx = 4;
                    tx.output.push(tx.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
            ),
            "transaction format: decode_commitment_tx: \
             tx output[5]: more than one to_broadcaster output"
        );
    }

    // policy-commitment-singular-to-counterparty
    #[test]
    fn sign_holder_commitment_tx_with_multiple_to_counterparty() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_with_mutators(
                |_commit_tx_ctx| {},
                |_state| {},
                |_keys| {},
                |_cstate, tx, witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {
                    // Duplicate the to_counterparty output
                    let ndx = 3;
                    tx.output.push(tx.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
            ),
            "transaction format: decode_commitment_tx: \
             tx output[5]: more than one to_countersigner output"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_holder_commitment_tx_retry_success() {
        assert_status_ok!(sign_holder_commitment_tx_retry_with_mutators(
            |_commit_tx_ctx| {},
            |_state| {},
            |_keys| {},
            |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_holder_commitment_tx_retry_with_bad_to_holder() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(
                |commit_tx_ctx| {
                    commit_tx_ctx.to_broadcaster -= 1;
                },
                |_state| {},
                |_keys| {},
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 23 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_holder_commitment_tx_retry_with_bad_to_counterparty() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(
                |commit_tx_ctx| {
                    commit_tx_ctx.to_countersignatory -= 1;
                },
                |_state| {},
                |_keys| {},
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 23 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_holder_commitment_tx_retry_with_bad_offered_htlcs() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(
                |commit_tx_ctx| {
                    // Remove the offered HTLC, give it's value to the first received HTLC.
                    commit_tx_ctx.received_htlcs[0].value_sat =
                        commit_tx_ctx.offered_htlcs[0].value_sat;
                    commit_tx_ctx.offered_htlcs.remove(0);
                },
                |_state| {},
                |_keys| {},
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 23 with changed info"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_holder_commitment_tx_retry_with_bad_received_htlcs() {
        assert_failed_precondition_err!(
            sign_holder_commitment_tx_retry_with_mutators(
                |commit_tx_ctx| {
                    // Remove the first received HTLC, give its value to the offered HTLC.
                    // Remove the offered HTLC, give it's value to the first received HTLC.
                    commit_tx_ctx.offered_htlcs[0].value_sat =
                        commit_tx_ctx.received_htlcs[0].value_sat;
                    commit_tx_ctx.received_htlcs.remove(0);
                },
                |_state| {},
                |_keys| {},
                |_cstate, _tx, _witscripts, _commit_num, _feerate_per_kw, _o_htlcs, _r_htlcs| {},
            ),
            "policy failure: validate_holder_commitment_tx: \
             retry holder commitment 23 with changed info"
        );
    }
}
