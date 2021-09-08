#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::util::psbt::serialize::Serialize;
    use lightning::ln::chan_utils::{
        make_funding_redeemscript, BuiltCommitmentTransaction, TxCreationKeys,
    };

    use test_env_log::test;

    use crate::channel::{Channel, ChannelBase, ChannelSetup, CommitmentType};
    use crate::policy::validator::EnforcementState;
    use crate::util::crypto_utils::signature_to_bitcoin_vec;
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
                let to_broadcaster = 2_000_000;
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

                let sig = chan
                    .sign_holder_commitment_tx(
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
            "566333b63b2696cd51516dee93baa01243a0c0f17d646da1d1450a4f98de6a5e"
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
        let to_counterparty_value_sat = 2_000_000;
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
            "deb063aa75d0a43fecd8330a150dce8fd794d835c0b6db97b755cb8cfa3803fc"
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

    fn sign_holder_commitment_tx_with_mutators<StateMutator, KeysMutator, TxMutator>(
        statemut: StateMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut BuiltCommitmentTransaction, &mut Vec<Vec<u8>>),
    {
        let (node, setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup();

        let (sig, tx) = node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let commit_num = 23;
            let feerate_per_kw = 0;
            let to_broadcaster = 1_999_997;
            let to_countersignatory = 1_000_000;

            chan.enforcement_state
                .set_next_holder_commit_num_for_testing(commit_num);

            // Mutate the signer state.
            statemut(&mut chan.enforcement_state);

            let parameters = channel_parameters.as_holder_broadcastable();

            let per_commitment_point = chan.get_per_commitment_point(commit_num).expect("point");
            let mut keys = chan.make_holder_tx_keys(&per_commitment_point)?;

            // Mutate the tx creation keys.
            keysmut(&mut keys);

            let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

            let redeem_scripts = build_tx_scripts(
                &keys,
                to_broadcaster,
                to_countersignatory,
                &htlcs,
                &parameters,
            )
            .expect("scripts");
            let mut output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let commitment_tx = chan.make_holder_commitment_tx_with_keys(
                keys,
                commit_num,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );
            // rebuild to get the scripts
            let trusted_tx = commitment_tx.trust();
            let mut tx = trusted_tx.built_transaction().clone();

            // Mutate the transaction and recalculate the txid.
            txmut(&mut tx, &mut output_witscripts);
            tx.txid = tx.transaction.txid();

            let sig = chan.sign_holder_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                commit_num,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;
            Ok((sig, tx.transaction.clone()))
        })?;

        assert_eq!(
            tx.txid().to_hex(),
            "f438eac18af86e17f7dd74a8630e7427fefb2d81becb0ae563914a4e3e9aef9f"
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

        Ok(())
    }

    #[test]
    fn sign_holder_commitment_tx_with_no_mut_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tx, _witscripts| {
                // don't mutate the tx, should pass
            },
        );
        assert!(status.is_ok());
    }

    // policy-commitment-version
    #[test]
    fn sign_holder_commitment_tx_with_bad_version_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {},
            |tx, _witscripts| {
                tx.transaction.version = 3;
            },
        );
        assert_failed_precondition_err!(
            status,
            "policy failure: make_info: bad commitment version: 3"
        );
    }

    // policy-commitment-locktime
    #[test]
    fn sign_holder_commitment_tx_with_bad_locktime_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {
                // don't mutate the keys
            },
            |tx, _witscripts| {
                tx.transaction.lock_time = 42;
            },
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-sequence
    #[test]
    fn sign_holder_commitment_tx_with_bad_sequence_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {},
            |tx, _witscripts| {
                tx.transaction.input[0].sequence = 42;
            },
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-input-single
    #[test]
    fn sign_holder_commitment_tx_with_bad_numinputs_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {},
            |tx, _witscripts| {
                let mut inp2 = tx.transaction.input[0].clone();
                inp2.previous_output.txid = bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
                tx.transaction.input.push(inp2);
            },
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-input-match-funding
    #[test]
    fn sign_holder_commitment_tx_with_input_mismatch_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {},
            |tx, _witscripts| {
                tx.transaction.input[0].previous_output.txid =
                    bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
            },
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-revocation-pubkey
    #[test]
    fn sign_holder_commitment_tx_with_bad_revpubkey_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |keys| {
                keys.revocation_key = make_test_pubkey(42);
            },
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-htlc-pubkey
    #[test]
    fn sign_holder_commitment_tx_with_bad_htlcpubkey_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |keys| {
                keys.countersignatory_htlc_key = make_test_pubkey(42);
            },
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-delayed-pubkey
    #[test]
    fn sign_holder_commitment_tx_with_bad_delayed_pubkey_test() {
        let status = sign_holder_commitment_tx_with_mutators(
            |_state| {},
            |keys| {
                keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
            },
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    #[test]
    fn sign_holder_commitment_tx_after_mutual_close() {
        let status = sign_holder_commitment_tx_with_mutators(
            |state| state.mutual_close_signed = true,
            |_keys| {},
            |_tx, _witscripts| {},
        );
        assert!(status.is_ok());
    }
}
