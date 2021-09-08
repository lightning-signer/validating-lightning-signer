#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::util::psbt::serialize::Serialize;
    use lightning::ln::chan_utils::{
        make_funding_redeemscript, BuiltCommitmentTransaction, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use test_env_log::test;

    use crate::channel::{Channel, ChannelSetup, CommitmentType};
    use crate::policy::validator::EnforcementState;
    use crate::tx::tx::{HTLCInfo2, ANCHOR_SAT};
    use crate::util::crypto_utils::{payload_for_p2wpkh, signature_to_bitcoin_vec};
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn sign_counterparty_commitment_tx_static_test() {
        let setup = make_test_channel_setup();
        sign_counterparty_commitment_tx_test(&setup);
    }

    #[test]
    fn sign_counterparty_commitment_tx_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_counterparty_commitment_tx_test(&setup);
    }

    fn sign_counterparty_commitment_tx_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();
        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let keys = chan
                    .make_counterparty_tx_keys(&remote_percommitment_point)
                    .unwrap();
                let commit_num = 23;
                let feerate_per_kw = 0;
                let to_broadcaster = 2_000_000;
                let to_countersignatory = 1_000_000;
                let mut htlcs = vec![];

                // Set the commit_num and revoke_num.
                chan.enforcement_state
                    .set_next_counterparty_commit_num_for_testing(
                        commit_num,
                        make_test_pubkey(0x10),
                    );
                chan.enforcement_state
                    .set_next_counterparty_revoke_num_for_testing(commit_num - 1);

                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_broadcaster,
                    to_countersignatory,
                    htlcs.clone(),
                );

                let redeem_scripts = build_tx_scripts(
                    &keys,
                    to_countersignatory,
                    to_broadcaster,
                    &mut htlcs,
                    &parameters,
                )
                .expect("scripts");
                let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

                // rebuild to get the scripts
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();

                let sig = chan
                    .sign_counterparty_commitment_tx(
                        &tx.transaction,
                        &output_witscripts,
                        &remote_percommitment_point,
                        commit_num,
                        feerate_per_kw,
                        vec![],
                        vec![],
                    )
                    .expect("sign");
                Ok((sig, tx.transaction.clone()))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            tx.txid().to_hex(),
            "770f45e5093d10ed3c7dc05f152bcf954200015cca98e701811714b6a4132b38"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

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
    #[ignore] // we don't support anchors yet
    fn sign_counterparty_commitment_tx_with_anchors_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();
        let to_counterparty_value_sat = 2_000_000;
        let to_holder_value_sat =
            setup.channel_value_sat - to_counterparty_value_sat - (2 * ANCHOR_SAT);
        let feerate_per_kw = 0;
        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let info = chan.build_counterparty_commitment_info(
                    &remote_percommitment_point,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                    vec![],
                )?;
                let commit_num = 23;
                let (tx, output_scripts, _) =
                    chan.build_commitment_tx(&remote_percommitment_point, commit_num, &info)?;
                let output_witscripts = output_scripts.iter().map(|s| s.serialize()).collect();
                let sig = chan
                    .sign_counterparty_commitment_tx(
                        &tx,
                        &output_witscripts,
                        &remote_percommitment_point,
                        commit_num,
                        feerate_per_kw,
                        vec![],
                        vec![],
                    )
                    .expect("sign");
                Ok((sig, tx))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            tx.txid().to_hex(),
            "68a0916cea22e66438f0cd2c50f667866ebd16f59ba395352602bd817d6c0fd9"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

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
    fn sign_counterparty_commitment_tx_with_htlc_static_test() {
        let setup = make_test_channel_setup();
        sign_counterparty_commitment_tx_with_htlc_test(&setup);
    }

    #[test]
    fn sign_counterparty_commitment_tx_with_htlc_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_counterparty_commitment_tx_with_htlc_test(&setup);
    }

    fn sign_counterparty_commitment_tx_with_htlc_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();

        let htlc1 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([1; 32]),
            cltv_expiry: 2 << 16,
        };

        let htlc2 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([3; 32]),
            cltv_expiry: 3 << 16,
        };

        let htlc3 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
        };

        let offered_htlcs = vec![htlc1];
        let received_htlcs = vec![htlc2, htlc3];

        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let mut htlcs =
                    Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());
                let keys = chan
                    .make_counterparty_tx_keys(&remote_percommitment_point)
                    .unwrap();
                let to_broadcaster_value_sat = 1_000_000;
                let to_countersignatory_value_sat = 1_999_997;
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    to_broadcaster_value_sat,
                    to_countersignatory_value_sat,
                    &mut htlcs,
                    &parameters,
                )
                .expect("scripts");

                let commit_num = 23;
                let feerate_per_kw = 0;

                // Set the commit_num and revoke_num.
                chan.enforcement_state
                    .set_next_counterparty_commit_num_for_testing(
                        commit_num,
                        make_test_pubkey(0x10),
                    );
                chan.enforcement_state
                    .set_next_counterparty_revoke_num_for_testing(commit_num - 1);

                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_countersignatory_value_sat,
                    to_broadcaster_value_sat,
                    htlcs,
                );
                // rebuild to get the scripts
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();
                let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();
                let sig = chan
                    .sign_counterparty_commitment_tx(
                        &tx.transaction,
                        &output_witscripts,
                        &remote_percommitment_point,
                        commit_num,
                        feerate_per_kw,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                    .expect("sign");
                Ok((sig, tx.transaction.clone()))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            tx.txid().to_hex(),
            "3f3238ed033a13ab1cf43d8eb6e81e5beca2080f9530a13931c10f40e04697fb"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

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
    #[ignore] // we don't support anchors yet
    fn sign_counterparty_commitment_tx_with_htlc_and_anchors_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let counterparty_points = make_test_counterparty_points();

        let htlc1 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([1; 32]),
            cltv_expiry: 2 << 16,
        };

        let htlc2 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([3; 32]),
            cltv_expiry: 3 << 16,
        };

        let htlc3 = HTLCInfo2 {
            value_sat: 1,
            payment_hash: PaymentHash([5; 32]),
            cltv_expiry: 4 << 16,
        };

        let offered_htlcs = vec![htlc1.clone()];
        let received_htlcs = vec![htlc2.clone(), htlc3.clone()];
        let feerate_per_kw = 0;

        let to_counterparty_value_sat = 2_000_000;
        let to_holder_value_sat =
            setup.channel_value_sat - to_counterparty_value_sat - 3 - (2 * ANCHOR_SAT);

        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let info = chan.build_counterparty_commitment_info(
                    &remote_percommitment_point,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?;
                let commit_num = 23;
                let (tx, output_scripts, _) =
                    chan.build_commitment_tx(&remote_percommitment_point, commit_num, &info)?;
                let output_witscripts = output_scripts.iter().map(|s| s.serialize()).collect();
                let sig = chan
                    .sign_counterparty_commitment_tx(
                        &tx,
                        &output_witscripts,
                        &remote_percommitment_point,
                        commit_num,
                        feerate_per_kw,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                    .expect("sign");
                Ok((sig, tx))
            })
            .expect("build_commitment_tx");

        assert_eq!(
            tx.txid().to_hex(),
            "52aa09518edbdbd77ca56790efbb9392710c3bed10d7d27b04d98f6f6d8a207d"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

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
    fn sign_counterparty_commitment_tx_phase2_static_test() {
        let setup = make_test_channel_setup();
        sign_counterparty_commitment_tx_phase2_test(&setup);
    }

    #[test]
    fn sign_counterparty_commitment_tx_phase2_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_counterparty_commitment_tx_phase2_test(&setup);
    }

    fn sign_counterparty_commitment_tx_phase2_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);

        let commit_num = 23;
        let to_holder_value_sat = 1_000_000;
        let to_counterparty_value_sat = 2_000_000;

        let tx = node
            .with_ready_channel(&channel_id, |chan| {
                // Set the commit_num and revoke_num.
                chan.enforcement_state
                    .set_next_counterparty_commit_num_for_testing(
                        commit_num,
                        make_test_pubkey(0x10),
                    );
                chan.enforcement_state
                    .set_next_counterparty_revoke_num_for_testing(commit_num - 1);

                let commitment_tx = chan.make_counterparty_commitment_tx(
                    &remote_percommitment_point,
                    commit_num,
                    0,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                );
                let trusted_tx = commitment_tx.trust();
                let tx = trusted_tx.built_transaction();
                assert_eq!(
                    tx.txid.to_hex(),
                    "75a87d13138017f2c62c86be375e526821a40805e5f31808bf782ce7e13fe951"
                );
                Ok(tx.transaction.clone())
            })
            .expect("build");
        let (ser_signature, _) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_counterparty_commitment_tx_phase2(
                    &remote_percommitment_point,
                    commit_num,
                    0, // we are not looking at HTLCs yet
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    vec![],
                    vec![],
                )
            })
            .expect("sign");
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

    fn sign_counterparty_commitment_tx_with_mutators<StateMutator, KeysMutator, TxMutator>(
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

        let remote_percommitment_point = make_test_pubkey(10);

        let (sig, tx) = node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let commit_num = 23;
            let feerate_per_kw = 0;
            let to_broadcaster = 1_999_997;
            let to_countersignatory = 1_000_000;

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state
                .set_next_counterparty_revoke_num_for_testing(commit_num - 1);

            // Mutate the signer state.
            statemut(&mut chan.enforcement_state);

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let mut keys = chan.make_counterparty_tx_keys(&remote_percommitment_point)?;

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

            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                keys,
                commit_num,
                feerate_per_kw,
                to_countersignatory,
                to_broadcaster,
                htlcs.clone(),
            );

            // rebuild to get the scripts
            let trusted_tx = commitment_tx.trust();
            let mut tx = trusted_tx.built_transaction().clone();

            // Mutate the transaction and recalculate the txid.
            txmut(&mut tx, &mut output_witscripts);
            tx.txid = tx.transaction.txid();

            let sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommitment_point,
                commit_num,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;
            Ok((sig, tx.transaction.clone()))
        })?;

        assert_eq!(
            tx.txid().to_hex(),
            "1a5988ac95fffa4f92cc22ea96cc0b6e4cbd2752dd796596b56c32baba1f792d"
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
    fn sign_counterparty_commitment_tx_with_no_mut_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_version_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_locktime_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_sequence_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_numinputs_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_input_mismatch_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_revpubkey_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
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
    fn sign_counterparty_commitment_tx_with_bad_htlcpubkey_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
            |_state| {},
            |keys| {
                keys.countersignatory_htlc_key = make_test_pubkey(42);
            },
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-broadcaster-pubkey
    #[test]
    fn sign_counterparty_commitment_tx_with_bad_delayed_pubkey_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
            |_state| {},
            |keys| {
                keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
            },
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-countersignatory-pubkey
    #[test]
    fn sign_counterparty_commitment_tx_with_bad_countersignatory_pubkey_test() {
        let status = sign_counterparty_commitment_tx_with_mutators(
            |_state| {},
            |_keys| {},
            |tx, _witscripts| {
                tx.transaction.output[3].script_pubkey =
                    payload_for_p2wpkh(&make_test_pubkey(42)).script_pubkey();
            },
        );
        assert_failed_precondition_err!(status, "policy failure: recomposed tx mismatch");
    }

    // policy-commitment-previous-revoked
    #[test]
    fn sign_counterparty_commitment_tx_with_unrevoked_prior() {
        let status = sign_counterparty_commitment_tx_with_mutators(
            |state| {
                state.set_next_counterparty_revoke_num_for_testing(21);
            },
            |_keys| {},
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(
            status,
            "policy failure: validate_commitment_tx: invalid attempt \
             to sign counterparty commit_num 23 \
             with next_counterparty_revoke_num 21"
        );
    }

    #[test]
    fn sign_counterparty_commitment_tx_with_old_commit_num() {
        let status = sign_counterparty_commitment_tx_with_mutators(
            |state| {
                // Advance both commit_num and revoke_num:
                state.set_next_counterparty_commit_num_for_testing(25, make_test_pubkey(0x10));
                state.set_next_counterparty_revoke_num_for_testing(24);
            },
            |_keys| {},
            |_tx, _witscripts| {},
        );
        assert_failed_precondition_err!(
            status,
            "policy failure: set_next_counterparty_commit_num: \
             24 too small relative to next_counterparty_revoke_num 24"
        );
    }

    // policy-commitment-singular-to-holder
    #[test]
    fn sign_counterparty_commitment_tx_with_multiple_to_holder() {
        assert_failed_precondition_err!(
            sign_counterparty_commitment_tx_with_mutators(
                |_state| {},
                |_keys| {},
                |tx, witscripts| {
                    // Duplicate the to_holder output
                    let ndx = 3;
                    tx.transaction
                        .output
                        .push(tx.transaction.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
            ),
            "policy failure: tx output[5]: \
             TransactionFormat(\"more than one to_countersigner output\")"
        );
    }

    // policy-commitment-singular-to-counterparty
    #[test]
    fn sign_counterparty_commitment_tx_with_multiple_to_counterparty() {
        assert_failed_precondition_err!(
            sign_counterparty_commitment_tx_with_mutators(
                |_state| {},
                |_keys| {},
                |tx, witscripts| {
                    // Duplicate the to_counterparty output
                    let ndx = 4;
                    tx.transaction
                        .output
                        .push(tx.transaction.output[ndx].clone());
                    witscripts.push(witscripts[ndx].clone());
                },
            ),
            "policy failure: tx output[5]: \
             TransactionFormat(\"more than one to_broadcaster output\")"
        );
    }

    fn sign_counterparty_commitment_tx_retry_with_mutator<SignCommitmentMutator>(
        sign_comm_mut: SignCommitmentMutator,
    ) -> Result<(), Status>
    where
        SignCommitmentMutator: Fn(
            &mut bitcoin::Transaction,
            &mut Vec<Vec<u8>>,
            &mut PublicKey,
            &mut u32,
            &mut Vec<HTLCInfo2>,
            &mut Vec<HTLCInfo2>,
        ),
    {
        let (node, _setup, channel_id, offered_htlcs0, received_htlcs0) =
            sign_commitment_tx_with_mutators_setup();

        node.with_ready_channel(&channel_id, |chan| {
            let mut offered_htlcs = offered_htlcs0.clone();
            let mut received_htlcs = received_htlcs0.clone();
            let channel_parameters = chan.make_channel_parameters();

            let mut remote_percommitment_point = make_test_pubkey(10);

            let commit_num = 23;
            let mut feerate_per_kw = 0;
            let to_broadcaster = 1_999_997;
            let to_countersignatory = 1_000_000;
            let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state
                .set_next_counterparty_revoke_num_for_testing(commit_num - 1);

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point)?;

            let redeem_scripts = build_tx_scripts(
                &keys,
                to_countersignatory,
                to_broadcaster,
                &htlcs,
                &parameters,
            )
            .expect("scripts");
            let mut output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
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

            // Sign the commitment the first time.
            let _sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommitment_point,
                commit_num,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;

            // Mutate the arguments to the commitment.
            sign_comm_mut(
                &mut tx.transaction,
                &mut output_witscripts,
                &mut remote_percommitment_point,
                &mut feerate_per_kw,
                &mut offered_htlcs,
                &mut received_htlcs,
            );

            // Sign it again (retry).
            let _sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommitment_point,
                commit_num,
                feerate_per_kw,
                offered_htlcs,
                received_htlcs,
            )?;

            Ok(())
        })
    }

    #[test]
    fn sign_counterparty_commitment_tx_retry_same() {
        assert!(sign_counterparty_commitment_tx_retry_with_mutator(
            |_tx,
             _output_witscripts,
             _remote_percommitment_point,
             _feerate_per_kw,
             _offered_htlcs,
             _received_htlcs| {
                // If we don't mutate anything it should succeed.
            }
        )
        .is_ok());
    }

    // policy-commitment-retry-same (remote_percommitment_point)
    #[test]
    fn sign_counterparty_commitment_tx_retry_with_bad_point() {
        assert_failed_precondition_err!(
            sign_counterparty_commitment_tx_retry_with_mutator(
                |_tx,
                 _output_witscripts,
                 remote_percommitment_point,
                 _feerate_per_kw,
                 _offered_htlcs,
                 _received_htlcs| {
                    *remote_percommitment_point = make_test_pubkey(42);
                }
            ),
            "policy failure: validate_commitment_tx: \
             retry of sign_counterparty_commitment 23 with changed point: \
             prev 03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e != \
             new 035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
        );
    }
}
