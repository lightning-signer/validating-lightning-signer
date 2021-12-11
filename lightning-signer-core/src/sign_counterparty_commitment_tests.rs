#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::util::psbt::serialize::Serialize;
    use lightning::chain::keysinterface::BaseSign;
    use lightning::ln::chan_utils::{
        make_funding_redeemscript, BuiltCommitmentTransaction, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use test_env_log::test;

    use crate::channel::{Channel, ChannelSetup, CommitmentType};
    use crate::policy::validator::{ChainState, EnforcementState};
    use crate::tx::script::get_to_countersignatory_with_anchors_redeemscript;
    use crate::tx::tx::{HTLCInfo2, ANCHOR_SAT};
    use crate::util::crypto_utils::{payload_for_p2wpkh, signature_to_bitcoin_vec};
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    use paste::paste;

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
                let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point).unwrap();
                // fee = 1000
                let commit_num = 23;
                let feerate_per_kw = 0;
                let to_broadcaster = 1_999_000;
                let to_countersignatory = 1_000_000;
                let mut htlcs = vec![];

                // Set the commit_num and revoke_num.
                chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                    commit_num,
                    make_test_pubkey(0x10),
                );
                chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

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
                    &chan.keys.pubkeys().funding_pubkey,
                    &chan.setup.counterparty_points.funding_pubkey,
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
            "d167e8e687f93170e787d210bac57538910050138b7d088684fe7fdcf735bf6d"
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
                    feerate_per_kw,
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

        let (sig, tx) = node
            .with_ready_channel(&channel_id, |chan| {
                let channel_parameters = chan.make_channel_parameters();
                let parameters = channel_parameters.as_counterparty_broadcastable();
                let mut htlcs =
                    Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());
                let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point).unwrap();
                let to_broadcaster_value_sat = 1_000_000;
                let to_countersignatory_value_sat = 1_979_997;
                let redeem_scripts = build_tx_scripts(
                    &keys,
                    to_broadcaster_value_sat,
                    to_countersignatory_value_sat,
                    &mut htlcs,
                    &parameters,
                    &chan.keys.pubkeys().funding_pubkey,
                    &chan.setup.counterparty_points.funding_pubkey,
                )
                .expect("scripts");

                let commit_num = 23;
                let feerate_per_kw = 0;

                // Set the commit_num and revoke_num.
                chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                    commit_num,
                    make_test_pubkey(0x10),
                );
                chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

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
            "98fe7f855e1cc99ca29a7c18caf1b8c6ac81fcdc44a854c60bf1b28d390323c4"
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

        let htlc1 =
            HTLCInfo2 { value_sat: 1, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

        let htlc2 =
            HTLCInfo2 { value_sat: 1, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

        let htlc3 =
            HTLCInfo2 { value_sat: 1, payment_hash: PaymentHash([5; 32]), cltv_expiry: 4 << 16 };

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
                    feerate_per_kw,
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

        // fee = 1000
        let commit_num = 23;
        let to_holder_value_sat = 1_000_000;
        let to_counterparty_value_sat = 1_999_000;

        let tx = node
            .with_ready_channel(&channel_id, |chan| {
                // Set the commit_num and revoke_num.
                chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                    commit_num,
                    make_test_pubkey(0x10),
                );
                chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

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
                    "b7a48f1201c6d5bddf5c2a247a9c622969fc5048e84f0d25b00b8fa40815632b"
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

    #[allow(dead_code)]
    struct TxMutationState<'a> {
        cstate: &'a mut ChainState,
        tx: &'a mut BuiltCommitmentTransaction,
        witscripts: &'a mut Vec<Vec<u8>>,
    }

    fn sign_counterparty_commitment_tx_with_mutators<StateMutator, KeysMutator, TxMutator>(
        commitment_type: CommitmentType,
        statemut: StateMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut TxMutationState),
    {
        let (node, setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(commitment_type);

        let remote_percommitment_point = make_test_pubkey(10);

        let (sig, tx) = node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let commit_num = 23;
            let feerate_per_kw = 0;
            let to_broadcaster = 1_979_997;
            let to_countersignatory = 1_000_000;

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

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
                &chan.keys.pubkeys().funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
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

            let mut cstate = make_test_chain_state();

            // Mutate the transaction and recalculate the txid.
            txmut(&mut TxMutationState {
                cstate: &mut cstate,
                tx: &mut tx,
                witscripts: &mut output_witscripts,
            });
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

    fn sign_counterparty_commitment_tx_phase2_with_mutators<StateMutator, KeysMutator, TxMutator>(
        commitment_type: CommitmentType,
        statemut: StateMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut TxMutationState),
    {
        let (node, setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(commitment_type);

        let remote_percommitment_point = make_test_pubkey(10);

        let (sig, tx) = node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            // fee = 1000
            let commit_num = 23;
            let feerate_per_kw = 0;
            let to_broadcaster = 1_978_997;
            let to_countersignatory = 1_000_000;

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

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
                &chan.keys.pubkeys().funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
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

            let mut cstate = make_test_chain_state();

            // Mutate the transaction and recalculate the txid.
            txmut(&mut TxMutationState {
                cstate: &mut cstate,
                tx: &mut tx,
                witscripts: &mut output_witscripts,
            });
            tx.txid = tx.transaction.txid();

            let (sig, _htlc_sigs) = chan.sign_counterparty_commitment_tx_phase2(
                &remote_percommitment_point,
                commit_num,
                feerate_per_kw,
                to_countersignatory,
                to_broadcaster,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;
            Ok((sig, tx.transaction.clone()))
        })?;

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            sig,
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );

        Ok(())
    }

    #[test]
    fn success_phase2_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_phase2_with_mutators(
            CommitmentType::StaticRemoteKey,
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tms| {
                // don't mutate the tx, should pass
            },
        ));
    }

    #[test]
    fn success_phase1_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            CommitmentType::StaticRemoteKey,
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tms| {
                // don't mutate the tx, should pass
            },
        ));
    }

    #[test]
    fn success_phase2_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_phase2_with_mutators(
            CommitmentType::Anchors,
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tms| {
                // don't mutate the tx, should pass
            },
        ));
    }

    #[test]
    fn success_phase1_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            CommitmentType::Anchors,
            |_state| {
                // don't mutate the signer, should pass
            },
            |_keys| {
                // don't mutate the keys, should pass
            },
            |_tms| {
                // don't mutate the tx, should pass
            },
        ));
    }

    macro_rules! generate_failed_precondition_error_phase1_variations {
        ($name: ident, $sm: expr, $km: expr, $tm: expr, $errmsg: expr) => {
            paste! {
                #[test]
                fn [<$name _phase1_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            CommitmentType::StaticRemoteKey, $sm, $km, $tm),
                        $errmsg
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase1_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            CommitmentType::Anchors, $sm, $km, $tm),
                        $errmsg
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_phase2_variations {
        ($name: ident, $sm: expr, $km: expr, $tm: expr, $errmsg: expr) => {
            paste! {
                #[test]
                fn [<$name _phase2_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_phase2_with_mutators(
                            CommitmentType::StaticRemoteKey, $sm, $km, $tm),
                        $errmsg
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase2_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_phase2_with_mutators(
                            CommitmentType::Anchors, $sm, $km, $tm),
                        $errmsg
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $sm: expr, $km: expr, $tm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_phase1_variations!($name, $sm, $km, $tm, $errmsg);
            generate_failed_precondition_error_phase2_variations!($name, $sm, $km, $tm, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_state {
        ($name: ident, $sm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, $sm, |_| {}, |_| {}, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_phase1_with_mutated_keys {
        ($name: ident, $km: expr, $errmsg: expr) => {
            generate_failed_precondition_error_phase1_variations!(
                $name,
                |_| {},
                $km,
                |_| {},
                $errmsg
            );
        };
    }

    macro_rules! generate_failed_precondition_error_phase1_with_mutated_tx {
        ($name: ident, $tm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_phase1_variations!(
                $name,
                |_| {},
                |_| {},
                $tm,
                $errmsg
            );
        };
    }

    // policy-commitment-previous-revoked
    generate_failed_precondition_error_with_mutated_state!(
        unrevoked_prior,
        |state| {
            state.set_next_counterparty_revoke_num_for_testing(21);
        },
        "policy failure: validate_counterparty_commitment_tx: \
         invalid attempt to sign counterparty commit_num 23 with next_counterparty_revoke_num 21"
    );

    // policy-commitment-version
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_version,
        |tms| {
            tms.tx.transaction.version = 3;
        },
        "policy failure: decode_commitment_tx: bad commitment version: 3"
    );

    // policy-commitment-locktime
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_locktime,
        |tms| {
            tms.tx.transaction.lock_time = 42;
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-sequence
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_sequence,
        |tms| {
            tms.tx.transaction.input[0].sequence = 42;
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-input-single
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_num_inputs,
        |tms| {
            let mut inp2 = tms.tx.transaction.input[0].clone();
            inp2.previous_output.txid = bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
            tms.tx.transaction.input.push(inp2);
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-input-match-funding
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        input_mismatch,
        |tms| {
            tms.tx.transaction.input[0].previous_output.txid =
                bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-revocation-pubkey
    // policy-commitment-htlc-revocation-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_revpubkey,
        |keys| {
            keys.revocation_key = make_test_pubkey(42);
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-htlc-holder-htlc-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_htlcpubkey,
        |keys| {
            keys.countersignatory_htlc_key = make_test_pubkey(42);
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-broadcaster-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_delayed_pubkey,
        |keys| {
            keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
        },
        "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-countersignatory-pubkey
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_countersignatory_pubkey,
        |tms| {
            if tms.tx.transaction.output.len() <= 5 {
                tms.tx.transaction.output[3].script_pubkey =
                    payload_for_p2wpkh(&make_test_pubkey(42)).script_pubkey();
            } else {
                // anchors in effect
                let redeem_script =
                    get_to_countersignatory_with_anchors_redeemscript(&make_test_pubkey(42));
                tms.tx.transaction.output[5].script_pubkey = redeem_script.to_v0_p2wsh();
                tms.witscripts[5] = redeem_script.serialize();
            };
        },
        "policy failure: recomposed tx mismatch"
    );

    generate_failed_precondition_error_with_mutated_state!(
        old_commit_num,
        |state| {
            // Advance both commit_num and revoke_num:
            state.set_next_counterparty_commit_num_for_testing(25, make_test_pubkey(0x10));
            state.set_next_counterparty_revoke_num_for_testing(24);
        },
        "policy failure: set_next_counterparty_commit_num: \
         24 too small relative to next_counterparty_revoke_num 24"
    );

    // policy-commitment-singular-to-holder
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        multiple_to_holder,
        |tms| {
            // Duplicate the to_holder output
            let ndx = tms.tx.transaction.output.len() - 2;
            tms.tx.transaction.output.push(tms.tx.transaction.output[ndx].clone());
            tms.witscripts.push(tms.witscripts[ndx].clone());
        },
        "transaction format: decode_commitment_tx: \
         tx output[5]: more than one to_countersigner output"
    );

    // policy-commitment-singular-to-counterparty
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        multiple_to_counterparty,
        |tms| {
            // Duplicate the to_counterparty output
            let ndx = tms.tx.transaction.output.len() - 1;
            tms.tx.transaction.output.push(tms.tx.transaction.output[ndx].clone());
            tms.witscripts.push(tms.witscripts[ndx].clone());
        },
        "transaction format: decode_commitment_tx: \
         tx output[5]: more than one to_broadcaster output"
    );

    #[allow(dead_code)]
    struct RetryMutationState<'a> {
        cstate: &'a mut ChainState,
        tx: &'a mut bitcoin::Transaction,
        output_witscripts: &'a mut Vec<Vec<u8>>,
        remote_percommitment_point: &'a mut PublicKey,
        feerate_per_kw: &'a mut u32,
        offered_htlcs: &'a mut Vec<HTLCInfo2>,
        received_htlcs: &'a mut Vec<HTLCInfo2>,
    }

    fn sign_counterparty_commitment_tx_retry_with_mutator<SignCommitmentMutator>(
        commitment_type: CommitmentType,
        sign_comm_mut: SignCommitmentMutator,
    ) -> Result<(), Status>
    where
        SignCommitmentMutator: Fn(&mut RetryMutationState),
    {
        let (node, _setup, channel_id, offered_htlcs0, received_htlcs0) =
            sign_commitment_tx_with_mutators_setup(commitment_type);

        node.with_ready_channel(&channel_id, |chan| {
            let mut offered_htlcs = offered_htlcs0.clone();
            let mut received_htlcs = received_htlcs0.clone();
            let channel_parameters = chan.make_channel_parameters();

            let mut remote_percommitment_point = make_test_pubkey(10);

            let commit_num = 23;
            let mut feerate_per_kw = 0;
            let to_broadcaster = 1_979_997;
            let to_countersignatory = 1_000_000;
            let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point)?;

            let redeem_scripts = build_tx_scripts(
                &keys,
                to_countersignatory,
                to_broadcaster,
                &htlcs,
                &parameters,
                &chan.keys.pubkeys().funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
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

            let mut cstate = make_test_chain_state();

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
            sign_comm_mut(&mut RetryMutationState {
                cstate: &mut cstate,
                tx: &mut tx.transaction,
                output_witscripts: &mut output_witscripts,
                remote_percommitment_point: &mut remote_percommitment_point,
                feerate_per_kw: &mut feerate_per_kw,
                offered_htlcs: &mut offered_htlcs,
                received_htlcs: &mut received_htlcs,
            });

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

    // policy-commitment-retry-same
    #[test]
    fn sign_counterparty_commitment_tx_retry_same() {
        assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
            CommitmentType::StaticRemoteKey,
            |_cms| {
                // If we don't mutate anything it should succeed.
            }
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_counterparty_commitment_tx_retry_with_bad_point() {
        assert_failed_precondition_err!(
            sign_counterparty_commitment_tx_retry_with_mutator(
                CommitmentType::StaticRemoteKey,
                |cms| {
                    *cms.remote_percommitment_point = make_test_pubkey(42);
                }
            ),
            "policy failure: validate_counterparty_commitment_tx: \
             retry of sign_counterparty_commitment 23 with changed point: \
             prev 03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e != \
             new 035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
        );
    }

    // policy-commitment-retry-same
    #[test]
    fn sign_counterparty_commitment_tx_retry_with_removed_htlc() {
        assert_failed_precondition_err!(
            sign_counterparty_commitment_tx_retry_with_mutator(
                CommitmentType::StaticRemoteKey,
                |cms| {
                    // Remove the last received HTLC
                    let htlc = cms.received_htlcs.pop().unwrap();

                    // Credit the value to the broadcaster
                    cms.tx.output[3].value += htlc.value_sat;

                    // Remove the htlc from the tx and witscripts
                    cms.tx.output.remove(2);
                    cms.output_witscripts.remove(2);
                }
            ),
            "policy failure: validate_counterparty_commitment_tx: \
             retry of sign_counterparty_commitment 23 with changed info"
        );
    }
}
