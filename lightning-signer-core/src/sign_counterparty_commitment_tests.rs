#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::Network;
    use bitcoin::{PackedLockTime, Sequence};
    use lightning::chain::keysinterface::BaseSign;
    use lightning::ln::chan_utils::{
        make_funding_redeemscript, BuiltCommitmentTransaction,
        DirectedChannelTransactionParameters, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use std::sync::Arc;
    use test_log::test;

    use crate::channel::{Channel, ChannelBalance, ChannelSetup, CommitmentType, TypedSignature};
    use crate::node::NodeMonitor;
    use crate::policy::validator::{ChainState, EnforcementState};
    use crate::tx::script::get_to_countersignatory_with_anchors_redeemscript;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::crypto_utils::payload_for_p2wpkh;
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    use crate::node::Node;
    use crate::policy::filter::PolicyFilter;
    use crate::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
    use paste::paste;

    #[allow(unused_imports)]
    use log::debug;

    fn disable_policies(node: &Arc<Node>) {
        let mut policy = make_simple_policy(Network::Testnet);
        policy.filter = PolicyFilter::new_permissive();
        *node.validator_factory.lock().unwrap() =
            Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    }

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
            "1645eee89d5a231702eda1c1b02dee7d42742c8b763c731b7b4cf7936054eae6"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            TypedSignature::all(sig),
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
            "08491fe78992b402bbc51771386395fc81bf20d0178b4156bc039b5a84e92aea"
        );

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            TypedSignature::all(sig),
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
                    "3b157ff3091373a904ccf571f913eef9bdb94b9a6acda0651df2c240c63df22b"
                );
                Ok(tx.transaction.clone())
            })
            .expect("build");
        let (signature, _) = node
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
            TypedSignature::all(signature),
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );
    }

    #[allow(dead_code)]
    struct TxMutationState<'a> {
        opt_anchors: bool,
        cstate: &'a mut ChainState,
        tx: &'a mut BuiltCommitmentTransaction,
        witscripts: &'a mut Vec<Vec<u8>>,
    }

    fn sign_counterparty_commitment_tx_with_mutators<
        StateMutator,
        KeysMutator,
        TxMutator,
        NodeMutator,
    >(
        is_phase2: bool,
        commitment_type: CommitmentType,
        statemut: StateMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
        nodemut: NodeMutator,
    ) -> Result<(), Status>
    where
        NodeMutator: Fn(&Arc<Node>),
        StateMutator: Fn(&mut EnforcementState),
        KeysMutator: Fn(&mut TxCreationKeys),
        TxMutator: Fn(&mut TxMutationState),
    {
        let (node, setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(commitment_type);
        nodemut(&node);

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
                opt_anchors: commitment_type == CommitmentType::Anchors,
                cstate: &mut cstate,
                tx: &mut tx,
                witscripts: &mut output_witscripts,
            });
            tx.txid = tx.transaction.txid();

            let sig = if !is_phase2 {
                chan.sign_counterparty_commitment_tx(
                    &tx.transaction,
                    &output_witscripts,
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
            } else {
                chan.sign_counterparty_commitment_tx_phase2(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_countersignatory,
                    to_broadcaster,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
                .0
            };

            Ok((sig, tx.transaction.clone()))
        })?;

        // no holder commitment, balance is "opening"
        assert_eq!(node.channel_balance(), ChannelBalance::new(0, 0, 0, 0));

        let funding_pubkey = get_channel_funding_pubkey(&node, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &setup.counterparty_points.funding_pubkey);

        check_signature(
            &tx,
            0,
            TypedSignature::all(sig),
            &funding_pubkey,
            setup.channel_value_sat,
            &channel_funding_redeemscript,
        );

        Ok(())
    }

    #[test]
    fn success_phase2_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            true, // is_phase2
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
            |_node| {
                // don't mutate the node
            },
        ));
    }

    #[test]
    fn success_phase1_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            false, // is_phase2
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
            |_node| {
                // don't mutate the node
            },
        ));
    }

    #[test]
    fn success_phase2_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            true, // is_phase2
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
            |_node| {
                // don't mutate the node
            },
        ));
    }

    #[test]
    fn success_phase1_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
            false, // is_phase2
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
            |_node| {
                // don't mutate the node
            },
        ));
    }

    #[allow(dead_code)]
    struct ErrMsgContext {
        is_phase2: bool,
        opt_anchors: bool,
    }
    const ERR_MSG_CONTEXT_PHASE1_STATIC: ErrMsgContext =
        ErrMsgContext { is_phase2: false, opt_anchors: false };
    const ERR_MSG_CONTEXT_PHASE1_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_phase2: false, opt_anchors: true };
    const ERR_MSG_CONTEXT_PHASE2_STATIC: ErrMsgContext =
        ErrMsgContext { is_phase2: true, opt_anchors: false };
    const ERR_MSG_CONTEXT_PHASE2_ANCHORS: ErrMsgContext =
        ErrMsgContext { is_phase2: true, opt_anchors: true };

    macro_rules! generate_failed_precondition_error_phase1_variations {
        ($name: ident, $sm: expr, $km: expr, $tm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _phase1_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $sm, $km, $tm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE1_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase1_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            false, CommitmentType::Anchors, $sm, $km, $tm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE1_ANCHORS)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_phase2_variations {
        ($name: ident, $sm: expr, $km: expr, $tm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _phase2_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $sm, $km, $tm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE2_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase2_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_with_mutators(
                            true, CommitmentType::Anchors, $sm, $km, $tm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE2_ANCHORS)
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
            paste! {
                #[test]
                fn [<$name _phase2_static_warn>]() {
                    assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
                        true, // is_phase2
                        CommitmentType::StaticRemoteKey,
                        $sm,
                        |_| {},
                        |_| {},
                        disable_policies,
                    ));
                }
            }
            paste! {
                #[test]
                fn [<$name _phase1_static_warn>]() {
                    assert_status_ok!(sign_counterparty_commitment_tx_with_mutators(
                        false,
                        CommitmentType::StaticRemoteKey,
                        $sm,
                        |_| {},
                        |_| {},
                        disable_policies,
                    ));
                }
            }
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
        |_| "policy failure: validate_counterparty_commitment_tx: \
         invalid attempt to sign counterparty commit_num 23 with next_counterparty_revoke_num 21"
    );

    // policy-commitment-version
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_version,
        |tms| {
            tms.tx.transaction.version = 3;
        },
        |_| "policy failure: decode_commitment_tx: bad commitment version: 3"
    );

    // policy-commitment-locktime
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_locktime,
        |tms| {
            tms.tx.transaction.lock_time = PackedLockTime(42);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-sequence
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_sequence,
        |tms| {
            tms.tx.transaction.input[0].sequence = Sequence(42);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-input-single
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_num_inputs,
        |tms| {
            let mut inp2 = tms.tx.transaction.input[0].clone();
            inp2.previous_output.txid = bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
            tms.tx.transaction.input.push(inp2);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-input-match-funding
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        input_mismatch,
        |tms| {
            tms.tx.transaction.input[0].previous_output.txid =
                bitcoin::Txid::from_slice(&[3u8; 32]).unwrap();
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-revocation-pubkey
    // policy-commitment-htlc-revocation-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_revpubkey,
        |keys| {
            keys.revocation_key = make_test_pubkey(42);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-htlc-holder-htlc-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_htlcpubkey,
        |keys| {
            keys.countersignatory_htlc_key = make_test_pubkey(42);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-broadcaster-pubkey
    generate_failed_precondition_error_phase1_with_mutated_keys!(
        bad_delayed_pubkey,
        |keys| {
            keys.broadcaster_delayed_payment_key = make_test_pubkey(42);
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    // policy-commitment-countersignatory-pubkey
    generate_failed_precondition_error_phase1_with_mutated_tx!(
        bad_countersignatory_pubkey,
        |tms| {
            if tms.opt_anchors {
                let redeem_script =
                    get_to_countersignatory_with_anchors_redeemscript(&make_test_pubkey(42));
                tms.tx.transaction.output[5].script_pubkey = redeem_script.to_v0_p2wsh();
                tms.witscripts[5] = redeem_script.serialize();
            } else {
                tms.tx.transaction.output[3].script_pubkey =
                    payload_for_p2wpkh(&make_test_pubkey(42)).script_pubkey();
            };
        },
        |_| "policy failure: recomposed tx mismatch"
    );

    generate_failed_precondition_error_with_mutated_state!(
        old_commit_num,
        |state| {
            // Advance both commit_num and revoke_num:
            state.set_next_counterparty_commit_num_for_testing(25, make_test_pubkey(0x10));
            state.set_next_counterparty_revoke_num_for_testing(24);
        },
        |_| "policy failure: set_next_counterparty_commit_num: \
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
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
                        tx output[{}]: more than one to_countersigner output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
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
        |ectx: ErrMsgContext| format!(
            "transaction format: decode_commitment_tx: \
                        tx output[{}]: more than one to_broadcaster output",
            if ectx.opt_anchors { 7 } else { 5 }
        )
    );

    #[allow(dead_code)]
    struct RetryMutationState<'a> {
        cstate: &'a mut ChainState,
        remote_percommitment_point: &'a mut PublicKey,
        feerate_per_kw: &'a mut u32,
        offered_htlcs: &'a mut Vec<HTLCInfo2>,
        received_htlcs: &'a mut Vec<HTLCInfo2>,
    }

    fn sign_counterparty_commitment_tx_retry_with_mutator<SignCommitmentMutator, NodeMutator>(
        is_phase2: bool,
        commitment_type: CommitmentType,
        sign_comm_mut: SignCommitmentMutator,
        nodemut: NodeMutator,
    ) -> Result<(), Status>
    where
        NodeMutator: Fn(&Arc<Node>),
        SignCommitmentMutator: Fn(&mut RetryMutationState),
    {
        let (node, _setup, channel_id, offered_htlcs0, received_htlcs0) =
            sign_commitment_tx_with_mutators_setup(commitment_type);

        nodemut(&node);

        node.with_ready_channel(&channel_id, |chan| {
            let mut offered_htlcs = offered_htlcs0.clone();
            let mut received_htlcs = received_htlcs0.clone();
            let channel_parameters = chan.make_channel_parameters();

            let mut remote_percommitment_point = make_test_pubkey(10);

            let commit_num = 23;
            let mut feerate_per_kw = 0;
            let to_broadcaster = 1_979_997;
            let to_countersignatory = 1_000_000;

            chan.enforcement_state
                .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point)?;

            let (output_witscripts, tx) = create_tx(
                chan,
                &offered_htlcs,
                &received_htlcs,
                commit_num,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                &parameters,
                keys.clone(),
            );

            let mut cstate = make_test_chain_state();

            // Sign the commitment the first time.
            let _sig = if !is_phase2 {
                chan.sign_counterparty_commitment_tx(
                    &tx.transaction,
                    &output_witscripts,
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
            } else {
                chan.sign_counterparty_commitment_tx_phase2(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_countersignatory,
                    to_broadcaster,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
                .0
            };

            // Mutate the arguments to the commitment.
            sign_comm_mut(&mut RetryMutationState {
                cstate: &mut cstate,
                remote_percommitment_point: &mut remote_percommitment_point,
                feerate_per_kw: &mut feerate_per_kw,
                offered_htlcs: &mut offered_htlcs,
                received_htlcs: &mut received_htlcs,
            });

            let keys = chan.make_counterparty_tx_keys(&remote_percommitment_point)?;
            let (output_witscripts, tx) = create_tx(
                chan,
                &offered_htlcs,
                &received_htlcs,
                commit_num,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                &parameters,
                keys,
            );

            // Sign it again (retry).
            let _sig = if !is_phase2 {
                chan.sign_counterparty_commitment_tx(
                    &tx.transaction,
                    &output_witscripts,
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
            } else {
                chan.sign_counterparty_commitment_tx_phase2(
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    to_countersignatory,
                    to_broadcaster,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?
                .0
            };

            Ok(())
        })
    }

    fn create_tx(
        chan: &mut Channel,
        offered_htlcs: &Vec<HTLCInfo2>,
        received_htlcs: &Vec<HTLCInfo2>,
        commit_num: u64,
        feerate_per_kw: u32,
        to_broadcaster: u64,
        to_countersignatory: u64,
        parameters: &DirectedChannelTransactionParameters,
        keys: TxCreationKeys,
    ) -> (Vec<Vec<u8>>, BuiltCommitmentTransaction) {
        let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());
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
        let output_witscripts = redeem_scripts.iter().map(|s| s.serialize()).collect();

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
        let tx = trusted_tx.built_transaction().clone();
        (output_witscripts, tx)
    }

    // policy-commitment-retry-same
    #[test]
    fn retry_same_phase1_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
            false, // is_phase2
            CommitmentType::StaticRemoteKey,
            |_cms| {
                // If we don't mutate anything it should succeed.
            },
            |_node| {},
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn retry_same_phase2_static() {
        assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
            true, // is_phase2
            CommitmentType::StaticRemoteKey,
            |_cms| {
                // If we don't mutate anything it should succeed.
            },
            |_node| {},
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn retry_same_phase1_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
            false, // is_phase2
            CommitmentType::Anchors,
            |_cms| {
                // If we don't mutate anything it should succeed.
            },
            |_node| {},
        ));
    }

    // policy-commitment-retry-same
    #[test]
    fn retry_same_phase2_anchors() {
        assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
            true, // is_phase2
            CommitmentType::Anchors,
            |_cms| {
                // If we don't mutate anything it should succeed.
            },
            |_node| {},
        ));
    }

    macro_rules! generate_failed_precondition_error_retry_with_mutations {
        ($name: ident, $rm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _phase1_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_retry_with_mutator(
                            false, CommitmentType::StaticRemoteKey, $rm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE1_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase2_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_retry_with_mutator(
                            true, CommitmentType::StaticRemoteKey, $rm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE2_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase1_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_retry_with_mutator(
                            false, CommitmentType::Anchors, $rm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE1_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase2_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_commitment_tx_retry_with_mutator(
                            true, CommitmentType::Anchors, $rm, |_| {}),
                        ($errcls)(ERR_MSG_CONTEXT_PHASE2_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _phase2_static_warn>]() {
                    assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
                            true, CommitmentType::Anchors, $rm, disable_policies));
                }
            }
            paste! {
                #[test]
                fn [<$name _phase1_static_warn>]() {
                    assert_status_ok!(sign_counterparty_commitment_tx_retry_with_mutator(
                            false, CommitmentType::Anchors, $rm, disable_policies));
                }
            }
        };
    }

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutations!(
        retry_with_bad_point,
        |cms| {
            *cms.remote_percommitment_point = make_test_pubkey(42);
        },
        |_| "policy failure: validate_counterparty_commitment_tx: \
             retry of sign_counterparty_commitment 23 with changed point: \
             prev 03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e != \
             new 035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c"
    );

    // policy-commitment-retry-same
    generate_failed_precondition_error_retry_with_mutations!(
        retry_with_removed_htlc,
        |cms| {
            // Remove the last received HTLC
            cms.received_htlcs.pop().unwrap();
        },
        |_| "policy failure: validate_counterparty_commitment_tx: \
             retry of sign_counterparty_commitment 23 with changed info"
    );
}
