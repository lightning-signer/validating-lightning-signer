#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::util::psbt::serialize::Serialize;
    use lightning::chain::keysinterface::ChannelSigner;
    use lightning::ln::chan_utils;

    use test_log::test;

    use crate::channel::{Channel, CommitmentType};
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;
    use crate::util::INITIAL_COMMITMENT_NUMBER;

    // TODO - policy-v2-commitment-retry-same (tx)
    // TODO - policy-v2-commitment-retry-same (output_witscripts)
    // TODO - policy-v2-commitment-retry-same (payment_hashmap)

    const REV_COMMIT_NUM: u64 = 23;

    fn make_per_commitment(idx: u64) -> (PublicKey, SecretKey) {
        let commitment_seed = [55u8; 32];

        let secp_ctx = Secp256k1::new();
        let secret = SecretKey::from_slice(&chan_utils::build_commitment_secret(
            &commitment_seed,
            INITIAL_COMMITMENT_NUMBER - idx,
        ))
        .unwrap();
        let point = PublicKey::from_secret_key(&secp_ctx, &secret);
        (point, secret)
    }

    fn validate_counterparty_revocation_with_mutator<RevocationMutator, ChannelStateValidator>(
        mutate_revocation_input: RevocationMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        RevocationMutator: Fn(&mut Channel, &mut SecretKey),
        ChannelStateValidator: Fn(&Channel),
    {
        let (node, _setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(CommitmentType::StaticRemoteKey);

        node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let feerate_per_kw = 0;
            let to_broadcaster = 1_979_997;
            let to_countersignatory = 1_000_000;

            // provide all secrets so that we don't worry about secret chaining
            for idx in 0..REV_COMMIT_NUM {
                let (_, secret) = make_per_commitment(idx);
                let secrets = chan.enforcement_state.counterparty_secrets.as_mut().unwrap();
                secrets
                    .provide_secret(INITIAL_COMMITMENT_NUMBER - idx, secret.secret_bytes())
                    .unwrap();
            }

            let (remote_percommit_point, mut remote_percommit_secret) =
                make_per_commitment(REV_COMMIT_NUM);

            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM - 1);
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                REV_COMMIT_NUM,
                remote_percommit_point,
            );

            // check cp points from 0 to REV_COMMIT_NUM
            for idx in 0..REV_COMMIT_NUM - 1 {
                let (expected_point, _) = make_per_commitment(idx);
                let point = chan.get_counterparty_commitment_point(idx);
                assert_eq!(point, Some(expected_point), "idx={}", idx);
            }

            assert!(chan.get_counterparty_commitment_point(REV_COMMIT_NUM).is_none());

            // commit 21: revoked
            // commit 22: current  <- next revoke
            // commit 23: next     <- next commit

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommit_point)?;
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
            let output_witscripts: Vec<_> = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                keys,
                REV_COMMIT_NUM,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );

            let trusted_tx = commitment_tx.trust();
            let tx = trusted_tx.built_transaction().clone();

            for received_htlc in received_htlcs.clone() {
                node.add_keysend(
                    make_test_pubkey(1),
                    received_htlc.payment_hash,
                    received_htlc.value_sat * 1000,
                )?;
            }

            let _sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommit_point,
                REV_COMMIT_NUM,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;

            // commit 21: revoked
            // commit 22: unrevoked <- next revoke
            // commit 23: current
            // commit 24: next      <- next commit

            // Advance the state one full cycle:
            // - validate_counterparty_revocation(22, ..)
            // - sign_counterparty_commitment_tx(.., 24)
            chan.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM);
            chan.set_next_counterparty_commit_num_for_testing(
                REV_COMMIT_NUM + 2,
                make_test_pubkey(0x10),
            );

            // commit 23: unrevoked <- next revoke
            // commit 24: current
            // commit 25: next      <- next commit

            // Let unit tests mess with stuff.
            mutate_revocation_input(chan, &mut remote_percommit_secret);

            // Validate the revocation, but defer error returns till after we've had
            // a chance to validate the channel state for side-effects
            let deferred_rv =
                chan.validate_counterparty_revocation(REV_COMMIT_NUM, &remote_percommit_secret);

            // commit 23: revoked
            // commit 24: current   <- next revoke
            // commit 25: next      <- next commit

            // Make sure the revocation state is as expected for each test.
            validate_channel_state(chan);
            deferred_rv?;

            assert_eq!(
                tx.txid.to_hex(),
                "325f6443f45049da5a4d99cb54407ff8eaabfd8324bea18933a0ff40983275a3"
            );

            Ok(())
        })
    }

    #[test]
    fn validate_counterparty_revocation_success() {
        assert!(validate_counterparty_revocation_with_mutator(
            |_chan, _old_secret| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel state should advance.
                assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_counterparty_revocation_can_retry() {
        assert!(validate_counterparty_revocation_with_mutator(
            |chan, _old_secret| {
                // Set the channel's next_revoke_num ahead one;
                // pretend we already revoked it.
                chan.enforcement_state
                    .set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM + 1);
            },
            |chan| {
                // Channel state should stay where we advanced it..
                assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_counterparty_revocation_not_ahead() {
        assert_failed_precondition_err!(
            validate_counterparty_revocation_with_mutator(
                |chan, _old_secret| {
                    // Set the channel's next_revoke_num ahead two, past the retry ...
                    chan.enforcement_state
                        .set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM + 2);
                },
                |chan| {
                    // Channel state should stay where we advanced it..
                    assert_eq!(
                        chan.enforcement_state.next_counterparty_revoke_num,
                        REV_COMMIT_NUM + 2
                    );
                }
            ),
            "policy failure: validate_counterparty_revocation: \
             invalid counterparty revoke_num 23 with next_counterparty_revoke_num 25"
        );
    }

    #[test]
    fn validate_counterparty_revocation_not_behind() {
        assert_failed_precondition_err!(
            validate_counterparty_revocation_with_mutator(
                |chan, _old_secret| {
                    // Set the channel's next_revoke_num behind 1, in the past ...
                    chan.enforcement_state
                        .set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM - 1);
                },
                |chan| {
                    // Channel state should stay where we set it..
                    assert_eq!(
                        chan.enforcement_state.next_counterparty_revoke_num,
                        REV_COMMIT_NUM - 1
                    );
                }
            ),
            "policy failure: validate_counterparty_revocation: \
             invalid counterparty revoke_num 23 with next_counterparty_revoke_num 22"
        );
    }

    // policy-commitment-previous-revoked (invalid secret on revoke)
    #[test]
    fn validate_counterparty_revocation_with_bad_secret() {
        assert_failed_precondition_err!(
            validate_counterparty_revocation_with_mutator(
                |_chan, old_secret| {
                    *old_secret = make_test_privkey(42);
                },
                |chan| {
                    // Channel state should NOT advance.
                    assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM);
                }
            ),
            "policy failure: validate_counterparty_revocation: \
             revocation commit point mismatch for commit_num 23: \
             supplied 035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c, \
             previous 0393b4f3cd135b4f71fdb7ded8aad92cf22212a6893e89a2068a71e15a5ba560a3"
        );
    }

    #[test]
    fn validate_counterparty_revocation_with_retry() {
        let (node, _setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(CommitmentType::StaticRemoteKey);

        // Setup enforcement state
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            // provide all secrets so that we don't worry about secret chaining
            for idx in 0..REV_COMMIT_NUM {
                let (_, secret) = make_per_commitment(idx);
                let secrets = chan.enforcement_state.counterparty_secrets.as_mut().unwrap();
                secrets
                    .provide_secret(INITIAL_COMMITMENT_NUMBER - idx, secret.secret_bytes())
                    .unwrap();
            }
            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM - 1);
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                REV_COMMIT_NUM,
                make_per_commitment(REV_COMMIT_NUM - 1).0,
            );
            // commit 21: revoked
            // commit 22: current  <- next revoke
            // commit 23: next     <- next commit
            Ok(())
        }));

        // Sign counterparty REV_COMMIT_NUM
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let (remote_percommit_point, _) = make_per_commitment(REV_COMMIT_NUM);

            let feerate_per_kw = 0;
            let to_broadcaster = 1_979_997;
            let to_countersignatory = 1_000_000;

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommit_point)?;
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
            let output_witscripts: Vec<_> = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                keys,
                REV_COMMIT_NUM,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );

            let trusted_tx = commitment_tx.trust();
            let tx = trusted_tx.built_transaction().clone();

            for received_htlc in received_htlcs.clone() {
                node.add_keysend(
                    make_test_pubkey(1),
                    received_htlc.payment_hash,
                    received_htlc.value_sat * 1000,
                )?;
            }

            let _sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommit_point,
                REV_COMMIT_NUM,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;

            // commit 21: revoked
            // commit 22: unrevoked <- next revoke
            // commit 23: current
            // commit 24: next      <- next commit
            Ok(())
        }));

        // Revoke REV_COMMIT_NUM - 1
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            assert_status_ok!(chan.validate_counterparty_revocation(
                REV_COMMIT_NUM - 1,
                &make_per_commitment(REV_COMMIT_NUM - 1).1,
            ));

            // commit 22: revoked
            // commit 23: current   <- next revoke
            // commit 24: next      <- next commit
            Ok(())
        }));

        // Sign counterparty REV_COMMIT_NUM + 1
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            let (remote_percommit_point, _) = make_per_commitment(REV_COMMIT_NUM + 1);

            let feerate_per_kw = 0;
            let to_broadcaster = 1_979_097; // -900
            let to_countersignatory = 1_000_900; // +900

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommit_point)?;
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
            let output_witscripts: Vec<_> = redeem_scripts.iter().map(|s| s.serialize()).collect();

            let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                keys,
                REV_COMMIT_NUM + 1,
                feerate_per_kw,
                to_broadcaster,
                to_countersignatory,
                htlcs.clone(),
            );

            let trusted_tx = commitment_tx.trust();
            let tx = trusted_tx.built_transaction().clone();

            let _sig = chan.sign_counterparty_commitment_tx(
                &tx.transaction,
                &output_witscripts,
                &remote_percommit_point,
                REV_COMMIT_NUM + 1,
                feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;

            // commit 22: revoked
            // commit 23: unrevoked <- next revoke
            // commit 24: current
            // commit 25: next      <- next commit
            Ok(())
        }));

        // Revoke REV_COMMIT_NUM with lots of checking
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            // state is what we think it is
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_some());

            // Can't assert older
            assert_failed_precondition_err!(
                chan.validate_counterparty_revocation(
                    REV_COMMIT_NUM - 2,
                    &make_per_commitment(REV_COMMIT_NUM - 2).1
                ),
                "policy failure: validate_counterparty_revocation: \
                 invalid counterparty revoke_num 21 with next_counterparty_revoke_num 23"
            );

            // state is unchanged
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_some());

            // Can't skip
            assert_failed_precondition_err!(
                chan.validate_counterparty_revocation(
                    REV_COMMIT_NUM + 1,
                    &make_per_commitment(REV_COMMIT_NUM + 1).1
                ),
                "policy failure: validate_counterparty_revocation: \
                 invalid counterparty revoke_num 24 with next_counterparty_revoke_num 23"
            );

            // state is unchanged
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_some());

            // can revoke correctly
            assert_status_ok!(chan.validate_counterparty_revocation(
                REV_COMMIT_NUM,
                &make_per_commitment(REV_COMMIT_NUM).1
            ));

            // state is modified
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_none());

            // Retry is ok
            assert_status_ok!(chan.validate_counterparty_revocation(
                REV_COMMIT_NUM,
                &make_per_commitment(REV_COMMIT_NUM).1
            ));

            // state is unchanged
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_none());

            // Can't assert older
            assert_failed_precondition_err!(
                chan.validate_counterparty_revocation(
                    REV_COMMIT_NUM - 1,
                    &make_per_commitment(REV_COMMIT_NUM - 1).1
                ),
                "policy failure: validate_counterparty_revocation: \
                 invalid counterparty revoke_num 22 with next_counterparty_revoke_num 24"
            );

            // state is unchanged
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_none());

            // Can't skip
            assert_failed_precondition_err!(
                chan.validate_counterparty_revocation(
                    REV_COMMIT_NUM + 2,
                    &make_per_commitment(REV_COMMIT_NUM + 2).1
                ),
                "policy failure: validate_counterparty_revocation: \
                 invalid counterparty revoke_num 25 with next_counterparty_revoke_num 24"
            );

            // state is unchanged
            assert_eq!(chan.enforcement_state.next_counterparty_revoke_num, REV_COMMIT_NUM + 1);
            assert!(chan.enforcement_state.previous_counterparty_commit_info.is_none());

            Ok(())
        }))
    }
}
