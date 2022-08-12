#[cfg(test)]
mod tests {
    use std::mem;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{self, Address, Network, OutPoint, Script, Transaction, TxOut};
    use lightning::ln::chan_utils::{
        make_funding_redeemscript, ChannelPublicKeys, ClosingTransaction,
    };
    use lightning::ln::PaymentHash;

    use test_log::test;

    use crate::channel::{
        Channel, ChannelBalance, ChannelBase, ChannelId, ChannelSetup, TypedSignature,
    };
    use crate::node::{Node, NodeMonitor};
    use crate::sync::Arc;
    use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;
    use crate::util::transaction_utils::mutual_close_tx_weight;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));

    fn setup_mutual_close_tx(
        outbound: bool,
    ) -> Result<
        (
            Secp256k1<secp256k1::SignOnly>,
            ChannelSetup,
            Arc<Node>,
            ChannelId,
            u64,
            u64,
            u64,
            Vec<u32>,
            ChannelPublicKeys,
        ),
        Status,
    > {
        let secp_ctx = Secp256k1::signing_only();
        let mut setup = make_test_channel_setup();
        setup.is_outbound = outbound;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let counterparty_points = make_test_counterparty_points();
        let holder_commit_num = 22;
        let counterparty_commit_num = 43;
        let holder_wallet_path_hint = vec![7];

        let feerate_per_kw = 7500;
        let fee = 2000;
        let mut to_holder_value_sat = 2_000_000;
        let mut to_counterparty_value_sat = setup.channel_value_sat - to_holder_value_sat; // 1_000_000
        if outbound {
            to_holder_value_sat -= fee;
        } else {
            to_counterparty_value_sat -= fee;
        };

        node.with_ready_channel(&channel_id, |chan| {
            // Construct the EnforcementState prior to the mutual_close.
            let mut estate = &mut chan.enforcement_state;
            estate.next_holder_commit_num = holder_commit_num + 1;
            estate.next_counterparty_commit_num = counterparty_commit_num + 1;
            estate.next_counterparty_revoke_num = counterparty_commit_num;
            estate.current_counterparty_point =
                Some(make_test_pubkey(counterparty_commit_num as u8));
            estate.previous_counterparty_point = None;
            estate.current_holder_commit_info = Some(CommitmentInfo2 {
                is_counterparty_broadcaster: false,
                to_countersigner_pubkey: make_test_pubkey((holder_commit_num + 100) as u8),
                to_countersigner_value_sat: to_counterparty_value_sat,
                revocation_pubkey: make_test_pubkey((holder_commit_num + 101) as u8),
                to_broadcaster_delayed_pubkey: make_test_pubkey((holder_commit_num + 102) as u8),
                to_broadcaster_value_sat: to_holder_value_sat,
                to_self_delay: setup.counterparty_selected_contest_delay,
                offered_htlcs: vec![],
                received_htlcs: vec![],
                feerate_per_kw,
            });
            estate.current_counterparty_commit_info = Some(CommitmentInfo2 {
                is_counterparty_broadcaster: true,
                to_countersigner_pubkey: make_test_pubkey((counterparty_commit_num + 100) as u8),
                to_countersigner_value_sat: to_holder_value_sat,
                revocation_pubkey: make_test_pubkey((counterparty_commit_num + 101) as u8),
                to_broadcaster_delayed_pubkey: make_test_pubkey(
                    (counterparty_commit_num + 102) as u8,
                ),
                to_broadcaster_value_sat: to_counterparty_value_sat,
                to_self_delay: setup.holder_selected_contest_delay,
                offered_htlcs: vec![],
                received_htlcs: vec![],
                feerate_per_kw,
            });
            estate.previous_counterparty_commit_info = None;
            estate.channel_closed = false;
            Ok(())
        })
        .expect("state setup");

        Ok((
            secp_ctx,
            setup,
            node,
            channel_id,
            holder_commit_num,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_wallet_path_hint,
            counterparty_points,
        ))
    }

    fn sign_mutual_close_tx_with_mutators<
        MutualCloseInputMutator,
        MutualCloseTxMutator,
        ChannelStateValidator,
    >(
        outbound: bool,
        mutate_close_input: MutualCloseInputMutator,
        mutate_close_tx: MutualCloseTxMutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        MutualCloseInputMutator:
            Fn(&mut Channel, &mut u64, &mut u64, &mut Script, &mut Script, &mut OutPoint),
        MutualCloseTxMutator: Fn(&mut Transaction, &mut Vec<Vec<u32>>, &mut Vec<String>),
        ChannelStateValidator: Fn(&Channel),
    {
        let (
            secp_ctx,
            setup,
            node,
            channel_id,
            holder_commit_num,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_wallet_path_hint,
            counterparty_points,
        ) = setup_mutual_close_tx(outbound)?;

        assert_eq!(node.channel_balance(), ChannelBalance::new(2_000_000, 0, 0, 0));

        let (tx, sig) = node.with_ready_channel(&channel_id, |chan| {
            let mut holder_value_sat = to_holder_value_sat;
            let mut counterparty_value_sat = to_counterparty_value_sat;
            let mut holder_shutdown_script = Address::p2wpkh(
                &node.get_wallet_pubkey(&secp_ctx, &holder_wallet_path_hint).unwrap(),
                Network::Testnet,
            )
            .expect("Address")
            .script_pubkey();
            let mut counterparty_shutdown_script =
                Script::from_hex("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565")
                    .expect("script_pubkey");
            let mut funding_outpoint = setup.funding_outpoint;

            mutate_close_input(
                chan,
                &mut holder_value_sat,
                &mut counterparty_value_sat,
                &mut holder_shutdown_script,
                &mut counterparty_shutdown_script,
                &mut funding_outpoint,
            );

            let closing_tx = ClosingTransaction::new(
                holder_value_sat,
                counterparty_value_sat,
                holder_shutdown_script,
                counterparty_shutdown_script,
                funding_outpoint,
            );
            let trusted = closing_tx.trust();
            let tx = trusted.built_transaction();

            // Secrets can be released before the mutual close.
            assert!(chan.get_per_commitment_secret(holder_commit_num - 1).is_ok());

            let mut mtx = tx.clone();
            let mut wallet_paths = vec![vec![], holder_wallet_path_hint.clone()];
            let mut allowlist = vec![];

            mutate_close_tx(&mut mtx, &mut wallet_paths, &mut allowlist);

            node.add_allowlist(&allowlist)?;

            // Sign the mutual close, but defer error returns till after
            // we check the state of the channel for side-effects.
            let deferred_rv = chan.sign_mutual_close_tx(&mtx, &wallet_paths);

            // This will panic if the state is not good.
            validate_channel_state(chan);

            let sig = deferred_rv?;
            Ok((tx.clone(), sig))
        })?;

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

        // Secrets can still be released if they are old enough.
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            chan.get_per_commitment_secret(holder_commit_num - 1)
        }));

        // policy-revoke-not-closed
        // Channel is marked closed.
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            assert_eq!(chan.enforcement_state.channel_closed, true);
            Ok(())
        }));

        Ok(())
    }

    fn sign_mutual_close_tx_phase2_with_mutators<MutualCloseInput2Mutator, ChannelStateValidator>(
        outbound: bool,
        mutate_close_input: MutualCloseInput2Mutator,
        validate_channel_state: ChannelStateValidator,
    ) -> Result<(), Status>
    where
        MutualCloseInput2Mutator: Fn(
            &mut Channel,
            &mut u64,
            &mut u64,
            &mut Script,
            &mut Script,
            &mut OutPoint,
            &mut Vec<u32>,
            &mut Vec<String>,
        ),
        ChannelStateValidator: Fn(&Channel),
    {
        let (
            secp_ctx,
            setup,
            node,
            channel_id,
            holder_commit_num,
            to_holder_value_sat,
            to_counterparty_value_sat,
            init_holder_wallet_path_hint,
            counterparty_points,
        ) = setup_mutual_close_tx(outbound)?;

        let (
            holder_value_sat,
            counterparty_value_sat,
            holder_shutdown_script,
            counterparty_shutdown_script,
            funding_outpoint,
            sig,
        ) = node.with_ready_channel(&channel_id, |chan| {
            let mut wallet_path = init_holder_wallet_path_hint.clone();
            let mut holder_value_sat = to_holder_value_sat;
            let mut counterparty_value_sat = to_counterparty_value_sat;
            let mut holder_shutdown_script = Address::p2wpkh(
                &node.get_wallet_pubkey(&secp_ctx, &wallet_path).unwrap(),
                Network::Testnet,
            )
            .expect("Address")
            .script_pubkey();
            let mut counterparty_shutdown_script =
                Script::from_hex("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565")
                    .expect("script_pubkey");
            let mut funding_outpoint = setup.funding_outpoint;

            // Secrets can be released before the mutual close.
            assert!(chan.get_per_commitment_secret(holder_commit_num - 1).is_ok());

            let mut allowlist = vec![];

            mutate_close_input(
                chan,
                &mut holder_value_sat,
                &mut counterparty_value_sat,
                &mut holder_shutdown_script,
                &mut counterparty_shutdown_script,
                &mut funding_outpoint,
                &mut wallet_path,
                &mut allowlist,
            );

            node.add_allowlist(&allowlist)?;

            // Sign the mutual close, but defer error returns till after
            // we check the state of the channel for side-effects.
            let deferred_rv = chan.sign_mutual_close_tx_phase2(
                holder_value_sat,
                counterparty_value_sat,
                &Some(holder_shutdown_script.clone()),
                &Some(counterparty_shutdown_script.clone()),
                &wallet_path,
            );
            // This will panic if the state is not good.
            validate_channel_state(chan);

            let sig = deferred_rv?;
            Ok((
                holder_value_sat,
                counterparty_value_sat,
                holder_shutdown_script,
                counterparty_shutdown_script,
                funding_outpoint,
                sig,
            ))
        })?;

        let closing_tx = ClosingTransaction::new(
            holder_value_sat,
            counterparty_value_sat,
            holder_shutdown_script,
            counterparty_shutdown_script,
            funding_outpoint,
        );
        let trusted = closing_tx.trust();
        let tx = trusted.built_transaction();

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

        // Secrets can still be released if they are old enough.
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            chan.get_per_commitment_secret(holder_commit_num - 1)
        }));

        // policy-revoke-not-closed
        // Channel is marked closed.
        assert_status_ok!(node.with_ready_channel(&channel_id, |chan| {
            assert_eq!(chan.enforcement_state.channel_closed, true);
            Ok(())
        }));

        Ok(())
    }

    macro_rules! sign_mutual_close_tx_with_mutators_inbound {
        ($mci: expr, $mct: expr, $vcs: expr) => {
            sign_mutual_close_tx_with_mutators(false, $mci, $mct, $vcs)
        };
    }

    macro_rules! sign_mutual_close_tx_with_mutators_outbound {
        ($mci: expr, $mct: expr, $vcs: expr) => {
            sign_mutual_close_tx_with_mutators(true, $mci, $mct, $vcs)
        };
    }

    macro_rules! sign_mutual_close_tx_phase2_with_mutators_inbound {
        ($mci: expr, $vcs: expr) => {
            sign_mutual_close_tx_phase2_with_mutators(false, $mci, $vcs)
        };
    }

    macro_rules! sign_mutual_close_tx_phase2_with_mutators_outbound {
        ($mci: expr, $vcs: expr) => {
            sign_mutual_close_tx_phase2_with_mutators(true, $mci, $vcs)
        };
    }

    #[test]
    fn sign_mutual_close_tx_phase2_success() {
        assert_status_ok!(sign_mutual_close_tx_phase2_with_mutators_outbound!(
            |_chan,
             _to_holder,
             _to_counterparty,
             _holder_script,
             _counter_script,
             _outpoint,
             _wallet_path,
             _allowlist| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_success() {
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |_chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                // If we don't mutate anything it should succeed.
            },
            |_tx, _wallet_paths, _allowlist| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_phase2_inbound_success() {
        assert_status_ok!(sign_mutual_close_tx_phase2_with_mutators_inbound!(
            |_chan,
             _to_holder,
             _to_counterparty,
             _holder_script,
             _counter_script,
             _outpoint,
             _wallet_path,
             _allowlist| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_inbound_success() {
        assert_status_ok!(sign_mutual_close_tx_with_mutators_inbound!(
            |_chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                // If we don't mutate anything it should succeed.
            },
            |_tx, _wallet_paths, _allowlist| {
                // If we don't mutate anything it should succeed.
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_only_holder_success() {
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |chan, to_holder, to_counterparty, _holder_script, counter_script, _outpoint| {
                // remove the counterparty from current_holder_commit_info
                let mut holder =
                    chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                holder.to_broadcaster_value_sat += holder.to_countersigner_value_sat;
                holder.to_countersigner_value_sat = 0;
                chan.enforcement_state.current_holder_commit_info = Some(holder);

                // remove the counterparty from current_counterparty_commit_info
                let mut cparty = chan
                    .enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .unwrap()
                    .clone();
                cparty.to_countersigner_value_sat += cparty.to_broadcaster_value_sat;
                cparty.to_broadcaster_value_sat = 0;
                chan.enforcement_state.current_counterparty_commit_info = Some(cparty);

                // from the constructed tx
                *to_holder += *to_counterparty;
                *to_counterparty = 0;
                *counter_script = Script::new();
            },
            |_tx, wallet_paths, _allowlist| {
                // remove the counterparties wallet_path
                wallet_paths[0] = wallet_paths[1].clone();
                wallet_paths.pop();
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_only_counterparty_success() {
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |chan, to_holder, to_counterparty, holder_script, _counter_script, _outpoint| {
                let fee = 2000;

                // remove the holder from current_holder_commit_info
                let mut holder =
                    chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                holder.to_countersigner_value_sat += holder.to_broadcaster_value_sat - fee;
                holder.to_broadcaster_value_sat = 0;
                chan.enforcement_state.current_holder_commit_info = Some(holder);

                // remove the holder from current_counterparty_commit_info
                let mut cparty = chan
                    .enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .unwrap()
                    .clone();
                cparty.to_broadcaster_value_sat += cparty.to_countersigner_value_sat - fee;
                cparty.to_countersigner_value_sat = 0;
                chan.enforcement_state.current_counterparty_commit_info = Some(cparty);

                // from the constructed tx
                *to_counterparty += *to_holder - fee;
                *to_holder = 0;
                *holder_script = Script::new();
            },
            |_tx, wallet_paths, _allowlist| {
                // remove the holders wallet_path
                wallet_paths.pop();
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_catch_allowlist_bad_assign_success() {
        // This could happen if:
        // 1. A company used a common allowlist for all of it's nodes.
        // 2. NodeA opens a channel to NodeB (both company nodes).
        // 3. Channel is mutually closed immediately (only one output, to NodeA).
        // 4. NodeB incorrectly assigns the output because it's in the allowlist.
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |chan, to_holder, to_counterparty, holder_script, counter_script, _outpoint| {
                let fee = 2000;

                // remove the holder from current_holder_commit_info
                let mut holder =
                    chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                holder.to_countersigner_value_sat += holder.to_broadcaster_value_sat - fee;
                holder.to_broadcaster_value_sat = 0;
                chan.enforcement_state.current_holder_commit_info = Some(holder);

                // remove the holder from current_counterparty_commit_info
                let mut cparty = chan
                    .enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .unwrap()
                    .clone();
                cparty.to_broadcaster_value_sat += cparty.to_countersigner_value_sat - fee;
                cparty.to_countersigner_value_sat = 0;
                chan.enforcement_state.current_counterparty_commit_info = Some(cparty);

                // from the constructed tx
                *to_counterparty += *to_holder - fee;
                *to_holder = 0;
                *holder_script = Script::new();

                // counterparty is using the allowlist
                *counter_script = hex_script!("0014be56df7de366ad8ee9ccdad54e9a9993e99ef565");
            },
            |_tx, wallet_paths, allowlist| {
                // remove all the walletpaths
                wallet_paths.pop();
                wallet_paths.pop();
                wallet_paths.push(vec![]); // only push one back, one output

                // add allowlist entry
                allowlist.push("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string());
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    // policy-mutual-destination-allowlisted
    #[test]
    fn sign_mutual_close_tx_with_allowlist_success() {
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |_chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                // If we don't mutate anything it should succeed.
            },
            |_tx, wallet_paths, allowlist| {
                // empty the wallet paths
                wallet_paths.pop();
                wallet_paths.pop();
                wallet_paths.push(vec![]);
                wallet_paths.push(vec![]);
                // use the allowlist
                allowlist.push("tb1qkakav8jpkhhs22hjrndrycyg3srshwd09gax07".to_string());
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    // policy-mutual-destination-allowlisted
    #[test]
    fn sign_mutual_close_tx_phase2_with_allowlist_success() {
        assert_status_ok!(sign_mutual_close_tx_phase2_with_mutators_outbound!(
            |_chan,
             _to_holder,
             _to_counterparty,
             _holder_script,
             _counter_script,
             _outpoint,
             wallet_path,
             allowlist| {
                // Remove the wallet_path and use allowlist instead.
                *wallet_path = vec![];
                allowlist.push("tb1qkakav8jpkhhs22hjrndrycyg3srshwd09gax07".to_string());
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    // policy-mutual-destination-allowlisted
    #[test]
    fn sign_mutual_close_tx_phase2_no_wallet_path_or_allowlist() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_phase2_with_mutators_outbound!(
                |_chan,
                 _to_holder,
                 _to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint,
                 wallet_path,
                 _allowlist| {
                    // Remove the wallet_path
                    *wallet_path = vec![];
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: holder output not to wallet or in allowlist"
        );
    }

    #[test]
    fn sign_mutual_close_tx_phase2_holder_upfront_script_mismatch() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_phase2_with_mutators_outbound!(
                |chan,
                 _to_holder,
                 _to_counterparty,
                 holder_script,
                 _counter_script,
                 _outpoint,
                 _wallet_path,
                 _allowlist| {
                    chan.setup.holder_shutdown_script =
                        Some(hex_script!("0014b76dd61e41b5ef052af21cda3260888c070bb9af"));
                    *holder_script =
                        hex_script!("76a9149f9a7abd600c0caa03983a77c8c3df8e062cb2fa88ac");
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             holder_script doesn't match upfront holder_shutdown_script"
        );
    }

    // policy-mutual-fee-range
    #[test]
    fn sign_mutual_close_tx_phase2_with_fee_too_large() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_phase2_with_mutators_outbound!(
                |_chan,
                 to_holder,
                 to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint,
                 _wallet_path,
                 _allowlist| {
                    *to_holder -= 40_000;
                    *to_counterparty -= 40_000;
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             validate_fee: feerate above maximum: 121663 > 100000"
        );
    }

    // policy-mutual-fee-range
    #[test]
    fn sign_mutual_close_tx_phase2_with_fee_too_small() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_phase2_with_mutators_outbound!(
                |_chan,
                 to_holder,
                 to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint,
                 _wallet_path,
                 _allowlist| {
                    *to_holder += 1_000;
                    *to_counterparty += 950;
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: validate_fee: \
             feerate below minimum: 75 < 253"
        );
    }

    #[test]
    fn sign_mutual_close_tx_with_bad_num_txout() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |_chan,
                 _to_holder,
                 _to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint| {
                    // don't need to mutate these
                },
                |tx, wallet_paths, _allowlist| {
                    // Steal some of the first output and make a new output.
                    let steal_amt = 1_000;
                    tx.output[0].value -= steal_amt;
                    tx.output.push(TxOut {
                        value: steal_amt,
                        script_pubkey: hex_script!(
                            "76a9149f9a7abd600c0caa03983a77c8c3df8e062cb2fa88ac"
                        ),
                    });
                    wallet_paths.push(vec![]); // needs to match
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "transaction format: decode_and_validate_mutual_close_tx: invalid number of outputs: 3"
        );
    }

    #[test]
    fn sign_mutual_close_tx_with_opath_len_mismatch() {
        assert_invalid_argument_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |_chan,
                 _to_holder,
                 _to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint| {
                    // don't need to mutate these
                },
                |_tx, wallet_paths, _allowlist| {
                    wallet_paths.push(vec![]); // an extra opath element
                },
                |chan| {
                    // Channel should be not marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "sign_mutual_close_tx: bad opath len 3 with tx.output len 2"
        );
    }

    // policy-mutual-destination-allowlisted
    #[test]
    fn sign_mutual_close_tx_with_unestablished_holder() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |_chan,
                 _to_holder,
                 _to_counterparty,
                 _holder_script,
                 _counter_script,
                 _outpoint| {
                    // don't need to mutate these
                },
                |_tx, wallet_paths, _allowlist| {
                    wallet_paths.pop();
                    wallet_paths.pop();
                    wallet_paths.push(vec![]);
                    wallet_paths.push(vec![]);
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: holder output not to wallet or in allowlist"
        );
    }

    #[test]
    fn sign_mutual_close_tx_with_ambiguous_holder_output() {
        // Both outputs are allowlisted (common company allowlist,
        // channel w/ two company nodes).  Need to use value to pick the output ...
        assert_status_ok!(sign_mutual_close_tx_with_mutators_outbound!(
            |chan, to_holder, to_counterparty, _holder_script, _counter_script, _outpoint| {
                // The hard case is when the holder's input is the first, so we need
                // to swap the outputs and values here.

                // Swap the setup values
                mem::swap(to_holder, to_counterparty);

                // Swap the holder commitment's values
                let mut hinfo =
                    chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                mem::swap(
                    &mut hinfo.to_broadcaster_value_sat,
                    &mut hinfo.to_countersigner_value_sat,
                );
                chan.enforcement_state.current_holder_commit_info = Some(hinfo);

                // Swap the counterparty commitment values
                let mut cinfo = chan
                    .enforcement_state
                    .current_counterparty_commit_info
                    .as_ref()
                    .unwrap()
                    .clone();
                mem::swap(
                    &mut cinfo.to_broadcaster_value_sat,
                    &mut cinfo.to_countersigner_value_sat,
                );
                chan.enforcement_state.current_counterparty_commit_info = Some(cinfo);
            },
            |_tx, wallet_paths, allowlist| {
                // remove the wallet paths
                wallet_paths.pop();
                wallet_paths.pop();
                wallet_paths.push(vec![]);
                wallet_paths.push(vec![]);

                // add both outputs to the allowlist
                allowlist.push("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string());
                allowlist.push("tb1qkakav8jpkhhs22hjrndrycyg3srshwd09gax07".to_string());
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }

    #[test]
    fn sign_mutual_close_tx_without_holder_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    chan.enforcement_state.current_holder_commit_info = None;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: decode_and_validate_mutual_close_tx: \
             current_holder_commit_info missing"
        );
    }

    #[test]
    fn sign_mutual_close_tx_without_counterparty_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    chan.enforcement_state.current_counterparty_commit_info = None;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: decode_and_validate_mutual_close_tx: \
             current_counterparty_commit_info missing"
        );
    }

    // policy-mutual-no-pending-htlcs
    #[test]
    fn sign_mutual_close_tx_with_holder_offered_htlcs() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    holder.offered_htlcs.push(HTLCInfo2 {
                        value_sat: 1,
                        payment_hash: PaymentHash([1; 32]),
                        cltv_expiry: 2 << 16,
                    });
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: cannot close with pending htlcs"
        );
    }

    // policy-mutual-no-pending-htlcs
    #[test]
    fn sign_mutual_close_tx_with_holder_received_htlcs() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    holder.received_htlcs.push(HTLCInfo2 {
                        value_sat: 1,
                        payment_hash: PaymentHash([1; 32]),
                        cltv_expiry: 2 << 16,
                    });
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: cannot close with pending htlcs"
        );
    }

    // policy-mutual-no-pending-htlcs
    #[test]
    fn sign_mutual_close_tx_with_counterparty_offered_htlcs() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    cparty.offered_htlcs.push(HTLCInfo2 {
                        value_sat: 1,
                        payment_hash: PaymentHash([1; 32]),
                        cltv_expiry: 2 << 16,
                    });
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: cannot close with pending htlcs"
        );
    }

    // policy-mutual-no-pending-htlcs
    #[test]
    fn sign_mutual_close_tx_with_counterparty_received_htlcs() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    cparty.received_htlcs.push(HTLCInfo2 {
                        value_sat: 1,
                        payment_hash: PaymentHash([1; 32]),
                        cltv_expiry: 2 << 16,
                    });
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: cannot close with pending htlcs"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_pos_skewed_holder_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat += 14_000; // outside epsilon
                    holder.to_countersigner_value_sat -= 14_000; // outside epsilon
                    cparty.to_countersigner_value_sat += 9_000;
                    cparty.to_broadcaster_value_sat -= 9_000;
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 1000000 is larger than \
             holder_info.countersigner_value_sat 986000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_neg_skewed_holder_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat -= 14_000; // outside epsilon
                    holder.to_countersigner_value_sat += 14_000; // outside epsilon
                    cparty.to_countersigner_value_sat -= 9_000;
                    cparty.to_broadcaster_value_sat += 9_000;
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 1000000 is smaller than \
             holder_info.countersigner_value_sat 1014000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_pos_skewed_cparty_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat -= 9_000;
                    holder.to_countersigner_value_sat += 9_000;
                    cparty.to_countersigner_value_sat -= 14_000; // outside epsilon
                    cparty.to_broadcaster_value_sat += 14_000; // outside epsilon
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 1000000 is smaller than \
             counterparty_info.broadcaster_value_sat 1014000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_neg_skewed_cparty_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat += 9_000;
                    holder.to_countersigner_value_sat -= 9_000;
                    cparty.to_countersigner_value_sat += 14_000; // outside epsilon
                    cparty.to_broadcaster_value_sat -= 14_000; // outside epsilon
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 1000000 is larger than \
             counterparty_info.broadcaster_value_sat 986000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_pos_skewed_holder_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat += 14_000; // outside epsilon
                    holder.to_countersigner_value_sat -= 14_000; // outside epsilon
                    cparty.to_countersigner_value_sat += 9_000;
                    cparty.to_broadcaster_value_sat -= 9_000;
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 2000000 is smaller than \
             holder_info.broadcaster_value_sat 2014000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_neg_skewed_holder_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat -= 14_000; // outside epsilon
                    holder.to_countersigner_value_sat += 14_000; // outside epsilon
                    cparty.to_countersigner_value_sat -= 9_000;
                    cparty.to_broadcaster_value_sat += 9_000;
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 2000000 is larger than \
             holder_info.broadcaster_value_sat 1986000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_pos_skewed_cparty_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat -= 9_000;
                    holder.to_countersigner_value_sat += 9_000;
                    cparty.to_countersigner_value_sat -= 14_000; // outside epsilon
                    cparty.to_broadcaster_value_sat += 14_000; // outside epsilon
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 2000000 is larger than \
             counterparty_info.countersigner_value_sat 1986000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_neg_skewed_cparty_commitment() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |chan, _to_holder, _to_counterparty, _holder_script, _counter_script, _outpoint| {
                    let mut holder =
                        chan.enforcement_state.current_holder_commit_info.as_ref().unwrap().clone();
                    let mut cparty = chan
                        .enforcement_state
                        .current_counterparty_commit_info
                        .as_ref()
                        .unwrap()
                        .clone();
                    // Need to move both commitments so they are within epsilon of each other.
                    holder.to_broadcaster_value_sat += 9_000;
                    holder.to_countersigner_value_sat -= 9_000;
                    cparty.to_countersigner_value_sat += 14_000; // outside epsilon
                    cparty.to_broadcaster_value_sat -= 14_000; // outside epsilon
                    chan.enforcement_state.current_holder_commit_info = Some(holder);
                    chan.enforcement_state.current_counterparty_commit_info = Some(cparty);
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 2000000 is smaller than \
             counterparty_info.countersigner_value_sat 2014000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_holder_output_too_large() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |_chan, to_holder, to_counterparty, _holder_script, _counter_script, _outpoint| {
                    // Redistribute the outputs more than epsilon
                    *to_holder += 15_000;
                    *to_counterparty -= 15_000;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 985000 is smaller than \
             counterparty_info.broadcaster_value_sat 1000000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_outbound_with_holder_output_too_small() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_outbound!(
                |_chan, to_holder, to_counterparty, _holder_script, _counter_script, _outpoint| {
                    // Redistribute the outputs more than epsilon
                    *to_holder -= 15_000;
                    *to_counterparty += 15_000;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_counterparty_value 1015000 is larger than \
             counterparty_info.broadcaster_value_sat 1000000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_holder_output_too_large() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |_chan, to_holder, to_counterparty, _holder_script, _counter_script, _outpoint| {
                    // Redistribute the outputs more than epsilon
                    *to_holder += 15_000;
                    *to_counterparty -= 15_000;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 2015000 is larger than holder_info.broadcaster_value_sat 2000000"
        );
    }

    // policy-mutual-value-matches-commitment
    #[test]
    fn sign_mutual_close_tx_inbound_with_holder_output_too_small() {
        assert_failed_precondition_err!(
            sign_mutual_close_tx_with_mutators_inbound!(
                |_chan, to_holder, to_counterparty, _holder_script, _counter_script, _outpoint| {
                    // Redistribute the outputs more than epsilon
                    *to_holder -= 15_000;
                    *to_counterparty += 15_000;
                },
                |_tx, _wallet_paths, _allowlist| {
                    // don't need to mutate these
                },
                |chan| {
                    // Channel should not be marked closed
                    assert_eq!(chan.enforcement_state.channel_closed, false);
                }
            ),
            "policy failure: validate_mutual_close_tx: \
             to_holder_value 1985000 is smaller than holder_info.broadcaster_value_sat 2000000"
        );
    }

    #[test]
    fn check_expected_weight() {
        assert_status_ok!(sign_mutual_close_tx_phase2_with_mutators_outbound!(
            |_chan,
             to_holder,
             to_counterparty,
             holder_script,
             counter_script,
             outpoint,
             _wallet_path,
             _allowlist| {
                // We aren't changing anything, but we have everything to make
                // a close tx here.
                let weight = mutual_close_tx_weight(
                    &ClosingTransaction::new(
                        *to_holder,
                        *to_counterparty,
                        holder_script.clone(),
                        counter_script.clone(),
                        *outpoint,
                    )
                    .trust()
                    .built_transaction(),
                );
                // mainnet: d31a89acdedfe28b397a96c572714255df8441f696f3eca225bd7f8519ba76ff
                assert_eq!(weight, 674);
            },
            |chan| {
                // Channel should be marked closed
                assert_eq!(chan.enforcement_state.channel_closed, true);
            }
        ));
    }
}
