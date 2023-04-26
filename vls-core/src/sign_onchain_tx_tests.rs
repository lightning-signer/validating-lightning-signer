#[cfg(test)]
mod tests {
    use bitcoin::hashes::hash160::Hash as Hash160;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{
        self, Address, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn,
        TxOut, Txid, Witness,
    };
    use itertools::multiunzip;

    use test_log::test;

    use crate::channel::CommitmentType;
    use crate::node::SpendType;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[allow(unused_imports)]
    use log::debug;

    #[test]
    fn onchain_velocity_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            }],
            output: vec![],
        };

        for i in 0..25 {
            println!("i = {}", i);
            node.check_onchain_tx(&tx, &vec![], &[40000], &[SpendType::P2wpkh], &[None], &[vec![]])
                .expect("should have been under fee velocity");
        }
        node.check_onchain_tx(&tx, &vec![], &[40000], &[SpendType::P2wpkh], &[None], &[vec![]])
            .expect_err("should have been over fee velocity");
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 100u64, SpendType::P2wpkh), (1, 300u64, SpendType::P2wpkh)];
        let chanamt = 300u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let input2 = TxIn {
            previous_output: OutPoint { txid, vout: 1 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };
        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1, input2], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();
        let uniclosekeys = vec![None, None];

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 2);

        tx.input[0].witness = Witness::from_vec(witvec[0].clone());
        tx.input[1].witness = Witness::from_vec(witvec[1].clone());

        let verify_result = tx.verify(|p| Some(previous_tx.output[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_empty_previous_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 100u64, SpendType::P2wpkh), (1, 300u64, SpendType::P2wpkh)];
        let chanamt = 300u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let input2 = TxIn {
            previous_output: OutPoint { txid, vout: 1 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };
        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1, input2], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();
        let uniclosekeys = vec![None, None];

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![], // empty, but ok, because not related to channel
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 2);

        tx.input[0].witness = Witness::from_vec(witvec[0].clone());
        tx.input[1].witness = Witness::from_vec(witvec[1].clone());

        let verify_result = tx.verify(|p| Some(previous_tx.output[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test1() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 200u64, SpendType::P2wpkh)];
        let chanamt = 100u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();
        let uniclosekeys = vec![None];

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        tx.input[0].witness = Witness::from_vec(witvec[0].clone());

        let verify_result = tx.verify(|p| Some(previous_tx.output[p.vout as usize].clone()));
        assert!(verify_result.is_ok());

        Ok(())
    }

    // policy-onchain-fee-range
    #[test]
    fn sign_funding_tx_fee_too_high() {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let fee = 281_000u64;
        let values = vec![(0, 100u64 + fee, SpendType::P2wpkh)];
        let chanamt = 100u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let (opath, tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();
        let uniclosekeys = vec![None];

        assert_failed_precondition_err!(
            node.check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys.clone(),
                &vec![opath.clone()],
            ),
            "policy failure: validate_onchain_tx: \
             validate_beneficial_value: non-beneficial value considered as fees is above maximum feerate: 641554 > 151000"
        );
    }

    #[test]
    fn sign_funding_tx_unilateral_close_info_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 300u64, SpendType::P2wpkh)];
        let chanamt = 200u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();

        let uniclosekey = SecretKey::from_slice(
            hex_decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let uniclosepubkey = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &uniclosekey).serialize()[..],
        )
        .unwrap();
        let uniclosekeys = vec![Some((uniclosekey, vec![uniclosepubkey.serialize()]))];

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        assert_eq!(witvec[0][1], uniclosepubkey.serialize());

        let address = Address::p2wpkh(&uniclosepubkey, Network::Testnet).unwrap();

        tx.input[0].witness = Witness::from_vec(witvec[0].clone());
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut { value: values_sat[0], script_pubkey: address.script_pubkey() }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2pkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 200u64, SpendType::P2pkh)];

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], 100);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();

        // NOTE - this does not trigger policy-onchain-funding-non-malleable because
        // there is no channel associated with this tx.

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                vec![None],
                &vec![opath.clone()],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        tx.input[0].script_sig = Builder::new()
            .push_slice(witvec[0][0].as_slice())
            .push_slice(witvec[0][1].as_slice())
            .into_script();

        let verify_result = tx.verify(|p| Some(previous_tx.output[p.vout as usize].clone()));
        assert!(verify_result.is_ok());
        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2sh_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let values = vec![(0, 200u64, SpendType::P2shP2wpkh)];
        let chanamt = 100u64;

        let (previous_tx, txid) = make_test_previous_tx(&secp_ctx, &node, &values);

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let (opath, mut tx) =
            make_test_funding_tx_with_p2shwpkh_change(&secp_ctx, &node, vec![input1], chanamt);
        let (wallet_ndx, values_sat, spendtypes): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(values);
        let ipaths: Vec<Vec<u32>> = wallet_ndx.into_iter().map(|n| vec![n]).collect();

        // NOTE - this does not trigger policy-onchain-funding-non-malleable because
        // there is no channel associated with this tx.

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &vec![&previous_tx],
                &ipaths,
                &values_sat,
                &spendtypes,
                vec![None],
                &vec![opath.clone()],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let pubkey = &node.get_wallet_pubkey(&secp_ctx, &ipaths[0]).unwrap();
        let keyhash = Hash160::hash(&pubkey.serialize()[..]);
        tx.input[0].script_sig = Builder::new()
            .push_slice(
                Builder::new()
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_slice(&keyhash.into_inner())
                    .into_script()
                    .as_bytes(),
            )
            .into_script();
        tx.input[0].witness = Witness::from_vec(witvec[0].clone());

        let verify_result = tx.verify(|p| Some(previous_tx.output[p.vout as usize].clone()));
        assert!(verify_result.is_ok());
        Ok(())
    }

    #[test]
    fn sign_funding_tx_psbt_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);

        let values0 = vec![(0, 100u64, SpendType::P2wpkh)];
        let values1 = vec![(1, 101u64, SpendType::P2wpkh)];
        let values2 = vec![(2, 102u64, SpendType::P2wpkh)];

        let previous = vec![
            make_test_previous_tx(&secp_ctx, &node, &values0),
            make_test_previous_tx(&secp_ctx, &node, &values1),
            make_test_previous_tx(&secp_ctx, &node, &values2),
        ];
        let (previous_txs, txids): (Vec<_>, Vec<_>) = previous.into_iter().unzip();

        let inputs = vec![
            TxIn {
                previous_output: OutPoint { txid: txids[0], vout: 0 },
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint { txid: txids[1], vout: 0 },
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint { txid: txids[2], vout: 0 },
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::default(),
            },
        ];

        let (opath, tx) = make_test_funding_tx(&secp_ctx, &node, inputs, 100);
        let uniclosekeys = vec![None, None, None];

        let ipaths = vec![vec![values0[0].0], vec![values1[0].0], vec![values2[0].0]];
        let values_sat = vec![values0[0].1, values1[0].1, values2[0].1];

        // In this test we pretend the first and last inputs are not ours
        let spendtypes = vec![SpendType::Invalid, SpendType::P2wpkh, SpendType::Invalid];

        let witvec = node
            .check_and_sign_onchain_tx(
                &tx,
                &previous_txs.iter().collect(),
                &ipaths,
                &values_sat,
                &spendtypes,
                uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        // Should have three witness stack items.
        assert_eq!(witvec.len(), 3);

        // First item should be empty sig/pubkey.
        assert_eq!(witvec[0].len(), 0);

        // Second should have values.
        assert!(witvec[1].len() > 0);

        // Third should be empty.
        assert_eq!(witvec[2].len(), 0);

        // Doesn't verify, not fully signed.
        Ok(())
    }

    #[allow(dead_code)]
    struct FundingTxMutationState<'a> {
        chan_ctx: &'a mut TestChannelContext,
        tx_ctx: &'a mut TestFundingTxContext,
        tx: &'a mut Transaction,
    }

    fn sign_funding_tx_with_mutator<FundingTxMutator>(
        mutate_funding_tx: FundingTxMutator,
    ) -> Result<(), Status>
    where
        FundingTxMutator: Fn(&mut FundingTxMutationState),
    {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming0 = 5_000_000;
        let incoming1 = 4_000_000;
        let channel_amount = 3_000_000;
        let allowlist = 200_000;
        let fee = 1000;
        let change0 = 90_000;
        let change1 = incoming0 + incoming1 - allowlist - channel_amount - fee - change0;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();
        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming0);
        tx_ctx.add_wallet_input(&node_ctx, stype, 2, incoming1);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change0);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change1);
        tx_ctx.add_allowlist_output(&node_ctx, stype, 42, allowlist);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        mutate_funding_tx(&mut FundingTxMutationState {
            chan_ctx: &mut chan_ctx,
            tx_ctx: &mut tx_ctx,
            tx: &mut tx,
        });

        let err_opt = funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);
        if let Some(err) = err_opt {
            return Err(err);
        }

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = tx_ctx.sign(&node_ctx, &tx)?;
        tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);

        Ok(())
    }

    #[test]
    fn success_static() {
        assert_status_ok!(sign_funding_tx_with_mutator(|fms| {
            fms.chan_ctx.setup.commitment_type = CommitmentType::StaticRemoteKey;
        }));
    }

    #[test]
    fn success_anchors() {
        assert_status_ok!(sign_funding_tx_with_mutator(|fms| {
            fms.chan_ctx.setup.commitment_type = CommitmentType::AnchorsZeroFeeHtlc;
        }));
    }

    // policy-onchain-format-standard
    #[test]
    fn bad_version_1() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx.version = 1;
            }),
            "policy failure: validate_onchain_tx: invalid version: 1"
        );
    }

    // policy-onchain-format-standard
    #[test]
    fn bad_version_3() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx.version = 3;
            }),
            "policy failure: validate_onchain_tx: invalid version: 3"
        );
    }

    #[test]
    fn wallet_cannot_spend() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx_ctx.opaths[0] = vec![33];
            }),
            "policy failure: validate_onchain_tx: output[0] is unknown"
        );
    }

    #[test]
    fn inputs_overflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx_ctx.ivals[0] = u64::MAX;
            }),
            "policy failure: funding sum inputs overflow"
        );
    }

    #[test]
    fn wallet_change_overflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx.output[1].value = u64::MAX;
            }),
            "policy failure: beneficial outputs overflow: \
             sum 90000 + to wallet 18446744073709551615"
        );
    }

    #[test]
    fn allowlist_overflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx.output[2].value = u64::MAX;
            }),
            "policy failure: beneficial outputs overflow: \
             sum 5799000 + allowlisted 18446744073709551615"
        );
    }

    #[test]
    fn channel_value_overflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                // bump the allowlisted value to almost overflow ... channel will overflow
                fms.tx.output[2].value = u64::MAX
                    - fms.tx.output[0].value
                    - fms.tx.output[1].value
                    - fms.tx.output[2].value
                    + 1;
            }),
            "policy failure: beneficial outputs overflow: \
             sum 18446744073709351616 + channel value 3000000"
        );
    }

    #[test]
    fn non_beneficial_value_underflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.tx.output[1].value += 10_000_000;
            }),
            "policy failure: validate_onchain_tx: non-beneficial value underflow: \
             sum of our inputs 9000000 < sum of our outputs 18999000"
        );
    }

    #[test]
    fn channel_value_underflow() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.chan_ctx.setup.push_value_msat =
                    (fms.chan_ctx.setup.channel_value_sat + 100) * 1000;
            }),
            "policy failure: beneficial channel value underflow: 3000000000 - 3000100000"
        );
    }

    // policy-onchain-no-fund-inbound
    #[test]
    fn dual_funding_not_supported() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|fms| {
                fms.chan_ctx.setup.is_outbound = false;
            }),
            "policy failure: validate_onchain_tx: \
             can't sign for inbound channel: dual-funding not supported yet"
        );
    }

    fn sign_funding_tx_with_output_and_change(stype: SpendType) {
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        match stype {
            SpendType::P2shP2wpkh => {
                assert_failed_precondition_err!(
                    tx_ctx.sign(&node_ctx, &tx),
                    "policy failure: validate_onchain_tx: funding tx has non-segwit-native input"
                );
            }
            SpendType::P2wpkh => {
                let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
                tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);

                // weight_lower_bound from node debug is: 612 and 608
                assert_eq!(tx.weight(), 610);
            }
            _ => panic!("unexpected spendtype"),
        }
    }

    #[test]
    fn sign_funding_tx_with_p2wpkh_wallet() {
        sign_funding_tx_with_output_and_change(SpendType::P2wpkh);
    }

    #[test]
    fn sign_funding_tx_with_p2sh_wallet() {
        sign_funding_tx_with_output_and_change(SpendType::P2shP2wpkh);
    }

    #[test]
    fn sign_funding_tx_with_multiple_wallet_inputs() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming0 = 2_000_000;
        let incoming1 = 3_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming0 + incoming1 - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming0);
        tx_ctx.add_wallet_input(&node_ctx, stype, 2, incoming1);

        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
        tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);

        // weight_lower_bound from node debug is 880
        assert_eq!(tx.weight(), 881);
    }

    #[test]
    fn sign_funding_tx_with_missing_input_txs() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming0 = 2_000_000;
        let incoming1 = 3_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming0 + incoming1 - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming0);
        tx_ctx.add_wallet_input(&node_ctx, stype, 2, incoming1);

        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        tx_ctx.input_txs.clear(); // Remove the input_txs

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: funding tx has non-segwit-native input"
        );
    }

    #[test]
    fn sign_funding_tx_with_non_segwit_input() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming0 = 2_000_000;
        let incoming1 = 3_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming0 + incoming1 - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming0);
        tx_ctx.add_wallet_input(
            &node_ctx,
            SpendType::P2pkh, // not segwit!
            2,
            incoming1,
        );

        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: funding tx has non-segwit-native input"
        );
    }

    #[test]
    fn sign_funding_tx_with_output_and_multiple_change() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change0 = 1_000_000;
        let change1 = incoming - channel_amount - fee - change0;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change0);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change1);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
        tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);
    }

    #[test]
    fn output_and_allowlisted() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change0 = 1_000_000;
        let change1 = incoming - channel_amount - fee - change0;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change0);
        tx_ctx.add_allowlist_output(&node_ctx, stype, 42, change1);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
        tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);
    }

    #[test]
    fn sign_funding_tx_with_multiple_outputs_and_change() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 10_000_000;
        let channel_amount0 = 3_000_000;
        let channel_amount1 = 4_000_000;
        let fee = 1000;
        let change = incoming - channel_amount0 - channel_amount1 - fee;

        let mut chan_ctx0 = test_chan_ctx(&node_ctx, 1, channel_amount0);
        let mut chan_ctx1 = test_chan_ctx(&node_ctx, 2, channel_amount1);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);

        let outpoint_ndx0 = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx0, channel_amount0);

        let outpoint_ndx1 = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx1, channel_amount1);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx0, &tx, outpoint_ndx0);
        funding_tx_ready_channel(&node_ctx, &mut chan_ctx1, &tx, outpoint_ndx1);

        let mut commit_tx_ctx0 = channel_initial_holder_commitment(&node_ctx, &chan_ctx0);
        let (csig0, hsigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx0, &mut commit_tx_ctx0);
        validate_holder_commitment(&node_ctx, &chan_ctx0, &commit_tx_ctx0, &csig0, &hsigs0)
            .expect("valid holder commitment");

        let mut commit_tx_ctx1 = channel_initial_holder_commitment(&node_ctx, &chan_ctx1);
        let (csig1, hsigs1) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx1, &mut commit_tx_ctx1);
        validate_holder_commitment(&node_ctx, &chan_ctx1, &commit_tx_ctx1, &csig1, &hsigs1)
            .expect("valid holder commitment");

        let witvec = tx_ctx.sign(&node_ctx, &tx).expect("witvec");
        tx_ctx.validate_sig(&node_ctx, &mut tx, &witvec);
    }

    // policy-onchain-initial-commitment-countersigned
    #[test]
    fn sign_funding_tx_with_missing_initial_commitment_validation() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 10_000_000;
        let channel_amount0 = 3_000_000;
        let channel_amount1 = 4_000_000;
        let fee = 1000;
        let change = incoming - channel_amount0 - channel_amount1 - fee;

        let mut chan_ctx0 = test_chan_ctx(&node_ctx, 1, channel_amount0);
        let mut chan_ctx1 = test_chan_ctx(&node_ctx, 2, channel_amount1);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);

        let outpoint_ndx0 = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx0, channel_amount0);

        let outpoint_ndx1 = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx1, channel_amount1);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx0, &tx, outpoint_ndx0);
        funding_tx_ready_channel(&node_ctx, &mut chan_ctx1, &tx, outpoint_ndx1);

        let mut commit_tx_ctx0 = channel_initial_holder_commitment(&node_ctx, &chan_ctx0);
        let (csig0, hsigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx0, &mut commit_tx_ctx0);
        validate_holder_commitment(&node_ctx, &chan_ctx0, &commit_tx_ctx0, &csig0, &hsigs0)
            .expect("valid holder commitment");

        // Don't validate the second channel's holder commitment.

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: initial holder commitment not validated"
        );
    }

    // policy-onchain-output-match-commitment
    // policy-onchain-no-unknown-outputs
    #[test]
    fn sign_funding_tx_with_unknown_output() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let unknown = 500_000;
        let fee = 1000;
        let change = incoming - channel_amount - unknown - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        tx_ctx.add_unknown_output(&node_ctx, stype, 42, unknown);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        // Because the channel isn't found the output is considered non-beneficial.
        assert_failed_precondition_err!(tx_ctx.sign(&node_ctx, &tx), "unknown destinations:  [1]");
    }

    #[test]
    fn sign_funding_tx_with_bad_input_path() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        tx_ctx.ipaths[0] = vec![42, 42]; // bad input path

        assert_invalid_argument_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "get_wallet_key: bad child_path len : 2"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_path() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        tx_ctx.opaths[0] = vec![42, 42]; // bad output path

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: output[0]: wallet_can_spend error: \
             status: InvalidArgument, message: \"get_wallet_key: bad child_path len : 2\""
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_value() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        // Modify the output value after funding_tx_ready_channel
        tx.output[1].value = channel_amount + 42; // bad output value

        // Because the amount is bogus, the channel isn't found and the output is considered
        // non-beneficial.
        assert_failed_precondition_err!(tx_ctx.sign(&node_ctx, &tx), "unknown destinations:  [1]");
    }

    #[test]
    fn sign_funding_tx_with_bad_output_value2() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        // Modify the output value before funding_tx_ready_channel
        tx.output[1].value = channel_amount + 42; // bad output value

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: \
             funding output amount mismatch w/ channel: 3000042 != 3000000"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_script_pubkey() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut tx_ctx = TestFundingTxContext::new();
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        // very bogus script
        tx.output[1].script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&[27; 32])
            .into_script();

        // Because the script is bogus, the channel isn't found and the output is considered
        // non-beneficial.
        assert_failed_precondition_err!(tx_ctx.sign(&node_ctx, &tx), "unknown destinations:  [1]");
    }

    // policy-onchain-output-scriptpubkey
    #[test]
    fn sign_funding_tx_with_bad_output_script_pubkey2() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let mut tx = tx_ctx.to_tx();

        // very bogus script
        tx.output[1].script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&[27; 32])
            .into_script();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: funding script_pubkey mismatch w/ channel: Script(OP_0 OP_PUSHBYTES_32 1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b) != Script(OP_0 OP_PUSHBYTES_32 738b77057fb1636913da743e18f0510a261dca80dd61e2852852e62e9aa334d9)"
        );
    }

    // policy-onchain-no-channel-push
    #[test]
    fn sign_funding_tx_with_bad_push_val() {
        let stype = SpendType::P2wpkh;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;
        let push_val_msat = 300_000 * 1000;

        let mut chan_ctx = test_chan_ctx_with_push_val(&node_ctx, 1, channel_amount, push_val_msat);
        let mut tx_ctx = TestFundingTxContext::new();

        tx_ctx.add_wallet_input(&node_ctx, stype, 1, incoming);
        tx_ctx.add_wallet_output(&node_ctx, stype, 1, change);
        let outpoint_ndx = tx_ctx.add_channel_outpoint(&node_ctx, &chan_ctx, channel_amount);

        let tx = tx_ctx.to_tx();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        assert_failed_precondition_err!(
            tx_ctx.sign(&node_ctx, &tx),
            "policy failure: validate_onchain_tx: \
             channel push not allowed: dual-funding not supported yet"
        );
    }
}
