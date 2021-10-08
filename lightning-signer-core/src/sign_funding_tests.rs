#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::hashes::hash160::Hash as Hash160;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{self, Address, Network, OutPoint, Script, Transaction, TxIn, TxOut};

    use test_env_log::test;

    use crate::node::SpendType;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[test]
    fn sign_funding_tx_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let ipaths = vec![vec![0u32], vec![1u32]];
        let ival0 = 100u64;
        let ival1 = 300u64;
        let chanamt = 300u64;
        let values_sat = vec![ival0, ival1];

        let input1 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let input2 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 1,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };
        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1, input2], chanamt);
        let spendtypes = vec![SpendType::P2wpkh, SpendType::P2wpkh];
        let uniclosekeys = vec![None, None];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 2);

        let address = |n: u32| {
            Address::p2wpkh(
                &node.get_wallet_pubkey(&secp_ctx, &vec![n]).unwrap(),
                Network::Testnet,
            )
            .unwrap()
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        tx.input[1].witness = vec![witvec[1].0.clone(), witvec[1].1.clone()];

        let outs = vec![
            TxOut {
                value: ival0,
                script_pubkey: address(0).script_pubkey(),
            },
            TxOut {
                value: ival1,
                script_pubkey: address(1).script_pubkey(),
            },
        ];
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test1() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ipaths = vec![vec![0u32]];
        let ival0 = 200u64;
        let chanamt = 100u64;
        let values_sat = vec![ival0];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let spendtypes = vec![SpendType::P2wpkh];
        let uniclosekeys = vec![None];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2wpkh(
                &node.get_wallet_pubkey(&secp_ctx, &vec![n]).unwrap(),
                Network::Testnet,
            )
            .unwrap()
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: ival0,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    // policy-funding-fee-range
    #[test]
    fn sign_funding_tx_fee_too_low() {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ipaths = vec![vec![0u32]];
        let ival0 = 199u64;
        let chanamt = 100u64;
        let values_sat = vec![ival0];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let spendtypes = vec![SpendType::P2wpkh];
        let uniclosekeys = vec![None];

        assert_failed_precondition_err!(
            node.sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath.clone()],
            ),
            "policy failure: validate_funding_tx: validate_fee: fee below minimum: 99 < 100"
        );
    }

    // policy-funding-fee-range
    #[test]
    fn sign_funding_tx_fee_too_high() {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ipaths = vec![vec![0u32]];
        let fee = 81_000u64;
        let ival0 = 100u64 + fee;
        let chanamt = 100u64;
        let values_sat = vec![ival0];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let spendtypes = vec![SpendType::P2wpkh];
        let uniclosekeys = vec![None];

        assert_failed_precondition_err!(
            node.sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath.clone()],
            ),
            "policy failure: validate_funding_tx: validate_fee: fee above maximum: 81000 > 80000"
        );
    }

    #[test]
    fn sign_funding_tx_unilateral_close_info_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ival0 = 300u64;
        let chanamt = 200u64;
        let ipaths = vec![vec![0u32]];
        let values_sat = vec![ival0];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], chanamt);
        let spendtypes = vec![SpendType::P2wpkh];

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
        let uniclosekeys = vec![Some(uniclosekey)];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        assert_eq!(witvec[0].1, uniclosepubkey.serialize());

        let address = Address::p2wpkh(&uniclosepubkey, Network::Testnet).unwrap();

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: ival0,
            script_pubkey: address.script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2pkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ipaths = vec![vec![0u32]];
        let values_sat = vec![200u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, mut tx) = make_test_funding_tx(&secp_ctx, &node, vec![input1], 100);
        let spendtypes = vec![SpendType::P2pkh];
        let uniclosekeys = vec![None];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2pkh(
                &node.get_wallet_pubkey(&secp_ctx, &vec![n]).unwrap(),
                Network::Testnet,
            )
        };

        tx.input[0].script_sig = Builder::new()
            .push_slice(witvec[0].0.as_slice())
            .push_slice(witvec[0].1.as_slice())
            .into_script();
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));
        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2sh_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let ipaths = vec![vec![0u32]];
        let ival0 = 200u64;
        let chanamt = 100u64;
        let values_sat = vec![ival0];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let (opath, mut tx) =
            make_test_funding_tx_with_p2shwpkh_change(&secp_ctx, &node, vec![input1], chanamt);
        let spendtypes = vec![SpendType::P2shP2wpkh];
        let uniclosekeys = vec![None];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2shwpkh(
                &node.get_wallet_pubkey(&secp_ctx, &vec![n]).unwrap(),
                Network::Testnet,
            )
            .unwrap()
        };

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

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: ival0,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_psbt_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let txids = vec![
            bitcoin::Txid::from_slice(&[2u8; 32]).unwrap(),
            bitcoin::Txid::from_slice(&[4u8; 32]).unwrap(),
            bitcoin::Txid::from_slice(&[6u8; 32]).unwrap(),
        ];

        let inputs = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: txids[0],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint {
                    txid: txids[1],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint {
                    txid: txids[2],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0,
                witness: vec![],
            },
        ];

        let (opath, tx) = make_test_funding_tx(&secp_ctx, &node, inputs, 100);
        let ipaths = vec![vec![0u32], vec![1u32], vec![2u32]];
        let values_sat = vec![100u64, 101u64, 102u64];
        let spendtypes = vec![
            SpendType::Invalid,
            SpendType::P2shP2wpkh,
            SpendType::Invalid,
        ];
        let uniclosekeys = vec![None, None, None];

        let witvec = node
            .sign_funding_tx(
                &tx,
                &ipaths,
                &values_sat,
                &spendtypes,
                &uniclosekeys,
                &vec![opath],
            )
            .expect("good sigs");
        // Should have three witness stack items.
        assert_eq!(witvec.len(), 3);

        // First item should be empty sig/pubkey.
        assert_eq!(witvec[0].0.len(), 0);
        assert_eq!(witvec[0].1.len(), 0);

        // Second should have values.
        assert!(witvec[1].0.len() > 0);
        assert!(witvec[1].1.len() > 0);

        // Third should be empty.
        assert_eq!(witvec[2].0.len(), 0);
        assert_eq!(witvec[2].1.len(), 0);

        // Doesn't verify, not fully signed.
        Ok(())
    }

    fn sign_funding_tx_with_mutator<TxMutator>(txmut: TxMutator) -> Result<(), Status>
    where
        TxMutator: Fn(&mut Transaction),
    {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        // mutate the tx before calling funding_tx_ready_channel so txid will be valid
        txmut(&mut tx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)?;

        let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx)?;
        funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);
        Ok(())
    }

    #[test]
    fn sign_funding_tx_with_no_mut_test() {
        let status = sign_funding_tx_with_mutator(|_tx| {
            // don't mutate the tx, should pass
        });
        assert!(status.is_ok());
    }

    // policy-funding-format-standard
    #[test]
    fn sign_funding_tx_with_version_1() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|tx| {
                tx.version = 1;
            }),
            "policy failure: validate_funding_tx: invalid version: 1"
        );
    }

    // policy-funding-format-standard
    #[test]
    fn sign_funding_tx_with_version_3() {
        assert_failed_precondition_err!(
            sign_funding_tx_with_mutator(|tx| {
                tx.version = 3;
            }),
            "policy failure: validate_funding_tx: invalid version: 3"
        );
    }

    fn sign_funding_tx_with_output_and_change(is_p2sh: bool) {
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
        funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);
    }

    #[test]
    fn sign_funding_tx_with_p2wpkh_wallet() {
        sign_funding_tx_with_output_and_change(false);
    }

    #[test]
    fn sign_funding_tx_with_p2sh_wallet() {
        sign_funding_tx_with_output_and_change(true);
    }

    #[test]
    fn sign_funding_tx_with_multiple_wallet_inputs() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming0 = 2_000_000;
        let incoming1 = 3_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming0 + incoming1 - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming0);
        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 2, incoming1);

        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
        funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);
    }

    #[test]
    fn sign_funding_tx_with_output_and_multiple_change() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change0 = 1_000_000;
        let change1 = incoming - channel_amount - fee - change0;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change0);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change1);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
        funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);
    }

    #[test]
    fn sign_funding_tx_with_multiple_outputs_and_change() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 10_000_000;
        let channel_amount0 = 3_000_000;
        let channel_amount1 = 4_000_000;
        let fee = 1000;
        let change = incoming - channel_amount0 - channel_amount1 - fee;

        let mut chan_ctx0 = test_chan_ctx(&node_ctx, 1, channel_amount0);
        let mut chan_ctx1 = test_chan_ctx(&node_ctx, 2, channel_amount1);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);

        let outpoint_ndx0 =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx0, &mut tx_ctx, channel_amount0);

        let outpoint_ndx1 =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx1, &mut tx_ctx, channel_amount1);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

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

        let witvec = funding_tx_sign(&node_ctx, &tx_ctx, &tx).expect("witvec");
        funding_tx_validate_sig(&node_ctx, &tx_ctx, &mut tx, &witvec);
    }

    // policy-funding-initial-commitment-countersigned
    #[test]
    fn sign_funding_tx_with_missing_initial_commitment_validation() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 10_000_000;
        let channel_amount0 = 3_000_000;
        let channel_amount1 = 4_000_000;
        let fee = 1000;
        let change = incoming - channel_amount0 - channel_amount1 - fee;

        let mut chan_ctx0 = test_chan_ctx(&node_ctx, 1, channel_amount0);
        let mut chan_ctx1 = test_chan_ctx(&node_ctx, 2, channel_amount1);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);

        let outpoint_ndx0 =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx0, &mut tx_ctx, channel_amount0);

        let outpoint_ndx1 =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx1, &mut tx_ctx, channel_amount1);

        let tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx0, &tx, outpoint_ndx0);
        funding_tx_ready_channel(&node_ctx, &mut chan_ctx1, &tx, outpoint_ndx1);

        let mut commit_tx_ctx0 = channel_initial_holder_commitment(&node_ctx, &chan_ctx0);
        let (csig0, hsigs0) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx0, &mut commit_tx_ctx0);
        validate_holder_commitment(&node_ctx, &chan_ctx0, &commit_tx_ctx0, &csig0, &hsigs0)
            .expect("valid holder commitment");

        // Don't validate the second channel's holder commitment.

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: validate_funding_tx: initial holder commitment not validated"
        );
    }

    // policy-funding-output-match-commitment
    // policy-funding-change-to-wallet
    #[test]
    fn sign_funding_tx_with_unknown_output() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let unknown = 500_000;
        let fee = 1000;
        let change = incoming - channel_amount - unknown - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        funding_tx_add_unknown_output(&node_ctx, &mut tx_ctx, is_p2sh, 42, unknown);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: unknown output: a5b4d12cf257a92e0536ddfce77635f92283f1e81e4d4f5ce7239bd36cfe925c:1"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_input_path() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        let mut commit_tx_ctx = channel_initial_holder_commitment(&node_ctx, &chan_ctx);
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);
        validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
            .expect("valid holder commitment");

        tx_ctx.ipaths[0] = vec![42, 42]; // bad input path

        assert_invalid_argument_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "get_wallet_key: bad child_path len : 2"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_path() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        tx_ctx.opaths[0] = vec![42, 42]; // bad output path

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: output[0]: wallet_can_spend error: \
             status: InvalidArgument, message: \"get_wallet_key: bad child_path len : 2\""
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_value() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        // Modify the output value after funding_tx_ready_channel
        tx.output[1].value = channel_amount + 42; // bad output value

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: unknown output: 445f380db31cb6647304fefe17d69df19d0a7e8840394a295cb99a98dfce2b73:1"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_value2() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        // Modify the output value before funding_tx_ready_channel
        tx.output[1].value = channel_amount + 42; // bad output value

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: validate_funding_tx: \
             funding output amount mismatch w/ channel: 3000042 != 3000000"
        );
    }

    #[test]
    fn sign_funding_tx_with_bad_output_script_pubkey() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut tx_ctx = test_funding_tx_ctx();
        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        // very bogus script
        tx.output[1].script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&[27; 32])
            .into_script();

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: unknown output: 81fe91f5705b1a893494726cc9019614aa108fd02809e9f23673c83ea6404bce:1"
        );
    }

    // policy-funding-output-scriptpubkey
    #[test]
    fn sign_funding_tx_with_bad_output_script_pubkey2() {
        let is_p2sh = false;
        let node_ctx = test_node_ctx(1);

        let incoming = 5_000_000;
        let channel_amount = 3_000_000;
        let fee = 1000;
        let change = incoming - channel_amount - fee;

        let mut chan_ctx = test_chan_ctx(&node_ctx, 1, channel_amount);
        let mut tx_ctx = test_funding_tx_ctx();

        funding_tx_add_wallet_input(&mut tx_ctx, is_p2sh, 1, incoming);
        funding_tx_add_wallet_output(&node_ctx, &mut tx_ctx, is_p2sh, 1, change);
        let outpoint_ndx =
            funding_tx_add_channel_outpoint(&node_ctx, &chan_ctx, &mut tx_ctx, channel_amount);

        let mut tx = funding_tx_from_ctx(&tx_ctx);

        // very bogus script
        tx.output[1].script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&[27; 32])
            .into_script();

        funding_tx_ready_channel(&node_ctx, &mut chan_ctx, &tx, outpoint_ndx);

        assert_failed_precondition_err!(
            funding_tx_sign(&node_ctx, &tx_ctx, &tx),
            "policy failure: validate_funding_tx: funding script_pubkey mismatch w/ channel: Script(OP_0 OP_PUSHBYTES_32 1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b) != Script(OP_0 OP_PUSHBYTES_32 7ac8486233edd675a9745d9eefd4386880312b3930a2195567b4b89220b5c833)"
        );
    }
}
