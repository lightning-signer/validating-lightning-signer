#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use bitcoin::{
        self, OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use lightning::ln::chan_utils::get_htlc_redeemscript;
    use test_log::test;

    use crate::channel::{Channel, CommitmentType, TypedSignature};
    use crate::node::SpendType::{P2shP2wpkh, P2wpkh};
    use crate::policy::validator::ChainState;
    use crate::sign_counterparty_htlc_sweep_tests::tests::HTLCKind::{OfferedHTLC, ReceivedHTLC};
    use crate::util::key_utils::make_test_pubkey;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    #[derive(PartialEq, Debug)]
    enum HTLCKind {
        OfferedHTLC,
        ReceivedHTLC,
    }

    fn make_test_counterparty_offered_htlc_sweep_tx(
        txid: Txid,
        vout: u32,
        is_anchors: bool,
        script_pubkey: Script,
        amount_sat: u64,
    ) -> Transaction {
        Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: Script::new(),
                sequence: Sequence(if is_anchors { 1 } else { 0 }),
                witness: Witness::default(),
            }],
            output: vec![TxOut { script_pubkey: script_pubkey, value: amount_sat }],
        }
    }

    fn make_test_counterparty_received_htlc_sweep_tx(
        lock_time: u32,
        txid: Txid,
        vout: u32,
        is_anchors: bool,
        script_pubkey: Script,
        amount_sat: u64,
    ) -> Transaction {
        Transaction {
            version: 2,
            lock_time: PackedLockTime(lock_time),
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: Script::new(),
                sequence: Sequence(if is_anchors { 1 } else { 0 }),
                witness: Witness::default(),
            }],
            output: vec![TxOut { script_pubkey: script_pubkey, value: amount_sat }],
        }
    }

    fn sign_counterparty_htlc_sweep_with_mutators<MakeDestination, InputMutator>(
        kind: HTLCKind,
        make_dest: MakeDestination,
        mutate_signing_input: InputMutator,
    ) -> Result<(), Status>
    where
        MakeDestination: Fn(&TestNodeContext) -> (Script, Vec<u32>),
        InputMutator: Fn(
            &mut Channel,
            &mut ChainState,
            &mut Transaction,
            &mut usize,
            &mut PublicKey,
            &mut Script,
            &mut u64,
        ),
    {
        let (node, setup, channel_id, offered_htlcs, received_htlcs) =
            sign_commitment_tx_with_mutators_setup(CommitmentType::StaticRemoteKey);

        let secp_ctx = Secp256k1::signing_only();
        let node_ctx = TestNodeContext { node, secp_ctx };
        let counterparty_keys =
            make_test_counterparty_keys(&node_ctx, &channel_id, setup.channel_value_sat);
        let chan_ctx = TestChannelContext { channel_id, setup: setup.clone(), counterparty_keys };

        let (sig, tx, remote_per_commitment_point, input, htlc_redeemscript, htlc_amount_sat) =
            node_ctx.node.with_ready_channel(&chan_ctx.channel_id, |chan| {
                // These need to match sign_commitment_tx_with_mutators_setup() ...
                let commit_num = 23;
                let feerate_per_kw = 5_000;
                let to_broadcaster = 1_979_997;
                let to_countersignatory = 1_000_000;

                let mut remote_per_commitment_point = make_test_pubkey(10);
                let keys = chan.make_counterparty_tx_keys(&remote_per_commitment_point)?;

                let htlcs =
                    Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

                let commitment_tx = chan.make_counterparty_commitment_tx_with_keys(
                    keys.clone(),
                    commit_num,
                    feerate_per_kw,
                    to_countersignatory,
                    to_broadcaster,
                    htlcs.clone(),
                );

                let mut input = 0;

                let built_commit = commitment_tx.trust().built_transaction().clone();
                let built_commit_txid = &built_commit.txid;

                let (script_pubkey, wallet_path) = make_dest(&node_ctx);

                let fee = 1_000;
                let (mut tx, mut htlc_redeemscript, mut htlc_amount_sat) = if kind == OfferedHTLC {
                    let outndx = 0;
                    let htlc = &htlcs[0];
                    let htlc_redeemscript =
                        get_htlc_redeemscript(htlc, setup.option_anchors(), &keys);
                    let htlc_amount_sat = htlc.amount_msat / 1000;
                    (
                        make_test_counterparty_offered_htlc_sweep_tx(
                            built_commit_txid.clone(),
                            outndx,
                            chan.setup.option_anchors(),
                            script_pubkey,
                            htlc_amount_sat - fee,
                        ),
                        htlc_redeemscript,
                        htlc_amount_sat,
                    )
                } else {
                    let outndx = 1;
                    let htlc = &htlcs[1];
                    let htlc_redeemscript =
                        get_htlc_redeemscript(htlc, setup.option_anchors(), &keys);
                    let htlc_amount_sat = htlc.amount_msat / 1000;
                    (
                        make_test_counterparty_received_htlc_sweep_tx(
                            htlc.cltv_expiry,
                            built_commit_txid.clone(),
                            outndx,
                            chan.setup.option_anchors(),
                            script_pubkey,
                            htlc_amount_sat - fee,
                        ),
                        htlc_redeemscript,
                        htlc_amount_sat,
                    )
                };

                let mut cstate = make_test_chain_state();

                mutate_signing_input(
                    chan,
                    &mut cstate,
                    &mut tx,
                    &mut input,
                    &mut remote_per_commitment_point,
                    &mut htlc_redeemscript,
                    &mut htlc_amount_sat,
                );

                let sig = chan.sign_counterparty_htlc_sweep(
                    &tx,
                    input,
                    &remote_per_commitment_point,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &wallet_path,
                )?;
                Ok((
                    sig,
                    tx,
                    remote_per_commitment_point,
                    input,
                    htlc_redeemscript,
                    htlc_amount_sat,
                ))
            })?;

        let htlc_pubkey = get_channel_htlc_pubkey(
            &node_ctx.node,
            &chan_ctx.channel_id,
            &remote_per_commitment_point,
        );

        check_signature(
            &tx,
            input,
            TypedSignature::all(sig),
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
        );

        Ok(())
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_wallet_p2wpkh_success() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            OfferedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
            |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
        ));
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_received_htlc_sweep_wallet_p2wpkh_success() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
            |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
        ));
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_wallet_p2shwpkh_success() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            OfferedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
            |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
        ));
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_received_htlc_sweep_wallet_p2shwpkh_success() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
            |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
        ));
    }

    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_bad_input_index() {
        assert_invalid_argument_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                ReceivedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
                |_chan, _cstate, _tx, input, _commit_num, _redeemscript, _amount_sat| {
                    *input = 1;
                },
            ),
            "sign_counterparty_htlc_sweep: bad input index: 1 >= 1"
        );
    }

    // policy-sweep-version
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_bad_version() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
                |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                    tx.version = 1;
                },
            ),
            "transaction format: validate_counterparty_htlc_sweep: validate_sweep: \
             bad version: 1"
        );
    }

    // policy-sweep-locktime
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_bad_locktime() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
                |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                    tx.lock_time = PackedLockTime(1_000_000);
                },
            ),
            "transaction format: validate_counterparty_htlc_sweep: \
             bad locktime: 1000000 > 3"
        );
    }

    // policy-sweep-sequence
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_bad_sequence() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                ReceivedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
                |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                    tx.input[0].sequence = Sequence(42);
                },
            ),
            "transaction format: validate_counterparty_htlc_sweep: \
             bad sequence: 42 not in [0, 4294967293, 4294967295]"
        );
    }

    // policy-sweep-sequence
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_seq_0() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
            |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                tx.input[0].sequence = Sequence::ZERO;
            },
        ));
    }

    // policy-sweep-sequence
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_seq_ffff_ffff() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
            |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                tx.input[0].sequence = Sequence::MAX;
            },
        ));
    }

    // policy-sweep-sequence
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_seq_ffff_fffd() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
            |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
            },
        ));
    }

    // policy-sweep-sequence
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_bad_seq_ffff_fffe() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                ReceivedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2wpkh) },
                |_chan, _cstate, tx, _input, _commit_num, _redeemscript, _amount_sat| {
                    tx.input[0].sequence = Sequence(u32::MAX - 1);
                },
            ),
            "transaction format: validate_counterparty_htlc_sweep: \
             bad sequence: 4294967294 not in [0, 4294967293, 4294967295]"
        );
    }

    #[test]
    #[ignore] // no fee validation for now
    fn sign_counterparty_offered_htlc_sweep_with_fee_underflow() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
                |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, amount_sat| {
                    *amount_sat = 2_000;
                },
            ),
            "policy failure: validate_counterparty_htlc_sweep: validate_sweep: \
             fee underflow: 2000 - 3000"
        );
    }

    // policy-sweep-fee-range
    #[test]
    #[ignore] // no fee validation for now
    fn sign_counterparty_offered_htlc_sweep_with_fee_too_small() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
                |_chan, _cstate, tx, _input, _commit_num, _redeemscript, amount_sat| {
                    *amount_sat = tx.output[0].value; // fee = 0
                },
            ),
            "policy failure: validate_counterparty_htlc_sweep: validate_sweep: validate_fee: \
             fee below minimum: 0 < 100"
        );
    }

    // policy-sweep-fee-range
    #[test]
    #[ignore] // no fee validation for now
    fn sign_counterparty_offered_htlc_sweep_with_fee_too_large() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_wallet_dest(node_ctx, 19, P2shP2wpkh) },
                |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, amount_sat| {
                    *amount_sat += 280_000;
                },
            ),
            "policy failure: validate_counterparty_htlc_sweep: validate_sweep: validate_fee: \
             fee above maximum: 281000 > 200000"
        );
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_unknown_p2wpkh_dest() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                OfferedHTLC,
                |node_ctx| { make_test_nonwallet_dest(node_ctx, 3, P2wpkh) },
                |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
            ),
            "policy failure: validate_counterparty_htlc_sweep: validate_sweep: \
             destination is not in wallet or allowlist"
        );
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_unknown_p2shwpkh_dest() {
        assert_failed_precondition_err!(
            sign_counterparty_htlc_sweep_with_mutators(
                ReceivedHTLC,
                |node_ctx| { make_test_nonwallet_dest(node_ctx, 3, P2shP2wpkh) },
                |_chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {},
            ),
            "policy failure: validate_counterparty_htlc_sweep: validate_sweep: \
             destination is not in wallet or allowlist"
        );
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_allowlisted_p2wpkh_dest() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            OfferedHTLC,
            |node_ctx| { make_test_nonwallet_dest(node_ctx, 3, P2wpkh) },
            |chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {
                chan.node
                    .upgrade()
                    .unwrap()
                    .add_allowlist(&vec!["tb1qg975h6gdx5mryeac72h6lj2nzygugxhyk6dnhr".to_string()])
                    .expect("add_allowlist");
            },
        ));
    }

    // policy-sweep-destination-allowlisted
    #[test]
    fn sign_counterparty_offered_htlc_sweep_with_allowlisted_p2shwpkh_dest() {
        assert_status_ok!(sign_counterparty_htlc_sweep_with_mutators(
            ReceivedHTLC,
            |node_ctx| { make_test_nonwallet_dest(node_ctx, 3, P2shP2wpkh) },
            |chan, _cstate, _tx, _input, _commit_num, _redeemscript, _amount_sat| {
                chan.node
                    .upgrade()
                    .unwrap()
                    .add_allowlist(&vec!["2MspRgcQvaVN2RkpumN1X8GkzsE7BVTTb6y".to_string()])
                    .expect("add_allowlist");
            },
        ));
    }
}
