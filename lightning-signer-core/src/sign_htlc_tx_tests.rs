#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::Hash;
    use bitcoin::{self, Transaction};
    use bitcoin::{PackedLockTime, Sequence};
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_htlc_redeemscript, get_revokeable_redeemscript,
        ChannelTransactionParameters, HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning::ln::PaymentHash;
    use test_log::test;

    use crate::channel::{ChannelBase, ChannelSetup, CommitmentType};
    use crate::policy::validator::ChainState;
    use crate::util::key_utils::*;
    use crate::util::status::{Code, Status};
    use crate::util::test_utils::*;

    use paste::paste;

    #[test]
    fn sign_local_htlc_tx_static_test() {
        let setup = make_test_channel_setup();
        sign_local_htlc_tx_test(&setup);
    }

    #[test]
    fn sign_local_htlc_tx_legacy_test() {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Legacy;
        sign_local_htlc_tx_test(&setup);
    }

    fn sign_local_htlc_tx_test(setup: &ChannelSetup) {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let htlc_amount_sat = 10 * 1000;

        let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: htlc_amount_sat * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let n: u64 = 1;

        let (per_commitment_point, txkeys, to_self_delay) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state.set_next_holder_commit_num_for_testing(n);
                let per_commitment_point = chan.get_per_commitment_point(n).expect("point");
                let txkeys =
                    chan.make_holder_tx_keys(&per_commitment_point).expect("failed to make txkeys");
                let to_self_delay =
                    chan.make_channel_parameters().as_holder_broadcastable().contest_delay();
                Ok((per_commitment_point, txkeys, to_self_delay))
            })
            .expect("point");

        let build_feerate = if setup.option_anchors_zero_fee_htlc() { 0 } else { feerate_per_kw };

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            build_feerate,
            to_self_delay,
            &htlc,
            setup.option_anchors(),
            &txkeys.broadcaster_delayed_payment_key,
            &txkeys.revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, setup.option_anchors(), &txkeys);

        let output_witscript = get_revokeable_redeemscript(
            &txkeys.revocation_key,
            to_self_delay,
            &txkeys.broadcaster_delayed_payment_key,
        );

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        let sig = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    n,
                    None,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sig, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);

        let sig1 = node
            .with_ready_channel(&channel_id, |chan| {
                chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    999,
                    Some(per_commitment_point),
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .unwrap();

        check_signature(&htlc_tx, 0, sig1, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);
    }

    #[allow(dead_code)]
    struct ChanParamMutationState<'a> {
        is_counterparty: bool,
        param: &'a mut ChannelTransactionParameters,
    }

    #[allow(dead_code)]
    struct KeysMutationState<'a> {
        keys: &'a mut TxCreationKeys,
    }

    #[allow(dead_code)]
    struct TxMutationState<'a> {
        is_offered: bool,
        cstate: &'a mut ChainState,
        tx: &'a mut Transaction,
    }

    fn sign_counterparty_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        commitment_type: CommitmentType,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_per_commitment_point = make_test_pubkey(10);
        let htlc_amount_sat = 1_000_000;

        let (typedsig, htlc_tx, htlc_redeemscript) =
            node.with_ready_channel(&channel_id, |chan| {
                let mut channel_parameters = chan.make_channel_parameters();

                // Mutate the channel parameters
                chanparammut(&mut ChanParamMutationState {
                    is_counterparty: true,
                    param: &mut channel_parameters,
                });

                let mut keys = chan.make_counterparty_tx_keys(&remote_per_commitment_point)?;

                // Mutate the tx creation keys.
                keysmut(&mut KeysMutationState { keys: &mut keys });

                let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
                let feerate_per_kw = 1000;
                let to_self_delay =
                    channel_parameters.as_counterparty_broadcastable().contest_delay();

                let htlc = HTLCOutputInCommitment {
                    offered: is_offered,
                    amount_msat: htlc_amount_sat * 1000,
                    cltv_expiry: if is_offered { 2 << 16 } else { 0 },
                    payment_hash: PaymentHash([1; 32]),
                    transaction_output_index: Some(0),
                };

                let build_feerate =
                    if setup.option_anchors_zero_fee_htlc() { 0 } else { feerate_per_kw };

                let mut htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    to_self_delay,
                    &htlc,
                    channel_parameters.opt_anchors.is_some(),
                    &keys.broadcaster_delayed_payment_key,
                    &keys.revocation_key,
                );

                let mut cstate = make_test_chain_state();

                // Mutate the transaction.
                txmut(&mut TxMutationState {
                    is_offered: is_offered,
                    cstate: &mut cstate,
                    tx: &mut htlc_tx,
                });

                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, channel_parameters.opt_anchors.is_some(), &keys);

                let output_witscript = get_revokeable_redeemscript(
                    &keys.revocation_key,
                    to_self_delay,
                    &keys.broadcaster_delayed_payment_key,
                );

                let typedsig = chan.sign_counterparty_htlc_tx(
                    &htlc_tx,
                    &remote_per_commitment_point,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok((typedsig, htlc_tx, htlc_redeemscript))
            })?;

        let expected_txid = if commitment_type == CommitmentType::StaticRemoteKey {
            if is_offered {
                "b93508d29f4866913340ce050c1f2fc366ac84824f1f4db388350cfa25a4f5cb"
            } else {
                "09bf12e4a113411134d9d8ee25e0d8e8ec3733867fe60bb4b8bebf29e393a08c"
            }
        } else if commitment_type == CommitmentType::Anchors {
            if is_offered {
                "cfb49b53f0ff73d3209372a56c9f7f64694ffa3f4a315c1216dbf24b95389ff9"
            } else {
                "6362ca6888aa61bb626aa55309af5e009e7c59211942a681bb6fca5625ba60e5"
            }
        } else if commitment_type == CommitmentType::AnchorsZeroFeeHtlc {
            if is_offered {
                "e3e293a3e9c447eab17baa88811cc10717bdbb805984eab08d12b8d6a271fd00"
            } else {
                "989947d5690c4823f28f66729be0cb09024a6b8279880dbede452db8772b8488"
            }
        } else {
            panic!("unknown commitment_type");
        };
        assert_eq!(htlc_tx.txid().to_hex(), expected_txid);

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &remote_per_commitment_point);

        check_counterparty_htlc_signature(
            &htlc_tx,
            0,
            typedsig,
            &htlc_pubkey,
            htlc_amount_sat,
            &htlc_redeemscript,
            setup.option_anchors(),
        );

        Ok(())
    }

    fn sign_holder_htlc_tx_with_mutators<ChanParamMutator, KeysMutator, TxMutator>(
        is_offered: bool,
        commitment_type: CommitmentType,
        chanparammut: ChanParamMutator,
        keysmut: KeysMutator,
        txmut: TxMutator,
    ) -> Result<(), Status>
    where
        ChanParamMutator: Fn(&mut ChanParamMutationState),
        KeysMutator: Fn(&mut KeysMutationState),
        TxMutator: Fn(&mut TxMutationState),
    {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = commitment_type;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let commit_num = 23;
        let htlc_amount_sat = 1_000_000;

        let (typedsig, per_commitment_point, htlc_tx, htlc_redeemscript) = node
            .with_ready_channel(&channel_id, |chan| {
                chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num);
                let mut channel_parameters = chan.make_channel_parameters();

                // Mutate the channel parameters
                chanparammut(&mut ChanParamMutationState {
                    is_counterparty: false,
                    param: &mut channel_parameters,
                });

                let per_commitment_point =
                    chan.get_per_commitment_point(commit_num).expect("point");
                let mut keys = chan.make_holder_tx_keys(&per_commitment_point)?;

                // Mutate the tx creation keys.
                keysmut(&mut KeysMutationState { keys: &mut keys });

                let commitment_txid = bitcoin::Txid::from_slice(&[2u8; 32]).unwrap();
                let feerate_per_kw = 1000;
                let to_self_delay = channel_parameters.as_holder_broadcastable().contest_delay();

                let htlc = HTLCOutputInCommitment {
                    offered: is_offered,
                    amount_msat: htlc_amount_sat * 1000,
                    cltv_expiry: if is_offered { 2 << 16 } else { 0 },
                    payment_hash: PaymentHash([1; 32]),
                    transaction_output_index: Some(0),
                };

                let build_feerate =
                    if setup.option_anchors_zero_fee_htlc() { 0 } else { feerate_per_kw };

                let mut htlc_tx = build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    to_self_delay,
                    &htlc,
                    channel_parameters.opt_anchors.is_some(),
                    &keys.broadcaster_delayed_payment_key,
                    &keys.revocation_key,
                );

                let mut cstate = make_test_chain_state();

                // Mutate the transaction.
                txmut(&mut TxMutationState {
                    is_offered: is_offered,
                    cstate: &mut cstate,
                    tx: &mut htlc_tx,
                });

                let htlc_redeemscript =
                    get_htlc_redeemscript(&htlc, channel_parameters.opt_anchors.is_some(), &keys);

                let output_witscript = get_revokeable_redeemscript(
                    &keys.revocation_key,
                    to_self_delay,
                    &keys.broadcaster_delayed_payment_key,
                );

                let typedsig = chan.sign_holder_htlc_tx(
                    &htlc_tx,
                    commit_num,
                    Some(per_commitment_point),
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok((typedsig, per_commitment_point, htlc_tx, htlc_redeemscript))
            })?;

        let expected_txid = if commitment_type == CommitmentType::StaticRemoteKey {
            if is_offered {
                "7358f246581726b4b5f51e361fb53e7ac23b46d05291ec9ed145835124291fe3"
            } else {
                "fd07a2d0bb62a2d6d64442e4ebb2208c0a64cee4a9727f02f457f26975960892"
            }
        } else if commitment_type == CommitmentType::Anchors {
            if is_offered {
                "59b9970727ae7a00576c5f0c0b4405882fb90d30a826d45dc713e905e355db47"
            } else {
                "a91d7f6fa13193b7aeab704d3585c0e9de54d4982227fe4b13ea94d8ae42542e"
            }
        } else if commitment_type == CommitmentType::AnchorsZeroFeeHtlc {
            if is_offered {
                "773b5faac142596f0aa385eba80e8abf44989528969763e8d8af2b4320644fa8"
            } else {
                "9e1c3501edc7490d1a04c848dbe1a2a988d977a54d287e294e03e4ac5947b1b2"
            }
        } else {
            panic!("unknown commitment_type");
        };
        assert_eq!(htlc_tx.txid().to_hex(), expected_txid);

        let htlc_pubkey = get_channel_htlc_pubkey(&node, &channel_id, &per_commitment_point);

        check_signature(&htlc_tx, 0, typedsig, &htlc_pubkey, htlc_amount_sat, &htlc_redeemscript);

        Ok(())
    }

    macro_rules! generate_status_ok_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_anchors>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_anchors>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_anchors>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_anchors>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_zerofee>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_zerofee>]() {
                    assert_status_ok!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_zerofee>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_zerofee>]() {
                    assert_status_ok!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm)
                    );
                }
            }
        };
    }

    generate_status_ok_variations!(success, |_| {}, |_| {}, |_| {});

    #[allow(dead_code)]
    struct ErrMsgContext {
        is_counterparty: bool,
        is_offered: bool,
        opt_anchors: bool,
        opt_zerofee: bool,
    }

    const ERR_MSG_CONTEXT_HOLDER_RECEIVED_STATIC: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: false,
        opt_anchors: false,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_HOLDER_OFFERED_STATIC: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: true,
        opt_anchors: false,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_CPARTY_RECEIVED_STATIC: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: false,
        opt_anchors: false,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_CPARTY_OFFERED_STATIC: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: true,
        opt_anchors: false,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_HOLDER_RECEIVED_ANCHORS: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: false,
        opt_anchors: true,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_HOLDER_OFFERED_ANCHORS: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: true,
        opt_anchors: true,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_CPARTY_RECEIVED_ANCHORS: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: false,
        opt_anchors: true,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_CPARTY_OFFERED_ANCHORS: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: true,
        opt_anchors: true,
        opt_zerofee: false,
    };
    const ERR_MSG_CONTEXT_HOLDER_RECEIVED_ZEROFEE: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: false,
        opt_anchors: true,
        opt_zerofee: true,
    };
    const ERR_MSG_CONTEXT_HOLDER_OFFERED_ZEROFEE: ErrMsgContext = ErrMsgContext {
        is_counterparty: false,
        is_offered: true,
        opt_anchors: true,
        opt_zerofee: true,
    };
    const ERR_MSG_CONTEXT_CPARTY_RECEIVED_ZEROFEE: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: false,
        opt_anchors: true,
        opt_zerofee: true,
    };
    const ERR_MSG_CONTEXT_CPARTY_OFFERED_ZEROFEE: ErrMsgContext = ErrMsgContext {
        is_counterparty: true,
        is_offered: true,
        opt_anchors: true,
        opt_zerofee: true,
    };

    macro_rules! generate_failed_precondition_error_variations {
        ($name: ident, $pm: expr, $km: expr, $tm: expr, $errcls: expr) => {
            paste! {
                #[test]
                fn [<$name _holder_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_static>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::StaticRemoteKey, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_STATIC)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_anchors>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::Anchors, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_ANCHORS)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_received_zerofee>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            false, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_RECEIVED_ZEROFEE)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _holder_offered_zerofee>]() {
                    assert_failed_precondition_err!(
                        sign_holder_htlc_tx_with_mutators(
                            true, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_HOLDER_OFFERED_ZEROFEE)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_received_zerofee>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            false, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_RECEIVED_ZEROFEE)
                    );
                }
            }
            paste! {
                #[test]
                fn [<$name _counterparty_offered_zerofee>]() {
                    assert_failed_precondition_err!(
                        sign_counterparty_htlc_tx_with_mutators(
                            true, CommitmentType::AnchorsZeroFeeHtlc, $pm, $km, $tm),
                        ($errcls)(ERR_MSG_CONTEXT_CPARTY_OFFERED_ZEROFEE)
                    );
                }
            }
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_param {
        ($name: ident, $pm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, $pm, |_| {}, |_| {}, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_keys {
        ($name: ident, $km: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, |_| {}, $km, |_| {}, $errmsg);
        };
    }

    macro_rules! generate_failed_precondition_error_with_mutated_tx {
        ($name: ident, $tm: expr, $errmsg: expr) => {
            generate_failed_precondition_error_variations!($name, |_| {}, |_| {}, $tm, $errmsg);
        };
    }

    // policy-htlc-version
    generate_failed_precondition_error_with_mutated_tx!(
        bad_version,
        |tms| tms.tx.version = 3, // only version 2 allowed
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-locktime
    generate_failed_precondition_error_with_mutated_tx!(
        bad_locktime,
        |tms| {
            // offered must have non-zero, received must have zero
            tms.tx.lock_time = PackedLockTime(if tms.is_offered { 0 } else { 42 });
        },
        |ectx: ErrMsgContext| {
            if ectx.is_offered {
                "policy failure: validate_htlc_tx: offered lock_time must be non-zero"
            } else {
                "policy failure: sighash mismatch"
            }
        }
    );

    // policy-htlc-sequence
    generate_failed_precondition_error_with_mutated_tx!(
        bad_sequence,
        |tms| tms.tx.input[0].sequence = Sequence(42), // sequence must be per BOLT#3
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-to-self-delay
    generate_failed_precondition_error_with_mutated_param!(
        bad_to_self_delay,
        |pms| {
            if pms.is_counterparty {
                pms.param.holder_selected_contest_delay = 42;
            } else {
                let mut cptp = pms.param.counterparty_parameters.as_ref().unwrap().clone();
                cptp.selected_contest_delay = 42;
                pms.param.counterparty_parameters = Some(cptp);
            }
        },
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-revocation-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_revpubkey,
        |kms| kms.keys.revocation_key = make_test_pubkey(42),
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-delayed-pubkey
    generate_failed_precondition_error_with_mutated_keys!(
        bad_delayedpubkey,
        |kms| kms.keys.broadcaster_delayed_payment_key = make_test_pubkey(42),
        |_| "policy failure: sighash mismatch"
    );

    // policy-htlc-fee-range
    generate_failed_precondition_error_with_mutated_tx!(
        low_feerate,
        |tms| tms.tx.output[0].value = 999_885, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.opt_zerofee {
                // zero-fee fails sooner, because we don't estimate_feerate_per_kw so the recomposed
                // tx does not match.
                "policy failure: sighash mismatch".to_string()
            } else {
                if ectx.is_offered {
                    format!(
                        "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is smaller than the minimum of 253",
                        if ectx.opt_anchors { 174 } else { 174 }
                    )
                } else {
                    format!(
                        "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is smaller than the minimum of 253",
                        if ectx.opt_anchors { 164 } else { 165 }
                    )
                }
            }
        }
    );

    // policy-htlc-fee-range
    generate_failed_precondition_error_with_mutated_tx!(
        high_feerate,
        |tms| tms.tx.output[0].value = 920_000, // htlc_amount_sat is 1_000_000
        |ectx: ErrMsgContext| {
            if ectx.opt_zerofee {
                // zero-fee fails sooner, because we don't estimate_feerate_per_kw so the recomposed
                // tx does not match.
                "policy failure: sighash mismatch".to_string()
            } else {
                if ectx.is_offered {
                    format!(
                        "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is larger than the maximum of 100000",
                        if ectx.opt_anchors { 120121 } else { 120665 }
                    )
                } else {
                    format!(
                        "policy failure: validate_htlc_tx: \
                     feerate_per_kw of {} is larger than the maximum of 100000",
                        if ectx.opt_anchors { 113315 } else { 113799 }
                    )
                }
            }
        }
    );
}
