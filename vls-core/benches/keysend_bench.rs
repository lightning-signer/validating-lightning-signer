use std::time::Duration;

use bitcoin::{
    psbt::serialize::Serialize,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use criterion::{criterion_group, criterion_main, Criterion};
use lightning::{
    chain::keysinterface::ChannelSigner,
    ln::{
        chan_utils::{self, HTLCOutputInCommitment},
        PaymentHash,
    },
};
use lightning_signer::{
    channel::{Channel, CommitmentType},
    tx::tx::HTLCInfo2,
    util::{
        test_utils::{
            build_tx_scripts, channel_commitment, counterparty_sign_holder_commitment,
            fund_test_channel, init_node_and_channel, key::make_test_pubkey,
            make_test_channel_setup, sign_commitment_tx_with_mutators_setup, test_node_ctx,
            validate_holder_commitment, TEST_NODE_CONFIG, TEST_SEED,
        },
        INITIAL_COMMITMENT_NUMBER,
    },
};

fn sign_counterparty_commitment_tx_bench(c: &mut Criterion) {
    let setup = make_test_channel_setup();
    let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

    let remote_percommitment_point = make_test_pubkey(10);

    let htlc1 =
        HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

    let htlc2 =
        HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

    let htlc3 =
        HTLCInfo2 { value_sat: 10_003, payment_hash: PaymentHash([5; 32]), cltv_expiry: 4 << 16 };

    let offered_htlcs = vec![htlc1];
    let received_htlcs = vec![htlc2, htlc3];

    node.with_ready_channel(&channel_id, |chan| {
        let channel_parameters = chan.make_channel_parameters();
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let mut htlcs = {
            let offered_htlcs = offered_htlcs.clone();
            let received_htlcs = received_htlcs.clone();
            let mut htlcs = Vec::new();
            for htlc in offered_htlcs {
                htlcs.push(HTLCOutputInCommitment {
                    offered: true,
                    amount_msat: htlc.value_sat * 1000,
                    cltv_expiry: htlc.cltv_expiry,
                    payment_hash: htlc.payment_hash,
                    transaction_output_index: None,
                });
            }
            for htlc in received_htlcs {
                htlcs.push(HTLCOutputInCommitment {
                    offered: false,
                    amount_msat: htlc.value_sat * 1000,
                    cltv_expiry: htlc.cltv_expiry,
                    payment_hash: htlc.payment_hash,
                    transaction_output_index: None,
                });
            }
            htlcs
        };

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
        chan.enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
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
        let output_witscripts: Vec<_> = redeem_scripts.iter().map(|s| s.serialize()).collect();

        for received_htlc in received_htlcs.clone() {
            node.add_keysend(
                make_test_pubkey(1),
                received_htlc.payment_hash,
                received_htlc.value_sat * 1000,
            )?;
        }

        c.bench_function("sign counterparty", |b| {
            b.iter(|| {
                chan.sign_counterparty_commitment_tx(
                    &tx.transaction,
                    &output_witscripts,
                    &remote_percommitment_point,
                    commit_num,
                    feerate_per_kw,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )
                .expect("sign");
            })
        });

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
}

fn validate_holder_commitment_bench(c: &mut Criterion) {
    let node_ctx = test_node_ctx(1);

    let channel_amount = 3_000_000;
    let chan_ctx = fund_test_channel(&node_ctx, channel_amount);

    let offered_htlcs = vec![
        HTLCInfo2 { value_sat: 10_000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 1 << 16 },
        HTLCInfo2 { value_sat: 10_000, payment_hash: PaymentHash([2; 32]), cltv_expiry: 2 << 16 },
    ];
    let received_htlcs = vec![
        HTLCInfo2 { value_sat: 10_000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 },
        HTLCInfo2 { value_sat: 10_000, payment_hash: PaymentHash([4; 32]), cltv_expiry: 4 << 16 },
        HTLCInfo2 { value_sat: 10_000, payment_hash: PaymentHash([5; 32]), cltv_expiry: 5 << 16 },
    ];
    let sum_htlc = 50_000;

    let commit_num = 1;
    let feerate_per_kw = 1100;
    let fees = 20_000;
    let to_broadcaster = 1_000_000;
    let to_countersignatory = channel_amount - to_broadcaster - sum_htlc - fees;

    let mut commit_tx_ctx = channel_commitment(
        &node_ctx,
        &chan_ctx,
        commit_num,
        feerate_per_kw,
        to_broadcaster,
        to_countersignatory,
        offered_htlcs,
        received_htlcs,
    );
    let (csig, hsigs) =
        counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

    c.bench_function("validate holder commitment", |b| {
        b.iter(|| {
            validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
                .expect("valid holder commitment")
        })
    });
}

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

fn validate_counterparty_revocation_bench(c: &mut Criterion) {
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
            secrets.provide_secret(INITIAL_COMMITMENT_NUMBER - idx, secret.secret_bytes()).unwrap();
        }

        let (remote_percommit_point, remote_percommit_secret) = make_per_commitment(REV_COMMIT_NUM);

        chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM - 1);
        chan.enforcement_state
            .set_next_counterparty_commit_num_for_testing(REV_COMMIT_NUM, make_test_pubkey(0x10));

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

        // Validate the revocation, but defer error returns till after we've had
        // a chance to validate the channel state for side-effects
        c.bench_function("validate revocation", |b| {
            b.iter(|| {
                chan.validate_counterparty_revocation(REV_COMMIT_NUM, &remote_percommit_secret)
                    .expect("validate revocation")
            })
        });

        chan.validate_counterparty_revocation(REV_COMMIT_NUM, &remote_percommit_secret)
    })
    .expect("success")
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = sign_counterparty_commitment_tx_bench, validate_holder_commitment_bench, validate_counterparty_revocation_bench
}

criterion_main!(benches);
