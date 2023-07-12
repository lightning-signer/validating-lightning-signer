use bitcoin::psbt::serialize::Serialize;
use criterion::{criterion_group, criterion_main, Criterion};
use lightning::{
    chain::keysinterface::ChannelSigner,
    ln::{
        chan_utils::{make_funding_redeemscript, HTLCOutputInCommitment},
        PaymentHash,
    },
};
use lightning_signer::{
    channel::TypedSignature,
    tx::tx::HTLCInfo2,
    util::test_utils::{
        build_tx_scripts, check_signature, get_channel_funding_pubkey, init_node_and_channel,
        key::{make_test_counterparty_points, make_test_pubkey},
        make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
    },
};

pub fn sign_counterparty_commitment_tx_bench(c: &mut Criterion) {
    let setup = make_test_channel_setup();
    let (node, channel_id) = init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

    let remote_percommitment_point = make_test_pubkey(10);
    let counterparty_points = make_test_counterparty_points();

    let htlc1 =
        HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };

    let htlc2 =
        HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([3; 32]), cltv_expiry: 3 << 16 };

    let htlc3 =
        HTLCInfo2 { value_sat: 10_003, payment_hash: PaymentHash([5; 32]), cltv_expiry: 4 << 16 };

    let offered_htlcs = vec![htlc1];
    let received_htlcs = vec![htlc2, htlc3];

    let (sig, tx) = node
        .with_ready_channel(&channel_id, |chan| {
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

criterion_group!(benches, sign_counterparty_commitment_tx_bench);
criterion_main!(benches);
