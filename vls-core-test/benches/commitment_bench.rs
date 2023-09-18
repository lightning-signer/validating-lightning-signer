use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use lightning_signer::{
    bitcoin::{
        psbt::serialize::Serialize,
        secp256k1::{PublicKey, Secp256k1, SecretKey},
    },
    channel::{Channel, CommitmentType},
    lightning::{
        ln::{
            chan_utils::{self, HTLCOutputInCommitment},
            PaymentHash,
        },
        sign::ChannelSigner,
    },
    tx::tx::HTLCInfo2,
    util::{
        test_utils::{
            build_tx_scripts, channel_commitment, counterparty_sign_holder_commitment,
            fund_test_channel, init_node_and_channel, key::make_test_pubkey,
            make_test_channel_setup, test_node_ctx, validate_holder_commitment, TEST_NODE_CONFIG,
            TEST_SEED,
        },
        INITIAL_COMMITMENT_NUMBER,
    },
};

const CHANNEL_AMOUNT: u64 = 3_000_000;

struct BenchTestConfig {
    commit_num: u64,
    feerate_per_kw: u32,
    to_broadcaster: u64,
    to_countersignator: u64,
}

impl BenchTestConfig {
    fn new(
        commit_num: u64,
        fees: u64,
        feerate_per_kw: u32,
        to_broadcaster: u64,
        sum_htlcs: u64,
    ) -> Self {
        let to_countersignator = CHANNEL_AMOUNT - to_broadcaster - sum_htlcs - fees;
        Self {
            commit_num: commit_num,
            feerate_per_kw: feerate_per_kw,
            to_broadcaster: to_broadcaster,
            to_countersignator: to_countersignator,
        }
    }
}

fn provide_htlc(num_of_htlcs: u32) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
    let offered_htlcs_num = num_of_htlcs / 2;
    let received_htlcs_num = num_of_htlcs - offered_htlcs_num;
    let offered_htlcs = (0..offered_htlcs_num)
        .map(|idx| HTLCInfo2 {
            value_sat: 5000,
            payment_hash: PaymentHash([idx as u8; 32]),
            cltv_expiry: idx << 16,
        })
        .collect_vec();

    let received_htlcs = (offered_htlcs_num..offered_htlcs_num + received_htlcs_num)
        .map(|idx| HTLCInfo2 {
            value_sat: 5000,
            payment_hash: PaymentHash([idx as u8; 32]),
            cltv_expiry: idx << 16,
        })
        .collect_vec();

    (offered_htlcs, received_htlcs)
}

fn sign_remote_commitment_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign remote commitment");
    for num_htlcs in [0, 2, 4, 8] {
        let setup = make_test_channel_setup();
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());

        let remote_percommitment_point = make_test_pubkey(10);
        let (offered_htlcs, received_htlcs) = provide_htlc(num_htlcs);
        let mut sum_htlcs = 0;
        for htlc in &offered_htlcs {
            sum_htlcs += htlc.value_sat;
        }
        for htlc in &received_htlcs {
            sum_htlcs += htlc.value_sat;
        }

        let test_config = BenchTestConfig::new(23, 20_000, 1100, 1_000_000, sum_htlcs);

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

            let redeem_scripts = build_tx_scripts(
                &keys,
                test_config.to_broadcaster,
                test_config.to_countersignator,
                &mut htlcs,
                &parameters,
                &chan.keys.pubkeys().funding_pubkey,
                &chan.setup.counterparty_points.funding_pubkey,
            )
            .expect("scripts");

            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                test_config.commit_num,
                make_test_pubkey(0x10),
            );
            chan.enforcement_state
                .set_next_counterparty_revoke_num_for_testing(test_config.commit_num - 1);

            let commitment_tx = chan.make_counterparty_commitment_tx(
                &remote_percommitment_point,
                test_config.commit_num,
                test_config.feerate_per_kw,
                test_config.to_countersignator,
                test_config.to_broadcaster,
                htlcs,
            );

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

            group.bench_function(format!("{} htlcs", num_htlcs), |b| {
                b.iter(|| {
                    chan.sign_counterparty_commitment_tx(
                        &tx.transaction,
                        &output_witscripts,
                        &remote_percommitment_point,
                        test_config.commit_num,
                        test_config.feerate_per_kw,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                    .expect("sign");
                })
            });

            Ok(())
        })
        .expect("build_commitment_tx");
    }
}

fn validate_commitment_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate commitment");
    for num_htlcs in [0, 2, 4, 8] {
        let node_ctx = test_node_ctx(1);

        let chan_ctx = fund_test_channel(&node_ctx, CHANNEL_AMOUNT);

        let (offered_htlcs, received_htlcs) = provide_htlc(num_htlcs);
        let mut sum_htlcs = 0;
        for htlc in &offered_htlcs {
            sum_htlcs += htlc.value_sat;
        }
        for htlc in &received_htlcs {
            sum_htlcs += htlc.value_sat;
        }

        let test_config = BenchTestConfig::new(1, 20_000, 1100, 1_000_000, sum_htlcs);

        let mut commit_tx_ctx = channel_commitment(
            &node_ctx,
            &chan_ctx,
            test_config.commit_num,
            test_config.feerate_per_kw,
            test_config.to_broadcaster,
            test_config.to_countersignator,
            offered_htlcs,
            received_htlcs,
        );
        let (csig, hsigs) =
            counterparty_sign_holder_commitment(&node_ctx, &chan_ctx, &mut commit_tx_ctx);

        group.bench_function(format!("{} htlcs", num_htlcs), |b| {
            b.iter(|| {
                validate_holder_commitment(&node_ctx, &chan_ctx, &commit_tx_ctx, &csig, &hsigs)
                    .expect("validate commitment")
            })
        });
    }
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

fn validate_revocation_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate revocation");
    for num_htlcs in [0, 2, 4, 8] {
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::StaticRemoteKey;
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], setup.clone());
        let (offered_htlcs, received_htlcs) = provide_htlc(num_htlcs);
        let mut sum_htlcs = 0;
        for htlc in &offered_htlcs {
            sum_htlcs += htlc.value_sat;
        }
        for htlc in &received_htlcs {
            sum_htlcs += htlc.value_sat;
        }

        let test_config = BenchTestConfig::new(1, 20_000, 1100, 1_000_000, sum_htlcs);
        node.with_ready_channel(&channel_id, |chan| {
            let channel_parameters = chan.make_channel_parameters();

            for idx in 0..REV_COMMIT_NUM {
                let (_, secret) = make_per_commitment(idx);
                let secrets = chan.enforcement_state.counterparty_secrets.as_mut().unwrap();
                secrets
                    .provide_secret(INITIAL_COMMITMENT_NUMBER - idx, secret.secret_bytes())
                    .unwrap();
            }

            let (remote_percommit_point, remote_percommit_secret) =
                make_per_commitment(REV_COMMIT_NUM);

            chan.enforcement_state.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM - 1);
            chan.enforcement_state.set_next_counterparty_commit_num_for_testing(
                REV_COMMIT_NUM,
                make_test_pubkey(0x10),
            );

            let parameters = channel_parameters.as_counterparty_broadcastable();
            let keys = chan.make_counterparty_tx_keys(&remote_percommit_point)?;
            let htlcs = Channel::htlcs_info2_to_oic(offered_htlcs.clone(), received_htlcs.clone());

            let redeem_scripts = build_tx_scripts(
                &keys,
                test_config.to_countersignator,
                test_config.to_broadcaster,
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
                test_config.feerate_per_kw,
                test_config.to_broadcaster,
                test_config.to_countersignator,
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
                test_config.feerate_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;

            chan.set_next_counterparty_revoke_num_for_testing(REV_COMMIT_NUM);
            chan.set_next_counterparty_commit_num_for_testing(
                REV_COMMIT_NUM + 2,
                make_test_pubkey(0x10),
            );

            group.bench_function(format!("{} htlcs", num_htlcs), |b| {
                b.iter(|| {
                    chan.validate_counterparty_revocation(REV_COMMIT_NUM, &remote_percommit_secret)
                        .expect("validate revocation")
                })
            });

            Ok(())
        })
        .expect("success")
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = sign_remote_commitment_bench, validate_commitment_bench, validate_revocation_bench
}

criterion_main!(benches);
