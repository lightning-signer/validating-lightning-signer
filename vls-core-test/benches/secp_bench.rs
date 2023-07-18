use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lightning_signer::bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{rand::thread_rng, Message, PublicKey, Secp256k1, SecretKey},
};

fn sign_bench(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::new(&mut thread_rng());
    c.bench_function("sign bench", |b| b.iter(|| black_box(secp.sign_ecdsa(&msg, &secret))));
}

fn verify_bench(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::new(&mut thread_rng());
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let sig = secp.sign_ecdsa(&msg, &secret);
    c.bench_function("verify bench", |b| {
        b.iter(|| black_box(secp.verify_ecdsa(&msg, &sig, &pubkey)))
    });
}

fn hash_bench(c: &mut Criterion) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    c.bench_function("hash bench", |b| b.iter(|| black_box(sha256::Hash::hash(&msg[..]))));
}

fn secp_create_bench(c: &mut Criterion) {
    c.bench_function("secp create bench", |b| b.iter(|| black_box(Secp256k1::new())));
}

criterion_group!(benches, sign_bench, verify_bench, hash_bench, secp_create_bench);
criterion_main!(benches);
