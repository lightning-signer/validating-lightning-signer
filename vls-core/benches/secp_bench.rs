use bencher::{benchmark_group, benchmark_main, black_box, Bencher};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

fn sign_bench(b: &mut Bencher) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::new(&mut thread_rng());
    b.iter(|| black_box(secp.sign_ecdsa(&msg, &secret)));
}

fn verify_bench(b: &mut Bencher) {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let secret = SecretKey::new(&mut thread_rng());
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let sig = secp.sign_ecdsa(&msg, &secret);
    b.iter(|| black_box(secp.verify_ecdsa(&msg, &sig, &pubkey)));
}

fn hash_bench(b: &mut Bencher) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    b.iter(|| black_box(sha256::Hash::hash(&msg[..])));
}

fn secp_create_bench(b: &mut Bencher) {
    b.iter(|| black_box(Secp256k1::new()));
}

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn fib_bench(b: &mut Bencher) {
    b.iter(|| fibonacci(black_box(20)));
}

fn fib1_bench(b: &mut Bencher) {
    b.iter(|| fibonacci(black_box(1)));
}

benchmark_group!(
    benches,
    fib_bench,
    fib1_bench,
    sign_bench,
    verify_bench,
    hash_bench,
    secp_create_bench
);
benchmark_main!(benches);
