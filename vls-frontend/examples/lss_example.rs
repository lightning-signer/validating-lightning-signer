//! Example of using the LSS implementation of `ExternalPersist`.
//!
//! Run lssd:
//!     (cd lightning-storage-server && cargo run --bin lssd -- --datadir /tmp/lssd)
//! Run lss_example:
//!    cargo run --example lss_example

use lightning_signer::bitcoin::secp256k1;
use lightning_signer::bitcoin::secp256k1::rand::RngCore;
use lightning_signer::persist::Mutations;
use lightning_storage_server::client::PrivAuth;
use lightning_storage_server::util::compute_shared_hmac;
use lightning_storage_server::{client::PrivAuth as LssAuth, Value};
use log::{info, LevelFilter};
use secp256k1::{rand, Secp256k1, SecretKey};
use vls_frontend::external_persist::lss::Client;
use vls_frontend::external_persist::ExternalPersist;

#[tokio::main]
async fn main() {
    setup_logging();
    let rpc_url = "http://127.0.0.1:55551";
    let server_pubkey = Client::get_server_pubkey(rpc_url).await.unwrap();
    info!("server pubkey: {}", server_pubkey);

    // In signer
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let secp = Secp256k1::new();
    let pubkey = secret_key.public_key(&secp);
    info!("generated client pubkey: {}", pubkey);
    let priv_auth = LssAuth::new_for_client(&secret_key, &server_pubkey); // in signer
    let auth = priv_auth.auth();

    let client = Client::new(rpc_url, &server_pubkey, auth).await.unwrap();

    let kvs = vec![
        ("x1".to_string(), Value { version: 0, value: "v1".as_bytes().to_vec() }),
        ("x2".to_string(), Value { version: 0, value: "v2".as_bytes().to_vec() }),
    ];

    let client_hmac = compute_shared_hmac(&priv_auth.shared_secret, &[0x01], &kvs); // in signer
    let server_hmac = compute_shared_hmac(&priv_auth.shared_secret, &[0x02], &kvs); // in signer

    let mutations = kvs.into_iter().map(|(k, v)| (k, (v.version as u64, v.value))).collect();

    info!("putting mutations: {:?}", mutations);
    let received_server_hmac = client.put(mutations, &client_hmac).await.unwrap();
    assert_eq!(received_server_hmac, server_hmac); // in signer

    let nonce = make_nonce();
    let (res, received_hmac) = client.get("x".to_string(), &nonce).await.unwrap();
    info!("got mutations: {:?}", res);
    assert_eq!(res.len(), 2);
    check_get_result(&priv_auth, &nonce, res, received_hmac);

    let nonce = make_nonce();
    let (res, received_hmac) = client.get("x1".to_string(), &nonce).await.unwrap();
    assert_eq!(res.len(), 1);
    check_get_result(&priv_auth, &nonce, res, received_hmac);

    let nonce = make_nonce();
    let (res, received_hmac) = client.get("y".to_string(), &nonce).await.unwrap();
    assert_eq!(res.len(), 0);
    check_get_result(&priv_auth, &nonce, res, received_hmac);

    info!("done");
}

// Checked in signer
fn check_get_result(
    auth: &PrivAuth,
    nonce: &[u8],
    res: Mutations,
    received_hmac: Vec<u8>,
) -> Vec<(String, Value)> {
    let kvs: Vec<_> =
        res.into_iter().map(|(k, (v, d))| (k, Value { version: v as i64, value: d })).collect();
    let hmac = compute_shared_hmac(&auth.shared_secret, &nonce, &kvs); // in signer
    assert_eq!(received_hmac, hmac); // in signer
    kvs
}

// Generated in signer
fn make_nonce() -> Vec<u8> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce.to_vec()
}

fn setup_logging() {
    let mut builder = env_logger::Builder::new();
    builder.filter(None, LevelFilter::Info);

    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        builder.parse_filters(&rust_log);
    }

    builder.init();
}
