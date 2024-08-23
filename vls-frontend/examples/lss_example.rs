//! Example of using the LSS implementation of `ExternalPersist`.
//!
//! Run lssd:
//!     (cd lightning-storage-server && cargo run --bin lssd -- --datadir /tmp/lssd)
//! Run lss_example:
//!    cargo run --example lss_example

use lightning_signer::bitcoin::{secp256k1, Network};
use lightning_signer::persist::{ExternalPersistHelper, Mutations};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::my_keys_manager::MyKeysManager;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_storage_server::client::Auth;
use log::{info, LevelFilter};
use secp256k1::{rand, rand::RngCore};
use vls_frontend::external_persist::lss::Client;
use vls_frontend::external_persist::ExternalPersist;

// Notes on signer protocol adjustments.
//
// on init:
// - provide to signer: persistence server pubkey(s)
// - from signer: client pubkey, auth token(s)
//
// on get:
// - from signer: nonce
// - to signer: key-value pairs, hmac
//
// on put:
// - from signer: mutations, client hmac
// - to signer: server hmac

#[tokio::main]
async fn main() {
    setup_logging();
    let rpc_url = "http://127.0.0.1:55551";
    let server_pubkey = Client::get_server_pubkey(rpc_url).await.unwrap();
    info!("server pubkey: {}", server_pubkey);

    // In signer
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let time_factory = ClockStartingTimeFactory::new();
    let keys =
        MyKeysManager::new(KeyDerivationStyle::Native, &seed, Network::Regtest, &*time_factory);
    let pubkey = keys.get_persistence_pubkey();
    let shared_secret = keys.get_persistence_shared_secret(&server_pubkey.inner);
    let mut helper = ExternalPersistHelper::new(shared_secret);

    let auth = Auth {
        client_id: pubkey,
        token: keys.get_persistence_auth_token(&server_pubkey.inner).to_vec(),
    };

    let client = Client::new(rpc_url, &server_pubkey, auth).await.unwrap();

    let mutations = Mutations::from_vec(vec![
        ("x1".to_string(), (0u64, "v1".as_bytes().to_vec())),
        ("x2".to_string(), (0u64, "v2".as_bytes().to_vec())),
    ]);

    let client_hmac = helper.client_hmac(&mutations);
    let server_hmac = helper.server_hmac(&mutations);

    info!("putting mutations: {:?}", mutations);
    let received_server_hmac = client.put(mutations, &client_hmac).await.unwrap();
    assert_eq!(received_server_hmac, server_hmac); // in signer

    let (res, received_hmac) = client.get("x".to_string(), &helper.new_nonce(&keys)).await.unwrap();
    info!("got mutations: {:?}", res);
    assert_eq!(res.len(), 2);
    assert!(helper.check_hmac(&res, received_hmac), "hmac check failed");

    let (res, received_hmac) =
        client.get("x1".to_string(), &helper.new_nonce(&keys)).await.unwrap();
    assert_eq!(res.len(), 1);
    assert!(helper.check_hmac(&res, received_hmac), "hmac check failed");

    let (res, received_hmac) = client.get("y".to_string(), &helper.new_nonce(&keys)).await.unwrap();
    assert_eq!(res.len(), 0);
    assert!(helper.check_hmac(&res, received_hmac), "hmac check failed");

    info!("done");
}

fn setup_logging() {
    let mut builder = env_logger::Builder::new();
    builder.filter(None, LevelFilter::Info);

    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        builder.parse_filters(&rust_log);
    }

    builder.init();
}
