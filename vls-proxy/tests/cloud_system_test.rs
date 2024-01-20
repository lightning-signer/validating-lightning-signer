use bitcoin::secp256k1::rand::{self, RngCore};
use bitcoin::Network;
use lightning_signer::bitcoin;
use lightning_signer::persist::{ExternalPersistHelper, Mutations, Persist};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::my_keys_manager::MyKeysManager;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_storage_server::client::Auth;
use log::*;
use vls_frontend::external_persist::lss::{Client as LssClient, Client};
use vls_frontend::external_persist::ExternalPersist;
use vls_persist::kvv::cloud::{CloudKVVStore, LAST_WRITER_KEY};
use vls_persist::kvv::{redb::RedbKVVStore, JsonFormat, KVVPersister, KVVStore};
use vls_proxy::util::setup_logging;

// requires a running lss instance
#[tokio::test]
async fn cloud_system_test() {
    let tmpdir = tempfile::tempdir().unwrap();
    let local = RedbKVVStore::new_store(tmpdir.path());
    let cloud = KVVPersister(CloudKVVStore::new(local), JsonFormat);
    setup_logging(tmpdir.path(), "cloud_system_test", "debug");
    let rpc_url = "http://127.0.0.1:55551";
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let time_factory = ClockStartingTimeFactory::new();
    let keys =
        MyKeysManager::new(KeyDerivationStyle::Native, &seed, Network::Regtest, &*time_factory);
    let pubkey = keys.get_persistence_pubkey();

    let server_pubkey = LssClient::get_server_pubkey(rpc_url).await.unwrap();
    let shared_secret = keys.get_persistence_shared_secret(&server_pubkey);
    let mut helper = ExternalPersistHelper::new(shared_secret);

    let auth =
        Auth { client_id: pubkey, token: keys.get_persistence_auth_token(&server_pubkey).to_vec() };
    let client = LssClient::new(rpc_url, &server_pubkey, auth).await.unwrap();

    do_put(&cloud, &helper, &client, b"foo", false).await;

    assert_eq!(cloud.0.get_local(LAST_WRITER_KEY).unwrap().unwrap().0, 0);

    // an empty transaction
    cloud.enter().unwrap();
    let muts = cloud.prepare();
    assert!(muts.is_empty());
    cloud.commit().unwrap();

    assert_eq!(cloud.0.get_local(LAST_WRITER_KEY).unwrap().unwrap().0, 0);

    do_put(&cloud, &helper, &client, b"boo", false).await;

    // emulate restart
    drop(cloud);
    let local = RedbKVVStore::new_store(tmpdir.path());
    let cloud = KVVPersister(CloudKVVStore::new(local), JsonFormat);

    do_put(&cloud, &helper, &client, b"cow", false).await;

    // get the last_writer key from lss
    let res = do_get(LAST_WRITER_KEY, &keys, &mut helper, &client).await;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, LAST_WRITER_KEY);
    assert_eq!(res[0].1, (2, cloud.signer_id().to_vec()));

    assert!(cloud.is_in_sync(Some(res[0].1.clone())));

    let res = do_get("foo", &keys, &mut helper, &client).await;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, "foo");
    assert_eq!(res[0].1, (2, b"cow".to_vec()));

    // rollback
    do_put(&cloud, &helper, &client, b"cow", true).await;

    // emulate restart
    drop(cloud);
    let local = RedbKVVStore::new_store(tmpdir.path());
    let cloud = KVVPersister(CloudKVVStore::new(local), JsonFormat);

    let key_res = do_get(LAST_WRITER_KEY, &keys, &mut helper, &client).await;
    assert!(!cloud.is_in_sync(Some(key_res[0].1.clone())));

    // get everything
    let everything = do_get("", &keys, &mut helper, &client).await;
    assert_eq!(everything.len(), 2);
    cloud.put_batch_unlogged(everything).unwrap();

    assert!(cloud.is_in_sync(Some(key_res[0].1.clone())));
}

async fn do_get(
    prefix: &str,
    keys: &MyKeysManager,
    helper: &mut ExternalPersistHelper,
    client: &Client,
) -> Mutations {
    let (res, received_hmac) =
        client.get(prefix.to_string(), &helper.new_nonce(keys)).await.unwrap();
    assert!(helper.check_hmac(&res, received_hmac), "hmac check failed");
    res
}

async fn do_put(
    cloud: &KVVPersister<CloudKVVStore<RedbKVVStore>, JsonFormat>,
    helper: &ExternalPersistHelper,
    client: &Client,
    value: &[u8; 3],
    rollback: bool,
) {
    cloud.enter().unwrap();
    cloud.put("foo", value.to_vec()).unwrap();

    let muts = cloud.prepare();
    // write muts into LSS
    let client_hmac = helper.client_hmac(&muts);
    let server_hmac = helper.server_hmac(&muts);

    trace!("putting mutations: {:?}", muts);

    let received_server_hmac = client.put(muts.clone(), &client_hmac).await.unwrap();
    assert_eq!(received_server_hmac, server_hmac);
    if !rollback {
        cloud.commit().unwrap();
    }
}
