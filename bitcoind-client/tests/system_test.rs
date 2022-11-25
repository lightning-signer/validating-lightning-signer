#[cfg(feature = "system-test")]
#[tokio::test]
async fn bitcoind_system_test() {
    let client =
        bitcoind_client::BitcoindClient::new("http://user:pass@localhost:18443".parse().unwrap())
            .await;
    let info = client.get_blockchain_info().await.unwrap();
    println!("info: {:?}", info);
}
