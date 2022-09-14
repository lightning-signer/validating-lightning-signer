use secp256k1::PublicKey;
use tonic::{transport, Request};

use crate::client::LightningStorageClient;
use crate::proto::{GetRequest, KeyValue, PingRequest, PutRequest};

pub async fn connect(
    uri: &str,
) -> Result<LightningStorageClient<transport::Channel>, Box<dyn std::error::Error>> {
    let uri_clone = String::from(uri);
    Ok(LightningStorageClient::connect(uri_clone).await?)
}

pub async fn ping(
    client: &mut LightningStorageClient<transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ping_request = Request::new(PingRequest { message: "hello".into() });

    let response = client.ping(ping_request).await?;

    println!("ping response={:?}", response);
    Ok(())
}

pub async fn get(
    client: &mut LightningStorageClient<transport::Channel>,
    client_id: PublicKey,
    key_prefix: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let get_request =
        Request::new(GetRequest { client_id: client_id.serialize().to_vec(), key_prefix });

    let response = client.get(get_request).await?;
    for kv in response.into_inner().kvs {
        println!("key: {}, version: {} value: {}", kv.key, kv.version, hex::encode(kv.value));
    }

    Ok(())
}

pub async fn put(
    client: &mut LightningStorageClient<transport::Channel>,
    client_id: PublicKey,
    key: String,
    version: u64,
    value: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = vec![0; 64];
    let kv = KeyValue { key, signature, version, value };

    let put_request =
        Request::new(PutRequest { client_id: client_id.serialize().to_vec(), kvs: vec![kv] });

    let response = client.put(put_request).await?;
    for kv in response.into_inner().conflicts {
        println!(
            "conflict key: {}, version: {} value: {}",
            kv.key,
            kv.version,
            hex::encode(kv.value)
        );
    }

    Ok(())
}
