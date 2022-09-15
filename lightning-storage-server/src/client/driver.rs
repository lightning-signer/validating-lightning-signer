use crate::client::auth::Auth;
use secp256k1::PublicKey;
use tonic::{transport, Request};

use crate::client::LightningStorageClient;
use crate::proto::{self, GetRequest, InfoRequest, PingRequest, PutRequest};
use crate::util::{append_hmac_to_value, remove_and_check_hmac};

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

pub fn make_auth_proto(auth: &Auth) -> Option<proto::Auth> {
    Some(proto::Auth { client_id: auth.client_id.serialize().to_vec(), token: auth.auth_token() })
}

pub async fn info(
    client: &mut LightningStorageClient<transport::Channel>,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let info_request = Request::new(InfoRequest {});

    let response = client.info(info_request).await?;
    PublicKey::from_slice(&response.into_inner().server_id).map_err(|_| "invalid server id".into())
}

pub async fn get(
    client: &mut LightningStorageClient<transport::Channel>,
    auth: Auth,
    hmac_secret: &[u8],
    key_prefix: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let get_request = Request::new(GetRequest { auth: make_auth_proto(&auth), key_prefix });

    let response = client.get(get_request).await?;
    for kv in response.into_inner().kvs {
        let key = kv.key;
        let value = remove_and_check_hmac(kv.value, &key, kv.version, &hmac_secret)
            .map_err(|()| format!("hmac failure for key {}", key.clone()))?;
        println!("key: {}, version: {} value: {}", key, kv.version, hex::encode(value));
    }

    Ok(())
}

pub async fn put(
    client: &mut LightningStorageClient<transport::Channel>,
    auth: Auth,
    hmac_secret: &[u8],
    key: String,
    version: u64,
    bare_value: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = append_hmac_to_value(bare_value, &key, version, &hmac_secret);
    let kv = proto::KeyValue { key, version, value };

    let put_request = Request::new(PutRequest { auth: make_auth_proto(&auth), kvs: vec![kv] });

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
