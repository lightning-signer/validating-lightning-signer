use crate::client::auth::Auth;
use crate::client::LightningStorageClient;
use crate::proto::{self, GetRequest, InfoRequest, PingRequest, PutRequest};
use crate::util::{append_hmac_to_value, remove_and_check_hmac};
use crate::Value;
use secp256k1::PublicKey;
use thiserror::Error;
use tonic::{transport, Request};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport error")]
    Connect(#[from] transport::Error),
    #[error("API error")]
    Tonic(#[from] tonic::Status),
    #[error("invalid response from server")]
    InvalidResponse,
    /// integrity error, with string
    #[error("invalid HMAC for key {0} version {1}")]
    InvalidHmac(String, u64),
    #[error("Put had conflicts")]
    PutConflict(Vec<(String, Value)>),
}

pub async fn connect(uri: &str) -> Result<LightningStorageClient<transport::Channel>, ClientError> {
    let uri_clone = String::from(uri);
    Ok(LightningStorageClient::connect(uri_clone).await?)
}

pub async fn ping(
    client: &mut LightningStorageClient<transport::Channel>,
    message: &str,
) -> Result<String, ClientError> {
    let ping_request = Request::new(PingRequest { message: message.into() });

    let response = client.ping(ping_request).await?;
    Ok(response.into_inner().message)
}

pub fn make_auth_proto(auth: &Auth) -> Option<proto::Auth> {
    Some(proto::Auth { client_id: auth.client_id.serialize().to_vec(), token: auth.auth_token() })
}

pub async fn info(
    client: &mut LightningStorageClient<transport::Channel>,
) -> Result<PublicKey, ClientError> {
    let info_request = Request::new(InfoRequest {});

    let response = client.info(info_request).await?;
    PublicKey::from_slice(&response.into_inner().server_id)
        .map_err(|_| ClientError::InvalidResponse)
}

pub async fn get(
    client: &mut LightningStorageClient<transport::Channel>,
    auth: Auth,
    hmac_secret: &[u8],
    key_prefix: String,
) -> Result<Vec<(String, Value)>, ClientError> {
    let get_request = Request::new(GetRequest { auth: make_auth_proto(&auth), key_prefix });

    let response = client.get(get_request).await?;
    let res = response.into_inner();
    kvs_from_proto(&hmac_secret, res.kvs)
}

pub async fn put(
    client: &mut LightningStorageClient<transport::Channel>,
    auth: Auth,
    hmac_secret: &[u8],
    key: String,
    version: u64,
    bare_value: Vec<u8>,
) -> Result<(), ClientError> {
    let value = append_hmac_to_value(bare_value, &key, version, &hmac_secret);
    let kv = proto::KeyValue { key, version, value };

    let put_request = Request::new(PutRequest { auth: make_auth_proto(&auth), kvs: vec![kv] });

    let response = client.put(put_request).await?;
    let res = response.into_inner();
    if res.success {
        Ok(())
    } else {
        let conflicts = kvs_from_proto(&hmac_secret, res.conflicts)?;
        Err(ClientError::PutConflict(conflicts))
    }
}

fn kvs_from_proto(
    hmac_secret: &&[u8],
    conflicts_proto: Vec<proto::KeyValue>,
) -> Result<Vec<(String, Value)>, ClientError> {
    conflicts_proto
        .into_iter()
        .map(|kv| {
            let key = kv.key;
            let version = kv.version;
            let value = remove_and_check_hmac(kv.value, &key, version, &hmac_secret)
                .map_err(|()| ClientError::InvalidHmac(key.clone(), version))?;
            Ok((key, Value { version, value }))
        })
        .collect::<Result<Vec<_>, ClientError>>()
}
