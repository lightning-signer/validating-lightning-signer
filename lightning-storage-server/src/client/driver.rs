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

pub struct Client {
    client: LightningStorageClient<transport::Channel>,
    auth: Auth,
}

impl Client {
    pub async fn init(uri: &str) -> Result<PublicKey, ClientError> {
        let mut client = connect(uri).await?;
        let info_request = Request::new(InfoRequest {});

        let response = client.info(info_request).await?;
        PublicKey::from_slice(&response.into_inner().server_id)
            .map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn new(uri: &str, auth: Auth) -> Result<Self, ClientError> {
        let client = connect(uri).await?;
        Ok(Self { client, auth })
    }

    pub async fn ping(uri: &str, message: &str) -> Result<String, ClientError> {
        let mut client = connect(uri).await?;
        let ping_request = Request::new(PingRequest { message: message.into() });

        let response = client.ping(ping_request).await?;
        Ok(response.into_inner().message)
    }

    pub async fn get(
        &mut self,
        hmac_secret: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, ClientError> {
        let get_request = Request::new(GetRequest { auth: self.make_auth_proto(), key_prefix });

        let response = self.client.get(get_request).await?;
        let res = response.into_inner();
        kvs_from_proto(&hmac_secret, res.kvs)
    }

    pub async fn put(
        &mut self,
        hmac_secret: &[u8],
        key: String,
        version: u64,
        bare_value: Vec<u8>,
    ) -> Result<(), ClientError> {
        let value = append_hmac_to_value(bare_value, &key, version, &hmac_secret);
        let kv = proto::KeyValue { key, version, value };

        let put_request = Request::new(PutRequest { auth: self.make_auth_proto(), kvs: vec![kv] });

        let response = self.client.put(put_request).await?;
        let res = response.into_inner();
        if res.success {
            Ok(())
        } else {
            let conflicts = kvs_from_proto(&hmac_secret, res.conflicts)?;
            Err(ClientError::PutConflict(conflicts))
        }
    }

    fn make_auth_proto(&self) -> Option<proto::Auth> {
        Some(proto::Auth {
            client_id: self.auth.client_id.serialize().to_vec(),
            token: self.auth.auth_token(),
        })
    }
}

async fn connect(uri: &str) -> Result<LightningStorageClient<transport::Channel>, ClientError> {
    let uri_clone = String::from(uri);
    Ok(LightningStorageClient::connect(uri_clone).await?)
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
