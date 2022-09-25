use crate::client::auth::Auth;
use crate::client::LightningStorageClient;
use crate::proto::{self, GetRequest, InfoRequest, PingRequest, PutRequest};
use crate::util::{append_hmac_to_value, compute_shared_hmac, remove_and_check_hmac};
use crate::Value;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
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
    /// client HMAC integrity error, with string
    #[error("invalid HMAC for key {0} version {1}")]
    InvalidHmac(String, i64),
    /// server HMAC integrity error, with string
    #[error("invalid server HMAC")]
    InvalidServerHmac(),
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
        auth: Auth,
        hmac_secret: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, ClientError> {
        let mut nonce = Vec::with_capacity(32);
        nonce.resize(32, 0);
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        let get_request = Request::new(GetRequest {
            auth: self.make_auth_proto(),
            key_prefix,
            nonce: nonce.clone(),
        });

        let response = self.client.get(get_request).await?;
        let res = response.into_inner();
        let mut kvs = kvs_from_proto(res.kvs);
        let hmac = compute_shared_hmac(&auth.shared_secret, &nonce, &kvs);

        if res.hmac == hmac {
            remove_and_check_hmacs(&hmac_secret, &mut kvs)?;
            Ok(kvs)
        } else {
            Err(ClientError::InvalidServerHmac())
        }
    }

    pub async fn put(
        &mut self,
        auth: Auth,
        hmac_secret: &[u8],
        key: String,
        version: i64,
        bare_value: Vec<u8>,
    ) -> Result<(), ClientError> {
        let value = append_hmac_to_value(bare_value, &key, version, &hmac_secret);

        let client_hmac = compute_shared_hmac(
            &auth.shared_secret,
            &[0x01],
            &vec![(key.clone(), Value { version, value: value.clone() })],
        );

        let server_hmac = compute_shared_hmac(
            &auth.shared_secret,
            &[0x02],
            &vec![(key.clone(), Value { version, value: value.clone() })],
        );

        let kv = proto::KeyValue { key, version, value };
        // TODO multiple kvs
        let kvs = vec![kv];
        let put_request =
            Request::new(PutRequest { auth: self.make_auth_proto(), kvs, hmac: client_hmac });

        let response = self.client.put(put_request).await?;
        let res = response.into_inner();
        if res.success {
            if res.hmac == server_hmac {
                Ok(())
            } else {
                Err(ClientError::InvalidServerHmac())
            }
        } else {
            let mut conflicts = kvs_from_proto(res.conflicts);
            remove_and_check_hmacs(&hmac_secret, &mut conflicts)?;
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

fn kvs_from_proto(conflicts_proto: Vec<proto::KeyValue>) -> Vec<(String, Value)> {
    conflicts_proto
        .into_iter()
        .map(|kv| (kv.key, Value { version: kv.version, value: kv.value }))
        .collect()
}

fn remove_and_check_hmacs(
    hmac_secret: &[u8],
    kvs: &mut Vec<(String, Value)>,
) -> Result<(), ClientError> {
    for (key, value) in kvs.iter_mut() {
        let value_without_hmac =
            remove_and_check_hmac(value.value.clone(), &key, value.version, &hmac_secret)
                .map_err(|()| ClientError::InvalidHmac(key.clone(), value.version))?;
        value.value = value_without_hmac;
    }
    Ok(())
}
