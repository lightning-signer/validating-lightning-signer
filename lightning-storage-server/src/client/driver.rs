use crate::client::auth::Auth;
use crate::client::LightningStorageClient;
use crate::proto::{self, GetRequest, InfoRequest, PingRequest, PutRequest};
use crate::util::{compute_shared_hmac, prepare_value_for_put, process_value_from_get};
use crate::Value;
use log::{debug, error};
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
        debug!("info");
        let mut client = connect(uri).await?;
        let info_request = Request::new(InfoRequest {});

        let response = client.info(info_request).await?.into_inner();
        debug!("info result {:?}", response);
        PublicKey::from_slice(&response.server_id).map_err(|_| ClientError::InvalidResponse)
    }

    pub async fn new(uri: &str, auth: Auth) -> Result<Self, ClientError> {
        let client = connect(uri).await?;
        Ok(Self { client, auth })
    }

    pub async fn ping(uri: &str, message: &str) -> Result<String, ClientError> {
        debug!("ping");
        let mut client = connect(uri).await?;
        let ping_request = Request::new(PingRequest { message: message.into() });

        let response = client.ping(ping_request).await?.into_inner();
        debug!("ping result {:?}", response);
        Ok(response.message)
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
        debug!("get request '{}'", key_prefix);
        let get_request = Request::new(GetRequest {
            auth: self.make_auth_proto(),
            key_prefix,
            nonce: nonce.clone(),
        });

        let response = self.client.get(get_request).await?.into_inner();
        let mut kvs = kvs_from_proto(response.kvs);
        let hmac = compute_shared_hmac(&auth.shared_secret, &nonce, &kvs);

        if response.hmac == hmac {
            remove_and_check_hmacs(&hmac_secret, &mut kvs)?;
            debug!("get result {:?}", kvs);
            Ok(kvs)
        } else {
            error!("get hmac mismatch");
            Err(ClientError::InvalidServerHmac())
        }
    }

    /// values do not include HMAC
    pub async fn put(
        &mut self,
        auth: Auth,
        hmac_secret: &[u8],
        mut kvs: Vec<(String, Value)>,
    ) -> Result<(), ClientError> {
        debug!("put request {:?}", kvs);
        kvs.sort_by_key(|(k, _)| k.clone());
        for (key, value) in kvs.iter_mut() {
            prepare_value_for_put(hmac_secret, key, value);
        }

        let client_hmac = compute_shared_hmac(&auth.shared_secret, &[0x01], &kvs);

        let server_hmac = compute_shared_hmac(&auth.shared_secret, &[0x02], &kvs);

        let kvs_proto = kvs
            .into_iter()
            .map(|(k, v)| proto::KeyValue {
                key: k.clone(),
                value: v.value.clone(),
                version: v.version,
            })
            .collect();

        let put_request = Request::new(PutRequest {
            auth: self.make_auth_proto(),
            kvs: kvs_proto,
            hmac: client_hmac,
        });

        let response = self.client.put(put_request).await?.into_inner();
        debug!("put result {:?}", response);
        if response.success {
            if response.hmac == server_hmac {
                Ok(())
            } else {
                error!("put hmac mismatch");
                Err(ClientError::InvalidServerHmac())
            }
        } else {
            let mut conflicts = kvs_from_proto(response.conflicts);
            remove_and_check_hmacs(&hmac_secret, &mut conflicts)?;
            error!("put conflicts {:?}", conflicts);
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
    debug!("connect to {}", uri.to_string());
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
        process_value_from_get(hmac_secret, key, value)
            .map_err(|()| ClientError::InvalidHmac(key.clone(), value.version))?;
    }
    Ok(())
}
