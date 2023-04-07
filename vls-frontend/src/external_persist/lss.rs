use super::{Error, ExternalPersist, Info};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning_signer::bitcoin;
use lightning_signer::persist::Mutations;
use lightning_storage_server::client::{Auth as LssAuth, Client as LssClient, ClientError};
use lightning_storage_server::Value as LssValue;
use log::error;
use tokio::sync::Mutex;

impl From<ClientError> for Error {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connect(e) => {
                error!("LSS connect error: {}", e);
                Error::NotAvailable
            }
            ClientError::Tonic(e) => {
                error!("LSS transport error: {}", e);
                Error::NotAvailable
            }
            ClientError::InvalidResponse => {
                error!("LSS invalid response");
                Error::NotAvailable
            }
            ClientError::InvalidHmac(key, value) => {
                error!("LSS invalid HMAC for key {} version {}", key, value);
                Error::NotAuthorized
            }
            ClientError::InvalidServerHmac() => {
                error!("LSS invalid server HMAC");
                Error::NotAuthorized
            }
            ClientError::PutConflict(c) => {
                error!("LSS put conflict: {:?}", c);
                Error::Conflicts(c.into_iter().map(|(k, v)| (k, v.version as u64)).collect())
            }
        }
    }
}

/// An external persistence implementation using lightning-storage-server.
pub struct Client {
    client: Mutex<LssClient>,
    server_public_key: PublicKey,
    uri: String,
}

impl Client {
    /// Get the server's public key.
    ///
    /// This will be needed later when calling `new`.  It is also used in the
    /// signer to create a shared secret with the server.
    ///
    /// In a production system, this should be verified and cached.
    pub async fn get_server_pubkey(uri: &str) -> Result<PublicKey, Error> {
        Ok(LssClient::get_info(uri).await?.0)
    }

    /// Create a new client.
    ///
    /// `uri` is the URI of the server.
    /// `server_public_key` is the server's public key as previously obtained via `get_server_pubkey`.
    /// `auth` is the authentication token to use.  It includes the client public key.
    ///
    /// Note that the client public key is used to locate the client's data on the server.
    pub async fn new(
        uri: &str,
        server_public_key: &PublicKey,
        auth: LssAuth,
    ) -> Result<Self, Error> {
        let (pubkey, _version) = LssClient::get_info(uri).await?;

        assert_eq!(pubkey, *server_public_key, "server public key mismatch");
        let client = LssClient::new(uri, auth).await?;
        Ok(Self {
            client: Mutex::new(client),
            server_public_key: server_public_key.clone(),
            uri: uri.to_string(),
        })
    }
}

#[async_trait]
impl ExternalPersist for Client {
    async fn put(&self, mutations: Mutations, client_hmac: &[u8]) -> Result<Vec<u8>, Error> {
        let mut client = self.client.lock().await;
        let kvs = mutations
            .into_iter()
            .map(|(k, (version, value))| (k, LssValue { version: version as i64, value }))
            .collect();
        let server_hmac = client.put(kvs, client_hmac).await?;
        Ok(server_hmac)
    }

    async fn get(&self, key_prefix: String, nonce: &[u8]) -> Result<(Mutations, Vec<u8>), Error> {
        let mut client = self.client.lock().await;
        let (kvs, received_hmac) = client.get(key_prefix, nonce).await?;
        let mutations = kvs.into_iter().map(|(k, v)| (k, (v.version as u64, v.value))).collect();
        Ok((mutations, received_hmac))
    }

    async fn info(&self) -> Result<Vec<Info>, Error> {
        let (server_public_key, version) = LssClient::get_info(&self.uri).await?;
        assert_eq!(self.server_public_key, server_public_key, "server public key mismatch");

        Ok(vec![Info { version, pubkey: server_public_key.clone() }])
    }
}
