//! see lss.proto in lightning_storage_server for more details

pub mod lss;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning_signer::bitcoin;
use lightning_signer::persist::Mutations;
use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    /// There was a put conflict for one or more keys
    Conflicts(Vec<(String, u64)>),
    /// There is no consensus among the quorum of backend servers
    NoConsensus,
    /// A quorum could not be reached or returned an error
    NotAvailable,
    /// Client was not authorized (e.g. HMAC was invalid)
    NotAuthorized,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

pub struct Auth {
    pub client_id: PublicKey,
    pub token: Vec<u8>,
}

/// External persister information
pub struct Info {
    /// The version
    pub version: String,
    /// The persister's public key (for calculating HMACs)
    pub pubkey: PublicKey,
}

/// External persister.
///
/// This trait is used to store the mutations in one or more external storage
/// backends. The backend can be, for example, an LSS implementation (see
/// lightning-storage-server).
#[async_trait]
pub trait ExternalPersist: Send + Sync {
    /// Store the mutations.
    /// Returns the server hmacs, proving that each backend server persisted the mutations.
    /// If a server did not respond in time, their HMAC will be empty.
    /// TODO multiple servers
    async fn put(&self, mutations: Mutations, client_hmac: &[u8]) -> Result<Vec<u8>, Error>;

    /// Get the full state from a quorum of backend servers and the matching server HMACs.
    /// Unavailable servers will have an empty HMAC.
    ///
    /// If there is no consensus, an error is returned.
    /// TODO multiple servers
    async fn get(&self, key_prefix: String, nonce: &[u8]) -> Result<(Mutations, Vec<u8>), Error>;

    /// Return server information for each backend server.
    async fn info(&self) -> Result<Vec<Info>, Error>;
}
