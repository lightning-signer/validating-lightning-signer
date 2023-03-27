//! see lss.proto in lightning_storage_server for more details

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning_signer::bitcoin;
use lightning_signer::persist::Mutations;

pub enum Error {
    /// There was a put conflict for one or more keys
    Conflicts(Vec<(String, u64)>),
    /// The backend servers don't have a quorum of consensus
    NoConsensus,
    /// A quorum could not be reached or returned an error
    NotAvailable,
    /// Client was not authorized (e.g. HMAC was invalid)
    NotAuthorized,
}

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
pub trait ExternalPersist {
    /// Store the mutations.
    /// Returns the server hmacs, proving that each backend server persisted the mutations.
    /// If a server did not respond in time, their HMAC will be empty.
    async fn put(
        &self,
        auth: Vec<Auth>,
        mutations: Mutations,
        client_hmac: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, Error>;

    /// Get consensus full state from the backend servers and the matching server HMACs.
    ///
    /// If there is no consensus, an error is returned.
    async fn get(
        &self,
        auth: Vec<Auth>,
        key_prefix: String,
        nonce: Vec<u8>,
    ) -> Result<(Mutations, Vec<Vec<u8>>), Error>;

    /// Return server information for each backend server.
    async fn info(&self) -> Result<Vec<Info>, Error>;
}
