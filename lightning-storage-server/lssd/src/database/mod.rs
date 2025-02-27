#[cfg(feature = "etcd")]
pub mod etcd;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod redb;

use lightning_storage_server::model::Value;
use thiserror::Error;
use tonic::async_trait;

/// Database errors
#[derive(Debug, Error)]
pub enum Error {
    /// underlying database error
    #[error("database error: {0}")]
    Redb(#[from] redb::RedbError),
    #[cfg(feature = "postgres")]
    #[error("database error: {0}")]
    /// underlying database error
    Postgres(#[from] postgres::PgError),
    /// etcd database error
    #[cfg(feature = "etcd")]
    #[error("database error: {0}")]
    Etcd(#[from] etcd_client::Error),
    /// version conflicts detected - existing values are returned
    #[error("put conflict: {0:?}")]
    Conflict(Vec<(String, Option<Value>)>),
    /// invalid key versions detected
    #[error("put invalid key versions: {0:?}")]
    InvalidVersions(Vec<(String, Value)>),
}

#[async_trait]
pub trait Database: Send + Sync {
    /// Atomically put a vector of key-values into the database.
    ///
    /// Note: versioning starts from index `0`.
    ///
    /// If any of the value versions are not the next version, the entire
    /// transaction is aborted and the error includes the existing key and values.
    /// In case of non existent values [`Value`] is [`None`].
    async fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error>;

    /// Get all keys matching a prefix from the database with key and values.
    async fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error>;
}
