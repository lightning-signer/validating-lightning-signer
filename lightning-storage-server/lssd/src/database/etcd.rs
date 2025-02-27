use std::sync::Arc;

use async_trait::async_trait;
use etcd_client::{
    Client, Compare, ConnectOptions, DeleteOptions, GetOptions, KeyValue, KvClient, Txn, TxnOp,
    TxnOpResponse,
};
use futures::lock::Mutex;
use itertools::Itertools;

use lightning_storage_server::Value;
use log::{debug, error, info};

use super::{Database, Error};

/// Environment variable name for setting a comma separate list for etcd client to connect with.
pub const ETCD_URLS: &'static str = "ETCD_URLS";
/// Environment variable name for setting etcd authorized user name.
pub const ETCD_USERNAME: &'static str = "ETCD_USERNAME";
/// Environemtn variable name for setting etcd authorized user password.
pub const ETCD_PASSWORD: &'static str = "ETCD_PASSWORD";

pub struct EtcdDatabase {
    kv_client: Arc<Mutex<KvClient>>,
}

impl EtcdDatabase {
    pub async fn new<U, T>(url: Vec<T>, auth: Option<(U, U)>) -> Result<Self, Error>
    where
        T: AsRef<str>,
        U: Into<String>,
    {
        let options = match auth {
            Some((username, password)) => Some(ConnectOptions::new().with_user(username, password)),
            None => None,
        };
        let client = Client::connect(url, options).await?;
        Ok(Self { kv_client: Arc::new(Mutex::new(client.kv_client())) })
    }

    pub async fn clear(&self) -> Result<(), Error> {
        let mut client = self.kv_client.lock().await;
        client.delete("", Some(DeleteOptions::new().with_all_keys())).await?;
        Ok(())
    }

    /// Create the comparison vector for [`Txn::when`] operation before new key value insertion that ensures:
    /// - values with version 0 don't exist in database (create_revision = 0)
    /// - for rest the version should match the one in database as vls has 0 based versioning whereas etcd starts from 1.
    fn versions_valid(client_id_prefix: &str, kvs: &Vec<(String, Value)>) -> Vec<Compare> {
        kvs.iter()
            .filter(|&kv| kv.1.version == 0)
            .map(|kv| {
                Compare::create_revision(
                    format!("{}/{}", client_id_prefix, kv.0),
                    etcd_client::CompareOp::Equal,
                    0,
                )
            })
            .chain(kvs.iter().filter(|&kv| kv.1.version != 0).map(|kv| {
                Compare::version(
                    format!("{}/{}", client_id_prefix, kv.0),
                    etcd_client::CompareOp::Equal,
                    kv.1.version,
                )
            }))
            .collect_vec()
    }

    /// Returns [Some] if the result we got from the get operation is a conflicting [Value]:
    /// - If no value is their in get response than the version shouldn't be `0`
    /// - If we received some value than the version should match provided key value version
    fn invalid_kv_result(
        fetched_kv: Option<&KeyValue>,
        provided_kv: &(String, Value),
    ) -> Option<(String, Option<Value>)> {
        match fetched_kv {
            Some(kv) =>
                if kv.version() != provided_kv.1.version {
                    return Some((
                        provided_kv.0.to_string(),
                        Some(Value { version: kv.version() - 1, value: kv.value().to_vec() }),
                    ));
                },
            None =>
                if provided_kv.1.version != 0 {
                    return Some((provided_kv.0.to_string(), None));
                },
        };

        None
    }

    /// create a vector of [TxOp::put] operations for the provided key value vector.
    fn create_put_transaction(client_id_prefix: &str, kvs: &Vec<(String, Value)>) -> Vec<TxnOp> {
        kvs.iter()
            .map(|kv| {
                TxnOp::put(format!("{}/{}", client_id_prefix, kv.0), kv.1.value.clone(), None)
            })
            .collect_vec()
    }

    /// create a vector of [TxOp::get] operations for the provided key value vector
    fn create_get_transaction(client_id_prefix: &str, kvs: &Vec<(String, Value)>) -> Vec<TxnOp> {
        kvs.iter()
            .map(|kv| TxnOp::get(format!("{}/{}", client_id_prefix, kv.0), None))
            .collect_vec()
    }
}

#[async_trait]
impl Database for EtcdDatabase {
    async fn get_with_prefix(
        &self,
        client_id: &[u8],
        key_prefix: String,
    ) -> Result<Vec<(String, Value)>, Error> {
        let mut client = self.kv_client.lock().await;
        let prefix = format!("{}/{}", hex::encode(client_id), key_prefix);
        let results =
            client.get(prefix, Some(GetOptions::new().with_prefix())).await?.kvs().to_owned();
        drop(client);

        Ok(results
            .iter()
            .map(|kv| {
                let key =
                    kv.key_str().expect("empty key").to_owned().split_off(client_id.len() * 2 + 1);
                let value = Value { version: kv.version() - 1, value: kv.value().to_vec() };

                (key, value)
            })
            .collect_vec())
    }

    async fn put(&self, client_id: &[u8], kvs: &Vec<(String, Value)>) -> Result<(), Error> {
        let mut client = self.kv_client.lock().await;
        let non_positive_versions = kvs.iter().filter(|kv| kv.1.version < 0).cloned().collect_vec();
        if !non_positive_versions.is_empty() {
            return Err(Error::InvalidVersions(non_positive_versions));
        }

        let client_id_prefix = hex::encode(client_id);
        debug!("starting transaction for client {:?}", client_id_prefix);

        let txn = Txn::new()
            .when(Self::versions_valid(&client_id_prefix, kvs))
            .and_then(Self::create_put_transaction(&client_id_prefix, kvs))
            .or_else(Self::create_get_transaction(&client_id_prefix, kvs));

        let txn_result = client.txn(txn).await?;
        drop(client);

        info!("transaction result {:?}", txn_result);
        if txn_result.succeeded() {
            info!("transaction succeeded");
            return Ok(());
        }

        error!("transaction failed returning conflicts");
        let conflicts = txn_result
            .op_responses()
            .iter()
            .zip(kvs)
            .filter_map(|(response, kv)| match response {
                TxnOpResponse::Get(get_response) =>
                    Self::invalid_kv_result(get_response.kvs().first(), kv),
                _ => None,
            })
            .collect_vec();

        Err(Error::Conflict(conflicts))
    }
}
