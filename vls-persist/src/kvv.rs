pub mod cloud;
pub mod memory;
#[cfg(any(feature = "redb-kvv", test))]
pub mod redb;

use crate::model::*;
use alloc::format;
use core::fmt::Debug;
use core::ops::Deref;
use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::bitcoin::Network;
use lightning_signer::chain::tracker::ChainTracker;
use lightning_signer::channel::{Channel, ChannelId, ChannelStub};
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::node::{Allowable, NodeConfig, NodeState};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::persist::{ChainTrackerListenerEntry, Error, Persist, SignerId};
use lightning_signer::policy::validator::{EnforcementState, ValidatorFactory};
use lightning_signer::prelude::*;
use lightning_signer::{persist::Mutations, SendSync};
use serde_json::{from_slice, to_vec};

const NODE_ENTRY_PREFIX: &str = "node/entry";
const NODE_STATE_PREFIX: &str = "node/state";
const NODE_TRACKER_PREFIX: &str = "node/tracker";
const ALLOWLIST_PREFIX: &str = "node/allowlist";
const CHANNEL_PREFIX: &str = "channel";
const SEPARATOR: &str = "/";

/// key-version-value
pub struct KVV(pub String, pub (u64, Vec<u8>));

impl Debug for KVV {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("KVV").field(&self.0).field(&self.1 .0).field(&self.1 .1).finish()
    }
}

impl KVV {
    /// convert to the inner tuple
    pub fn into_inner(self) -> (String, (u64, Vec<u8>)) {
        (self.0, self.1)
    }
}

pub trait ValueFormat: SendSync {
    /// Serialize a value
    fn ser_value<T: ?Sized + serde::Serialize>(value: &T) -> Result<Vec<u8>, Error>;
    /// Deserialize a value
    fn de_value<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T, Error>;
}

pub struct JsonFormat;

impl SendSync for JsonFormat {}

impl ValueFormat for JsonFormat {
    /// Serialize a value
    fn ser_value<T: ?Sized + serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
        to_vec(value).map_err(|e| Error::SerdeError(e.to_string()))
    }
    /// Deserialize a value
    fn de_value<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T, Error> {
        from_slice(value).map_err(|e| Error::SerdeError(e.to_string()))
    }
}

/// A key-version-value store
pub trait KVVStore: SendSync {
    type Iter: Iterator<Item = KVV>;

    /// Put a key-value pair into the store
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error>;
    /// If the key already exists, the version must be greater than the existing version.
    fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error>;
    /// Atomically put several KVVs into the store
    fn put_batch(&self, kvvs: Vec<KVV>) -> Result<(), Error>;
    /// Get a key-value pair from the store
    /// Returns Ok(None) if the key does not exist.
    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error>;
    /// Get the version of a key-value pair from the store
    /// Returns Ok(None) if the key does not exist.
    fn get_version(&self, key: &str) -> Result<Option<u64>, Error>;
    /// Get all key-value pairs with the given prefix
    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error>;
    /// Delete a key-value pair from the store
    fn delete(&self, key: &str) -> Result<(), Error>;
    /// Clear the database
    fn clear_database(&self) -> Result<(), Error>;
    /// Start a transaction
    fn enter(&self) -> Result<(), Error> {
        Ok(())
    }
    /// Get the commit log as a Mutations object, to be stored in the cloud
    fn prepare(&self) -> Mutations {
        Mutations::new()
    }
    /// Commit the commit log to the local KVVStore
    fn commit(&self) -> Result<(), Error> {
        Ok(())
    }
    /// Apply a batch from the cloud to the local store, without logging it
    fn put_batch_unlogged(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        self.put_batch(kvvs)
    }
    /// Reset the versions of all keys to 0, so that a replica can be initialized from scratch
    fn reset_versions(&self) -> Result<(), Error>;
    /// Get the signer ID
    fn signer_id(&self) -> SignerId;
}

/// Adapter for a KVVStore to implement Persist.
// NOTE: we can't use a generic impl because Persist is not in this crate.
pub struct KVVPersister<S: KVVStore, F: ValueFormat>(pub S, pub F);

impl<S: KVVStore, F: ValueFormat> Deref for KVVPersister<S, F> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: KVVStore, F: ValueFormat> SendSync for KVVPersister<S, F> {}

impl<S: KVVStore, F: ValueFormat> Persist for KVVPersister<S, F> {
    fn new_node(
        &self,
        node_id: &PublicKey,
        config: &NodeConfig,
        state: &NodeState,
    ) -> Result<(), Error> {
        self.update_node(node_id, state).unwrap();
        let key = make_key(NODE_ENTRY_PREFIX, &node_id.serialize());
        let entry = NodeEntry {
            key_derivation_style: config.key_derivation_style as u8,
            network: config.network.to_string(),
        };
        let value = F::ser_value(&entry)?;
        self.put(&key, value)
    }

    fn update_node(&self, node_id: &PublicKey, state: &NodeState) -> Result<(), Error> {
        let key = make_key(NODE_STATE_PREFIX, &node_id.serialize());
        let entry: NodeStateEntry = state.into();
        let value = F::ser_value(&entry)?;
        self.put(&key, value)
    }

    fn delete_node(&self, node_id: &PublicKey) -> Result<(), Error> {
        let id = node_id.serialize();
        self.delete(&make_key(NODE_ENTRY_PREFIX, &id))?;
        self.delete(&make_key(NODE_STATE_PREFIX, &id))
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), Error> {
        let key = make_key2(CHANNEL_PREFIX, &node_id.serialize(), stub.id0.as_slice());
        let channel_value_satoshis = 0;

        let entry = ChannelEntry {
            channel_value_satoshis,
            channel_setup: None,
            id: None,
            enforcement_state: EnforcementState::new(0),
            blockheight: Some(stub.blockheight),
        };
        let value = F::ser_value(&entry)?;
        self.put(&key, value)
    }

    fn delete_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<(), Error> {
        let key = make_key2(CHANNEL_PREFIX, &node_id.serialize(), channel_id.as_slice());
        self.delete(&key)
    }

    fn new_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        self.update_tracker(node_id, tracker)
    }

    fn update_tracker(
        &self,
        node_id: &PublicKey,
        tracker: &ChainTracker<ChainMonitor>,
    ) -> Result<(), Error> {
        let key = make_key(NODE_TRACKER_PREFIX, &node_id.serialize());
        let model: ChainTrackerEntry = tracker.into();
        let value = F::ser_value(&model)?;
        self.put(&key, value)
    }

    fn get_tracker(
        &self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> Result<(ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>), Error> {
        let key = make_key(NODE_TRACKER_PREFIX, &node_id.serialize());
        let value = self.get(&key)?.expect("tracker not found").1;
        let model: ChainTrackerEntry = F::de_value(&value)?;
        Ok(model.into_tracker(node_id.clone(), validator_factory))
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), Error> {
        let key = make_key2(CHANNEL_PREFIX, &node_id.serialize(), channel.id0.as_slice());

        let channel_value_satoshis = channel.setup.channel_value_sat;
        let entry = ChannelEntry {
            channel_value_satoshis,
            channel_setup: Some(channel.setup.clone()),
            id: channel.id.clone(),
            enforcement_state: channel.enforcement_state.clone(),
            blockheight: None,
        };
        let value = F::ser_value(&entry)?;
        self.put(&key, value)
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<CoreChannelEntry, Error> {
        let key = make_key2(CHANNEL_PREFIX, &node_id.serialize(), channel_id.as_slice());
        let value = self.get(&key)?.expect("channel not found").1;
        let entry: ChannelEntry = F::de_value(&value)?;
        Ok(entry.into())
    }

    fn get_node_channels(
        &self,
        node_id: &PublicKey,
    ) -> Result<Vec<(ChannelId, CoreChannelEntry)>, Error> {
        let prefix = make_key(CHANNEL_PREFIX, &node_id.serialize()) + SEPARATOR;
        let mut res = Vec::new();
        for kvv in self.get_prefix(&prefix)? {
            let (key, (_r, value)) = kvv.into_inner();
            if value.is_empty() {
                continue; // ignore tombstones
            }
            let suffix = extract_key_suffix(&prefix, &key);
            let channel_id = ChannelId::new(&suffix);
            let entry: ChannelEntry = F::de_value(&value)?;
            res.push((channel_id, entry.into()));
        }
        Ok(res)
    }

    fn update_node_allowlist(
        &self,
        node_id: &PublicKey,
        allowlist: Vec<String>,
    ) -> Result<(), Error> {
        let key = make_key(ALLOWLIST_PREFIX, &node_id.serialize());
        let entry = AllowlistItemEntry { allowlist };
        let value = F::ser_value(&entry)?;
        self.put(&key, value)
    }

    fn get_node_allowlist(&self, node_id: &PublicKey) -> Result<Vec<String>, Error> {
        let key = make_key(ALLOWLIST_PREFIX, &node_id.serialize());
        let value = self.get(&key)?.expect("allowlist not found").1;
        let entry: AllowlistItemEntry = F::de_value(&value)?;
        Ok(entry.allowlist)
    }

    fn get_nodes(&self) -> Result<Vec<(PublicKey, CoreNodeEntry)>, Error> {
        let prefix = NODE_ENTRY_PREFIX.to_string() + SEPARATOR;
        let mut res = Vec::new();
        let kvvs = self
            .get_prefix(&prefix)?
            .map(KVV::into_inner)
            .filter(|(_k, (_r, value))| !value.is_empty());
        for (key, (_r, value)) in kvvs {
            let suffix = extract_key_suffix(&prefix, &key);
            let node_id = PublicKey::from_slice(&suffix).unwrap();
            let entry: NodeEntry = F::de_value(&value)?;

            let state_value = self
                .get(&make_key(NODE_STATE_PREFIX, &node_id.serialize()))?
                .ok_or(Error::NotFound("state not found".to_string()))?
                .1;
            let state_entry: NodeStateEntry = F::de_value(&state_value)?;

            let network: Network = entry.network.parse().map_err(|_| {
                Error::SerdeError(format!("Invalid network string: {}", entry.network))
            })?;

            let allowlist =
                self.get_node_allowlist(&node_id)
                    .map(|strings| {
                        strings
                            .into_iter()
                            .map(|s| Allowable::from_str(&s, network))
                            .collect::<Result<Vec<Allowable>, _>>()
                    })
                    .unwrap_or(Ok(Vec::new()))
                    .map_err(|e| Error::SerdeError(format!("Invalid allowlist entry: {}", e)))?;

            let state = NodeState::restore(
                state_entry.invoices,
                state_entry.issued_invoices,
                state_entry.preimages,
                0,
                state_entry.velocity_control.into(),
                state_entry.fee_velocity_control.into(),
                state_entry.dbid_high_water_mark.into(),
                allowlist,
            );
            let node_entry = CoreNodeEntry {
                key_derivation_style: entry.key_derivation_style as u8,
                network: entry.network,
                state,
            };
            res.push((node_id, node_entry));
        }
        Ok(res)
    }

    fn clear_database(&self) -> Result<(), Error> {
        // delegate to the underlying store
        self.0.clear_database()
    }

    fn enter(&self) -> Result<(), Error> {
        self.0.enter()
    }

    fn prepare(&self) -> Mutations {
        self.0.prepare()
    }

    fn commit(&self) -> Result<(), Error> {
        self.0.commit()
    }

    fn put_batch_unlogged(&self, muts: Mutations) -> Result<(), Error> {
        let kvvs = muts.into_iter().map(|(k, (v, vv))| KVV(k, (v, vv))).collect::<Vec<_>>();
        self.0.put_batch_unlogged(kvvs)
    }

    fn begin_replication(&self) -> Result<Mutations, Error> {
        self.reset_versions()?;
        let res = self
            .get_prefix("")?
            .map(|kvv| {
                let (k, (v, vv)) = kvv.into_inner();
                (k, (v, vv))
            })
            .collect();
        Ok(Mutations::from_vec(res))
    }

    fn signer_id(&self) -> SignerId {
        self.0.signer_id()
    }
}

fn make_key(prefix: impl Into<String>, key: &[u8]) -> String {
    format!("{}/{}", prefix.into(), hex::encode(key))
}

fn make_key2(prefix: impl Into<String>, key1: &[u8], key2: &[u8]) -> String {
    format!("{}/{}/{}", prefix.into(), hex::encode(key1), hex::encode(key2))
}

fn extract_key_suffix(prefix: &str, key: &str) -> Vec<u8> {
    assert!(prefix.ends_with(SEPARATOR), "prefix must end with separator");
    let suffix = key.strip_prefix(prefix).expect("key must start with prefix");
    hex::decode(suffix).expect("invalid hex in key suffix")
}
