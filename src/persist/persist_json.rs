use bitcoin::Network;
use kv::{Bucket, Config, Json, Store, TransactionError};
use secp256k1::PublicKey;

use crate::node::node::{Channel, ChannelId, ChannelStub, NodeConfig};
use crate::persist::model::{ChannelEntry, NodeChannelId, NodeEntry};
use crate::persist::Persist;

/// A persister that uses the kv crate and JSON serialization for values.
pub struct KVJsonPersister<'a> {
    pub node_bucket: Bucket<'a, Vec<u8>, Json<NodeEntry>>,
    pub channel_bucket: Bucket<'a, NodeChannelId, Json<ChannelEntry>>,
}

impl KVJsonPersister<'_> {
    pub fn new(path: &str) -> Self {
        let cfg = Config::new(path);
        let store = Store::new(cfg).expect("create store");
        let node_bucket =
            store.bucket(Some("nodes"))
                .expect("create node bucket");
        let channel_bucket=
            store.bucket(Some("channels"))
                .expect("create channel bucket");
        Self {
            node_bucket,
            channel_bucket
        }
    }
}

impl<'a> Persist for KVJsonPersister<'a> {
    fn new_node(&self, node_id: &PublicKey, config: &NodeConfig, seed: &[u8], network: Network) {
        let entry = NodeEntry {
            seed: seed.to_vec(),
            key_derivation_style: config.key_derivation_style as u8,
            network: network.to_string(),
        };
        self.node_bucket.set(node_id.serialize().to_vec(), Json(entry)).expect("insert node");
        self.node_bucket.flush().expect("flush");
    }

    fn new_channel(&self, node_id: &PublicKey, stub: &ChannelStub) -> Result<(), ()> {
        let enforcing_keys = &stub.keys;
        let channel_value_satoshis = 0; // TODO not known yet

        self.channel_bucket.transaction(|txn| {
            let id = NodeChannelId::new(node_id, &stub.id0);
            let entry = ChannelEntry {
                nonce: stub.nonce.clone(),
                channel_value_satoshis,
                channel_setup: None,
                id: None,
                enforcement_state: enforcing_keys.enforcement_state(),
            };
            if txn.get(id.clone()).unwrap().is_some() { return Err(TransactionError::Abort(kv::Error::Message("already exists".to_string())))}
            txn.set(id, Json(entry)).expect("insert channel");
            Ok(())
        }).expect("new transaction");
        self.node_bucket.flush().expect("flush");
        Ok(())
    }

    fn update_channel(&self, node_id: &PublicKey, channel: &Channel) -> Result<(), ()> {
        let enforcing_keys = &channel.keys;
        let channel_value_satoshis = channel.setup.channel_value_sat;

        self.channel_bucket.transaction(|txn| {
            let node_channel_id = NodeChannelId::new(node_id, &channel.id0);
            let entry = ChannelEntry {
                nonce: channel.nonce.clone(),
                channel_value_satoshis,
                channel_setup: Some(channel.setup.clone()),
                id: channel.id,
                enforcement_state: enforcing_keys.enforcement_state()
            };
            if txn.get(node_channel_id.clone()).unwrap().is_none() { return Err(TransactionError::Abort(kv::Error::Message("not found".to_string())))}
            let json = Json(entry);
            txn.set(node_channel_id, json).expect("update channel");
            Ok(())
        }).expect("update transaction");
        self.node_bucket.flush().expect("flush");
        Ok(())
    }

    fn get_channel(&self, node_id: &PublicKey, channel_id: &ChannelId) -> Result<ChannelEntry, ()> {
        let id = NodeChannelId::new(node_id, channel_id);
        let json = self.channel_bucket.get(id)
            .unwrap().ok_or_else(|| ())?;
        Ok(json.0)
    }

    fn get_node_channels(&self, node_id: &PublicKey) -> Vec<(ChannelId, ChannelEntry)> {
        let mut res = Vec::new();
        for item_res in self.channel_bucket.iter_prefix(NodeChannelId::new_prefix(node_id)) {
            let item = item_res.unwrap();
            let value: Json<ChannelEntry> = item.value().unwrap();
            let key: NodeChannelId = item.key().unwrap();
            res.push((key.channel_id(), value.0));
        }
        res
    }

    fn get_nodes(&self) -> Vec<(PublicKey, NodeEntry)> {
        let mut res = Vec::new();
        for item_res in self.node_bucket.iter() {
            let item = item_res.unwrap();
            let value: Json<NodeEntry> = item.value().unwrap();
            let key: Vec<u8> = item.key().unwrap();
            res.push((PublicKey::from_slice(key.as_slice()).unwrap(), value.0));
        }
        res
    }

    fn clear_database(&self) {
        self.channel_bucket.clear().unwrap();
        self.node_bucket.clear().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lightning::chain::keysinterface::InMemorySigner;
    use lightning::util::logger::Logger;
    use lightning::util::ser::Writeable;
    use tempfile::TempDir;

    use crate::node::node::ChannelSlot;
    use crate::persist::ser_util::VecWriter;
    use crate::persist::util::*;
    use crate::server::my_signer::channel_nonce_to_id;
    use crate::util::enforcing_trait_impls::EnforcingSigner;
    use crate::util::test_utils::{TEST_NODE_CONFIG, TestLogger};

    use super::*;

    fn make_temp_persister<'a>() -> (KVJsonPersister<'a>, TempDir, String) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_owned();
        let path_str = path.to_str().unwrap();

        let persister = KVJsonPersister::new(path_str);
        persister.clear_database();
        (persister, dir, path_str.to_string())
    }

    #[test]
    fn round_trip_signer_test() {
        let (persister, temp_dir, path) = make_temp_persister();

        let channel_nonce = "nonce0".as_bytes().to_vec();
        let channel_id0 = channel_nonce_to_id(&channel_nonce);

        let logger: Arc<dyn Logger> = Arc::new(TestLogger::with_id("server".to_owned()));
        let (node_id, node_arc, stub) = make_node_and_channel(&logger, &channel_nonce, channel_id0);

        let node = &*node_arc;

        persister.new_node(&node_id, &TEST_NODE_CONFIG, &[3u8; 32], Network::Regtest);

        {
            persister.new_channel(&node_id, &stub).unwrap();

            let entry = persister.get_channel(&node_id, &channel_id0).unwrap();
            let (_, restored_node_arc) = make_node(&logger);
            let slot = restored_node_arc.restore_channel(channel_id0, None, entry.nonce, entry.channel_value_satoshis, entry.channel_setup, entry.enforcement_state, &restored_node_arc).unwrap();

            let guard = slot.lock().unwrap();
            if let ChannelSlot::Stub(s) = &*guard {
                check_signer_roundtrip(&stub.keys, &s.keys.inner());
            } else { panic!() }
        }

        // Ready the channel
        {
            let dummy_pubkey = make_dummy_pubkey(0x12);
            let setup = create_test_channel_setup(dummy_pubkey);

            let channel_nonce1 = "nonce1".as_bytes().to_vec();
            let channel_id1 = channel_nonce_to_id(&channel_nonce1);

            let channel = node.ready_channel(channel_id0, Some(channel_id1), setup).unwrap();
            persister.update_channel(&node_id, &channel).unwrap();

            let entry = persister.get_channel(&node_id, &channel_id0).unwrap();
            let (_, restored_node_arc) = make_node(&logger);
            let slot = restored_node_arc.restore_channel(channel_id0, entry.id, entry.nonce, entry.channel_value_satoshis, entry.channel_setup, entry.enforcement_state, &restored_node_arc).unwrap();
            assert!(node.channels().contains_key(&channel_id0));
            assert!(node.channels().contains_key(&channel_id1));
            let guard = slot.lock().unwrap();
            if let ChannelSlot::Ready(s) = &*guard {
                check_signer_roundtrip(&channel.keys, &s.keys.inner());
            } else { panic!() }
        }

        drop(persister);

        {
            let persister1 = KVJsonPersister::new(path.as_str());
            let nodes = persister1.get_nodes();
            assert_eq!(nodes.len(), 1);
        }

        drop(temp_dir);

        {
            let persister1 = KVJsonPersister::new(path.as_str());
            let nodes = persister1.get_nodes();
            assert_eq!(nodes.len(), 0);
        }
    }

    fn check_signer_roundtrip(existing_enforcing_signer: &EnforcingSigner, signer: &InMemorySigner) {
        let existing_signer = existing_enforcing_signer.inner();
        let mut existing_w = VecWriter(Vec::new());
        existing_signer.write(&mut existing_w).unwrap();
        let mut w = VecWriter(Vec::new());
        signer.write(&mut w).unwrap();
        assert_eq!(existing_w.0, w.0);
    }
}