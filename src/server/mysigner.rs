use core::fmt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use bitcoin_hashes::core::fmt::Formatter;
use lightning::chain::keysinterface::{InMemoryChannelKeys, KeysInterface, KeysManager};
use lightning::util::logger::Logger;
use secp256k1::{PublicKey, Secp256k1};

use crate::util::test_utils::TestLogger;

type ChannelId = [u8; 32];

pub struct Channel {
    keys: InMemoryChannelKeys,
}

impl Debug for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("channel")
    }
}

pub struct Node {
    keys_manager: KeysManager,
    channels: Mutex<HashMap<ChannelId, Channel>>,
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}

pub struct MySigner {
    pub logger: Arc<Logger>,
    nodes: Mutex<HashMap<PublicKey, Node>>,
}

impl MySigner {
    pub fn new() -> MySigner {
        let test_logger = Arc::new(TestLogger::with_id("server".to_owned()));
        let logger = Arc::clone(&test_logger) as Arc<Logger>;
        let signer = MySigner {
            logger: test_logger,
            nodes: Mutex::new(HashMap::new()),
        };
        log_info!(signer, "new MySigner");
        signer
    }

    fn new_node(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;
        let seed = [0; 32]; // FIXME
        let logger = Arc::clone(&self.logger);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
        let node = Node {
            keys_manager: KeysManager::new(&seed, network, logger, now.as_secs(), now.subsec_nanos()),
            channels: Mutex::new(HashMap::new()),
        };
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, node);
        node_id
    }

    fn new_channel(&self, node_id: &PublicKey, channel_value_satoshi: u64) -> Result<ChannelId, ()> {
        let nodes = self.nodes.lock().unwrap();
        let node = match nodes.get(node_id) {
            Some(n) => n,
            None => {
                log_error!(self, "no such node {}", node_id);
                return Err(());
            }
        };
        let mut channels = node.channels.lock().unwrap();
        let keys_manager = &node.keys_manager;
        let channel_id = keys_manager.get_channel_id();
        if channels.contains_key(&channel_id) {
            log_error!(self, "already have channel ID {}", hex::encode(channel_id));
            return Err(());
        }
        let unused_inbound_flag = false;
        let chan_keys = keys_manager.get_channel_keys(unused_inbound_flag, channel_value_satoshi);
        let channel = Channel {
            keys: chan_keys
        };
        channels.insert(channel_id, channel);
        Ok(channel_id)
    }

    fn with_node<F: Sized, T, E>(&self, node_id: &PublicKey, f: F) -> Result<T, E>
        where F: Fn(Option<&Node>) -> Result<T, E> {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        f(node)
    }

    fn with_channel<F: Sized, T, E>(&self, node_id: &PublicKey,
                                    channel_id: &ChannelId,
                                    f: F) -> Result<T, E>
        where F: Fn(Option<&Channel>) -> Result<T, E> {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or(f(None), |n| {
            f(n.channels.lock().unwrap().get(channel_id))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::util::test_utils::*;

    use super::*;

    #[test]
    fn new_channel_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = signer.new_channel(&node_id, 1000)?;
        signer.with_node(&node_id, |node| {
            assert(node.ok_or(()))
        })?;
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert(chan.ok_or(()))
        })?;
        Ok(())
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = [1; 32];
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert_not(chan.ok_or(()))
        })?;
        Ok(())
    }

    #[test]
    fn bad_node_lookup_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex("0101010101010101010101010101010101010101010101010101010101010101", &secp_ctx);

        let channel_id = [1; 32];
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert_not(chan.ok_or(()))
        })?;

        signer.with_node(&node_id, |node| {
            assert_not(node.ok_or(()))
        })?;
        Ok(())
    }

    #[test]
    fn new_channel_bad_node_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex("0101010101010101010101010101010101010101010101010101010101010101", &secp_ctx);
        assert_not(signer.new_channel(&node_id, 1000))?;
        Ok(())
    }
}
