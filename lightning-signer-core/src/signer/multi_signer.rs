use crate::chain::tracker::ChainTracker;
use bitcoin;
#[cfg(feature = "std")]
use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
use bitcoin::secp256k1::PublicKey;
use bitcoin::OutPoint;

use crate::channel::{Channel, ChannelBase, ChannelId, ChannelSlot};
use crate::monitor::ChainMonitor;
use crate::node::{Node, NodeConfig, NodeServices};
use crate::persist::Persist;
use crate::prelude::*;
use crate::sync::Arc;
use crate::util::status::{invalid_argument, Status};

/// A signer for multiple nodes.
///
/// If you need just one node, use [Node] directly.
pub struct MultiSigner {
    pub(crate) nodes: Mutex<Map<PublicKey, Arc<Node>>>,
    pub(crate) persister: Arc<dyn Persist>,
    pub(crate) test_mode: bool,
    pub(crate) initial_allowlist: Vec<String>,
    services: NodeServices,
}

impl MultiSigner {
    /// Construct
    pub fn new_with_test_mode(
        test_mode: bool,
        initial_allowlist: Vec<String>,
        services: NodeServices,
    ) -> MultiSigner {
        let nodes = Node::restore_nodes(services.clone());
        MultiSigner {
            nodes: Mutex::new(nodes),
            persister: services.persister.clone(),
            test_mode,
            initial_allowlist,
            services,
        }
    }

    /// Construct
    pub fn new(services: NodeServices) -> MultiSigner {
        let nodes = Node::restore_nodes(services.clone());
        MultiSigner {
            nodes: Mutex::new(nodes),
            persister: services.persister.clone(),
            test_mode: false,
            initial_allowlist: vec![],
            services,
        }
    }

    /// Create a node with a random seed
    #[cfg(feature = "std")]
    pub fn new_node(&self, node_config: NodeConfig) -> Result<PublicKey, Status> {
        let mut rng = OsRng;

        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        self.new_node_with_seed(node_config, &seed)
    }

    /// New node with externally supplied cryptographic seed
    pub fn new_node_with_seed(
        &self,
        node_config: NodeConfig,
        seed: &[u8],
    ) -> Result<PublicKey, Status> {
        let tracker = Node::make_tracker(node_config.clone());
        self.new_node_with_seed_and_tracker(node_config, seed, tracker)
    }

    /// New node with externally supplied cryptographic seed and chain tracker
    pub fn new_node_with_seed_and_tracker(
        &self,
        node_config: NodeConfig,
        seed: &[u8],
        tracker: ChainTracker<ChainMonitor>,
    ) -> Result<PublicKey, Status> {
        let node = Node::new_extended(node_config, &seed, vec![], tracker, self.services.clone());
        let node_id = node.get_id();
        let mut nodes = self.nodes.lock().unwrap();
        if self.test_mode {
            // In test mode we allow overwriting the node (thereby resetting all of its channels)
            self.persister.delete_node(&node_id);
        } else {
            // In production, the node must not have existed

            if nodes.contains_key(&node_id) {
                return Err(invalid_argument("node_exists"));
            }
        }
        node.add_allowlist(&self.initial_allowlist).expect("valid initialallowlist");
        self.persister.new_node(&node_id, &node_config, &*node.get_state(), &seed);
        self.persister.new_chain_tracker(&node_id, &node.get_tracker());
        nodes.insert(node_id, Arc::new(node));
        Ok(node_id)
    }

    /// Get all node IDs
    pub fn get_node_ids(&self) -> Vec<PublicKey> {
        let nodes = self.nodes.lock().unwrap();
        nodes.keys().map(|k| k.clone()).collect()
    }

    /// Ensure that a node exists given its seed
    pub fn warmstart_with_seed(
        &self,
        node_config: NodeConfig,
        seed: &[u8],
    ) -> Result<PublicKey, Status> {
        let node = Node::new(node_config, &seed, vec![], self.services.clone());
        let node_id = node.get_id();
        let nodes = self.nodes.lock().unwrap();
        nodes.get(&node_id).ok_or_else(|| {
            invalid_argument(format!("warmstart failed: no such node: {}", node_id))
        })?;
        Ok(node_id)
    }

    /// Temporary, until phase 2 is fully implemented
    pub fn additional_setup(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        outpoint: OutPoint,
    ) -> Result<(), Status> {
        self.with_ready_channel(node_id, channel_id, |chan| {
            if chan.setup.funding_outpoint.is_null() {
                chan.setup.funding_outpoint = outpoint;
            } else if chan.setup.funding_outpoint != outpoint {
                panic!("funding outpoint changed");
            }
            self.persist_channel(node_id, chan);
            Ok(())
        })
    }

    /// See [`Node::with_channel_base`]
    pub fn with_channel_base<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, Status>
    where
        F: Fn(&mut ChannelBase) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel(&node_id, &channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        let base = match &mut *slot {
            ChannelSlot::Stub(stub) => stub as &mut ChannelBase,
            ChannelSlot::Ready(chan) => chan as &mut ChannelBase,
        };
        f(base)
    }

    fn get_channel(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<Arc<Mutex<ChannelSlot>>, Status> {
        self.get_node(node_id)?.get_channel(channel_id)
    }

    /// Get a node
    pub fn get_node(&self, node_id: &PublicKey) -> Result<Arc<Node>, Status> {
        // Grab a reference to the node and release the nodes mutex
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id).ok_or_else(|| invalid_argument("no such node"))?;
        Ok(Arc::clone(node))
    }

    /// See [`Node::with_ready_channel`]
    pub fn with_ready_channel<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, Status>
    where
        F: Fn(&mut Channel) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel(&node_id, &channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        match &mut *slot {
            ChannelSlot::Stub(_) =>
                Err(invalid_argument(format!("channel not ready: {}", &channel_id))),
            ChannelSlot::Ready(chan) => f(chan),
        }
    }

    fn persist_channel(&self, node_id: &PublicKey, chan: &Channel) {
        self.persister
            .update_channel(&node_id, &chan)
            .expect("channel was in storage but not in memory");
    }

    /// Get the node services
    pub fn node_services(&self) -> NodeServices {
        self.services.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::persist::DummyPersister;
    use crate::policy::simple_validator::SimpleValidatorFactory;
    use crate::util::clock::StandardClock;
    use crate::util::status::Code;
    use crate::util::test_utils::hex_decode;
    use crate::util::test_utils::*;
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    fn make_test_services() -> NodeServices {
        let validator_factory = Arc::new(SimpleValidatorFactory::new());
        let persister = Arc::new(DummyPersister {});
        let clock = Arc::new(StandardClock());
        let starting_time_factory = make_genesis_starting_time_factory(TEST_NODE_CONFIG.network);
        NodeServices { validator_factory, starting_time_factory, persister, clock }
    }

    #[test]
    fn warmstart_with_seed_test() {
        let signer = MultiSigner::new(make_test_services());
        let mut seed = [0; 32];
        seed.copy_from_slice(hex_decode(TEST_SEED[1]).unwrap().as_slice());

        // First try a warmstart w/ no existing node.
        let result = signer.warmstart_with_seed(TEST_NODE_CONFIG, &seed);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "warmstart failed: no such node: 022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59");

        // Then a "coldstart" from seed should succeed.
        let node_id = signer.new_node_with_seed(TEST_NODE_CONFIG, &seed).unwrap();

        // Now a warmstart will work, should get the same node_id.
        let result = signer.warmstart_with_seed(TEST_NODE_CONFIG, &seed);
        assert!(!result.is_err());
        assert_eq!(result.unwrap(), node_id);
    }

    #[test]
    fn bad_node_lookup_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MultiSigner::new(make_test_services());
        let node_id = pubkey_from_secret_hex(
            "0101010101010101010101010101010101010101010101010101010101010101",
            &secp_ctx,
        );

        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        assert!(signer.get_channel(&node_id, &channel_id).is_err());
        assert!(signer.get_node(&node_id).is_err());

        Ok(())
    }
}
