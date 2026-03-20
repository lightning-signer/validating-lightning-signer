use crate::approver::{Approve, NegativeApprover};
use crate::handler::{HandlerBuilder, InitHandler, RootHandler};
use lightning_signer::bitcoin::blockdata::constants::genesis_block;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::model::ChannelEntry;
use lightning_signer::persist::Persist;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::policy::validator::{EnforcementState, ValidatorFactory};
use lightning_signer::prelude::*;
use lightning_signer::signer::{ClockStartingTimeFactory, StartingTimeFactory};
use lightning_signer::util::clock::{Clock, StandardClock};
use std::sync::Arc;
use vls_common::HexEncode;
use vls_persist::kvv::memory::MemoryKVVStore;
use vls_persist::kvv::{JsonFormat, KVVPersister, KVVStore, ValueFormat};
use vls_protocol::msgs::{self, Message};

/// Builder for constructing [`SignerTestHarness`].
pub struct SignerTestHarnessBuilder {
    network: Network,
    seed: [u8; 32],
    validator_factory: Arc<dyn ValidatorFactory>,
    starting_time_factory: Arc<dyn StartingTimeFactory>,
    persister: Option<MemoryKVVStore>,
    clock: Arc<dyn Clock>,
    approver: Arc<dyn Approve>,
    signer_id: lightning_signer::persist::SignerId,
}

impl Default for SignerTestHarnessBuilder {
    fn default() -> Self {
        Self {
            network: Network::Regtest,
            seed: [0u8; 32],
            validator_factory: Arc::new(SimpleValidatorFactory::new()),
            starting_time_factory: ClockStartingTimeFactory::new(),
            persister: None,
            clock: Arc::new(StandardClock()),
            approver: Arc::new(NegativeApprover()),
            signer_id: [1u8; 16],
        }
    }
}

impl SignerTestHarnessBuilder {
    /// Create a builder with sensible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Build the harness.
    pub fn build(self) -> SignerTestHarness<MemoryKVVStore, JsonFormat> {
        let memory_store = self.persister.unwrap_or_else(|| MemoryKVVStore::new(self.signer_id));
        let kvv_store = Arc::new(KVVPersister(memory_store, JsonFormat));
        let services = NodeServices {
            validator_factory: Arc::clone(&self.validator_factory),
            starting_time_factory: Arc::clone(&self.starting_time_factory),
            persister: Arc::clone(&kvv_store) as Arc<dyn Persist>,
            clock: Arc::clone(&self.clock),
            trusted_oracle_pubkeys: vec![],
        };

        SignerTestHarness {
            network: self.network,
            services,
            seed: self.seed,
            approver: Arc::clone(&self.approver),
            kvv_persister: kvv_store,
        }
    }
}

/// Convenience harness for exercising signer handlers in unit tests.
pub struct SignerTestHarness<T: KVVStore, U: ValueFormat> {
    network: Network,
    services: NodeServices,
    seed: [u8; 32],
    approver: Arc<dyn Approve>,
    kvv_persister: Arc<KVVPersister<T, U>>,
}

impl<T: KVVStore, U: ValueFormat> SignerTestHarness<T, U> {
    /// Construct a [`RootHandler`] and perform the handshake.
    pub fn root_handler(&self) -> RootHandler {
        let mut init = self.build_init_handler();
        let (done, reply) = init.handle(Self::hsmd_init_message(self.network)).expect("hsmd init");
        assert!(done, "handshake not complete");
        let reply = reply.expect("hsmd init reply");
        assert!(
            reply.as_any().downcast_ref::<msgs::HsmdInitReplyV4>().is_some(),
            "expected HsmdInitReplyV4"
        );
        init.into()
    }

    fn build_init_handler(&self) -> InitHandler {
        HandlerBuilder::new(self.network, 0, self.services.clone(), self.seed)
            .approver(Arc::clone(&self.approver))
            .build()
            .expect("init handler")
    }

    fn hsmd_init_message(network: Network) -> Message {
        Message::HsmdInit(msgs::HsmdInit {
            key_version: vls_protocol::model::Bip32KeyVersion {
                pubkey_version: 0x0488b21e,
                privkey_version: 0x0488ade4,
            },
            chain_params: genesis_block(network).block_hash(),
            encryption_key: None,
            dev_privkey: None,
            dev_bip32_seed: None,
            dev_channel_secrets: None,
            dev_channel_secrets_shaseed: None,
            hsm_wire_min_version: msgs::MIN_PROTOCOL_VERSION,
            hsm_wire_max_version: msgs::DEFAULT_MAX_PROTOCOL_VERSION,
        })
    }

    /// Seed a channel entry directly into the backing persister.
    pub fn seed_channel_entry(
        &self,
        node_id: &lightning_signer::bitcoin::secp256k1::PublicKey,
        entry: &ChannelEntry,
    ) -> Result<(), lightning_signer::persist::Error> {
        let channel_id = entry.id.as_ref().expect("channel entry must include a channel id");
        let key =
            format!("channel/{}/{}", node_id.serialize().to_hex(), channel_id.as_slice().to_hex());
        let value = JsonFormat::ser_value(entry)?;
        self.kvv_persister.put(&key, value)
    }
}

/// Utility to construct a minimal [`ChannelEntry`] for tests.
pub fn channel_entry_with_id(channel_id: lightning_signer::channel::ChannelId) -> ChannelEntry {
    ChannelEntry {
        channel_value_satoshis: 0,
        channel_setup: None,
        id: Some(channel_id),
        enforcement_state: EnforcementState::new(0),
        blockheight: None,
    }
}
