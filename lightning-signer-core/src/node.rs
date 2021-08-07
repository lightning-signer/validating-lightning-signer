use core::any::Any;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::{self, Debug, Formatter};
use core::str::FromStr;
use core::time::Duration;

use bitcoin;
use bitcoin::{Address, secp256k1, Transaction, TxOut};
use bitcoin::{Network, OutPoint, Script, SigHashType};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use lightning::chain;
use lightning::chain::keysinterface::{
    BaseSign, KeysInterface, SpendableOutputDescriptor,
};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters,
    CounterpartyChannelTransactionParameters
};
use log::info;

use crate::channel::{Channel, ChannelId, ChannelSetup, ChannelStub};
use crate::persist::model::NodeEntry;
use crate::persist::Persist;
use crate::policy::validator::{
    SimpleValidatorFactory, ValidatorFactory, ValidatorState,
};
use crate::policy::validator::EnforcementState;
use crate::prelude::*;
use crate::signer::multi_signer::SpendType;
use crate::signer::my_keys_manager::{KeyDerivationStyle, MyKeysManager};
use crate::sync::{Arc, Weak};
use crate::util::crypto_utils::signature_to_bitcoin_vec;
use crate::util::invoice_utils;
use crate::util::status::{internal_error, invalid_argument, Status};
use crate::wallet::Wallet;

// NOTE - this "ChannelId" does *not* correspond to the "channel_id"
// defined in BOLT #2.

/// A channel can be in two states - before [Node::ready_channel] it's a
/// [ChannelStub], afterwards it's a [Channel].  This enum keeps track
/// of the two different states.
pub enum ChannelSlot {
    Stub(ChannelStub),
    Ready(Channel),
}

impl ChannelSlot {
    /// Get the channel nonce, used to derive the channel keys
    pub fn nonce(&self) -> Vec<u8> {
        match self {
            ChannelSlot::Stub(stub) => stub.nonce(),
            ChannelSlot::Ready(chan) => chan.nonce(),
        }
    }

    pub fn id(&self) -> ChannelId {
        match self {
            ChannelSlot::Stub(stub) => stub.id0,
            ChannelSlot::Ready(chan) => chan.id0,
        }
    }
}

/// A trait implemented by both channel states.  See [ChannelSlot]
pub trait ChannelBase: Any {
    /// Get the channel basepoints and public keys
    fn get_channel_basepoints(&self) -> ChannelPublicKeys;
    /// Get the per-commitment point for a holder commitment transaction
    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status>;
    /// Get the per-commitment secret for a holder commitment transaction
    // TODO leaking secret
    fn get_per_commitment_secret(&self, commitment_number: u64) -> Result<SecretKey, Status>;
    /// Check a future secret to support `option_data_loss_protect`
    fn check_future_secret(&self, commit_num: u64, suggested: &SecretKey) -> Result<bool, Status>;
    /// Get the channel nonce, used to derive the channel keys
    // TODO should this be exposed?
    fn nonce(&self) -> Vec<u8>;

    // TODO remove when LDK workaround is removed in LoopbackSigner
    #[cfg(feature = "test_utils")]
    fn set_next_holder_commit_num_for_testing(&mut self, _num: u64) {
        // Do nothing for ChannelStub.  Channel will override.
    }
}

#[derive(Copy, Clone)]
pub struct NodeConfig {
    pub key_derivation_style: KeyDerivationStyle,
}

/// A signer for one Lightning node.
///
/// ```rust
/// use lightning_signer::node::{Node, NodeConfig, ChannelSlot, ChannelBase};
/// use lightning_signer::persist::{DummyPersister, Persist};
/// use lightning_signer::util::test_utils::TEST_NODE_CONFIG;
/// use lightning_signer::util::test_logger::TestLogger;
/// use lightning_signer::signer::multi_signer::SyncLogger;
///
/// use bitcoin::Network;
/// use std::sync::Arc;
///
/// let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
/// let network = Network::Testnet;
/// let seed = [0; 32];
/// let config = TEST_NODE_CONFIG;
/// let node = Arc::new(Node::new(config, &seed, network, &persister));
/// let (channel_id, opt_stub) = node.new_channel(None, None, &node).expect("new channel");
/// assert!(opt_stub.is_some());
/// let channel_slot_mutex = node.get_channel(&channel_id).expect("get channel");
/// let channel_slot = channel_slot_mutex.lock().expect("lock");
/// match &*channel_slot {
///     ChannelSlot::Stub(stub) => {
///         // Do things with the stub, such as readying it or getting the points
///         let holder_basepoints = stub.get_channel_basepoints();
///     }
///     ChannelSlot::Ready(_) => panic!("expected a stub")
/// }
/// ```
pub struct Node {
    pub(crate) node_config: NodeConfig,
    pub(crate) keys_manager: MyKeysManager,
    channels: Mutex<Map<ChannelId, Arc<Mutex<ChannelSlot>>>>,
    pub(crate) network: Network,
    pub(crate) validator_factory: Box<dyn ValidatorFactory>,
    pub(crate) persister: Arc<dyn Persist>,
}

impl Wallet for Node {
    fn wallet_can_spend(
        &self,
        child_path: &Vec<u32>,
        output: &TxOut,
    ) -> Result<bool, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let pubkey = self
            .get_wallet_key(&secp_ctx, child_path)?
            .public_key(&secp_ctx);

        // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
        let native_addr = Address::p2wpkh(&pubkey, self.network)
            .expect("p2wpkh failed");
        let wrapped_addr = Address::p2shwpkh(&pubkey, self.network)
            .expect("p2shwpkh failed");

        Ok(output.script_pubkey == native_addr.script_pubkey()
            || output.script_pubkey == wrapped_addr.script_pubkey())
    }
}

impl Node {
    /// Create a node.
    ///
    /// NOTE: you must persist the node yourself if it is new.
    pub fn new(
        node_config: NodeConfig,
        seed: &[u8],
        network: Network,
        persister: &Arc<Persist>,
    ) -> Node {
        let now = Duration::from_secs(genesis_block(network).header.time as u64);

        Node {
            keys_manager: MyKeysManager::new(
                node_config.key_derivation_style,
                seed,
                network,
                now.as_secs(),
                now.subsec_nanos(),
            ),
            node_config,
            channels: Mutex::new(Map::new()),
            network,
            validator_factory: Box::new(SimpleValidatorFactory {}),
            persister: Arc::clone(persister),
        }
    }

    /// Get the node ID, which is the same as the node public key
    pub fn get_id(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret())
    }

    pub(crate) fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.keys_manager.get_secure_random_bytes()
    }

    /// Get the [Mutex] protected channel slot
    pub fn get_channel(&self, channel_id: &ChannelId) -> Result<Arc<Mutex<ChannelSlot>>, Status> {
        let mut guard = self.channels();
        let elem = guard.get_mut(channel_id);
        let slot_arc = elem.ok_or_else(|| Status::invalid_argument("no such channel"))?;
        Ok(Arc::clone(slot_arc))
    }

    pub fn find_channel_with_funding_outpoint(
        &self,
        outpoint: &OutPoint,
    ) -> Option<Arc<Mutex<ChannelSlot>>> {
        let guard = self.channels.lock().unwrap();
        for (_, slot_arc) in guard.iter() {
            let slot = slot_arc.lock().unwrap();
            match &*slot {
                ChannelSlot::Ready(chan) => {
                    if chan.setup.funding_outpoint == *outpoint {
                        return Some(Arc::clone(slot_arc));
                    }
                }
                ChannelSlot::Stub(_stub) => {
                    // ignore stubs ...
                }
            }
        }
        None
    }

    /// Create a new channel, which starts out as a stub.
    ///
    /// The initial channel ID may be specified in `opt_channel_id`.  If the channel
    /// with this ID already exists, the existing stub is returned.
    ///
    /// If unspecified, the channel nonce will default to the channel ID.
    ///
    /// This function is currently infallible.
    ///
    /// Returns the channel ID and the stub.
    // TODO the relationship between nonce and ID is different from
    // the behavior used in the gRPC driver.  Here the nonce defaults to the ID
    // but in the gRPC driver, the nonce is supplied by the caller, and the ID
    // is set to the sha256 of the nonce.
    pub fn new_channel(
        &self,
        opt_channel_id: Option<ChannelId>,
        opt_channel_nonce0: Option<Vec<u8>>,
        arc_self: &Arc<Node>,
    ) -> Result<(ChannelId, Option<ChannelStub>), Status> {
        let channel_id =
            opt_channel_id.unwrap_or_else(|| ChannelId(self.keys_manager.get_channel_id()));
        let channel_nonce0 = opt_channel_nonce0.unwrap_or_else(|| channel_id.0.to_vec());
        let mut channels = self.channels.lock().unwrap();

        // Is there a preexisting channel slot?
        let maybe_slot = channels.get(&channel_id);
        if maybe_slot.is_some() {
            match &*maybe_slot.unwrap().lock().unwrap() {
                ChannelSlot::Stub(stub) => {
                    if channel_nonce0 != stub.nonce {
                        return Err(invalid_argument(format!(
                            "new_channel nonce mismatch with existing stub: \
                             channel_id={} channel_nonce0={} stub.nonce={}",
                            channel_id,
                            channel_nonce0.to_hex(),
                            stub.nonce.to_hex()
                        )));
                    }
                    // This stub is "embryonic" (hasn't signed a commitment).  This
                    // can happen if the initial channel create to this peer failed
                    // in negotiation.  It's ok to just use this stub.
                    return Ok((channel_id, Some(stub.clone())));
                }
                ChannelSlot::Ready(_) => {
                    // Calling new_channel on a channel that's already been marked
                    // ready is not allowed.
                    return Err(invalid_argument(format!(
                        "channel already ready: {}",
                        channel_id
                    )));
                }
            };
        }

        let channel_value_sat = 0; // Placeholder value, not known yet.
        let keys = self.keys_manager.get_channel_keys_with_id(
            channel_id,
            channel_nonce0.as_slice(),
            channel_value_sat,
        );

        let stub = ChannelStub {
            node: Arc::downgrade(arc_self),
            nonce: channel_nonce0,
            secp_ctx: Secp256k1::new(),
            keys,
            id0: channel_id,
        };
        // TODO this clone is expensive
        channels.insert(
            channel_id,
            Arc::new(Mutex::new(ChannelSlot::Stub(stub.clone()))),
        );
        self.persister
            .new_channel(&self.get_id(), &stub)
            // Persist.new_channel should only fail if the channel was previously persisted.
            // So if it did fail, we have an internal error.
            .expect("channel was in storage but not in memory");
        Ok((channel_id, Some(stub)))
    }

    pub(crate) fn restore_channel(
        &self,
        channel_id0: ChannelId,
        channel_id: Option<ChannelId>,
        nonce: Vec<u8>,
        channel_value_sat: u64,
        channel_setup: Option<ChannelSetup>,
        enforcement_state: EnforcementState,
        arc_self: &Arc<Node>,
    ) -> Result<Arc<Mutex<ChannelSlot>>, ()> {
        let mut channels = self.channels.lock().unwrap();
        assert!(!channels.contains_key(&channel_id0));
        let mut keys = self.keys_manager.get_channel_keys_with_id(
            channel_id0,
            nonce.as_slice(),
            channel_value_sat,
        );

        let slot = match channel_setup {
            None => {
                let stub = ChannelStub {
                    node: Arc::downgrade(arc_self),
                    nonce,
                    secp_ctx: Secp256k1::new(),
                    keys,
                    id0: channel_id0,
                };
                // TODO this clone is expensive
                let slot = Arc::new(Mutex::new(ChannelSlot::Stub(stub.clone())));
                channels.insert(channel_id0, Arc::clone(&slot));
                channel_id.map(|id| channels.insert(id, Arc::clone(&slot)));
                slot
            }
            Some(setup) => {
                let channel_transaction_parameters =
                    Node::channel_setup_to_channel_transaction_parameters(&setup, keys.pubkeys());
                keys.ready_channel(&channel_transaction_parameters);
                let channel = Channel {
                    node: Arc::downgrade(arc_self),
                    nonce,
                    secp_ctx: Secp256k1::new(),
                    keys,
                    enforcement_state,
                    setup,
                    id0: channel_id0,
                    id: channel_id,
                };
                // TODO this clone is expensive
                let slot = Arc::new(Mutex::new(ChannelSlot::Ready(channel.clone())));
                channels.insert(channel_id0, Arc::clone(&slot));
                channel_id.map(|id| channels.insert(id, Arc::clone(&slot)));
                slot
            }
        };
        self.keys_manager.increment_channel_id_child_index();
        Ok(slot)
    }

    /// Restore a node from a persisted [NodeEntry].
    ///
    /// You can get the [NodeEntry] from [Persist::get_nodes].
    ///
    /// The channels are also restored from the `persister`.
    pub fn restore_node(
        node_id: &PublicKey,
        node_entry: NodeEntry,
        persister: Arc<dyn Persist>,
    ) -> Arc<Node> {
        let config = NodeConfig {
            key_derivation_style: KeyDerivationStyle::try_from(node_entry.key_derivation_style)
                .unwrap(),
        };
        let network = Network::from_str(node_entry.network.as_str()).expect("bad network");
        let node = Arc::new(Node::new(
            config,
            node_entry
                .seed
                .as_slice()
                .try_into()
                .expect("seed wrong length"),
            network,
            &persister,
        ));
        assert_eq!(&node.get_id(), node_id);
        info!("Restore node {}", node_id);
        for (channel_id0, channel_entry) in persister.get_node_channels(node_id) {
            info!("  Restore channel {}", channel_id0);
            node.restore_channel(
                channel_id0,
                channel_entry.id,
                channel_entry.nonce,
                channel_entry.channel_value_satoshis,
                channel_entry.channel_setup,
                channel_entry.enforcement_state,
                &node,
            )
            .expect("restore channel");
        }
        node
    }

    /// Restore all nodes from `persister`.
    ///
    /// The channels of each node are also restored.
    pub fn restore_nodes(persister: Arc<dyn Persist>) -> Map<PublicKey, Arc<Node>> {
        let mut nodes = Map::new();
        for (node_id, node_entry) in persister.get_nodes() {
            let node = Node::restore_node(&node_id, node_entry, Arc::clone(&persister));
            nodes.insert(node_id, node);
        }
        nodes
    }

    /// Ready a new channel, making it available for use.
    ///
    /// This populates fields that are known later in the channel creation flow,
    /// such as fields that are supplied by the counterparty and funding outpoint.
    ///
    /// * `channel_id0` - the original channel ID supplied to [`Node::new_channel`]
    /// * `opt_channel_id` - the permanent channel ID
    ///
    /// The channel is promoted from a [ChannelStub] to a [Channel].
    /// After this call, the channel may be referred to by either ID.
    pub fn ready_channel(
        &self,
        channel_id0: ChannelId,
        opt_channel_id: Option<ChannelId>,
        setup: ChannelSetup,
    ) -> Result<Channel, Status> {
        let chan = {
            let channels = self.channels.lock().unwrap();
            let arcobj = channels.get(&channel_id0).ok_or_else(|| {
                invalid_argument(format!("channel does not exist: {}", channel_id0))
            })?;
            let slot = arcobj.lock().unwrap();
            let stub = match &*slot {
                ChannelSlot::Stub(stub) => Ok(stub),
                ChannelSlot::Ready(_) => Err(invalid_argument(format!(
                    "channel already ready: {}",
                    channel_id0
                ))),
            }?;
            let mut keys = stub.channel_keys_with_channel_value(setup.channel_value_sat);
            let holder_pubkeys = keys.pubkeys();
            let channel_transaction_parameters =
                Node::channel_setup_to_channel_transaction_parameters(&setup, holder_pubkeys);
            keys.ready_channel(&channel_transaction_parameters);
            Channel {
                node: Weak::clone(&stub.node),
                nonce: stub.nonce.clone(),
                secp_ctx: stub.secp_ctx.clone(),
                keys,
                enforcement_state: EnforcementState::new(),
                setup: setup.clone(),
                id0: channel_id0,
                id: opt_channel_id,
            }
        };
        let validator = self.validator_factory.make_validator(chan.network());

        validator.validate_channel_open(&setup)?;

        let mut channels = self.channels.lock().unwrap();

        // Wrap the ready channel with an arc so we can potentially
        // refer to it multiple times.
        // TODO this clone is expensive
        let arcobj = Arc::new(Mutex::new(ChannelSlot::Ready(chan.clone())));

        // If a permanent channel_id was provided use it, otherwise
        // continue with the initial channel_id0.
        let chan_id = opt_channel_id.unwrap_or(channel_id0);

        // Associate the new ready channel with the channel id.
        channels.insert(chan_id, arcobj.clone());

        // If we are using a new permanent channel_id additionally
        // associate the channel with the original (initial)
        // channel_id as well.
        if channel_id0 != chan_id {
            channels.insert(channel_id0, arcobj.clone());
        }

        self.persister
            .update_channel(&self.get_id(), &chan)
            .map_err(|_| Status::internal("persist failed"))?;

        Ok(chan)
    }

    pub fn sign_funding_tx(
        &self,
        tx: &bitcoin::Transaction,
        ipaths: &Vec<Vec<u32>>,
        values_sat: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: &Vec<Option<SecretKey>>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Status> {
        let secp_ctx = Secp256k1::signing_only();

        // Funding transactions cannot be associated with a single channel; a single
        // transaction may fund multiple channels

        let validator = self.validator_factory.make_validator(self.network);

        let channels: Vec<Option<Arc<Mutex<ChannelSlot>>>> =
            tx.output.iter().enumerate()
                .map(|(ndx, _)| {
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: ndx as u32,
                    };
                    self.find_channel_with_funding_outpoint(&outpoint)
                }).collect();
        // TODO - initialize the state
        let state = ValidatorState { current_height: 0 };
        validator.validate_funding_tx(self, channels, &state, tx, values_sat, opaths)?;

        let mut witvec: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for idx in 0..tx.input.len() {
            if spendtypes[idx] == SpendType::Invalid {
                // If we are signing a PSBT some of the inputs may be
                // marked as SpendType::Invalid (we skip these), push
                // an empty witness element instead.
                witvec.push((vec![], vec![]));
            } else {
                let value_sat = values_sat[idx];
                let privkey = match uniclosekeys[idx] {
                    // There was a unilateral_close_key.
                    Some(sk) => Ok(bitcoin::PrivateKey {
                        compressed: true,
                        network: Network::Testnet, // FIXME
                        key: sk,
                    }),
                    // Derive the HD key.
                    None => self.get_wallet_key(&secp_ctx, &ipaths[idx]),
                }?;
                let pubkey = privkey.public_key(&secp_ctx);
                let script_code = Address::p2pkh(&pubkey, privkey.network).script_pubkey();
                let sighash = match spendtypes[idx] {
                    SpendType::P2pkh => {
                        // legacy address
                        Message::from_slice(&tx.signature_hash(0, &script_code, 0x01)[..])
                            .map_err(|err| internal_error(format!("p2pkh sighash failed: {}", err)))
                    }
                    SpendType::P2wpkh | SpendType::P2shP2wpkh => {
                        // segwit native and wrapped
                        Message::from_slice(
                            &SigHashCache::new(tx).signature_hash(
                                idx,
                                &script_code,
                                value_sat,
                                SigHashType::All,
                            )[..],
                        )
                        .map_err(|err| internal_error(format!("p2wpkh sighash failed: {}", err)))
                    }

                    _ => Err(invalid_argument(format!(
                        "unsupported spend_type: {}",
                        spendtypes[idx] as i32
                    ))),
                }?;
                let sig = secp_ctx.sign(&sighash, &privkey.key);
                let sigvec = signature_to_bitcoin_vec(sig);

                witvec.push((sigvec, pubkey.key.serialize().to_vec()));
            }
        }
        // TODO(devrandom) self.persist_channel(node_id, chan);
        Ok(witvec)
    }

    fn channel_setup_to_channel_transaction_parameters(
        setup: &ChannelSetup,
        holder_pubkeys: &ChannelPublicKeys,
    ) -> ChannelTransactionParameters {
        let funding_outpoint = Some(chain::transaction::OutPoint {
            txid: setup.funding_outpoint.txid,
            index: setup.funding_outpoint.vout as u16,
        });
        let channel_transaction_parameters = ChannelTransactionParameters {
            holder_pubkeys: holder_pubkeys.clone(),
            holder_selected_contest_delay: setup.holder_selected_contest_delay,
            is_outbound_from_holder: setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: setup.counterparty_points.clone(),
                selected_contest_delay: setup.counterparty_selected_contest_delay,
            }),
            funding_outpoint,
        };
        channel_transaction_parameters
    }

    pub(crate) fn get_wallet_key(
        &self,
        secp_ctx: &Secp256k1<secp256k1::SignOnly>,
        child_path: &Vec<u32>,
    ) -> Result<bitcoin::PrivateKey, Status> {
        if child_path.len() != self.node_config.key_derivation_style.get_key_path_len() {
            return Err(invalid_argument(format!(
                "get_wallet_key: bad child_path len : {}",
                child_path.len()
            )));
        }
        // Start with the base xpriv for this wallet.
        let mut xkey = self.get_account_extended_key().clone();

        // Derive the rest of the child_path.
        for elem in child_path {
            xkey = xkey
                .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(*elem).unwrap())
                .map_err(|err| internal_error(format!("derive child_path failed: {}", err)))?;
        }
        Ok(xkey.private_key)
    }

    /// Get the node secret key
    /// This function will be eliminated once the node key related items
    /// are implemented.  This includes onion decoding and p2p handshake.
    // TODO leaking secret
    pub fn get_node_secret(&self) -> SecretKey {
        self.keys_manager.get_node_secret()
    }

    /// Get destination redeemScript to encumber static protocol exit points.
    pub fn get_destination_script(&self) -> Script {
        self.keys_manager.get_destination_script()
    }

    /// Get shutdown_pubkey to use as PublicKey at channel closure
    pub fn get_shutdown_pubkey(&self) -> PublicKey {
        self.keys_manager.get_shutdown_pubkey()
    }

    /// Get the layer-1 xprv
    // TODO leaking private key
    pub fn get_account_extended_key(&self) -> &ExtendedPrivKey {
        self.keys_manager.get_account_extended_key()
    }

    /// Get the layer-1 xpub
    pub fn get_account_extended_pubkey(&self) -> ExtendedPubKey {
        let secp_ctx = Secp256k1::signing_only();
        ExtendedPubKey::from_private(&secp_ctx, &self.get_account_extended_key())
    }

    /// Sign a node announcement using the node key
    pub fn sign_node_announcement(&self, na: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let na_hash = Sha256dHash::hash(na);
        let encmsg = secp256k1::Message::from_slice(&na_hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign(&encmsg, &self.get_node_secret());
        let res = sig.serialize_der().to_vec();
        Ok(res)
    }

    /// Sign a channel update using the node key
    pub fn sign_channel_update(&self, cu: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let cu_hash = Sha256dHash::hash(cu);
        let encmsg = secp256k1::Message::from_slice(&cu_hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign(&encmsg, &self.get_node_secret());
        let res = sig.serialize_der().to_vec();
        Ok(res)
    }

    /// Sign an invoice
    pub fn sign_invoice_in_parts(
        &self,
        data_part: &Vec<u8>,
        human_readable_part: &String,
    ) -> Result<Vec<u8>, Status> {
        use bitcoin::bech32::CheckBase32;

        let hash = invoice_utils::hash_from_parts(
            human_readable_part.as_bytes(),
            &data_part.check_base32().expect("needs to be base32 data"),
        );

        let secp_ctx = Secp256k1::signing_only();
        let encmsg = secp256k1::Message::from_slice(&hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let node_secret = SecretKey::from_slice(self.get_node_secret().as_ref()).unwrap();
        let sig = secp_ctx.sign_recoverable(&encmsg, &node_secret);
        let (rid, sig) = sig.serialize_compact();
        let mut res = sig.to_vec();
        res.push(rid.to_i32() as u8);
        Ok(res)
    }

    /// Sign an invoice
    pub fn sign_invoice(&self, invoice_preimage: &Vec<u8>) -> RecoverableSignature {
        let secp_ctx = Secp256k1::signing_only();
        let hash = Sha256Hash::hash(invoice_preimage);
        let message = secp256k1::Message::from_slice(&hash).unwrap();
        secp_ctx.sign_recoverable(&message, &self.get_node_secret())
    }

    /// Sign a Lightning message
    pub fn sign_message(&self, message: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let secp_ctx = Secp256k1::signing_only();
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = secp256k1::Message::from_slice(&hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign_recoverable(&encmsg, &self.get_node_secret());
        let (rid, sig) = sig.serialize_compact();
        let mut res = sig.to_vec();
        res.push(rid.to_i32() as u8);
        Ok(res)
    }

    /// Get the channels this node knows about.
    /// Currently, channels are not pruned once closed, but this will change.
    pub fn channels(&self) -> MutexGuard<Map<ChannelId, Arc<Mutex<ChannelSlot>>>> {
        self.channels.lock().unwrap()
    }

    /// Perform an ECDH operation between the node key and a public key
    /// This can be used for onion packet decoding
    pub fn ecdh(&self, other_key: &PublicKey) -> Vec<u8> {
        let our_key = self.keys_manager.get_node_secret();
        let ss = SharedSecret::new(&other_key, &our_key);
        ss[..].to_vec()
    }

    pub fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Transaction, ()> {
        self.keys_manager.spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
            secp_ctx,
        )
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}
