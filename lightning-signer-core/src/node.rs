use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::{self, Debug, Formatter};
use core::iter::FromIterator;
use core::str::FromStr;
use core::time::Duration;

use bitcoin;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, Address, Transaction, TxOut};
use bitcoin::{Network, OutPoint, Script, SigHashType};
use lightning::chain;
use lightning::chain::keysinterface::{BaseSign, KeysInterface, SpendableOutputDescriptor};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
};
use lightning::util::logger::Logger;
use log::{info, trace};

use crate::channel::{Channel, ChannelBase, ChannelId, ChannelSetup, ChannelSlot, ChannelStub};
use crate::persist::model::NodeEntry;
use crate::persist::Persist;
use crate::policy::simple_validator::SimpleValidatorFactory;
use crate::policy::validator::EnforcementState;
use crate::policy::validator::{ChainState, ValidatorFactory};
use crate::prelude::*;
use crate::signer::my_keys_manager::{KeyDerivationStyle, MyKeysManager};
use crate::sync::{Arc, Weak};
use crate::util::crypto_utils::signature_to_bitcoin_vec;
use crate::util::invoice_utils;
use crate::util::status::{internal_error, invalid_argument, Status};
use crate::wallet::Wallet;
use lightning::ln::script::ShutdownScript;

/// Node configuration parameters.

#[derive(Copy, Clone)]
pub struct NodeConfig {
    /// The network type
    pub network: Network,
    /// The derivation style to use when deriving purpose-specific keys
    pub key_derivation_style: KeyDerivationStyle,
}

/// A signer for one Lightning node.
///
/// ```rust
/// use lightning_signer::node::{Node, NodeConfig};
/// use lightning_signer::channel::{ChannelSlot, ChannelBase};
/// use lightning_signer::persist::{DummyPersister, Persist};
/// use lightning_signer::util::test_utils::TEST_NODE_CONFIG;
/// use lightning_signer::util::test_logger::TestLogger;
/// use lightning_signer::node::SyncLogger;
///
/// use std::sync::Arc;
///
/// let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
/// let seed = [0; 32];
/// let config = TEST_NODE_CONFIG;
/// let node = Arc::new(Node::new(config, &seed, &persister, vec![]));
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
    pub(crate) validator_factory: Mutex<Box<dyn ValidatorFactory>>,
    pub(crate) persister: Arc<dyn Persist>,
    allowlist: Mutex<UnorderedSet<Script>>,
}

impl Wallet for Node {
    fn can_spend(&self, child_path: &Vec<u32>, script_pubkey: &Script) -> Result<bool, Status> {
        // If there is no path we can't spend it ...
        if child_path.len() == 0 {
            return Ok(false);
        }

        let secp_ctx = Secp256k1::signing_only();
        let pubkey = self.get_wallet_pubkey(&secp_ctx, child_path)?;

        // Lightning layer-1 wallets can spend native segwit or wrapped segwit addresses.
        let native_addr = Address::p2wpkh(&pubkey, self.network()).expect("p2wpkh failed");
        let wrapped_addr = Address::p2shwpkh(&pubkey, self.network()).expect("p2shwpkh failed");

        Ok(*script_pubkey == native_addr.script_pubkey()
            || *script_pubkey == wrapped_addr.script_pubkey())
    }

    /// Returns true if script_pubkey is in the node's allowlist.
    fn allowlist_contains(&self, script_pubkey: &Script) -> bool {
        self.allowlist.lock().unwrap().contains(script_pubkey)
    }

    fn network(&self) -> Network {
        self.node_config.network
    }
}

impl Node {
    /// Create a node.
    ///
    /// NOTE: you must persist the node yourself if it is new.
    pub fn new(
        node_config: NodeConfig,
        seed: &[u8],
        persister: &Arc<Persist>,
        allowlist: Vec<Script>,
    ) -> Node {
        let now = Duration::from_secs(genesis_block(node_config.network).header.time as u64);

        Node {
            keys_manager: MyKeysManager::new(
                node_config.key_derivation_style,
                seed,
                node_config.network,
                now.as_secs(),
                now.subsec_nanos(),
            ),
            node_config,
            channels: Mutex::new(Map::new()),
            validator_factory: Mutex::new(Box::new(SimpleValidatorFactory {})),
            persister: Arc::clone(persister),
            allowlist: Mutex::new(UnorderedSet::from_iter(allowlist)),
        }
    }

    /// Set the node's validator factory
    pub fn set_validator_factory(&self, validator_factory: Box<dyn ValidatorFactory>) {
        let mut vfac = self.validator_factory.lock().unwrap();
        *vfac = validator_factory;
    }

    /// Get the node ID, which is the same as the node public key
    pub fn get_id(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret())
    }

    #[allow(dead_code)]
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

    /// Execute a function with an existing channel.
    ///
    /// The channel may be a stub or a ready channel.
    /// An invalid_argument [Status] will be returned if the channel does not exist.
    pub fn with_channel_base<F: Sized, T>(&self, channel_id: &ChannelId, f: F) -> Result<T, Status>
    where
        F: Fn(&mut ChannelBase) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel(channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        let base = match &mut *slot {
            ChannelSlot::Stub(stub) => stub as &mut ChannelBase,
            ChannelSlot::Ready(chan) => chan as &mut ChannelBase,
        };
        f(base)
    }

    /// Execute a function with an existing ready channel.
    ///
    /// An invalid_argument [Status] will be returned if the channel does not exist.
    pub fn with_ready_channel<F: Sized, T>(&self, channel_id: &ChannelId, f: F) -> Result<T, Status>
    where
        F: Fn(&mut Channel) -> Result<T, Status>,
    {
        let slot_arc = self.get_channel(channel_id)?;
        let mut slot = slot_arc.lock().unwrap();
        match &mut *slot {
            ChannelSlot::Stub(_) => Err(invalid_argument(format!(
                "channel not ready: {}",
                &channel_id
            ))),
            ChannelSlot::Ready(chan) => f(chan),
        }
    }

    /// Get a channel given its funding outpoint, or None if no such channel exists.
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
    /// This function will return an invalid_argument [Status] if there is
    /// an existing channel with this ID and it's not a compatible stub
    /// channel.
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
            network: Network::from_str(node_entry.network.as_str()).expect("bad network"),
            key_derivation_style: KeyDerivationStyle::try_from(node_entry.key_derivation_style)
                .unwrap(),
        };
        let node = Arc::new(Node::new(
            config,
            node_entry
                .seed
                .as_slice()
                .try_into()
                .expect("seed wrong length"),
            &persister,
            persister.get_node_allowlist(node_id),
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
        holder_shutdown_key_path: &Vec<u32>,
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
        let validator = self
            .validator_factory
            .lock()
            .unwrap()
            .make_validator(chan.network());

        validator.validate_ready_channel(self, &setup, holder_shutdown_key_path)?;

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

        trace_enforcement_state!(&chan.enforcement_state);
        self.persister
            .update_channel(&self.get_id(), &chan)
            .map_err(|_| Status::internal("persist failed"))?;

        Ok(chan)
    }

    /// Sign a funding transaction.
    ///
    /// The transaction may fund multiple channels at once.
    /// Returns a witness stack for each input.  Inputs that are marked
    /// as [SpendType::Invalid] are not signed and get an empty witness stack.
    /// * `ipaths` - derivation path for the wallet key per input
    /// * `values_sat` - the amount in satoshi per input
    /// * `spendtypes` - spend type per input, or `Invalid` if this input is
    ///   to be signed by someone else.
    /// * `uniclosekeys` - an optional unilateral close key to use instead of the
    ///   wallet key.  Takes precedence over the `ipaths` entry.  This is used when
    ///   we are sweeping a unilateral close and funding a channel in a single tx.
    /// * `opaths` - derivation path for change, one per output.  Empty for
    ///   non-change outputs.
    pub fn sign_funding_tx(
        &self,
        cstate: &ChainState,
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

        let validator = self
            .validator_factory
            .lock()
            .unwrap()
            .make_validator(self.network());

        let channels: Vec<Option<Arc<Mutex<ChannelSlot>>>> = tx
            .output
            .iter()
            .enumerate()
            .map(|(ndx, _)| {
                let outpoint = OutPoint {
                    txid: tx.txid(),
                    vout: ndx as u32,
                };
                self.find_channel_with_funding_outpoint(&outpoint)
            })
            .collect();

        validator.validate_funding_tx(self, channels, &cstate, tx, values_sat, opaths)?;

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
                    None => self.get_wallet_privkey(&secp_ctx, &ipaths[idx]),
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

    pub(crate) fn get_wallet_privkey(
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

    pub(crate) fn get_wallet_pubkey(
        &self,
        secp_ctx: &Secp256k1<secp256k1::SignOnly>,
        child_path: &Vec<u32>,
    ) -> Result<bitcoin::PublicKey, Status> {
        Ok(self
            .get_wallet_privkey(secp_ctx, child_path)?
            .public_key(secp_ctx))
    }

    /// Get the node secret key
    /// This function will be eliminated once the node key related items
    /// are implemented.  This includes onion decoding and p2p handshake.
    // TODO leaking secret
    pub fn get_node_secret(&self) -> SecretKey {
        self.keys_manager.get_node_secret()
    }

    /// Get shutdown_pubkey to use as PublicKey at channel closure
    // FIXME - this method is deprecated
    pub fn get_ldk_shutdown_scriptpubkey(&self) -> ShutdownScript {
        self.keys_manager.get_shutdown_scriptpubkey()
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

    /// See [`MyKeysManager::spend_spendable_outputs`].
    ///
    /// For LDK compatibility.
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

    /// Returns the node's current allowlist.
    pub fn allowlist(&self) -> Result<Vec<String>, Status> {
        let alset = self.allowlist.lock().unwrap();
        (*alset)
            .iter()
            .map(|script_pubkey| {
                let addr = Address::from_script(&script_pubkey, self.network());
                if addr.is_none() {
                    return Err(invalid_argument(format!(
                        "address from script faied on {}",
                        &script_pubkey
                    )));
                }
                Ok(addr.unwrap().to_string())
            })
            .collect::<Result<Vec<String>, Status>>()
    }

    /// Adds addresses to the node's current allowlist.
    pub fn add_allowlist(&self, addlist: &Vec<String>) -> Result<(), Status> {
        let addresses = addlist
            .iter()
            .map(|addrstr| {
                let addr = addrstr.parse::<Address>().map_err(|err| {
                    invalid_argument(format!("parse address {} failed: {}", addrstr, err))
                })?;
                if addr.network != self.network() {
                    return Err(invalid_argument(format!(
                        "network mismatch for addr {}: addr={}, node={}",
                        addr,
                        addr.network,
                        self.network()
                    )));
                }
                Ok(addr)
            })
            .collect::<Result<Vec<Address>, Status>>()?;
        let mut alset = self.allowlist.lock().unwrap();
        for addr in addresses {
            alset.insert(addr.script_pubkey());
        }
        let wlvec = (*alset).iter().cloned().collect();
        self.persister
            .update_node_allowlist(&self.get_id(), wlvec)
            .map_err(|_| Status::internal("persist failed"))?;
        Ok(())
    }

    /// Removes addresses from the node's current allowlist.
    pub fn remove_allowlist(&self, rmlist: &Vec<String>) -> Result<(), Status> {
        let addresses = rmlist
            .iter()
            .map(|addrstr| {
                let addr = addrstr.parse::<Address>().map_err(|err| {
                    invalid_argument(format!("parse address {} failed: {}", addrstr, err))
                })?;
                if addr.network != self.network() {
                    return Err(invalid_argument(format!(
                        "network mismatch for addr {}: addr={}, node={}",
                        addr,
                        addr.network,
                        self.network()
                    )));
                }
                Ok(addr)
            })
            .collect::<Result<Vec<Address>, Status>>()?;
        let mut alset = self.allowlist.lock().unwrap();
        for addr in addresses {
            alset.remove(&addr.script_pubkey());
        }
        let wlvec = (*alset).iter().cloned().collect();
        self.persister
            .update_node_allowlist(&self.get_id(), wlvec)
            .map_err(|_| Status::internal("persist failed"))?;
        Ok(())
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}

/// The type of address, for layer-1 input signing
#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(i32)]
pub enum SpendType {
    /// To be signed by someone else
    Invalid = 0,
    /// Pay to public key hash
    P2pkh = 1,
    /// Pay to witness public key hash
    P2wpkh = 3,
    /// Pay to p2sh wrapped p2wpkh
    P2shP2wpkh = 4,
}

impl TryFrom<i32> for SpendType {
    type Error = ();

    fn try_from(i: i32) -> Result<Self, Self::Error> {
        let res = match i {
            x if x == SpendType::Invalid as i32 => SpendType::Invalid,
            x if x == SpendType::P2pkh as i32 => SpendType::P2pkh,
            x if x == SpendType::P2wpkh as i32 => SpendType::P2wpkh,
            x if x == SpendType::P2shP2wpkh as i32 => SpendType::P2shP2wpkh,
            _ => return Err(()),
        };
        Ok(res)
    }
}

/// Marker trait for LDK compatible logger
pub trait SyncLogger: Logger + SendSync {}

#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::sha256d::Hash as Sha256dHash;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1;
    use bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::util::bip143::SigHashCache;
    use bitcoin::{Address, OutPoint, SigHashType};
    use test_env_log::test;

    use crate::channel::ChannelBase;
    use crate::util::status::{internal_error, invalid_argument, Code, Status};
    use crate::util::test_utils::*;

    use super::*;

    #[test]
    fn channel_debug_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let _status: Result<(), Status> = node.with_ready_channel(&channel_id, |chan| {
            assert_eq!(format!("{:?}", chan), "channel");
            Ok(())
        });
    }

    #[test]
    fn node_debug_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        assert_eq!(format!("{:?}", node), "node");
    }

    #[test]
    fn node_invalid_argument_test() {
        let err = invalid_argument("testing invalid_argument");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "testing invalid_argument");
    }

    #[test]
    fn node_internal_error_test() {
        let err = internal_error("testing internal_error");
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "testing internal_error");
    }

    #[test]
    fn new_channel_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);

        let (channel_id, _) = node.new_channel(None, None, &node).unwrap();
        assert!(node.get_channel(&channel_id).is_ok());
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let channel_id = ChannelId([1; 32]);
        assert!(node.get_channel(&channel_id).is_err());
        Ok(())
    }

    #[test]
    fn get_per_commitment_point_and_secret_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let commit_num = 23;

        let (point, secret) = node
            .with_ready_channel(&channel_id, |chan| {
                // The channel next_holder_commit_num must be 2 past the
                // requested commit_num for get_per_commitment_secret.
                chan.enforcement_state
                    .set_next_holder_commit_num_for_testing(commit_num + 2);
                let point = chan.get_per_commitment_point(commit_num)?;
                let secret = chan.get_per_commitment_secret(commit_num)?;
                Ok((point, secret))
            })
            .expect("point");

        let derived_point = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        assert_eq!(point, derived_point);
    }

    #[test]
    fn get_check_future_secret_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let n: u64 = 10;

        let suggested = SecretKey::from_slice(
            hex_decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let correct = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n, &suggested))
            .unwrap();
        assert_eq!(correct, true);

        let notcorrect = node
            .with_channel_base(&channel_id, |base| {
                base.check_future_secret(n + 1, &suggested)
            })
            .unwrap();
        assert_eq!(notcorrect, false);
    }

    #[test]
    fn sign_channel_announcement_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let ann = hex_decode("0123456789abcdef").unwrap();
        let (nsig, bsig) = node
            .with_ready_channel(&channel_id, |chan| Ok(chan.sign_channel_announcement(&ann)))
            .unwrap();

        let ca_hash = Sha256dHash::hash(&ann);
        let encmsg = secp256k1::Message::from_slice(&ca_hash[..]).expect("encmsg");
        let secp_ctx = Secp256k1::new();
        secp_ctx
            .verify(&encmsg, &nsig, &node.get_id())
            .expect("verify nsig");
        let _res: Result<(), Status> = node.with_ready_channel(&channel_id, |chan| {
            let funding_pubkey = PublicKey::from_secret_key(&secp_ctx, &chan.keys.funding_key);
            Ok(secp_ctx
                .verify(&encmsg, &bsig, &funding_pubkey)
                .expect("verify bsig"))
        });
    }

    #[test]
    fn sign_node_announcement_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let ann = hex_decode("000302aaa25e445fef0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b65180265b64c4f554450484f544f2d2e302d3139392d67613237336639642d6d6f646465640000").unwrap();
        let sigvec = node.sign_node_announcement(&ann).unwrap();
        assert_eq!(sigvec, hex_decode("30450221008ef1109b95f127a7deec63b190b72180f0c2692984eaf501c44b6bfc5c4e915502207a6fa2f250c5327694967be95ff42a94a9c3d00b7fa0fbf7daa854ceb872e439").unwrap());
        Ok(())
    }

    #[test]
    fn sign_channel_update_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let cu = hex_decode("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015e42ddc6010000060000000000000000000000010000000a000000003b023380").unwrap();
        let sigvec = node.sign_channel_update(&cu).unwrap();
        assert_eq!(sigvec, hex_decode("3045022100be9840696c868b161aaa997f9fa91a899e921ea06c8083b2e1ea32b8b511948d0220352eec7a74554f97c2aed26950b8538ca7d7d7568b42fd8c6f195bd749763fa5").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt1230n");
        let data_part = hex_decode("010f0418090a010101141917110f01040e050f06100003021e1b0e13161c150301011415060204130c0018190d07070a18070a1c1101111e111f130306000d00120c11121706181b120d051807081a0b0f0d18060004120e140018000105100114000b130b01110c001a05041a181716020007130c091d11170d10100d0b1a1b00030e05190208171e16080d00121a00110719021005000405001000").unwrap();
        let rsig = node
            .sign_invoice_in_parts(&data_part, &human_readable_part)
            .unwrap();
        assert_eq!(rsig, hex_decode("739ffb91aa7c0b3d3c92de1600f7a9afccedc5597977095228232ee4458685531516451b84deb35efad27a311ea99175d10c6cdb458cd27ce2ed104eb6cf806400").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_with_overhang_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt2m");
        let data_part = hex_decode("010f0a001d051e0101140c0c000006140009160c09051a0d1a190708020d17141106171f0f07131616111f1910070b0d0e150c0c0c0d010d1a01181c15100d010009181a06101a0a0309181b040a111a0a06111705100c0b18091909030e151b14060004120e14001800010510011419080f1307000a0a0517021c171410101a1e101605050a08180d0d110e13150409051d02091d181502020f050e1a1f161a09130005000405001000").unwrap();
        // The data_part is 170 bytes.
        // overhang = (data_part.len() * 5) % 8 = 2
        // looking for a verified invoice where overhang is in 1..3
        let rsig = node
            .sign_invoice_in_parts(&data_part, &human_readable_part)
            .unwrap();
        assert_eq!(rsig, hex_decode("f278cdba3fd4a37abf982cee5a66f52e142090631ef57763226f1232eead78b43da7962fcfe29ffae9bd918c588df71d6d7b92a4787de72801594b22f0e7e62a00").unwrap());
        Ok(())
    }

    #[test]
    fn ecdh_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let pointvec =
            hex_decode("0330febba06ba074378dec994669cf5ebf6b15e24a04ec190fb93a9482e841a0ca")
                .unwrap();
        let other_key = PublicKey::from_slice(pointvec.as_slice()).unwrap();

        let ssvec = node.ecdh(&other_key);
        assert_eq!(
            ssvec,
            hex_decode("48db1582f4b42a0068b5727fd37090a65fbf1f9bd842f4393afc2e794719ae47").unwrap()
        );
    }

    #[test]
    fn get_unilateral_close_key_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let channel_nonce = hex_decode(
            "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590100000000000000",
        )
        .unwrap();
        let (channel_id, _) = node.new_channel(None, Some(channel_nonce), &node).unwrap();

        node.ready_channel(channel_id, None, make_test_channel_setup(), &vec![])
            .expect("ready channel");

        let uck = node
            .with_ready_channel(&channel_id, |chan| chan.get_unilateral_close_key(&None))
            .unwrap();

        assert_eq!(
            uck,
            SecretKey::from_slice(
                &hex_decode("d5f8a9fdd0e4be18c33656944b91dc1f6f2c38ce2a4bbd0ef330ffe4e106127c")
                    .unwrap()[..]
            )
            .unwrap()
        );
    }

    #[test]
    fn get_account_ext_pub_key_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let xpub = node.get_account_extended_pubkey();
        assert_eq!(format!("{}", xpub), "tpubDAu312RD7nE6R9qyB4xJk9QAMyi3ppq3UJ4MMUGpB9frr6eNDd8FJVPw27zTVvWAfYFVUtJamgfh5ZLwT23EcymYgLx7MHsU8zZxc9L3GKk");
    }

    #[test]
    fn sign_message_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let message = String::from("Testing 1 2 3").into_bytes();
        let mut rsigvec = node.sign_message(&message).unwrap();
        let rid = rsigvec.pop().unwrap() as i32;
        let rsig =
            RecoverableSignature::from_compact(&rsigvec[..], RecoveryId::from_i32(rid).unwrap())
                .unwrap();
        let secp_ctx = secp256k1::Secp256k1::new();
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = secp256k1::Message::from_slice(&hash[..]).unwrap();
        let sig =
            secp256k1::Signature::from_compact(&rsig.to_standard().serialize_compact()).unwrap();
        let pubkey = secp_ctx.recover(&encmsg, &rsig).unwrap();
        assert!(secp_ctx.verify(&encmsg, &sig, &pubkey).is_ok());
        assert_eq!(
            pubkey.serialize().to_vec(),
            node.get_id().serialize().to_vec()
        );
    }

    // TODO move this elsewhere
    #[test]
    fn transaction_verify_test() {
        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let spending: bitcoin::Transaction = deserialize(hex_decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();
        let spent1: bitcoin::Transaction = deserialize(hex_decode("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .unwrap().as_slice()).unwrap();
        let spent2: bitcoin::Transaction = deserialize(hex_decode("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .unwrap().as_slice()).unwrap();
        let spent3: bitcoin::Transaction = deserialize(hex_decode("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .unwrap().as_slice()).unwrap();

        println!("{:?}", &spending.txid());
        println!("{:?}", &spent1.txid());
        println!("{:?}", &spent2.txid());
        println!("{:?}", &spent3.txid());
        println!("{:?}", &spent1.output[0].script_pubkey);
        println!("{:?}", &spent2.output[0].script_pubkey);
        println!("{:?}", &spent3.output[0].script_pubkey);

        let mut spent = Map::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .unwrap();
    }

    // TODO move this elsewhere
    #[test]
    fn bip143_p2wpkh_test() {
        let tx: bitcoin::Transaction = deserialize(hex_decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
            .unwrap().as_slice()).unwrap();
        let secp_ctx = Secp256k1::signing_only();
        let priv2 = SecretKey::from_slice(
            hex_decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let pub2 = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &priv2).serialize(),
        )
        .unwrap();

        let script_code = Address::p2pkh(&pub2, Network::Testnet).script_pubkey();
        assert_eq!(
            hex_encode(script_code.as_bytes()),
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
        );
        let value = 600_000_000;

        let sighash =
            &SigHashCache::new(&tx).signature_hash(1, &script_code, value, SigHashType::All)[..];
        assert_eq!(
            hex_encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    fn vecs_match<T: PartialEq + std::cmp::Ord>(mut a: Vec<T>, mut b: Vec<T>) -> bool {
        a.sort();
        b.sort();
        let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
        matching == a.len() && matching == b.len()
    }

    #[test]
    fn node_allowlist_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);

        // initial allowlist should be empty
        assert!(node.allowlist().expect("allowlist").len() == 0);

        // can insert some entries
        let adds0 = vec![
            "mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB",
            "2N6i2gfgTonx88yvYm32PRhnHxqxtEfocbt",
            "tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z",
            "tb1qycu764qwuvhn7u0enpg0x8gwumyuw565f3mspnn58rsgar5hkjmqtjegrh",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_status_ok!(node.add_allowlist(&adds0));

        // now allowlist should have the added entries
        assert!(vecs_match(
            node.allowlist().expect("allowlist").clone(),
            adds0.clone()
        ));

        // adding duplicates shouldn't change the node allowlist
        assert_status_ok!(node.add_allowlist(&adds0));
        assert!(vecs_match(
            node.allowlist().expect("allowlist").clone(),
            adds0.clone()
        ));

        // can remove some elements from the allowlist
        let removes0 = vec![adds0[0].clone(), adds0[3].clone()];
        assert_status_ok!(node.remove_allowlist(&removes0));
        assert!(vecs_match(
            node.allowlist().expect("allowlist").clone(),
            vec![adds0[1].clone(), adds0[2].clone()]
        ));

        // can't add bogus addresses
        assert_invalid_argument_err!(
            node.add_allowlist(&vec!["1234567890".to_string()]),
            "parse address 1234567890 failed: base58: invalid base58 character 0x30"
        );

        // can't add w/ wrong network
        assert_invalid_argument_err!(
            node.add_allowlist(&vec!["1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp".to_string()]),
            "network mismatch for addr 1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp: addr=bitcoin, node=testnet"
        );

        // can't remove w/ wrong network
        assert_invalid_argument_err!(
            node.remove_allowlist(&vec!["1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp".to_string()]),
            "network mismatch for addr 1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp: addr=bitcoin, node=testnet"
        );
    }
}
