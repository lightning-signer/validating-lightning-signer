use core::borrow::Borrow;
use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::{self, Debug, Formatter};
use core::iter::FromIterator;
use core::str::FromStr;
use core::time::Duration;

use bitcoin;
use bitcoin::bech32::{u5, FromBase32};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{schnorr, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::util::key::XOnlyPublicKey;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{secp256k1, Address, PrivateKey, Transaction, TxOut};
use bitcoin::{EcdsaSighashType, Network, OutPoint, Script};
use lightning::chain;
use lightning::chain::keysinterface::{
    BaseSign, KeyMaterial, KeysInterface, Recipient, SpendableOutputDescriptor,
};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, CounterpartyChannelTransactionParameters,
};
use lightning::ln::script::ShutdownScript;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::util::invoice::construct_invoice_preimage;
use lightning::util::logger::Logger;
use lightning_invoice::{Invoice, RawDataPart, RawHrp, RawInvoice, SignedRawInvoice};

#[allow(unused_imports)]
use log::{debug, info, trace, warn};

use crate::chain::tracker::ChainTracker;
use crate::channel::{
    Channel, ChannelBalance, ChannelBase, ChannelId, ChannelSetup, ChannelSlot, ChannelStub,
};
use crate::monitor::ChainMonitor;
use crate::persist::model::NodeEntry;
use crate::persist::Persist;
use crate::policy::error::{policy_error, unbalanced_error, ValidationError};
use crate::policy::validator::{BalanceDelta, ValidatorFactory};
use crate::policy::validator::{EnforcementState, Validator};
use crate::policy::Policy;
use crate::prelude::*;
use crate::signer::derive::KeyDerivationStyle;
use crate::signer::my_keys_manager::MyKeysManager;
use crate::signer::StartingTimeFactory;
use crate::sync::{Arc, Weak};
use crate::tx::tx::PreimageMap;
use crate::util::clock::Clock;
use crate::util::crypto_utils::signature_to_bitcoin_vec;
use crate::util::status::{failed_precondition, internal_error, invalid_argument, Status};
use crate::util::velocity::VelocityControl;
use crate::wallet::Wallet;

/// Node configuration parameters.

#[derive(Copy, Clone, Debug)]
pub struct NodeConfig {
    /// The network type
    pub network: Network,
    /// The derivation style to use when deriving purpose-specific keys
    pub key_derivation_style: KeyDerivationStyle,
}

/// Invoice payment details and payment state
#[derive(Clone)]
pub struct InvoiceState {
    /// The hash of the invoice, as a unique ID
    pub invoice_hash: [u8; 32],
    /// Invoiced amount
    pub amount_msat: u64,
    /// Payee's public key
    pub payee: PublicKey,
    /// Timestamp of invoice, as duration since the UNIX epoch
    pub duration_since_epoch: Duration,
    /// Expiry, as duration since the timestamp
    pub expiry_duration: Duration,
    /// Whether the invoice was fulfilled
    /// note: for issued invoices only
    pub is_fulfilled: bool,
}

/// Keeps track of incoming and outgoing HTLCs for a routed payment
#[derive(Clone)]
pub struct RoutedPayment {
    /// Incoming payments per channel in satoshi
    pub incoming: OrderedMap<ChannelId, u64>,
    /// Outgoing payments per channel in satoshi
    pub outgoing: OrderedMap<ChannelId, u64>,
    /// The preimage for the hash, filled in on success
    pub preimage: Option<PaymentPreimage>,
}

impl RoutedPayment {
    /// Create an empty routed payment
    pub fn new() -> RoutedPayment {
        RoutedPayment { incoming: OrderedMap::new(), outgoing: OrderedMap::new(), preimage: None }
    }

    /// Whether we know the preimage, and therefore the incoming is claimable
    pub fn is_fulfilled(&self) -> bool {
        self.preimage.is_some()
    }

    /// The total incoming and outgoing, if this channel updates to the specified values
    pub fn updated_incoming_outgoing(
        &self,
        channel_id: &ChannelId,
        incoming_amount: u64,
        outgoing_amount: u64,
    ) -> (u64, u64) {
        // TODO this can be optimized to eliminate the clone
        let mut incoming = self.incoming.clone();
        incoming.insert(channel_id.clone(), incoming_amount);
        let mut outgoing = self.outgoing.clone();
        outgoing.insert(channel_id.clone(), outgoing_amount);
        (incoming.values().into_iter().sum::<u64>(), outgoing.values().into_iter().sum::<u64>())
    }

    /// The total incoming and outgoing
    pub fn incoming_outgoing(&self) -> (u64, u64) {
        (
            self.incoming.values().into_iter().sum::<u64>(),
            self.outgoing.values().into_iter().sum::<u64>(),
        )
    }

    /// Apply incoming and outgoing payment for a channel, in satoshi
    pub fn apply(&mut self, channel_id: &ChannelId, incoming_amount: u64, outgoing_amount: u64) {
        self.incoming.insert(channel_id.clone(), incoming_amount);
        self.outgoing.insert(channel_id.clone(), outgoing_amount);
    }
}

/// Enforcement state for a node
// TODO move allowlist into this struct
pub struct NodeState {
    /// Added invoices for outgoing payments indexed by their payment hash
    pub invoices: Map<PaymentHash, InvoiceState>,
    /// Issued invoices for incoming payments indexed by their payment hash
    pub issued_invoices: Map<PaymentHash, InvoiceState>,
    /// Payment states
    pub payments: Map<PaymentHash, RoutedPayment>,
    /// Accumulator of excess payment amount in satoshi, for tracking certain
    /// payment corner cases.
    /// If this falls below zero, the attempted commit is failed.
    // TODO fee accumulation adjustment
    // As we accumulate routing fees, this value grows without bounds.  We should
    // take accumulated fees out over time to keep this bounded.
    pub excess_amount: u64,
    /// Prefix for emitted logs lines
    pub log_prefix: String,
    /// Per node velocity control
    pub velocity_control: VelocityControl,
}

impl PreimageMap for NodeState {
    fn has_preimage(&self, hash: &PaymentHash) -> bool {
        self.payments.get(hash).map(|p| p.preimage.is_some()).unwrap_or(false)
    }
}

impl NodeState {
    /// Create a state
    pub fn new(velocity_control: VelocityControl) -> Self {
        NodeState {
            invoices: Map::new(),
            issued_invoices: Map::new(),
            payments: Map::new(),
            excess_amount: 0,
            log_prefix: String::new(),
            velocity_control,
        }
    }

    fn with_log_prefix(self, velocity_control: VelocityControl, log_prefix: String) -> Self {
        NodeState {
            invoices: self.invoices,
            issued_invoices: self.issued_invoices,
            payments: self.payments,
            excess_amount: self.excess_amount,
            log_prefix,
            velocity_control,
        }
    }

    #[cfg(test)]
    pub(crate) fn validate_and_apply_payments(
        &mut self,
        channel_id: &ChannelId,
        incoming_payment_summary: &Map<PaymentHash, u64>,
        outgoing_payment_summary: &Map<PaymentHash, u64>,
        balance_delta: &BalanceDelta,
        validator: Arc<dyn Validator>,
    ) -> Result<(), ValidationError> {
        self.validate_payments(
            channel_id,
            incoming_payment_summary,
            outgoing_payment_summary,
            balance_delta,
            validator.clone(),
        )?;
        self.apply_payments(
            channel_id,
            incoming_payment_summary,
            outgoing_payment_summary,
            balance_delta,
            validator.clone(),
        );
        Ok(())
    }
    /// Validate outgoing in-flight payment amounts as a result of a new commitment tx.
    ///
    /// The following policies are checked:
    /// - no overpayment for any invoice.
    /// - Sends without invoices (e.g. keysend) are only allowed if
    /// `policy.require_invoices` is false.
    pub fn validate_payments(
        &self,
        channel_id: &ChannelId,
        incoming_payment_summary: &Map<PaymentHash, u64>,
        outgoing_payment_summary: &Map<PaymentHash, u64>,
        balance_delta: &BalanceDelta,
        validator: Arc<dyn Validator>,
    ) -> Result<(), ValidationError> {
        debug!(
            "validating payments on channel {} - in {:?} out {:?}",
            channel_id, incoming_payment_summary, outgoing_payment_summary
        );

        let mut hashes: UnorderedSet<&PaymentHash> = UnorderedSet::new();
        hashes.extend(incoming_payment_summary.keys());
        hashes.extend(outgoing_payment_summary.keys());

        let mut unbalanced = Vec::new();

        // Preflight check
        for hash_r in hashes.iter() {
            let incoming_for_chan = incoming_payment_summary.get(hash_r).map(|a| *a).unwrap_or(0);
            let outgoing_for_chan = outgoing_payment_summary.get(hash_r).map(|a| *a).unwrap_or(0);
            let hash = **hash_r;
            let payment = self.payments.get(&hash);
            let (incoming, outgoing) = if let Some(p) = payment {
                p.updated_incoming_outgoing(channel_id, incoming_for_chan, outgoing_for_chan)
            } else {
                (incoming_for_chan, outgoing_for_chan)
            };
            let invoiced_amount = self.invoices.get(&hash).map(|i| i.amount_msat);
            if validator.validate_payment_balance(incoming, outgoing, invoiced_amount).is_err() {
                unbalanced.push(hash);
            }
        }

        if !unbalanced.is_empty() {
            return Err(unbalanced_error(unbalanced));
        }

        if validator.enforce_balance() {
            info!(
                "{} validate payments adjust excess {} +{} -{}",
                self.log_prefix, self.excess_amount, balance_delta.1, balance_delta.0
            );
            self.excess_amount
                .checked_add(balance_delta.1)
                .expect("overflow")
                .checked_sub(balance_delta.0)
                .ok_or_else(|| {
                    // policy-routing-deltas-only-htlc
                    policy_error(format!(
                        "shortfall {} + {} - {}",
                        self.excess_amount, balance_delta.1, balance_delta.0
                    ))
                })?;
        }
        Ok(())
    }

    /// Apply outgoing in-flight payment amounts as a result of a new commitment tx.
    /// Must call [`validate_payments`] first.
    pub fn apply_payments(
        &mut self,
        channel_id: &ChannelId,
        incoming_payment_summary: &Map<PaymentHash, u64>,
        outgoing_payment_summary: &Map<PaymentHash, u64>,
        balance_delta: &BalanceDelta,
        validator: Arc<dyn Validator>,
    ) {
        debug!("applying payments on channel {}", channel_id);

        let mut hashes: UnorderedSet<&PaymentHash> = UnorderedSet::new();
        hashes.extend(incoming_payment_summary.keys());
        hashes.extend(outgoing_payment_summary.keys());

        let mut fulfilled_issued_invoices = Vec::new();

        // Preflight check
        for hash_r in hashes.iter() {
            let hash = **hash_r;
            let payment = self.payments.entry(hash).or_insert_with(|| RoutedPayment::new());
            if let Some(issued) = self.issued_invoices.get(&hash) {
                if !payment.is_fulfilled() {
                    let incoming_for_chan =
                        incoming_payment_summary.get(hash_r).map(|a| *a).unwrap_or(0);
                    let outgoing_for_chan =
                        outgoing_payment_summary.get(hash_r).map(|a| *a).unwrap_or(0);
                    let (incoming, outgoing) = payment.updated_incoming_outgoing(
                        channel_id,
                        incoming_for_chan,
                        outgoing_for_chan,
                    );
                    if incoming >= outgoing + issued.amount_msat / 1000 {
                        fulfilled_issued_invoices.push(hash);
                    }
                }
            }
        }

        if validator.enforce_balance() {
            info!(
                "{} apply payments adjust excess {} +{} -{}",
                self.log_prefix, self.excess_amount, balance_delta.1, balance_delta.0
            );
            let excess_amount = self
                .excess_amount
                .checked_add(balance_delta.1)
                .expect("overflow")
                .checked_sub(balance_delta.0)
                .expect("validation didn't catch underflow");
            for hash in fulfilled_issued_invoices.iter() {
                debug!("mark issued invoice {} as fulfilled", hash.0.to_hex());
                let payment = self.payments.get_mut(&hash).expect("already checked");
                // Mark as fulfilled by setting a dummy preimage.
                // This has the side-effect of the payment amount not being added
                // to the excess_amount, because we set the preimage after the balance
                // delta has already been calculated.
                payment.preimage = Some(PaymentPreimage([0; 32]));
            }
            self.excess_amount = excess_amount;
        }

        debug!(
            "applying incoming payments from channel {} - {:?}",
            channel_id, incoming_payment_summary
        );

        for hash in hashes.iter() {
            let incoming = incoming_payment_summary.get(hash).map(|a| *a).unwrap_or(0);
            let outgoing = outgoing_payment_summary.get(hash).map(|a| *a).unwrap_or(0);
            let payment = self.payments.get_mut(hash).expect("created above");
            payment.apply(channel_id, incoming, outgoing);
        }
    }

    /// Fulfills an HTLC.
    /// Performs bookkeeping on any invoice or routed payment with this payment hash.
    pub fn htlc_fulfilled(
        &mut self,
        channel_id: &ChannelId,
        preimage: PaymentPreimage,
        validator: Arc<dyn Validator>,
    ) {
        let payment_hash = PaymentHash(Sha256Hash::hash(&preimage.0).into_inner());

        if let Some(payment) = self.payments.get_mut(&payment_hash) {
            // Getting an HTLC preimage moves HTLC values to the virtual balance of the recipient
            // on both input and output.
            // We gain the difference between the input and the output amounts,
            // so record that in the excess_amount register.
            // However, when we pay an invoice, the excess_amount is not
            // updated.
            if payment.preimage.is_some() {
                info!(
                    "{} duplicate preimage {} on channel {}",
                    self.log_prefix,
                    payment_hash.0.to_hex(),
                    channel_id
                );
            } else {
                let (incoming, outgoing) = payment.incoming_outgoing();
                if self.invoices.contains_key(&payment_hash) {
                    if incoming > 0 {
                        info!(
                            "{} preimage invoice+routing {} +{} -{} msat",
                            self.log_prefix,
                            payment_hash.0.to_hex(),
                            incoming,
                            outgoing
                        )
                    } else {
                        info!(
                            "{} preimage invoice {} -{} msat",
                            self.log_prefix,
                            payment_hash.0.to_hex(),
                            outgoing
                        )
                    }
                } else {
                    info!(
                        "{} preimage routing {} adjust excess {} +{} -{} msat",
                        self.log_prefix,
                        payment_hash.0.to_hex(),
                        self.excess_amount,
                        incoming,
                        outgoing
                    );
                    if validator.enforce_balance() {
                        self.excess_amount =
                            self.excess_amount.checked_add(incoming).expect("overflow");
                        // TODO convert to checked error
                        self.excess_amount =
                            self.excess_amount.checked_sub(outgoing).expect("underflow");
                    }
                }
                payment.preimage = Some(preimage);
            }
        }
    }
}

/// Allowlist entry
#[derive(Eq, PartialEq, Hash, Clone)]
pub enum Allowable {
    /// A layer-1 destination
    Script(Script),
    /// A layer-2 payee (node_id)
    Payee(PublicKey),
}

/// Convert to String for a specified Bitcoin network type
pub trait ToStringForNetwork {
    /// Convert to String for a specified Bitcoin network type
    fn to_string(&self, network: Network) -> String;
}

impl ToStringForNetwork for Allowable {
    fn to_string(&self, network: Network) -> String {
        match self {
            Allowable::Script(script) => {
                let addr_res = Address::from_script(&script, network);
                addr_res
                    .map(|a| format!("address:{}", a.to_string()))
                    .unwrap_or_else(|_| format!("invalid_script:{}", script.to_hex()))
            }
            Allowable::Payee(pubkey) => format!("payee:{}", pubkey.to_hex()),
        }
    }
}

impl Allowable {
    /// Convert from string, while checking that the network matches
    pub fn from_str(s: &str, network: Network) -> Result<Allowable, String> {
        let mut splits = s.splitn(2, ":");
        let prefix = splits.next().expect("failed to parse Allowable");
        if let Some(body) = splits.next() {
            if prefix == "address" {
                let address = Address::from_str(body).map_err(|_| s.to_string())?;
                if address.network != network {
                    return Err(format!("{}: expected network {}", s, network));
                }
                Ok(Allowable::Script(address.script_pubkey()))
            } else if prefix == "payee" {
                let pubkey = PublicKey::from_str(body).map_err(|_| s.to_string())?;
                Ok(Allowable::Payee(pubkey))
            } else {
                Err(s.to_string())
            }
        } else {
            let address = Address::from_str(prefix).map_err(|_| s.to_string())?;
            if address.network != network {
                return Err(format!("{}: expected network {}", s, network));
            }
            Ok(Allowable::Script(address.script_pubkey()))
        }
    }
}

/// A signer for one Lightning node.
///
/// ```rust
/// use std::sync::Arc;
///
/// use lightning_signer::channel::{ChannelSlot, ChannelBase};
/// use lightning_signer::node::{Node, NodeConfig, NodeServices, SyncLogger};
/// use lightning_signer::persist::{DummyPersister, Persist};
/// use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
/// use lightning_signer::signer::ClockStartingTimeFactory;
/// use lightning_signer::util::clock::StandardClock;
/// use lightning_signer::util::test_logger::TestLogger;
/// use lightning_signer::util::test_utils::TEST_NODE_CONFIG;
///
/// let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
/// let seed = [0; 32];
/// let config = TEST_NODE_CONFIG;
/// let validator_factory = Arc::new(SimpleValidatorFactory::new());
/// let starting_time_factory = ClockStartingTimeFactory::new();
/// let clock = Arc::new(StandardClock());
/// let services = NodeServices {
///     validator_factory,
///     starting_time_factory,
///     persister,
///     clock,
/// };
/// let node = Arc::new(Node::new(config, &seed, vec![], services));
/// let (channel_id, opt_stub) = node.new_channel(None, &node).expect("new channel");
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
    channels: Mutex<OrderedMap<ChannelId, Arc<Mutex<ChannelSlot>>>>,
    // This is Mutex because we want to be able to replace it on the fly
    pub(crate) validator_factory: Mutex<Arc<dyn ValidatorFactory>>,
    pub(crate) persister: Arc<dyn Persist>,
    pub(crate) clock: Arc<dyn Clock>,
    allowlist: Mutex<UnorderedSet<Allowable>>,
    tracker: Mutex<ChainTracker<ChainMonitor>>,
    pub(crate) state: Mutex<NodeState>,
    node_id: PublicKey,
}

/// Various services the Node uses
#[derive(Clone)]
pub struct NodeServices {
    /// The validator factory
    pub validator_factory: Arc<dyn ValidatorFactory>,
    /// The starting time factory
    pub starting_time_factory: Arc<dyn StartingTimeFactory>,
    /// The persister
    pub persister: Arc<dyn Persist>,
    /// Clock source
    pub clock: Arc<dyn Clock>,
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

    fn get_native_address(&self, child_path: &Vec<u32>) -> Result<Address, Status> {
        if child_path.len() == 0 {
            return Err(invalid_argument("empty child path"));
        }

        let secp_ctx = Secp256k1::signing_only();
        let pubkey = self.get_wallet_pubkey(&secp_ctx, child_path)?;
        Ok(Address::p2wpkh(&pubkey, self.network()).expect("p2wpkh failed"))
    }

    fn get_wrapped_address(&self, child_path: &Vec<u32>) -> Result<Address, Status> {
        if child_path.len() == 0 {
            return Err(invalid_argument("empty child path"));
        }

        let secp_ctx = Secp256k1::signing_only();
        let pubkey = self.get_wallet_pubkey(&secp_ctx, child_path)?;
        Ok(Address::p2shwpkh(&pubkey, self.network()).expect("p2wpkh failed"))
    }

    /// Returns true if script_pubkey is in the node's allowlist.
    fn allowlist_contains(&self, script_pubkey: &Script) -> bool {
        self.allowlist.lock().unwrap().contains(&Allowable::Script(script_pubkey.clone()))
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
        allowlist: Vec<Allowable>,
        services: NodeServices,
    ) -> Node {
        let tracker = Self::make_tracker(node_config);

        Self::new_extended(node_config, seed, allowlist, tracker, services)
    }

    pub(crate) fn make_tracker(node_config: NodeConfig) -> ChainTracker<ChainMonitor> {
        info!("creating node on {}", node_config.network);
        let genesis = genesis_block(node_config.network);

        // TODO supply current tip
        ChainTracker::new(node_config.network, 0, genesis.header).expect("bad  chain tip")
    }

    /// Create a node
    ///
    /// NOTE: you must persist the node yourself if it is new.
    pub fn new_extended(
        node_config: NodeConfig,
        seed: &[u8],
        allowlist: Vec<Allowable>,
        tracker: ChainTracker<ChainMonitor>,
        services: NodeServices,
    ) -> Node {
        let policy = services.validator_factory.policy(node_config.network);
        let global_velocity_control = Self::make_velocity_control(policy);
        let state = NodeState::new(global_velocity_control);
        Self::new_from_persistence(node_config, seed, allowlist, tracker, services, state)
    }

    /// Restore a node.
    pub fn new_from_persistence(
        node_config: NodeConfig,
        seed: &[u8],
        allowlist: Vec<Allowable>,
        tracker: ChainTracker<ChainMonitor>,
        services: NodeServices,
        state: NodeState,
    ) -> Node {
        let keys_manager = MyKeysManager::new(
            node_config.key_derivation_style,
            seed,
            node_config.network,
            services.starting_time_factory.borrow(),
        );
        let node_id = Self::id_from_key(&keys_manager.get_node_secret(Recipient::Node).unwrap());
        let log_prefix = &node_id.to_hex()[0..4];

        let persister = services.persister;
        let clock = services.clock;
        let validator_factory = services.validator_factory;
        let policy = validator_factory.policy(node_config.network);
        let global_velocity_control = Self::make_velocity_control(policy);

        let state =
            Mutex::new(state.with_log_prefix(global_velocity_control, log_prefix.to_string()));

        Node {
            keys_manager,
            node_config,
            channels: Mutex::new(OrderedMap::new()),
            validator_factory: Mutex::new(validator_factory),
            persister,
            clock,
            allowlist: Mutex::new(UnorderedSet::from_iter(allowlist)),
            tracker: Mutex::new(tracker),
            state,
            node_id,
        }
    }

    /// persister
    pub fn get_persister(&self) -> Arc<dyn Persist> {
        Arc::clone(&self.persister)
    }

    /// onion reply secret
    pub fn get_onion_reply_secret(&self) -> [u8; 32] {
        self.keys_manager.get_onion_reply_secret()
    }

    /// BOLT 12 x-only pubkey
    pub fn get_bolt12_pubkey(&self) -> XOnlyPublicKey {
        self.keys_manager.get_bolt12_pubkey()
    }

    /// BOLT 12 sign
    pub fn sign_bolt12(
        &self,
        messagename: &[u8],
        fieldname: &[u8],
        merkleroot: &[u8; 32],
        publictweak_opt: Option<&[u8]>,
    ) -> Result<schnorr::Signature, Status> {
        self.keys_manager
            .sign_bolt12(messagename, fieldname, merkleroot, publictweak_opt)
            .map_err(|_| internal_error("signature operation failed"))
    }

    /// derive secret
    pub fn derive_secret(&self, info: &[u8]) -> SecretKey {
        self.keys_manager.derive_secret(info)
    }

    /// Set the node's validator factory
    pub fn set_validator_factory(&self, validator_factory: Arc<dyn ValidatorFactory>) {
        let mut vfac = self.validator_factory.lock().unwrap();
        *vfac = validator_factory;
    }

    /// Get the node ID, which is the same as the node public key
    pub fn get_id(&self) -> PublicKey {
        self.node_id
    }

    fn id_from_key(key: &SecretKey) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp_ctx, key)
    }

    /// Get suitable node identity string for logging
    pub fn log_prefix(&self) -> String {
        self.get_id().to_hex()[0..4].to_string()
    }

    /// Lock and return the node state
    pub fn get_state(&self) -> MutexGuard<NodeState> {
        self.state.lock().unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.keys_manager.get_secure_random_bytes()
    }

    /// Get secret key material as bytes for use in encrypting and decrypting inbound payment data.
    ///
    /// This method must return the same value each time it is called.
    pub fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.keys_manager.get_inbound_payment_key_material()
    }

    /// Get the [Mutex] protected channel slot
    pub fn get_channel(&self, channel_id: &ChannelId) -> Result<Arc<Mutex<ChannelSlot>>, Status> {
        let mut guard = self.channels();
        let elem = guard.get_mut(channel_id);
        let slot_arc = elem.ok_or_else(|| invalid_argument("no such channel"))?;
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
            ChannelSlot::Stub(_) =>
                Err(invalid_argument(format!("channel not ready: {}", &channel_id))),
            ChannelSlot::Ready(chan) => f(chan),
        }
    }

    /// Get a channel given its funding outpoint, or None if no such channel exists.
    pub fn find_channel_with_funding_outpoint(
        &self,
        outpoint: &OutPoint,
    ) -> Option<Arc<Mutex<ChannelSlot>>> {
        let channels_lock = self.channels.lock().unwrap();
        find_channel_with_funding_outpoint(&channels_lock, outpoint)
    }

    /// Create a new channel, which starts out as a stub.
    ///
    /// The initial channel ID may be specified in `opt_channel_id`.  If the channel
    /// with this ID already exists, the existing stub is returned.
    ///
    /// If unspecified, a channel ID will be generated.
    ///
    /// This function will return an invalid_argument [Status] if there is
    /// an existing channel with this ID and it's not a stub channel.
    ///
    /// Returns the channel ID and the stub.
    pub fn new_channel(
        &self,
        opt_channel_id: Option<ChannelId>,
        arc_self: &Arc<Node>,
    ) -> Result<(ChannelId, Option<ChannelStub>), Status> {
        let channel_id = opt_channel_id.unwrap_or_else(|| self.keys_manager.get_channel_id());
        let mut channels = self.channels.lock().unwrap();

        // Is there an existing channel slot?
        let maybe_slot = channels.get(&channel_id);
        if maybe_slot.is_some() {
            match &*maybe_slot.unwrap().lock().unwrap() {
                ChannelSlot::Stub(stub) => {
                    // This stub is "embryonic" (hasn't signed a commitment).  This
                    // can happen if the initial channel create to this peer failed
                    // in negotiation.  It's ok to just use this stub.
                    return Ok((channel_id, Some(stub.clone())));
                }
                ChannelSlot::Ready(_) => {
                    // Calling new_channel on a channel that's already been marked
                    // ready is not allowed.
                    return Err(invalid_argument(format!("channel already ready: {}", channel_id)));
                }
            };
        }

        let channel_value_sat = 0; // Placeholder value, not known yet.
        let keys =
            self.keys_manager.get_channel_keys_with_id(channel_id.clone(), channel_value_sat);

        let stub = ChannelStub {
            node: Arc::downgrade(arc_self),
            secp_ctx: Secp256k1::new(),
            keys,
            id0: channel_id.clone(),
        };
        // TODO this clone is expensive
        channels.insert(channel_id.clone(), Arc::new(Mutex::new(ChannelSlot::Stub(stub.clone()))));
        self.persister
            .new_channel(&self.get_id(), &stub)
            // Persist.new_channel should only fail if the channel was previously persisted.
            // So if it did fail, we have an internal error.
            .expect("channel was in storage but not in memory");
        Ok((channel_id.clone(), Some(stub)))
    }

    pub(crate) fn restore_channel(
        &self,
        channel_id0: ChannelId,
        channel_id: Option<ChannelId>,
        channel_value_sat: u64,
        channel_setup: Option<ChannelSetup>,
        enforcement_state: EnforcementState,
        arc_self: &Arc<Node>,
    ) -> Result<Arc<Mutex<ChannelSlot>>, ()> {
        let mut channels = self.channels.lock().unwrap();
        assert!(!channels.contains_key(&channel_id0));
        let mut keys =
            self.keys_manager.get_channel_keys_with_id(channel_id0.clone(), channel_value_sat);

        let slot = match channel_setup {
            None => {
                let stub = ChannelStub {
                    node: Arc::downgrade(arc_self),
                    secp_ctx: Secp256k1::new(),
                    keys,
                    id0: channel_id0.clone(),
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
                let funding_outpoint = setup.funding_outpoint;
                // FIXME correct persistence
                let monitor = ChainMonitor::new(funding_outpoint, 0);
                let channel = Channel {
                    node: Arc::downgrade(arc_self),
                    secp_ctx: Secp256k1::new(),
                    keys,
                    enforcement_state,
                    setup,
                    id0: channel_id0.clone(),
                    id: channel_id.clone(),
                    monitor,
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
        services: NodeServices,
    ) -> Arc<Node> {
        let network = Network::from_str(node_entry.network.as_str()).expect("bad network");
        let config = NodeConfig {
            network,
            key_derivation_style: KeyDerivationStyle::try_from(node_entry.key_derivation_style)
                .unwrap(),
        };

        let allowlist = persister
            .get_node_allowlist(node_id)
            .iter()
            .map(|e| Allowable::from_str(e, network))
            .collect::<Result<_, _>>()
            .expect("allowable parse error");
        let tracker = persister.get_tracker(node_id).expect("tracker");

        // FIXME persist node state
        let policy = services.validator_factory.policy(network);
        let global_velocity_control = Self::make_velocity_control(policy);
        let state = NodeState::new(global_velocity_control);

        let node = Arc::new(Node::new_from_persistence(
            config,
            node_entry.seed.as_slice().try_into().expect("seed wrong length"),
            allowlist,
            tracker,
            services,
            state,
        ));
        assert_eq!(&node.get_id(), node_id);
        info!("Restore node {} on {}", node_id, config.network);
        for (channel_id0, channel_entry) in persister.get_node_channels(node_id) {
            info!("  Restore channel {}", channel_id0);
            node.restore_channel(
                channel_id0,
                channel_entry.id,
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
    pub fn restore_nodes(services: NodeServices) -> Map<PublicKey, Arc<Node>> {
        let mut nodes = Map::new();
        let persister = services.persister.clone();
        for (node_id, node_entry) in persister.get_nodes() {
            let node =
                Node::restore_node(&node_id, node_entry, Arc::clone(&persister), services.clone());
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
        let mut tracker = self.tracker.lock().unwrap();
        let validator = self.validator_factory.lock().unwrap().make_validator(
            self.network(),
            self.get_id(),
            Some(channel_id0.clone()),
        );

        let chan = {
            let channels = self.channels.lock().unwrap();
            let arcobj = channels.get(&channel_id0).ok_or_else(|| {
                invalid_argument(format!("channel does not exist: {}", channel_id0))
            })?;
            let slot = arcobj.lock().unwrap();
            let stub = match &*slot {
                ChannelSlot::Stub(stub) => Ok(stub),
                ChannelSlot::Ready(_) =>
                    Err(invalid_argument(format!("channel already ready: {}", channel_id0))),
            }?;
            let mut keys = stub.channel_keys_with_channel_value(setup.channel_value_sat);
            let holder_pubkeys = keys.pubkeys();
            let channel_transaction_parameters =
                Node::channel_setup_to_channel_transaction_parameters(&setup, holder_pubkeys);
            keys.ready_channel(&channel_transaction_parameters);
            let funding_outpoint = setup.funding_outpoint;
            let monitor = ChainMonitor::new(funding_outpoint, tracker.height());
            monitor.add_funding_outpoint(&funding_outpoint);
            let to_holder_msat = if setup.is_outbound {
                // This is also checked in the validator, but we have to check
                // here because we need it to create the validator
                (setup.channel_value_sat * 1000).checked_sub(setup.push_value_msat).ok_or_else(
                    || {
                        policy_error(format!(
                            "beneficial channel value underflow: {} - {}",
                            setup.channel_value_sat * 1000,
                            setup.push_value_msat
                        ))
                    },
                )?
            } else {
                setup.push_value_msat
            };
            let initial_holder_value_sat = validator.minimum_initial_balance(to_holder_msat);
            let enforcement_state = EnforcementState::new(initial_holder_value_sat);
            Channel {
                node: Weak::clone(&stub.node),
                secp_ctx: stub.secp_ctx.clone(),
                keys,
                enforcement_state,
                setup: setup.clone(),
                id0: channel_id0.clone(),
                id: opt_channel_id.clone(),
                monitor,
            }
        };

        validator.validate_ready_channel(self, &setup, holder_shutdown_key_path)?;

        let mut channels = self.channels.lock().unwrap();

        // Wrap the ready channel with an arc so we can potentially
        // refer to it multiple times.
        // TODO this clone is expensive
        let chan_arc = Arc::new(Mutex::new(ChannelSlot::Ready(chan.clone())));

        // If a permanent channel_id was provided use it, otherwise
        // continue with the initial channel_id0.
        let chan_id = opt_channel_id.unwrap_or(channel_id0.clone());

        // Associate the new ready channel with the channel id.
        channels.insert(chan_id.clone(), chan_arc.clone());

        // If we are using a new permanent channel_id additionally
        // associate the channel with the original (initial)
        // channel_id as well.
        if channel_id0 != chan_id {
            channels.insert(channel_id0, chan_arc.clone());
        }

        // Watch the funding outpoint, because we might not have any funding
        // inputs that are ours.
        // Note that the functional tests also have no inputs for the funder's tx
        // which might be a problem in the future with more validation.
        tracker.add_listener(
            chan.monitor.clone(),
            OrderedSet::from_iter(vec![setup.funding_outpoint.txid]),
        );

        debug_vals!(&chan.setup);
        trace_enforcement_state!(&chan.enforcement_state);
        self.persister
            .update_tracker(&self.get_id(), &tracker)
            .map_err(|_| internal_error("tracker persist failed"))?;
        self.persister
            .update_channel(&self.get_id(), &chan)
            .map_err(|_| internal_error("persist failed"))?;

        Ok(chan)
    }

    /// Sign an onchain transaction (funding tx or simple sweeps).
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
    ///   The second item in the tuple is the witness stack suffix - zero or more
    ///   script parameters and the redeemscript.
    /// * `opaths` - derivation path for change, one per output.  Empty for
    ///   non-change outputs.
    pub fn sign_onchain_tx(
        &self,
        tx: &bitcoin::Transaction,
        ipaths: &Vec<Vec<u32>>,
        values_sat: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: Vec<Option<(SecretKey, Vec<Vec<u8>>)>>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Vec<Vec<Vec<u8>>>, Status> {
        let channels_lock = self.channels.lock().unwrap();
        let secp_ctx = Secp256k1::signing_only();

        // Funding transactions cannot be associated with just a single channel;
        // a single transaction may fund multiple channels

        let validator = self.validator_factory.lock().unwrap().make_validator(
            self.network(),
            self.get_id(),
            None,
        );

        let txid = tx.txid();
        debug!("{}: txid: {}", short_function!(), txid);

        let channels: Vec<Option<Arc<Mutex<ChannelSlot>>>> = (0..tx.output.len())
            .map(|ndx| {
                let outpoint = OutPoint { txid, vout: ndx as u32 };
                find_channel_with_funding_outpoint(&channels_lock, &outpoint)
            })
            .collect();

        // Compute a lower bound for the tx weight for feerate checking.
        // TODO(dual-funding) - This estimate does not include witnesses for inputs we don't sign.
        let mut weight_lower_bound = tx.weight();
        for (idx, uck) in uniclosekeys.iter().enumerate() {
            if spendtypes[idx] == SpendType::Invalid {
                weight_lower_bound += 0;
            } else {
                let wit_len = match uck {
                    // length-byte + witness-element
                    Some((_key, stack)) => stack.iter().map(|v| 1 + v.len()).sum(),
                    None => 33,
                };
                // witness-header + element-count + length + sig + len + redeemscript
                weight_lower_bound += 2 + 1 + 1 + 72 + 1 + wit_len;
            }
        }
        debug!("weight_lower_bound: {}", weight_lower_bound);

        validator.validate_onchain_tx(
            self,
            channels.clone(),
            tx,
            values_sat,
            opaths,
            weight_lower_bound,
        )?;

        let mut witvec: Vec<Vec<Vec<u8>>> = Vec::new();
        for (idx, uck) in uniclosekeys.into_iter().enumerate() {
            if spendtypes[idx] == SpendType::Invalid {
                // If we are signing a PSBT some of the inputs may be
                // marked as SpendType::Invalid (we skip these), push
                // an empty witness element instead.
                witvec.push(vec![]);
            } else {
                let value_sat = values_sat[idx];
                let (privkey, mut witness) = match uck {
                    // There was a unilateral_close_key.
                    // TODO we don't care about the network here
                    Some((key, stack)) =>
                        (bitcoin::PrivateKey::new(key.clone(), Network::Testnet), stack),
                    // Derive the HD key.
                    None => {
                        let key = self.get_wallet_privkey(&secp_ctx, &ipaths[idx])?;
                        let redeemscript =
                            PublicKey::from_secret_key(&secp_ctx, &key.inner).serialize().to_vec();
                        (key, vec![redeemscript])
                    }
                };
                let pubkey = privkey.public_key(&secp_ctx);
                let script_code = Address::p2pkh(&pubkey, privkey.network).script_pubkey();
                let sighash = match spendtypes[idx] {
                    SpendType::P2pkh => {
                        // legacy address
                        let sighash = tx.signature_hash(0, &script_code, 0x01);
                        Ok(sighash)
                    }
                    SpendType::P2wpkh | SpendType::P2shP2wpkh => {
                        // segwit native and wrapped
                        let sighash = SighashCache::new(tx)
                            .segwit_signature_hash(
                                idx,
                                &script_code,
                                value_sat,
                                EcdsaSighashType::All,
                            )
                            .unwrap();
                        Ok(sighash)
                    }
                    SpendType::P2wsh => {
                        let sighash = SighashCache::new(tx)
                            .segwit_signature_hash(
                                idx,
                                &Script::from(witness[witness.len() - 1].clone()),
                                value_sat,
                                EcdsaSighashType::All,
                            )
                            .unwrap();
                        Ok(sighash)
                    }
                    st => Err(invalid_argument(format!("unsupported spend_type={:?}", st))),
                }?;
                let message = Message::from_slice(&sighash).map_err(|err| {
                    internal_error(format!("sighash {:?} failed: {}", spendtypes[idx], err))
                })?;
                let sig = secp_ctx.sign_ecdsa(&message, &privkey.inner);
                let sigvec = signature_to_bitcoin_vec(sig);
                witness.insert(0, sigvec);

                witvec.push(witness);
            }
        }

        // The tracker may be updated for multiple channels
        let mut tracker = self.tracker.lock().unwrap();

        // This locks channels in a random order, so we have to keep a global
        // lock to ensure no deadlock.  We grab the self.channels mutex above
        // for this purpose.
        // TODO(devrandom) consider sorting instead
        for (vout, slot_opt) in channels.iter().enumerate() {
            if let Some(slot_mutex) = slot_opt {
                let slot = slot_mutex.lock().unwrap();
                match &*slot {
                    ChannelSlot::Stub(_) => panic!("this can't happen"),
                    ChannelSlot::Ready(chan) => {
                        let inputs =
                            OrderedSet::from_iter(tx.input.iter().map(|i| i.previous_output));
                        tracker.add_listener_watches(chan.monitor.clone(), inputs);
                        chan.funding_signed(tx, vout as u32)
                    }
                }
            }
        }

        // the channels added some watches - persist
        self.persister
            .update_tracker(&self.get_id(), &tracker)
            .map_err(|_| internal_error("tracker persist failed"))?;

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
            opt_anchors: if setup.option_anchors() { Some(()) } else { None },
        };
        channel_transaction_parameters
    }

    pub(crate) fn get_wallet_privkey(
        &self,
        secp_ctx: &Secp256k1<secp256k1::SignOnly>,
        child_path: &Vec<u32>,
    ) -> Result<PrivateKey, Status> {
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
        Ok(PrivateKey::new(xkey.private_key, self.network()))
    }

    pub(crate) fn get_wallet_pubkey(
        &self,
        secp_ctx: &Secp256k1<secp256k1::SignOnly>,
        child_path: &Vec<u32>,
    ) -> Result<bitcoin::PublicKey, Status> {
        Ok(self.get_wallet_privkey(secp_ctx, child_path)?.public_key(secp_ctx))
    }

    /// Get the node secret key
    /// This function will be eliminated once the node key related items
    /// are implemented.  This includes onion decoding and p2p handshake.
    // TODO leaking secret
    pub fn get_node_secret(&self) -> SecretKey {
        self.keys_manager.get_node_secret(Recipient::Node).unwrap()
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
        ExtendedPubKey::from_priv(&secp_ctx, &self.get_account_extended_key())
    }

    /// Sign a node announcement using the node key
    pub fn sign_node_announcement(&self, na: &Vec<u8>) -> Result<Signature, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let na_hash = Sha256dHash::hash(na);
        let encmsg = secp256k1::Message::from_slice(&na_hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign_ecdsa(&encmsg, &self.get_node_secret());
        Ok(sig)
    }

    /// Sign a channel update using the node key
    pub fn sign_channel_update(&self, cu: &Vec<u8>) -> Result<Signature, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let cu_hash = Sha256dHash::hash(cu);
        let encmsg = secp256k1::Message::from_slice(&cu_hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign_ecdsa(&encmsg, &self.get_node_secret());
        Ok(sig)
    }

    /// Sign an invoice and start tracking incoming payment for its payment hash
    pub fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
    ) -> Result<RecoverableSignature, Status> {
        let signed_raw_invoice = self.do_sign_invoice(hrp_bytes, invoice_data)?;

        let sig = signed_raw_invoice.signature().0;
        let (hash, invoice_state, invoice_hash) =
            Self::invoice_state_from_invoice(signed_raw_invoice)?;
        info!(
            "{} signing an invoice {} -> {}",
            self.log_prefix(),
            hash.0.to_hex(),
            invoice_state.amount_msat
        );

        let mut state = self.get_state();
        if let Some(invoice_state) = state.issued_invoices.get(&hash) {
            return if invoice_state.invoice_hash == invoice_hash {
                Ok(sig)
            } else {
                Err(failed_precondition(
                    "already have a different invoice for same secret".to_string(),
                ))
            };
        }
        state.issued_invoices.insert(hash, invoice_state);

        Ok(sig)
    }

    pub(crate) fn do_sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
    ) -> Result<SignedRawInvoice, Status> {
        let hrp: RawHrp = String::from_utf8(hrp_bytes.to_vec())
            .map_err(|_| invalid_argument("invoice hrp not utf-8"))?
            .parse()
            .map_err(|e| invalid_argument(format!("parse error: {}", e)))?;
        let data = RawDataPart::from_base32(invoice_data)
            .map_err(|e| invalid_argument(format!("parse error: {}", e)))?;
        let raw_invoice = RawInvoice { hrp, data };

        let invoice_preimage = construct_invoice_preimage(&hrp_bytes, &invoice_data);
        let secp_ctx = Secp256k1::signing_only();
        let hash = Sha256Hash::hash(&invoice_preimage);
        let message = secp256k1::Message::from_slice(&hash).unwrap();
        let sig = secp_ctx.sign_ecdsa_recoverable(&message, &self.get_node_secret());

        raw_invoice
            .sign::<_, ()>(|_| Ok(sig))
            .map_err(|()| internal_error("failed to sign invoice"))
    }

    /// Sign a Lightning message
    pub fn sign_message(&self, message: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let secp_ctx = Secp256k1::signing_only();
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = secp256k1::Message::from_slice(&hash[..])
            .map_err(|err| internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign_ecdsa_recoverable(&encmsg, &self.get_node_secret());
        let (rid, sig) = sig.serialize_compact();
        let mut res = sig.to_vec();
        res.push(rid.to_i32() as u8);
        Ok(res)
    }

    /// Get the channels this node knows about.
    /// Currently, channels are not pruned once closed, but this will change.
    pub fn channels(&self) -> MutexGuard<OrderedMap<ChannelId, Arc<Mutex<ChannelSlot>>>> {
        self.channels.lock().unwrap()
    }

    /// Perform an ECDH operation between the node key and a public key
    /// This can be used for onion packet decoding
    pub fn ecdh(&self, other_key: &PublicKey) -> Vec<u8> {
        let our_key = self.keys_manager.get_node_secret(Recipient::Node).unwrap();
        let ss = SharedSecret::new(&other_key, &our_key);
        ss.as_ref().to_vec()
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
            .map(|allowable| Ok(allowable.to_string(self.network())))
            .collect::<Result<Vec<String>, Status>>()
    }

    /// Adds addresses to the node's current allowlist.
    pub fn add_allowlist(&self, addlist: &Vec<String>) -> Result<(), Status> {
        let allowables = addlist
            .iter()
            .map(|addrstr| Allowable::from_str(addrstr, self.network()))
            .collect::<Result<Vec<Allowable>, String>>()
            .map_err(|s| invalid_argument(format!("could not parse {}", s)))?;
        let mut alset = self.allowlist.lock().unwrap();
        for a in allowables {
            alset.insert(a);
        }
        self.update_allowlist(&alset)?;
        Ok(())
    }

    /// Replace the nodes allowlist with the provided allowlist.
    pub fn set_allowlist(&self, addlist: &Vec<String>) -> Result<(), Status> {
        let allowables = addlist
            .iter()
            .map(|addrstr| Allowable::from_str(addrstr, self.network()))
            .collect::<Result<Vec<Allowable>, String>>()
            .map_err(|s| invalid_argument(format!("could not parse {}", s)))?;
        let mut alset = self.allowlist.lock().unwrap();
        alset.clear();
        for a in allowables {
            alset.insert(a);
        }
        self.update_allowlist(&alset)?;
        Ok(())
    }

    fn update_allowlist(&self, alset: &MutexGuard<UnorderedSet<Allowable>>) -> Result<(), Status> {
        let wlvec = (*alset).iter().map(|a| a.to_string(self.network())).collect();
        self.persister
            .update_node_allowlist(&self.get_id(), wlvec)
            .map_err(|_| internal_error("persist failed"))
    }

    /// Removes addresses from the node's current allowlist.
    pub fn remove_allowlist(&self, rmlist: &Vec<String>) -> Result<(), Status> {
        let allowables = rmlist
            .iter()
            .map(|addrstr| Allowable::from_str(addrstr, self.network()))
            .collect::<Result<Vec<Allowable>, String>>()
            .map_err(|s| invalid_argument(format!("could not parse {}", s)))?;
        let mut alset = self.allowlist.lock().unwrap();
        for a in allowables {
            alset.remove(&a);
        }
        self.update_allowlist(&alset)?;
        Ok(())
    }

    /// Chain tracker with lock
    pub fn get_tracker(&self) -> MutexGuard<'_, ChainTracker<ChainMonitor>> {
        self.tracker.lock().unwrap()
    }

    ///Height of chain
    pub fn get_chain_height(&self) -> u32 {
        self.tracker.lock().unwrap().height()
    }

    // Process payment preimages for offered HTLCs.
    // Any invoice with a payment hash that matches a preimage is marked
    // as paid, so that the offered HTLC can be removed and our balance
    // adjusted downwards.
    pub(crate) fn htlcs_fulfilled(
        &self,
        channel_id: &ChannelId,
        preimages: Vec<PaymentPreimage>,
        validator: Arc<dyn Validator>,
    ) {
        let mut state = self.get_state();
        for preimage in preimages.into_iter() {
            state.htlc_fulfilled(channel_id, preimage, Arc::clone(&validator));
        }
    }

    /// Add an invoice.
    /// Used by the signer to map HTLCs to destination payees, so that payee
    /// public keys can be allowlisted for policy control.
    pub fn add_invoice(&self, raw_invoice: SignedRawInvoice) -> Result<(), Status> {
        let (hash, invoice_state, invoice_hash) = Self::invoice_state_from_invoice(raw_invoice)?;

        info!(
            "{} adding invoice {} -> {}",
            self.log_prefix(),
            hash.0.to_hex(),
            invoice_state.amount_msat
        );
        let mut state = self.get_state();
        if let Some(invoice_state) = state.invoices.get(&hash) {
            return if invoice_state.invoice_hash == invoice_hash {
                Ok(())
            } else {
                Err(failed_precondition("already have a different invoice for same secret"))
            };
        }
        if !state.velocity_control.insert(self.clock.now().as_secs(), invoice_state.amount_msat) {
            return Err(failed_precondition(format!(
                "global velocity would be exceeded - += {} = {} > {}",
                invoice_state.amount_msat,
                state.velocity_control.velocity(),
                state.velocity_control.limit
            )));
        }
        state.invoices.insert(hash, invoice_state);
        state.payments.insert(hash, RoutedPayment::new());
        self.persister.update_node(&self.get_id(), &*state).expect("node persistence failure");

        Ok(())
    }

    /// Check to see if an invoice has already been added
    pub fn has_invoice(&self, hash: &PaymentHash, invoice_hash: &[u8; 32]) -> Result<bool, Status> {
        let state = self.get_state();
        let retval = if let Some(invoice_state) = state.invoices.get(&hash) {
            if invoice_state.invoice_hash == *invoice_hash {
                Ok(true)
            } else {
                Err(failed_precondition("already have a different invoice for same secret"))
            }
        } else {
            Ok(false) // not found
        };
        debug!("{} has_invoice {} {:?}", self.log_prefix(), hash.0.to_hex(), retval,);
        retval
    }

    /// Validate the invoice and create a tracking state for it.
    ///
    /// Returns the payment hash, invoice state, and the hash of the raw invoice that was signed.
    pub fn invoice_state_from_invoice(
        raw_invoice: SignedRawInvoice,
    ) -> Result<(PaymentHash, InvoiceState, [u8; 32]), Status> {
        let invoice_hash = raw_invoice.hash().clone();

        // This performs all semantic checks and signature check
        let invoice =
            Invoice::from_signed(raw_invoice).map_err(|e| invalid_argument(e.to_string()))?;
        let hash = PaymentHash(invoice.payment_hash().as_inner().clone());
        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        // TODO check if payee public key in allowlist
        let payee = invoice
            .payee_pub_key()
            .map(|p| p.clone())
            .unwrap_or_else(|| invoice.recover_payee_pub_key());
        let invoice_state = InvoiceState {
            invoice_hash,
            amount_msat,
            payee,
            duration_since_epoch: invoice.duration_since_epoch(),
            expiry_duration: invoice.expiry_time(),
            is_fulfilled: false,
        };
        Ok((hash, invoice_state, invoice_hash))
    }

    fn make_velocity_control(policy: Box<dyn Policy>) -> VelocityControl {
        let global_velocity_control_spec = policy.global_velocity_control();
        VelocityControl::new(global_velocity_control_spec)
    }
}

/// Trait to monitor read-only features of Node
pub trait NodeMonitor {
    ///Get the balance
    fn channel_balance(&self) -> ChannelBalance;
}

impl NodeMonitor for Node {
    // TODO - lock while we sum so channels can't change until we are done
    fn channel_balance(&self) -> ChannelBalance {
        let mut sum = ChannelBalance::zero();
        let channels_lock = self.channels.lock().unwrap();
        for (_, slot_arc) in channels_lock.iter() {
            let slot = slot_arc.lock().unwrap();
            match &*slot {
                ChannelSlot::Ready(chan) => {
                    sum.accumulate(&chan.balance());
                }
                ChannelSlot::Stub(_stub) => {
                    // ignore stubs ...
                }
            }
        }
        sum
    }
}

fn find_channel_with_funding_outpoint(
    channels_lock: &MutexGuard<OrderedMap<ChannelId, Arc<Mutex<ChannelSlot>>>>,
    outpoint: &OutPoint,
) -> Option<Arc<Mutex<ChannelSlot>>> {
    for (_, slot_arc) in channels_lock.iter() {
        let slot = slot_arc.lock().unwrap();
        match &*slot {
            ChannelSlot::Ready(chan) =>
                if chan.setup.funding_outpoint == *outpoint {
                    return Some(Arc::clone(slot_arc));
                },
            ChannelSlot::Stub(_stub) => {
                // ignore stubs ...
            }
        }
    }
    None
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
    /// Pay to witness script hash
    P2wsh = 5,
}

impl TryFrom<i32> for SpendType {
    type Error = ();

    fn try_from(i: i32) -> Result<Self, Self::Error> {
        let res = match i {
            x if x == SpendType::Invalid as i32 => SpendType::Invalid,
            x if x == SpendType::P2pkh as i32 => SpendType::P2pkh,
            x if x == SpendType::P2wpkh as i32 => SpendType::P2wpkh,
            x if x == SpendType::P2shP2wpkh as i32 => SpendType::P2shP2wpkh,
            x if x == SpendType::P2wsh as i32 => SpendType::P2wsh,
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
    use bitcoin::bech32::{CheckBase32, ToBase32};
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::sha256d::Hash as Sha256dHash;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1;
    use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::util::sighash::SighashCache;
    use bitcoin::{Address, EcdsaSighashType, OutPoint};
    use lightning::ln::chan_utils::derive_private_key;
    use lightning::ln::{chan_utils, PaymentSecret};
    use lightning_invoice::{Currency, InvoiceBuilder};
    use test_log::test;

    use crate::channel::ChannelBase;
    use crate::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
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

        let (channel_id, _) = node.new_channel(None, &node).unwrap();
        assert!(node.get_channel(&channel_id).is_ok());
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        assert!(node.get_channel(&channel_id).is_err());
        Ok(())
    }

    #[test]
    fn invoice_test() {
        let payee_node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let hash = PaymentHash([2; 32]);
        // TODO check currency matches
        let invoice1 = make_test_invoice(&payee_node, "invoice1", hash);
        let invoice2 = make_test_invoice(&payee_node, "invoice2", hash);
        node.add_invoice(invoice1.clone()).expect("add invoice");
        node.add_invoice(invoice1.clone()).expect("add invoice");
        node.add_invoice(invoice2.clone())
            .expect_err("add a different invoice with same payment hash");

        let mut state = node.get_state();
        let hash1 = PaymentHash([1; 32]);
        let channel_id2 = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[1]).unwrap());

        // Create a strict invoice validator and one that does not validate invoices
        let mut policy = make_simple_policy(Network::Testnet);
        policy.require_invoices = true;
        let invoice_validator = SimpleValidatorFactory::new_with_policy(policy).make_validator(
            Network::Testnet,
            node.get_id(),
            None,
        );
        let lenient_validator =
            SimpleValidatorFactory::new().make_validator(Network::Testnet, node.get_id(), None);

        state
            .validate_and_apply_payments(
                &channel_id2,
                &Map::new(),
                &vec![(hash, 99)].into_iter().collect(),
                &Default::default(),
                invoice_validator.clone(),
            )
            .expect("channel1");

        let result = state.validate_and_apply_payments(
            &channel_id,
            &Map::new(),
            &vec![(hash, 12)].into_iter().collect(),
            &Default::default(),
            invoice_validator.clone(),
        );
        assert_eq!(result, Err(unbalanced_error(vec![hash])));

        let result = state.validate_and_apply_payments(
            &channel_id,
            &Map::new(),
            &vec![(hash, 11)].into_iter().collect(),
            &Default::default(),
            invoice_validator.clone(),
        );
        assert!(result.is_ok());

        let result = state.validate_and_apply_payments(
            &channel_id,
            &Map::new(),
            &vec![(hash1, 5)].into_iter().collect(),
            &Default::default(),
            lenient_validator.clone(),
        );

        assert!(result.is_ok());

        let result = state.validate_and_apply_payments(
            &channel_id,
            &Map::new(),
            &vec![(hash1, 5)].into_iter().collect(),
            &Default::default(),
            invoice_validator.clone(),
        );

        assert!(result.is_err());
    }

    fn make_test_invoice(
        payee_node: &Arc<Node>,
        description: &str,
        payment_hash: PaymentHash,
    ) -> SignedRawInvoice {
        let (hrp_bytes, invoice_data) = build_test_invoice(description, &payment_hash);
        payee_node.do_sign_invoice(&hrp_bytes, &invoice_data).unwrap()
    }

    fn build_test_invoice(description: &str, payment_hash: &PaymentHash) -> (Vec<u8>, Vec<u5>) {
        let raw_invoice = InvoiceBuilder::new(Currency::Bitcoin)
            .duration_since_epoch(Duration::from_secs(123456789))
            .amount_milli_satoshis(100_000)
            .payment_hash(Sha256Hash::from_slice(&payment_hash.0).unwrap())
            .payment_secret(PaymentSecret([0; 32]))
            .description(description.to_string())
            .build_raw()
            .expect("build");
        let hrp_str = raw_invoice.hrp.to_string();
        let hrp_bytes = hrp_str.as_bytes().to_vec();
        let invoice_data = raw_invoice.data.to_base32();
        (hrp_bytes, invoice_data)
    }

    #[test]
    fn fulfill_test() {
        let payee_node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        // TODO check currency matches
        let preimage = PaymentPreimage([0; 32]);
        let hash = PaymentHash(Sha256Hash::hash(&preimage.0).into_inner());

        let invoice = make_test_invoice(&payee_node, "invoice", hash);

        node.add_invoice(invoice).expect("add invoice");

        let mut policy = make_simple_policy(Network::Testnet);
        policy.require_invoices = true;
        policy.enforce_balance = true;
        let factory = SimpleValidatorFactory::new_with_policy(policy);
        let invoice_validator = factory.make_validator(Network::Testnet, node.get_id(), None);
        node.set_validator_factory(Arc::new(factory));

        {
            let mut state = node.get_state();
            assert_status_ok!(state.validate_and_apply_payments(
                &channel_id,
                &Map::new(),
                &vec![(hash, 110)].into_iter().collect(),
                &Default::default(),
                invoice_validator.clone()
            ));
        }
        node.with_ready_channel(&channel_id, |chan| {
            chan.htlcs_fulfilled(vec![preimage]);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn overpay_test() {
        let payee_node = init_node(TEST_NODE_CONFIG, TEST_SEED[0]);
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let preimage = PaymentPreimage([0; 32]);
        let hash = PaymentHash(Sha256Hash::hash(&preimage.0).into_inner());

        let invoice = make_test_invoice(&payee_node, "invoice", hash);

        node.add_invoice(invoice).expect("add invoice");

        let mut policy = make_simple_policy(Network::Testnet);
        policy.require_invoices = true;
        policy.enforce_balance = true;
        let factory = SimpleValidatorFactory::new_with_policy(policy);
        let invoice_validator = factory.make_validator(Network::Testnet, node.get_id(), None);
        node.set_validator_factory(Arc::new(factory));

        {
            let mut state = node.get_state();
            assert_eq!(
                state.validate_and_apply_payments(
                    &channel_id,
                    &Map::new(),
                    &vec![(hash, 111)].into_iter().collect(),
                    &Default::default(),
                    invoice_validator.clone()
                ),
                Err(unbalanced_error(vec![hash]))
            );
        }
    }

    #[test]
    fn shortfall_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());

        let mut policy = make_simple_policy(Network::Testnet);
        policy.require_invoices = true;
        policy.enforce_balance = true;
        let factory = SimpleValidatorFactory::new_with_policy(policy);
        let invoice_validator = factory.make_validator(Network::Testnet, node.get_id(), None);
        node.set_validator_factory(Arc::new(factory));

        {
            let mut state = node.get_state();
            assert_eq!(
                state.validate_and_apply_payments(
                    &channel_id,
                    &Map::new(),
                    &Map::new(),
                    &BalanceDelta(0, 0),
                    invoice_validator.clone()
                ),
                Ok(())
            );
            assert_eq!(
                state.validate_and_apply_payments(
                    &channel_id,
                    &Map::new(),
                    &Map::new(),
                    &BalanceDelta(1, 0),
                    invoice_validator.clone()
                ),
                Err(policy_error("shortfall 0 + 0 - 1"))
            );
        }
    }

    #[test]
    fn sign_invoice_no_amount_test() {
        let (node, _channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        let preimage = PaymentPreimage([0; 32]);
        let hash = PaymentHash(Sha256Hash::hash(&preimage.0).into_inner());
        let raw_invoice = InvoiceBuilder::new(Currency::Bitcoin)
            .duration_since_epoch(Duration::from_secs(123456789))
            .payment_hash(Sha256Hash::from_slice(&hash.0).unwrap())
            .payment_secret(PaymentSecret([0; 32]))
            .description("".to_string())
            .build_raw()
            .expect("build");
        let hrp_str = raw_invoice.hrp.to_string();
        let hrp = hrp_str.as_bytes().to_vec();
        let data = raw_invoice.data.to_base32();

        // This records the issued invoice
        node.sign_invoice(&hrp, &data).unwrap();
    }

    #[test]
    fn incoming_payment_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        // TODO check currency matches
        let preimage = PaymentPreimage([0; 32]);
        let hash = PaymentHash(Sha256Hash::hash(&preimage.0).into_inner());

        let (hrp, data) = build_test_invoice("invoice", &hash);
        // This records the issued invoice
        node.sign_invoice(&hrp, &data).unwrap();

        let mut policy = make_simple_policy(Network::Testnet);
        policy.require_invoices = true;
        policy.enforce_balance = true;
        let factory = SimpleValidatorFactory::new_with_policy(policy);
        let invoice_validator = factory.make_validator(Network::Testnet, node.get_id(), None);

        {
            let mut state = node.get_state();
            // Underpaid
            state
                .validate_and_apply_payments(
                    &channel_id,
                    &vec![(hash, 99)].into_iter().collect(),
                    &Map::new(),
                    &Default::default(),
                    invoice_validator.clone(),
                )
                .expect("ok");
            assert!(!state.payments.get(&hash).unwrap().is_fulfilled());
            // Paid
            state
                .validate_and_apply_payments(
                    &channel_id,
                    &vec![(hash, 100)].into_iter().collect(),
                    &Map::new(),
                    &Default::default(),
                    invoice_validator.clone(),
                )
                .expect("ok");
            assert!(state.payments.get(&hash).unwrap().is_fulfilled());
            // Already paid
            state
                .validate_and_apply_payments(
                    &channel_id,
                    &vec![(hash, 100)].into_iter().collect(),
                    &Map::new(),
                    &Default::default(),
                    invoice_validator.clone(),
                )
                .expect("ok");
            assert!(state.payments.get(&hash).unwrap().is_fulfilled());
        }
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
                chan.enforcement_state.set_next_holder_commit_num_for_testing(commit_num + 2);
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
            hex_decode("2f87fef68f2bafdb3c6425921894af44da9a984075c70c7ba31ccd551b3585db")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let correct = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n, &suggested))
            .unwrap();
        assert_eq!(correct, true);

        let notcorrect = node
            .with_channel_base(&channel_id, |base| base.check_future_secret(n + 1, &suggested))
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
        secp_ctx.verify_ecdsa(&encmsg, &nsig, &node.get_id()).expect("verify nsig");
        let _res: Result<(), Status> = node.with_ready_channel(&channel_id, |chan| {
            let funding_pubkey = PublicKey::from_secret_key(&secp_ctx, &chan.keys.funding_key);
            Ok(secp_ctx.verify_ecdsa(&encmsg, &bsig, &funding_pubkey).expect("verify bsig"))
        });
    }

    #[test]
    fn sign_node_announcement_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let ann = hex_decode("000302aaa25e445fef0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b65180265b64c4f554450484f544f2d2e302d3139392d67613237336639642d6d6f646465640000").unwrap();
        let sigvec = node.sign_node_announcement(&ann).unwrap().serialize_der().to_vec();
        assert_eq!(sigvec, hex_decode("30450221008ef1109b95f127a7deec63b190b72180f0c2692984eaf501c44b6bfc5c4e915502207a6fa2f250c5327694967be95ff42a94a9c3d00b7fa0fbf7daa854ceb872e439").unwrap());
        Ok(())
    }

    #[test]
    fn sign_channel_update_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let cu = hex_decode("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015e42ddc6010000060000000000000000000000010000000a000000003b023380").unwrap();
        let sigvec = node.sign_channel_update(&cu).unwrap().serialize_der().to_vec();
        assert_eq!(sigvec, hex_decode("3045022100be9840696c868b161aaa997f9fa91a899e921ea06c8083b2e1ea32b8b511948d0220352eec7a74554f97c2aed26950b8538ca7d7d7568b42fd8c6f195bd749763fa5").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt1230n");
        let data_part = hex_decode("010f0418090a010101141917110f01040e050f06100003021e1b0e13161c150301011415060204130c0018190d07070a18070a1c1101111e111f130306000d00120c11121706181b120d051807081a0b0f0d18060004120e140018000105100114000b130b01110c001a05041a181716020007130c091d11170d10100d0b1a1b00030e05190208171e16080d00121a00110719021005000405001000").unwrap().check_base32().unwrap();
        let (rid, rsig) = node
            .sign_invoice(human_readable_part.as_bytes(), &data_part)
            .unwrap()
            .serialize_compact();
        assert_eq!(rsig.to_vec(), hex_decode("739ffb91aa7c0b3d3c92de1600f7a9afccedc5597977095228232ee4458685531516451b84deb35efad27a311ea99175d10c6cdb458cd27ce2ed104eb6cf8064").unwrap());
        assert_eq!(rid.to_i32(), 0);
        Ok(())
    }

    #[test]
    fn sign_invoice_with_overhang_test() -> Result<(), ()> {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt2m");
        let data_part = hex_decode("010f0a001d051e0101140c0c000006140009160c09051a0d1a190708020d17141106171f0f07131616111f1910070b0d0e150c0c0c0d010d1a01181c15100d010009181a06101a0a0309181b040a111a0a06111705100c0b18091909030e151b14060004120e14001800010510011419080f1307000a0a0517021c171410101a1e101605050a08180d0d110e13150409051d02091d181502020f050e1a1f161a09130005000405001000").unwrap().check_base32().unwrap();
        // The data_part is 170 bytes.
        // overhang = (data_part.len() * 5) % 8 = 2
        // looking for a verified invoice where overhang is in 1..3
        let (rid, rsig) = node
            .sign_invoice(human_readable_part.as_bytes(), &data_part)
            .unwrap()
            .serialize_compact();
        assert_eq!(rsig.to_vec(), hex_decode("f278cdba3fd4a37abf982cee5a66f52e142090631ef57763226f1232eead78b43da7962fcfe29ffae9bd918c588df71d6d7b92a4787de72801594b22f0e7e62a").unwrap());
        assert_eq!(rid.to_i32(), 0);
        Ok(())
    }

    #[test]
    fn sign_bad_invoice_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let human_readable_part = String::from("lnbcrt1230n");
        let data_part = hex_decode("010f0418090a").unwrap().check_base32().unwrap();
        assert_invalid_argument_err!(
            node.sign_invoice(human_readable_part.as_bytes(), &data_part),
            "parse error: data part too short (should be at least 111 bech32 chars long)"
        );
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
        let (channel_id, chan) = node.new_channel(None, &node).unwrap();

        node.ready_channel(channel_id.clone(), None, make_test_channel_setup(), &vec![])
            .expect("ready channel");

        let uck = node
            .with_ready_channel(&channel_id, |chan| chan.get_unilateral_close_key(&None, &None))
            .unwrap();
        let keys = &chan.as_ref().unwrap().keys;
        let key = keys.pubkeys().payment_point;

        assert_eq!(
            uck,
            (
                SecretKey::from_slice(
                    &hex_decode("e6eb522940c9d1dcffc82f4eaff5b81ad318bdaa952061fa73fd6f717f73e160")
                        .unwrap()[..]
                )
                .unwrap(),
                vec![key.serialize().to_vec()]
            )
        );

        let secp_ctx = Secp256k1::new();
        let revocation_secret = SecretKey::from_slice(
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let revocation_point = PublicKey::from_secret_key(&secp_ctx, &revocation_secret);
        let commitment_secret = SecretKey::from_slice(
            hex_decode("0101010101010101010101010101010101010101010101010101010101010102")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let commitment_point = PublicKey::from_secret_key(&secp_ctx, &commitment_secret);
        let uck = node
            .with_ready_channel(&channel_id, |chan| {
                chan.get_unilateral_close_key(&Some(commitment_point), &Some(revocation_point))
            })
            .unwrap();

        let seckey =
            derive_private_key(&secp_ctx, &commitment_point, &keys.delayed_payment_base_key)
                .unwrap();
        let pubkey = PublicKey::from_secret_key(&secp_ctx, &seckey);

        let redeem_script = chan_utils::get_revokeable_redeemscript(&revocation_point, 7, &pubkey);

        assert_eq!(
            uck,
            (
                SecretKey::from_slice(
                    &hex_decode("fd5f03ea7b42be9a045097dfa1ef007a430f576302c76e6e6265812f1d1ce18f")
                        .unwrap()[..]
                )
                .unwrap(),
                vec![vec![], redeem_script.to_bytes()]
            )
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
        let sig = Signature::from_compact(&rsig.to_standard().serialize_compact()).unwrap();
        let pubkey = secp_ctx.recover_ecdsa(&encmsg, &rsig).unwrap();
        assert!(secp_ctx.verify_ecdsa(&encmsg, &sig, &pubkey).is_ok());
        assert_eq!(pubkey.serialize().to_vec(), node.get_id().serialize().to_vec());
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

        let sighash = &SighashCache::new(&tx)
            .segwit_signature_hash(1, &script_code, value, EcdsaSighashType::All)
            .unwrap()[..];
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
        fn prefix(a: &String) -> String {
            format!("address:{}", a)
        }

        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);

        // initial allowlist should be empty
        assert!(node.allowlist().expect("allowlist").len() == 0);

        // can insert some entries
        let adds0: Vec<String> = vec![
            "mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB",
            "2N6i2gfgTonx88yvYm32PRhnHxqxtEfocbt",
            "tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z",
            "tb1qycu764qwuvhn7u0enpg0x8gwumyuw565f3mspnn58rsgar5hkjmqtjegrh",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let prefixed_adds: Vec<String> = adds0.iter().cloned().map(|s| prefix(&s)).collect();
        assert_status_ok!(node.add_allowlist(&adds0));

        // now allowlist should have the added entries
        assert!(vecs_match(node.allowlist().expect("allowlist").clone(), prefixed_adds.clone()));

        // adding duplicates shouldn't change the node allowlist
        assert_status_ok!(node.add_allowlist(&adds0));
        assert!(vecs_match(node.allowlist().expect("allowlist").clone(), prefixed_adds.clone()));

        // can remove some elements from the allowlist
        let removes0 = vec![adds0[0].clone(), adds0[3].clone()];
        assert_status_ok!(node.remove_allowlist(&removes0));
        assert!(vecs_match(
            node.allowlist().expect("allowlist").clone(),
            vec![prefix(&adds0[1]), prefix(&adds0[2])]
        ));

        // set should replace the elements
        assert_status_ok!(node.set_allowlist(&removes0));
        assert!(vecs_match(
            node.allowlist().expect("allowlist").clone(),
            removes0.iter().map(|e| prefix(e)).collect()
        ));

        // can't add bogus addresses
        assert_invalid_argument_err!(
            node.add_allowlist(&vec!["1234567890".to_string()]),
            "could not parse 1234567890"
        );

        // can't add w/ wrong network
        assert_invalid_argument_err!(
            node.add_allowlist(&vec!["1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp".to_string()]),
            "could not parse 1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp: expected network testnet"
        );

        // can't remove w/ wrong network
        assert_invalid_argument_err!(
            node.remove_allowlist(&vec!["1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp".to_string()]),
            "could not parse 1287uUybCYgf7Tb76qnfPf8E1ohCgSZATp: expected network testnet"
        );
    }

    #[test]
    fn cln_node_param_compatibility() {
        // This test compares to known values generated by CLN's native hsmd
        let node = init_node(
            NodeConfig {
                network: Network::Regtest,
                key_derivation_style: KeyDerivationStyle::Native,
            },
            "6c696768746e696e672d31000000000000000000000000000000000000000000",
        );
        assert_eq!(
            node.get_id().serialize().to_hex(),
            "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518"
        );
        assert_eq!(
            node.get_account_extended_pubkey().to_string(),
            "tpubDBrTnjDZwRM6jznHEmo1sYqJWU9so1HRsGEWWjMKLRhVLtuCKYKaHPE3NzqFY3ZdTd64t65T8YrXZZ8Ugwkb7oNzQVBtokaAvtC8Km6EM2G");
        assert_eq!(
            node.get_bolt12_pubkey().serialize().to_hex(),
            "e25c37f1af7cb00984e594eae0f4d1d03537ffe202b7a6b2ebc1e5fcf1dfd9f4"
        );
        assert_eq!(
            node.get_onion_reply_secret().to_hex(),
            "cfd1fb341180bf3fa2f624ed7d4a809aedf388e3ba363c589faf341018cb83e1"
        );
    }
}
