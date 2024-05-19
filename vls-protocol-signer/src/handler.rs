#![allow(deprecated)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::fmt::{Debug, Display, Formatter};
use core::str::FromStr;
use lightning_signer::bitcoin::script::PushBytesBuf;
use lightning_signer::bitcoin::ScriptBuf;
use lightning_signer::lightning::ln::channel_keys::RevocationKey;
use vls_protocol::psbt::PsbtWrapper;

use bitcoin::bech32::u5;
use bitcoin::bip32::{DerivationPath, KeySource};
use bitcoin::blockdata::script;
use bitcoin::consensus::deserialize;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Address, Network};
use bitcoin::{OutPoint, Transaction, Witness};
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::key::XOnlyPublicKey;
use lightning_signer::bitcoin::sighash::EcdsaSighashType;
use lightning_signer::channel::{
    ChannelBalance, ChannelBase, ChannelId, ChannelSetup, SlotInfo, SlotInfoVariant, TypedSignature,
};
use lightning_signer::dbgvals;
use lightning_signer::invoice::Invoice;
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::node::{Node, NodeConfig, NodeMonitor, NodeServices};
use lightning_signer::persist::{Mutations, Persist};
use lightning_signer::signer::my_keys_manager::MyKeysManager;
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::util::status;
use lightning_signer::Arc;
use lightning_signer::{function, trace_node_state};
use log::*;
use secp256k1::{ecdsa, PublicKey, Secp256k1};

use lightning_signer::chain::tracker::{Error as TrackerError, Headers};
use lightning_signer::util::crypto_utils::signature_to_bitcoin_vec;
use lightning_signer::util::debug_utils::DebugUnilateralCloseInfo;
use lightning_signer::util::status::{Code, Status};
use lightning_signer::wallet::Wallet;
use serde_bolt::{to_vec, Array, Octets, WireString, WithSize};
use vls_protocol::model::{
    Basepoints, BitcoinSignature, DisclosedSecret, ExtKey, Htlc, PubKey, RecoverableSignature,
    Secret, Signature, Utxo,
};
use vls_protocol::msgs::{
    DeriveSecretReply, PreapproveInvoiceReply, PreapproveKeysendReply, SerBolt, SignBolt12Reply,
    DEFAULT_MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION_NO_SECRET,
    PROTOCOL_VERSION_REVOKE,
};
use vls_protocol::psbt::StreamedPSBT;
use vls_protocol::serde_bolt;
use vls_protocol::{msgs, msgs::DeBolt, msgs::Message, Error as ProtocolError};

use crate::approver::{Approve, NegativeApprover};
use crate::util::channel_type_to_commitment_type;

/// Error
#[derive(Debug)]
pub enum Error {
    /// Protocol error
    Protocol(ProtocolError),
    /// We failed to sign
    Signing(Status),
    /// We failed to sign because of a temporary error
    Temporary(Status),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::Protocol(e)
    }
}

impl From<Status> for Error {
    fn from(e: Status) -> Self {
        if e.code() == Code::Temporary {
            Error::Temporary(e)
        } else {
            Error::Signing(e)
        }
    }
}

fn to_bitcoin_sig(sig: ecdsa::Signature) -> BitcoinSignature {
    BitcoinSignature {
        signature: Signature(sig.serialize_compact()),
        sighash: EcdsaSighashType::All as u8,
    }
}

fn typed_to_bitcoin_sig(sig: TypedSignature) -> BitcoinSignature {
    BitcoinSignature { signature: Signature(sig.sig.serialize_compact()), sighash: sig.typ as u8 }
}

fn to_script(bytes: &Vec<u8>) -> Option<ScriptBuf> {
    if bytes.is_empty() {
        None
    } else {
        Some(ScriptBuf::from(bytes.clone()))
    }
}

/// Result
pub type Result<T> = core::result::Result<T, Error>;

/// A protocol handler
/// The handle function takes an incoming message, handles it and returns a response.
///
/// There are two implementations of this trait - [`RootHandler`] for node level
/// messages and [`ChannelHandler`] for channel level messages.
pub trait Handler {
    /// Handle a message
    fn handle(&self, msg: Message) -> Result<Box<dyn SerBolt>> {
        log_request(&msg);
        let result = self.do_handle(msg);
        if let Err(ref err) = result {
            log_error(err);
        }
        let reply = result?;
        log_reply(&reply);
        Ok(reply)
    }

    /// Commit the persister transaction if any
    fn commit(&self) {
        self.node().get_persister().commit().expect("commit");
    }

    /// Actual handling
    fn do_handle(&self, msg: Message) -> Result<Box<dyn SerBolt>>;
    /// Unused
    fn client_id(&self) -> u64;
    /// Create a channel handler
    fn for_new_client(&self, client_id: u64, peer_id: PubKey, dbid: u64) -> ChannelHandler;
    /// Get the associated signing node.
    /// Note that if you want to perform an operation that can result in a mutation
    /// of the node state requiring a persist, and your persister writes to the cloud,
    /// you must use [`Handler::with_persist`] instead.
    fn node(&self) -> &Arc<Node>;

    /// Perform an operation on the Node that requires persistence.
    /// The operation must not mutate if it fails (returns an error).
    /// You must call [`Handler::commit`] after you persist the mutations in the
    /// cloud.
    fn with_persist(&self, f: impl FnOnce(&Node) -> Result<()>) -> Result<Mutations> {
        let node = self.node();
        let persister = node.get_persister();
        persister.enter().map_err(|e| {
            error!("failed to enter persister: {:?}", e);
            Status::internal("failed to start persister transaction")
        })?;
        let result = f(&*node);
        let muts = persister.prepare();

        match result {
            Ok(()) => Ok(muts),
            Err(e) => {
                if !muts.is_empty() {
                    #[cfg(not(feature = "log_pretty_print"))]
                    debug!("stranded mutations: {:?}", &muts);
                    #[cfg(feature = "log_pretty_print")]
                    debug!("stranded mutations: {:#?}", &muts);
                    panic!("failed operation with stranded mutations");
                }
                Err(e)
            }
        }
    }
}

fn log_request(msg: &Message) {
    #[cfg(not(feature = "log_pretty_print"))]
    debug!("{:?}", msg);
    #[cfg(feature = "log_pretty_print")]
    debug!("{:#?}", msg);
}

fn log_error(err: &Error) {
    #[cfg(not(feature = "log_pretty_print"))]
    error!("{:?}", err);
    #[cfg(feature = "log_pretty_print")]
    error!("{:#?}", err);
}

fn log_reply(reply: &Box<dyn SerBolt>) {
    #[cfg(not(feature = "log_pretty_print"))]
    debug!("{:?}", reply);
    #[cfg(feature = "log_pretty_print")]
    debug!("{:#?}", reply);
}

// Log the channel slot information
fn log_chaninfo(mut slotinfo: Vec<SlotInfo>) {
    // log header
    info!("chaninfo:  oid channel_id                                                                         funding_outpoint                                                   claimable  received   offered  sweeping f state");
    // sample record:   1 0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180100000000000000 beef1bf6c17657470880bf85819c775a8938c7f2dfb7e936b2d07c13fa813639:0         0      0  0      0  0    100000 1 MUTUALLY_CLOSED at 109, age till 209

    // Sort by oid
    slotinfo.sort_by_key(|k| k.oid);

    for slot in slotinfo {
        let oid = slot.oid;
        let id = slot.id;

        match slot.slot {
            SlotInfoVariant::StubInfo { pruneheight } => info!(
                "chaninfo: {:>4} {} prune after {}",
                oid,
                id,
                pruneheight // this comment makes the indentation awesome
            ),
            SlotInfoVariant::ChannelInfo { funding, balance, forget_seen, diagnostic } => info!(
                "chaninfo: {:>4} {} {:<67} {:>9} {:>6} {:>2} {:>6} {:>2} {:>9} {} {}",
                oid,
                id,
                funding.unwrap_or_else(|| {
                    let mut ph = OutPoint::default();
                    ph.vout = 0; // the default vout is much too large for our format
                    ph
                }),
                balance.claimable,
                balance.received_htlc,
                balance.received_htlc_count,
                balance.offered_htlc,
                balance.offered_htlc_count,
                balance.sweeping,
                if forget_seen { 1 } else { 0 },
                diagnostic,
            ),
        }
    }
}

/// Initial protocol handler, for negotiating the protocol version
#[derive(Clone)]
pub struct InitHandler {
    id: u64,
    node: Arc<Node>,
    approver: Arc<dyn Approve>,
    max_protocol_version: u32,
    protocol_version: Option<u32>,
}

/// Protocol handler
#[derive(Clone)]
pub struct RootHandler {
    id: u64,
    node: Arc<Node>,
    approver: Arc<dyn Approve>,
    protocol_version: u32,
}

/// Builder for RootHandler
///
/// WARNING: if you don't specify a seed, and you persist to LSS, you must get the seed
/// from the builder and persist it yourself.  LSS does not persist the seed.
/// If you don't persist, you will lose your keys.
pub struct HandlerBuilder {
    network: Network,
    id: u64,
    seed: [u8; 32],
    allowlist: Vec<String>,
    services: NodeServices,
    approver: Arc<dyn Approve>,
    max_protocol_version: u32,
}

impl HandlerBuilder {
    /// Create a InitHandlerBuilder
    pub fn new(
        network: Network,
        id: u64,
        services: NodeServices,
        seed: [u8; 32],
    ) -> HandlerBuilder {
        HandlerBuilder {
            network,
            id,
            seed,
            allowlist: vec![],
            services,
            approver: Arc::new(NegativeApprover()),
            max_protocol_version: DEFAULT_MAX_PROTOCOL_VERSION,
        }
    }

    /// Set the initial allowlist (only used if node is new)
    pub fn allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Set the approver
    pub fn approver(mut self, approver: Arc<dyn Approve>) -> Self {
        self.approver = approver;
        self
    }

    /// Set the hsmd max protocol version, may still be negotiated down by node
    pub fn max_protocol_version(mut self, max_version: u32) -> Self {
        self.max_protocol_version = max_version;
        self
    }

    /// Create a keys manager - useful for bootstrapping a node from persistence, so the
    /// persistence key can be derived.
    pub fn build_keys_manager(&self) -> (MyKeysManager, PublicKey) {
        let config = NodeConfig::new(self.network);
        Node::make_keys_manager(&config, &self.seed, &self.services)
    }

    /// Build the root handler.
    ///
    /// Returns the handler and any mutations that need to be stored.
    /// You must call [`Handler::commit`] after you persist the mutations in the
    /// cloud.
    pub fn build(self) -> Result<InitHandler> {
        let config = NodeConfig::new(self.network);

        let persister = self.services.persister.clone();
        let nodes = persister.get_nodes().expect("get_nodes");
        let node = if nodes.is_empty() {
            let node = Arc::new(Node::new(config, &self.seed, vec![], self.services));
            info!("New node {}", node.get_id());
            node.add_allowlist(&self.allowlist).expect("allowlist");
            // NOTE: if we persist to LSS, we don't actually persist the seed here,
            // and the caller must provide the seed each time we restore from persistence
            persister.new_node(&node.get_id(), &config, &*node.get_state()).expect("new_node");
            persister.new_tracker(&node.get_id(), &node.get_tracker()).expect("new_chain_tracker");
            node
        } else {
            assert_eq!(nodes.len(), 1);
            let (node_id, entry) = nodes.into_iter().next().unwrap();
            info!("Restore node {}", node_id);
            Node::restore_node(&node_id, entry, &self.seed, self.services)?
        };
        trace_node_state!(node.get_state());

        Ok(InitHandler::new(self.id, node, self.approver, self.max_protocol_version))
    }

    /// The persister
    pub fn persister(&self) -> Arc<dyn Persist> {
        self.services.persister.clone()
    }
}

impl RootHandler {
    fn channel_id(node_id: &PubKey, dbid: u64) -> ChannelId {
        let mut nonce = [0u8; 33 + 8];
        nonce[0..33].copy_from_slice(&node_id.0);
        nonce[33..].copy_from_slice(&dbid.to_le_bytes());
        let channel_id = ChannelId::new(&nonce);
        channel_id
    }

    /// Log channel information
    pub fn log_chaninfo(&self) {
        log_chaninfo(self.node.chaninfo());
    }

    /// Get the channel balances
    pub fn channel_balance(&self) -> ChannelBalance {
        self.node.channel_balance()
    }

    /// Get the current chain height based on the tracker
    pub fn get_chain_height(&self) -> u32 {
        self.node.get_chain_height()
    }

    // sign any inputs that are ours, modifying the PSBT in place
    fn sign_withdrawal(&self, streamed: &mut StreamedPSBT, utxos: Array<Utxo>) -> Result<()> {
        let psbt = &mut streamed.psbt.inner;
        let opaths = extract_psbt_output_paths(&psbt);

        let tx = &mut psbt.unsigned_tx;

        let prev_outs = psbt
            .inputs
            .iter()
            .map(|i| {
                i.witness_utxo.as_ref().expect("psbt input witness UTXOs must be populated").clone()
            })
            .collect::<Vec<_>>();

        let secp_ctx = Secp256k1::new();
        let mut uniclosekeys = Vec::new();
        let mut ipaths = Vec::new();
        for input in tx.input.iter() {
            if let Some(utxo) = utxos.iter().find(|u| {
                u.txid == input.previous_output.txid && u.outnum == input.previous_output.vout
            }) {
                ipaths.push(vec![utxo.keyindex]);
                if let Some(ci) = utxo.close_info.as_ref() {
                    let channel_id = Self::channel_id(&ci.peer_id, ci.channel_id);
                    let per_commitment_point = ci
                        .commitment_point
                        .as_ref()
                        .map(|p| PublicKey::from_slice(&p.0).expect("TODO"));

                    let ck = self.node.with_channel(&channel_id, |chan| {
                        let revocation_pubkey = per_commitment_point.as_ref().map(|p| {
                            let revocation_basepoint =
                                chan.counterparty_pubkeys().revocation_basepoint;
                            RevocationKey::from_basepoint(&secp_ctx, &revocation_basepoint, p)
                        });
                        chan.get_unilateral_close_key(&per_commitment_point, &revocation_pubkey)
                    })?;
                    uniclosekeys.push(Some(ck));
                } else {
                    uniclosekeys.push(None)
                }
            } else {
                ipaths.push(vec![]);
                uniclosekeys.push(None);
            }
        }

        // Populate script_sig for p2sh-p2wpkh signing
        for (psbt_in, tx_in) in psbt.inputs.iter_mut().zip(tx.input.iter_mut()) {
            if let Some(script) = psbt_in.redeem_script.as_ref() {
                assert!(psbt_in.final_script_sig.is_none());
                assert!(tx_in.script_sig.is_empty());
                let mut push_bytes = PushBytesBuf::new();
                push_bytes
                    .extend_from_slice(script.as_bytes())
                    .expect("push_bytes.extend_from_slice failed");
                let script_sig = script::Builder::new().push_slice(&push_bytes).into_script();
                psbt_in.final_script_sig = Some(script_sig);
            }
        }

        dbgvals!(
            ipaths,
            opaths,
            tx.txid(),
            tx,
            streamed.segwit_flags,
            DebugUnilateralCloseInfo(&uniclosekeys)
        );

        let approved = self.approver.handle_proposed_onchain(
            &self.node,
            &tx,
            &streamed.segwit_flags,
            &prev_outs,
            &uniclosekeys,
            &opaths,
        )?;

        if !approved {
            return Err(Status::failed_precondition("unapproved destination"))?;
        }

        let witvec = self.node.unchecked_sign_onchain_tx(&tx, &ipaths, &prev_outs, uniclosekeys)?;

        for (i, stack) in witvec.into_iter().enumerate() {
            if !stack.is_empty() {
                psbt.inputs[i].final_script_witness = Some(Witness::from_vec(stack));
            }
        }
        Ok(())
    }
}

impl InitHandler {
    /// Create a new InitHandler
    pub fn new(
        id: u64,
        node: Arc<Node>,
        approver: Arc<dyn Approve>,
        max_protocol_version: u32,
    ) -> InitHandler {
        InitHandler { id, node, approver, max_protocol_version, protocol_version: None }
    }

    /// Reset the handler
    pub fn reset(&mut self) {
        self.protocol_version = None;
    }

    /// Get the associated node
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// Log channel information
    pub fn log_chaninfo(&self) {
        log_chaninfo(self.node.chaninfo());
    }

    /// Handle a request message, returning a boolean indicating whether the initial negotiation is complete
    /// and a response.
    ///
    /// Panics if initial negotiation is already complete.
    pub fn handle(&mut self, msg: Message) -> Result<(bool, Option<Box<dyn SerBolt>>)> {
        assert!(self.protocol_version.is_none(), "initial negotiation already complete");
        log_request(&msg);
        let result = self.do_handle(msg);
        if let Err(ref err) = result {
            log_error(err);
        }
        let (is_done, maybe_reply) = result?;
        if let Some(ref reply) = maybe_reply {
            log_reply(&reply);
        }
        Ok((is_done, maybe_reply))
    }

    fn do_handle(&mut self, msg: Message) -> Result<(bool, Option<Box<dyn SerBolt>>)> {
        match msg {
            Message::Ping(p) => {
                info!("got ping with {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                let reply =
                    msgs::Pong { id: p.id, message: WireString("pong".as_bytes().to_vec()) };
                Ok((false, Some(Box::new(reply))))
            }
            Message::HsmdDevPreinit(m) => {
                // FIXME - this message should be disabled in production mode
                let node_id = self.node.get_id().serialize();
                // the seed is extracted before this handler is called to create the node
                let allowlist: Vec<_> = m
                    .allowlist
                    .iter()
                    .map(|ws| String::from_utf8(ws.0.clone()).expect("utf8"))
                    .collect();
                // FIXME disable in production
                self.node.add_allowlist(&allowlist)?;
                self.protocol_version = None;
                Ok((
                    false, // HsmdInit{,2} will follow ...
                    Some(Box::new(msgs::HsmdDevPreinitReply { node_id: PubKey(node_id) })),
                ))
            }
            Message::HsmdDevPreinit2(m) => {
                assert_ne!(self.node.network(), Network::Bitcoin);
                // the seed is extracted before this handler is called to create the node
                let allowlist = if let Some(ref alist) = m.options.allowlist {
                    alist.iter().map(|ws| String::from_utf8(ws.0.clone()).expect("utf8")).collect()
                } else {
                    vec![]
                };
                // FIXME disable in production
                self.node.add_allowlist(&allowlist)?;
                self.protocol_version = None;
                Ok((
                    false, // HsmdInit{,2} will follow ...
                    None,  // There is no HsmdDevPreinit2 reply
                ))
            }
            Message::HsmdInit(m) => {
                let node_id = self.node.get_id().serialize();
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let bolt12_pubkey = self.node.get_bolt12_pubkey().serialize();
                assert!(
                    m.hsm_wire_min_version <= self.max_protocol_version,
                    "node's minimum wire protocol version too large: {} > {}",
                    m.hsm_wire_min_version,
                    self.max_protocol_version
                );
                assert!(
                    m.hsm_wire_max_version >= MIN_PROTOCOL_VERSION,
                    "node's maximum wire protocol version too small: {} < {}",
                    m.hsm_wire_max_version,
                    MIN_PROTOCOL_VERSION
                );
                let mutual_version = min(self.max_protocol_version, m.hsm_wire_max_version);
                info!(
                    "signer protocol_version {}, \
                     node hsm_wire_max_version {}, \
                     setting protocol_version to {}",
                    self.max_protocol_version, m.hsm_wire_max_version, mutual_version
                );
                self.protocol_version = Some(mutual_version);
                if mutual_version < 4 {
                    return Ok((
                        true,
                        Some(Box::new(msgs::HsmdInitReplyV2 {
                            node_id: PubKey(node_id),
                            bip32: ExtKey(bip32),
                            bolt12: PubKey(bolt12_pubkey),
                        })),
                    ));
                }
                let mut hsm_capabilities = vec![
                    msgs::CheckPubKey::TYPE as u32,
                    msgs::SignAnyDelayedPaymentToUs::TYPE as u32,
                    msgs::SignAnchorspend::TYPE as u32,
                    msgs::SignHtlcTxMingle::TYPE as u32,
                    // TODO advertise splicing when it is implemented
                    // msgs::SignSpliceTx::TYPE as u32,
                    msgs::CheckOutpoint::TYPE as u32,
                    msgs::ForgetChannel::TYPE as u32,
                ];
                if mutual_version >= PROTOCOL_VERSION_REVOKE {
                    hsm_capabilities.push(msgs::RevokeCommitmentTx::TYPE as u32);
                }
                Ok((
                    true,
                    Some(Box::new(msgs::HsmdInitReplyV4 {
                        hsm_version: mutual_version,
                        hsm_capabilities: hsm_capabilities.into(),
                        node_id: PubKey(node_id),
                        bip32: ExtKey(bip32),
                        bolt12: PubKey(bolt12_pubkey),
                    })),
                ))
            }
            Message::HsmdInit2(m) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_id = self.node.get_id().serialize();
                let bolt12_pubkey = self.node.get_bolt12_pubkey().serialize();
                let allowlist: Vec<_> = m
                    .dev_allowlist
                    .iter()
                    .map(|ws| String::from_utf8(ws.0.clone()).expect("utf8"))
                    .collect();
                // FIXME disable in production
                self.node.add_allowlist(&allowlist)?;
                self.protocol_version = Some(4);
                Ok((
                    true,
                    Some(Box::new(msgs::HsmdInit2Reply {
                        node_id: PubKey(node_id),
                        bip32: ExtKey(bip32),
                        bolt12: PubKey(bolt12_pubkey),
                    })),
                ))
            }
            m => unimplemented!("init loop {}: unimplemented message {:?}", self.id, m),
        }
    }
}

impl Into<RootHandler> for InitHandler {
    fn into(self) -> RootHandler {
        let protocol_version = self.protocol_version.expect("initial negotiation not complete");
        RootHandler { id: self.id, node: self.node, approver: self.approver, protocol_version }
    }
}

impl Handler for RootHandler {
    fn do_handle(&self, msg: Message) -> Result<Box<dyn SerBolt>> {
        match msg {
            Message::Ping(p) => {
                info!("got ping with {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                let reply =
                    msgs::Pong { id: p.id, message: WireString("pong".as_bytes().to_vec()) };
                Ok(Box::new(reply))
            }
            Message::Memleak(_m) => Ok(Box::new(msgs::MemleakReply { result: false })),
            Message::SignBolt12(m) => {
                let tweak =
                    if m.public_tweak.is_empty() { None } else { Some(m.public_tweak.as_slice()) };
                let sig = self.node.sign_bolt12(
                    &m.message_name.0,
                    &m.field_name.0,
                    &m.merkle_root.0,
                    tweak,
                )?;
                Ok(Box::new(SignBolt12Reply { signature: Signature(sig.as_ref().clone()) }))
            }
            Message::PreapproveInvoice(m) => {
                let invstr = String::from_utf8(m.invstring.0)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;
                let invoice = Invoice::from_str(&invstr)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;
                let result = self.approver.handle_proposed_invoice(&self.node, invoice)?;
                Ok(Box::new(PreapproveInvoiceReply { result }))
            }
            Message::PreapproveKeysend(m) => {
                let result = self.approver.handle_proposed_keysend(
                    &self.node,
                    PublicKey::from_slice(&m.destination.0)
                        .map_err(|e| Status::invalid_argument(e.to_string()))?,
                    PaymentHash(m.payment_hash.0),
                    m.amount_msat,
                )?;
                Ok(Box::new(PreapproveKeysendReply { result }))
            }
            Message::DeriveSecret(m) => {
                let secret = self.node.derive_secret(&m.info);
                Ok(Box::new(DeriveSecretReply {
                    secret: Secret(secret[..].try_into().expect("secret")),
                }))
            }
            Message::SignMessage(m) => {
                let sig = self.node.sign_message(&m.message)?;
                let sig_slice = sig.try_into().expect("recoverable signature size");
                Ok(Box::new(msgs::SignMessageReply { signature: RecoverableSignature(sig_slice) }))
            }
            Message::Ecdh(m) => {
                let pubkey = PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                Ok(Box::new(msgs::EcdhReply { secret: Secret(secret) }))
            }
            Message::NewChannel(m) => {
                let channel_id = Self::channel_id(&m.node_id, m.dbid);
                self.node.new_channel(Some(channel_id), &self.node)?;
                Ok(Box::new(msgs::NewChannelReply {}))
            }
            Message::ForgetChannel(m) => {
                let channel_id = Self::channel_id(&m.node_id, m.dbid);
                self.node.forget_channel(&channel_id)?;
                Ok(Box::new(msgs::ForgetChannelReply {}))
            }
            Message::GetChannelBasepoints(m) => {
                let channel_id = Self::channel_id(&m.node_id, m.dbid);
                let bps = self
                    .node
                    .with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints()))?;

                let basepoints = Basepoints {
                    revocation: PubKey(bps.revocation_basepoint.0.serialize()),
                    payment: PubKey(bps.payment_point.serialize()),
                    htlc: PubKey(bps.htlc_basepoint.0.serialize()),
                    delayed_payment: PubKey(bps.delayed_payment_basepoint.0.serialize()),
                };
                let funding = PubKey(bps.funding_pubkey.serialize());

                Ok(Box::new(msgs::GetChannelBasepointsReply { basepoints, funding }))
            }
            Message::SignWithdrawal(m) => {
                let mut streamed = m.psbt.0;
                let utxos = m.utxos;

                #[cfg(not(feature = "log_pretty_print"))]
                debug!("SignWithdrawal psbt {:?}", streamed);
                #[cfg(feature = "log_pretty_print")]
                debug!("SignWithdrawal psbt {:#?}", streamed);

                self.sign_withdrawal(&mut streamed, utxos)?;

                Ok(Box::new(msgs::SignWithdrawalReply { psbt: WithSize(streamed.psbt) }))
            }
            Message::SignInvoice(m) => {
                let hrp = String::from_utf8(m.hrp.to_vec()).expect("hrp");
                let hrp_bytes = hrp.as_bytes();
                let data: Vec<_> = m
                    .u5bytes
                    .iter()
                    .map(|b| u5::try_from_u8(*b).expect("invoice not base32"))
                    .collect();
                let sig = self.node.sign_invoice(hrp_bytes, &data)?;
                let (rid, ser) = sig.serialize_compact();
                let mut sig_slice = [0u8; 65];
                sig_slice[0..64].copy_from_slice(&ser);
                sig_slice[64] = rid.to_i32() as u8;
                Ok(Box::new(msgs::SignInvoiceReply { signature: RecoverableSignature(sig_slice) }))
            }
            Message::SignHtlcTxMingle(m) => {
                // this is just an alias for SignWithdrawal (?!), and doesn't actually sign the HTLC tx -
                // those are signed by calls such as `SignAnyLocalHtlcTx`
                let mut streamed = m.psbt.0;
                let utxos = m.utxos;

                #[cfg(not(feature = "log_pretty_print"))]
                debug!("SignHtlcTxMingle psbt {:?}", streamed);
                #[cfg(feature = "log_pretty_print")]
                debug!("SignHtlcTxMingle psbt {:#?}", streamed);

                self.sign_withdrawal(&mut streamed, utxos)?;

                Ok(Box::new(msgs::SignHtlcTxMingleReply { psbt: WithSize(streamed.psbt) }))
            }
            Message::SignSpliceTx(_m) => {
                unimplemented!()
            }
            Message::SignCommitmentTx(m) => {
                // TODO why not channel handler??
                let channel_id = Self::channel_id(&m.peer_id, m.dbid);
                let tx = m.tx.0;

                // WORKAROUND - sometimes c-lightning calls handle_sign_commitment_tx
                // with mutual close transactions.  We can tell the difference because
                // the locktime field will be set to 0 for a mutual close.
                let sig = if tx.lock_time.to_consensus_u32() == 0 {
                    let opaths = extract_psbt_output_paths(&m.psbt.0.inner);
                    self.node
                        .with_channel(&channel_id, |chan| chan.sign_mutual_close_tx(&tx, &opaths))?
                } else {
                    // We ignore everything in the message other than the commitment number,
                    // since the signer already has this info.
                    self.node
                        .with_channel(&channel_id, |chan| {
                            chan.sign_holder_commitment_tx_phase2(m.commitment_number)
                        })?
                        .0
                };
                Ok(Box::new(msgs::SignCommitmentTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::TipInfo(_) => {
                let tracker = self.node.get_tracker();
                Ok(Box::new(msgs::TipInfoReply {
                    height: tracker.height(),
                    block_hash: tracker.tip().0.block_hash(),
                }))
            }
            Message::ForwardWatches(_) => {
                let (txids, outpoints) = self.node.get_tracker().get_all_forward_watches();
                Ok(Box::new(msgs::ForwardWatchesReply {
                    txids: txids.into(),
                    outpoints: outpoints.into(),
                }))
            }
            Message::ReverseWatches(_) => {
                let (txids, outpoints) = self.node.get_tracker().get_all_reverse_watches();
                Ok(Box::new(msgs::ReverseWatchesReply {
                    txids: txids.into(),
                    outpoints: outpoints.into(),
                }))
            }
            Message::AddBlock(m) => {
                let mut tracker = self.node.get_tracker();
                let proof = m
                    .unspent_proof
                    .ok_or(Status::invalid_argument("could not deserialize proof"))?;
                match tracker
                    .add_block(deserialize(m.header.0.as_slice()).expect("header"), proof.0)
                {
                    Ok(_) => (),
                    Err(TrackerError::OrphanBlock(msg)) => {
                        return Ok(Box::new(msgs::SignerError {
                            code: msgs::CODE_ORPHAN_BLOCK,
                            message: WireString(msg.into_bytes()),
                        }));
                    }
                    Err(_e) => panic!("add_block"),
                }
                self.node
                    .get_persister()
                    .update_tracker(&self.node.get_id(), &tracker)
                    .unwrap_or_else(|e| {
                        panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
                    });
                #[cfg(feature = "timeless_workaround")]
                {
                    // WORKAROUND for #206, #339, #235 - If our implementation has no clock use the
                    // BlockHeader timestamp.
                    use crate::handler::bitcoin::blockdata::block::Header as BlockHeader;
                    use core::time::Duration;
                    let header: BlockHeader =
                        deserialize(m.header.0.as_slice()).expect("header again");
                    let old_now = self.node.get_clock().now();
                    let new_now = tracker.tip_time();
                    // Don't allow retrograde time updates ...
                    if new_now > old_now {
                        self.node.get_clock().set_workaround_time(new_now);
                    }
                }
                Ok(Box::new(msgs::AddBlockReply {}))
            }
            Message::RemoveBlock(m) => {
                let mut tracker = self.node.get_tracker();
                let proof = m
                    .unspent_proof
                    .map(|prf| deserialize(prf.0.as_slice()).expect("deserialize TxoProof"))
                    .ok_or(Status::invalid_argument("could not deserialize proof"))?;
                let prev_headers = Headers(m.prev_block_header, m.prev_filter_header);
                tracker.remove_block(proof, prev_headers).expect("remove_block");
                self.node
                    .get_persister()
                    .update_tracker(&self.node.get_id(), &tracker)
                    .unwrap_or_else(|e| {
                        panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
                    });
                Ok(Box::new(msgs::RemoveBlockReply {}))
            }
            Message::BlockChunk(m) => {
                let mut tracker = self.node.get_tracker();
                tracker.block_chunk(m.hash, m.offset, &m.content.0).expect("block_chunk");
                Ok(Box::new(msgs::BlockChunkReply {}))
            }
            Message::GetHeartbeat(_m) => {
                let heartbeat = self.node.get_heartbeat();
                let ser_hb = to_vec(&heartbeat).expect("heartbeat");
                Ok(Box::new(msgs::GetHeartbeatReply { heartbeat: ser_hb.into() }))
            }
            Message::NodeInfo(_m) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_id = self.node.get_id().serialize();
                let node_info = msgs::NodeInfoReply {
                    network_name: WireString(self.node.network().to_string().into_bytes()),
                    node_id: PubKey(node_id),
                    bip32: ExtKey(bip32),
                };
                Ok(Box::new(node_info))
            }
            Message::Unknown(u) => {
                unimplemented!("loop {}: unknown message type {}", self.id, u.message_type)
            }
            Message::SignNodeAnnouncement(m) => {
                let message = m.announcement[64 + 2..].to_vec();
                let sig = self.node.sign_node_announcement(&message)?;

                Ok(Box::new(msgs::SignNodeAnnouncementReply {
                    signature: Signature(sig.serialize_compact()),
                }))
            }
            Message::SignChannelUpdate(m) => {
                // NOTE this is called without a dbid by gossipd, so it gets dispatched to the root handler
                let message = m.update[2 + 64..].to_vec();
                let sig = self.node.sign_channel_update(&message)?;
                let mut update = m.update;
                update[2..2 + 64].copy_from_slice(&sig.serialize_compact());
                Ok(Box::new(msgs::SignChannelUpdateReply { update }))
            }
            Message::SignGossipMessage(m) => {
                let node_sig = self.node.sign_channel_update(&m.message.0)?;
                Ok(Box::new(msgs::SignGossipMessageReply {
                    signature: Signature(node_sig.serialize_compact()),
                }))
            }
            Message::CheckPubKey(m) => Ok(Box::new(msgs::CheckPubKeyReply {
                ok: self.node.check_wallet_pubkey(
                    &[m.index],
                    bitcoin::PublicKey::from_slice(&m.pubkey.0)
                        .map_err(|_| Status::invalid_argument("bad public key"))?,
                )?,
            })),
            Message::SignAnyDelayedPaymentToUs(m) => sign_delayed_payment_to_us(
                &self.node,
                &Self::channel_id(&m.peer_id, m.dbid),
                m.commitment_number,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.input,
            ),
            Message::SignAnyRemoteHtlcToUs(m) => sign_remote_htlc_to_us(
                &self.node,
                &Self::channel_id(&m.peer_id, m.dbid),
                &m.remote_per_commitment_point,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.option_anchors,
                m.input,
            ),
            Message::SignAnyPenaltyToUs(m) => sign_penalty_to_us(
                &self.node,
                &Self::channel_id(&m.peer_id, m.dbid),
                &m.revocation_secret,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.input,
            ),
            Message::SignAnyLocalHtlcTx(m) => sign_local_htlc_tx(
                &self.node,
                &Self::channel_id(&m.peer_id, m.dbid),
                m.commitment_number,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.option_anchors,
                m.input,
            ),
            Message::SignAnyChannelAnnouncement(m) => {
                let (node_signature, bitcoin_signature) = sign_channel_announcement(
                    &self.node,
                    &Self::channel_id(&m.peer_id, m.dbid),
                    &m.announcement,
                )?;
                Ok(Box::new(msgs::SignAnyChannelAnnouncementReply {
                    node_signature,
                    bitcoin_signature,
                }))
            }
            Message::SignAnchorspend(m) => {
                let mut streamed = m.psbt.0;
                let utxos = m.utxos;

                #[cfg(not(feature = "log_pretty_print"))]
                debug!("SignAnchorspend psbt {:?}", streamed);
                #[cfg(feature = "log_pretty_print")]
                debug!("SignAnchorspend psbt {:#?}", streamed);

                let channel_id = Self::channel_id(&m.peer_id, m.dbid);
                self.sign_withdrawal(&mut streamed, utxos)?;
                let anchor_redeemscript = self
                    .node
                    .with_channel(&channel_id, |channel| Ok(channel.get_anchor_redeemscript()))?;
                let anchor_scriptpubkey = anchor_redeemscript.to_v0_p2wsh();

                let mut psbt = streamed.psbt().clone();
                let anchor_index = psbt
                    .inputs
                    .iter()
                    .position(|input| {
                        input
                            .witness_utxo
                            .as_ref()
                            .map(|txout| txout.script_pubkey == anchor_scriptpubkey)
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| Status::invalid_argument("anchor not found in psbt"))?;
                let sig = self.node.with_channel(&channel_id, |channel| {
                    Ok(channel.sign_holder_anchor_input(&psbt.unsigned_tx, anchor_index)?)
                })?;
                let witness = vec![signature_to_bitcoin_vec(sig), anchor_redeemscript.to_bytes()];
                psbt.inputs[anchor_index].final_script_witness = Some(Witness::from_vec(witness));
                Ok(Box::new(msgs::SignAnchorspendReply {
                    psbt: WithSize(PsbtWrapper { inner: psbt }),
                }))
            }
            m => unimplemented!("loop {}: unimplemented message {:?}", self.id, m),
        }
    }

    fn client_id(&self) -> u64 {
        self.id
    }

    fn for_new_client(&self, client_id: u64, peer_id: PubKey, dbid: u64) -> ChannelHandler {
        let channel_id = Self::channel_id(&peer_id, dbid);
        ChannelHandler {
            id: client_id,
            node: Arc::clone(&self.node),
            protocol_version: self.protocol_version,
            peer_id: peer_id.0,
            dbid,
            channel_id,
        }
    }

    fn node(&self) -> &Arc<Node> {
        &self.node
    }
}

fn extract_output_path(
    bip32_derivation: &BTreeMap<PublicKey, KeySource>,
    tap_key_origins: &BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
) -> Vec<u32> {
    let path = if !bip32_derivation.is_empty() {
        if bip32_derivation.len() > 1 {
            unimplemented!("len > 1");
        }
        let (_fingerprint, path) = bip32_derivation.iter().next().unwrap().1;
        path.clone()
    } else if !tap_key_origins.is_empty() {
        if tap_key_origins.len() > 1 {
            unimplemented!("len > 1");
        }
        let (_xpub, (hashes, source)) = tap_key_origins.iter().next().unwrap();
        if !hashes.is_empty() {
            unimplemented!("hashes not empty");
        }
        source.1.clone()
    } else {
        DerivationPath::from(vec![])
    };
    path.into_iter().map(|i| i.clone().into()).collect()
}

fn extract_psbt_output_paths(psbt: &PartiallySignedTransaction) -> Vec<Vec<u32>> {
    psbt.outputs
        .iter()
        .map(|o| extract_output_path(&o.bip32_derivation, &o.tap_key_origins))
        .collect::<Vec<Vec<u32>>>()
}

/// Protocol handler
pub struct ChannelHandler {
    id: u64,
    node: Arc<Node>,
    protocol_version: u32,
    #[allow(unused)]
    peer_id: [u8; 33],
    dbid: u64,
    channel_id: ChannelId,
}

impl ChannelHandler {
    /// A unique ID for this channel
    pub fn dbid(&self) -> u64 {
        self.dbid
    }
}

impl Handler for ChannelHandler {
    fn do_handle(&self, msg: Message) -> Result<Box<dyn SerBolt>> {
        match msg {
            Message::Memleak(_m) => Ok(Box::new(msgs::MemleakReply { result: false })),
            Message::CheckFutureSecret(m) => {
                let secret_key = SecretKey::from_slice(&m.secret.0)
                    .map_err(|_| Status::invalid_argument("bad secret key"))?;
                let result = self.node.with_channel(&self.channel_id, |chan| {
                    chan.check_future_secret(m.commitment_number, &secret_key)
                })?;
                Ok(Box::new(msgs::CheckFutureSecretReply { result }))
            }
            Message::Ecdh(m) => {
                // TODO DRY with root handler
                let pubkey = PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                Ok(Box::new(msgs::EcdhReply { secret: Secret(secret) }))
            }
            Message::GetPerCommitmentPoint(m) => {
                let commitment_number = m.commitment_number;
                let res: core::result::Result<(PublicKey, Option<SecretKey>), status::Status> =
                    self.node.with_channel_base(&self.channel_id, |base| {
                        let point = base.get_per_commitment_point(commitment_number)?;
                        let secret = if self.protocol_version < PROTOCOL_VERSION_NO_SECRET
                            && commitment_number >= 2
                        {
                            Some(base.get_per_commitment_secret(commitment_number - 2)?)
                        } else {
                            None
                        };
                        Ok((point, secret))
                    });

                let (point, old_secret) = res?;

                let old_secret_reply =
                    old_secret.clone().map(|s| DisclosedSecret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::GetPerCommitmentPointReply {
                    point: PubKey(point.serialize()),
                    secret: old_secret_reply,
                }))
            }
            Message::GetPerCommitmentPoint2(m) => {
                let commitment_number = m.commitment_number;
                let point = self.node.with_channel_base(&self.channel_id, |base| {
                    base.get_per_commitment_point(commitment_number)
                })?;

                Ok(Box::new(msgs::GetPerCommitmentPoint2Reply { point: PubKey(point.serialize()) }))
            }
            Message::SetupChannel(m) => {
                let funding_outpoint =
                    OutPoint { txid: m.funding_txid, vout: m.funding_txout as u32 };

                let holder_shutdown_script = if m.local_shutdown_script.is_empty() {
                    None
                } else {
                    Some(ScriptBuf::from_bytes(m.local_shutdown_script.as_slice().to_vec()))
                };

                let points = m.remote_basepoints;
                let counterparty_points = ChannelPublicKeys {
                    funding_pubkey: extract_pubkey(&m.remote_funding_pubkey),
                    revocation_basepoint: points.revocation.into(),
                    payment_point: points.payment.into(),
                    delayed_payment_basepoint: points.delayed_payment.into(),
                    htlc_basepoint: points.htlc.into(),
                };

                let counterparty_shutdown_script = if m.remote_shutdown_script.is_empty() {
                    None
                } else {
                    Some(ScriptBuf::from_bytes(m.remote_shutdown_script.as_slice().to_vec()))
                };

                // FIXME
                let holder_shutdown_key_path = vec![];
                let setup = ChannelSetup {
                    is_outbound: m.is_outbound,
                    channel_value_sat: m.channel_value,
                    push_value_msat: m.push_value,
                    funding_outpoint,
                    holder_selected_contest_delay: m.to_self_delay as u16,
                    counterparty_points,
                    holder_shutdown_script,
                    counterparty_selected_contest_delay: m.remote_to_self_delay as u16,
                    counterparty_shutdown_script,
                    commitment_type: channel_type_to_commitment_type(&m.channel_type),
                };
                self.node.setup_channel(
                    self.channel_id.clone(),
                    None,
                    setup,
                    &holder_shutdown_key_path,
                )?;

                Ok(Box::new(msgs::SetupChannelReply {}))
            }
            Message::CheckOutpoint(m) => {
                let funding_outpoint =
                    OutPoint { txid: m.funding_txid, vout: m.funding_txout as u32 };
                // FIXME - make the call on the node!
                warn!("null placeholder for CheckOutpoint on outpoint {:?}", funding_outpoint);
                Ok(Box::new(msgs::CheckOutpointReply { is_buried: true }))
            }
            Message::LockOutpoint(m) => {
                let funding_outpoint =
                    OutPoint { txid: m.funding_txid, vout: m.funding_txout as u32 };
                // FIXME - make the call on the node!
                warn!("null placeholder for LockOutpoint on outpoint {:?}", funding_outpoint);
                Ok(Box::new(msgs::LockOutpointReply {}))
            }
            Message::SignRemoteHtlcTx(m) => {
                let psbt = &m.psbt.inner;
                let tx = m.tx.0;
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                assert_eq!(psbt.outputs.len(), 1);
                assert_eq!(psbt.inputs.len(), 1);
                assert_eq!(tx.output.len(), 1);
                assert_eq!(tx.input.len(), 1);
                let redeemscript = ScriptBuf::from(m.wscript.0);
                let htlc_amount_sat = psbt.inputs[0]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let output_witscript =
                    psbt.outputs[0].witness_script.as_ref().expect("output witscript");
                let sig = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_htlc_tx(
                        &tx,
                        &remote_per_commitment_point,
                        &redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                })?;

                Ok(Box::new(msgs::SignTxReply { signature: typed_to_bitcoin_sig(sig) }))
            }
            Message::SignRemoteCommitmentTx(m) => {
                let psbt = &m.psbt.inner;
                let witscripts = extract_psbt_witscripts(&psbt);
                let tx = m.tx;
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                // Flip offered and received
                let (offered_htlcs, received_htlcs) = extract_htlcs(&m.htlcs);
                let sig = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_commitment_tx(
                        &tx,
                        &witscripts,
                        &remote_per_commitment_point,
                        commit_num,
                        feerate_sat_per_kw,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::SignRemoteCommitmentTx2(m) => {
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                // Flip offered and received
                let (offered_htlcs, received_htlcs) = extract_htlcs(&m.htlcs);
                let (sig, htlc_sigs) = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_commitment_tx_phase2(
                        &remote_per_commitment_point,
                        commit_num,
                        feerate_sat_per_kw,
                        m.to_local_value_sat,
                        m.to_remote_value_sat,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                })?;
                Ok(Box::new(msgs::SignCommitmentTxWithHtlcsReply {
                    signature: to_bitcoin_sig(sig),
                    htlc_signatures: Array(
                        htlc_sigs.into_iter().map(|s| to_bitcoin_sig(s)).collect(),
                    ),
                }))
            }
            Message::SignDelayedPaymentToUs(m) => sign_delayed_payment_to_us(
                &self.node,
                &self.channel_id,
                m.commitment_number,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                0,
            ),
            Message::SignRemoteHtlcToUs(m) => sign_remote_htlc_to_us(
                &self.node,
                &self.channel_id,
                &m.remote_per_commitment_point,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.option_anchors,
                0,
            ),
            Message::SignLocalHtlcTx(m) => sign_local_htlc_tx(
                &self.node,
                &self.channel_id,
                m.commitment_number,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                m.option_anchors,
                0,
            ),
            Message::SignMutualCloseTx(m) => {
                let psbt = &m.psbt.inner;
                let tx = m.tx;
                let opaths = extract_psbt_output_paths(&psbt);
                debug!(
                    "mutual close derivation paths {:?} addresses {:?}",
                    opaths,
                    tx.output
                        .iter()
                        .map(|o| Address::from_script(&o.script_pubkey, self.node.network()))
                        .collect::<Vec<_>>()
                );
                let sig = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_mutual_close_tx(&tx, &opaths)
                })?;
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::SignMutualCloseTx2(m) => {
                let sig = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_mutual_close_tx_phase2(
                        m.to_local_value_sat,
                        m.to_remote_value_sat,
                        &to_script(&m.local_script),
                        &to_script(&m.remote_script),
                        &m.local_wallet_path_hint,
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::ValidateCommitmentTx(m) => {
                let psbt = &m.psbt.inner;
                let witscripts = extract_psbt_witscripts(&psbt);
                let tx = m.tx.0;
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                let (received_htlcs, offered_htlcs) = extract_htlcs(&m.htlcs);
                let commit_sig =
                    ecdsa::Signature::from_compact(&m.signature.signature.0).expect("signature");
                assert_eq!(m.signature.sighash, EcdsaSighashType::All as u8);
                let htlc_sigs: Vec<_> = m
                    .htlc_signatures
                    .iter()
                    .map(|s| {
                        assert!(
                            s.sighash == EcdsaSighashType::All as u8
                                || s.sighash == EcdsaSighashType::SinglePlusAnyoneCanPay as u8
                        );
                        ecdsa::Signature::from_compact(&s.signature.0).expect("signature")
                    })
                    .collect();
                let (next_per_commitment_point, old_secret) =
                    self.node.with_channel(&self.channel_id, |chan| {
                        chan.validate_holder_commitment_tx(
                            &tx,
                            &witscripts,
                            commit_num,
                            feerate_sat_per_kw,
                            offered_htlcs.clone(),
                            received_htlcs.clone(),
                            &commit_sig,
                            &htlc_sigs,
                        )?;
                        if self.protocol_version < PROTOCOL_VERSION_REVOKE {
                            // The older protcol presumes the previous is immediately revoked
                            chan.revoke_previous_holder_commitment(commit_num)
                        } else {
                            // The newer protocol defers until an explicit `RevokeCommitmentTx`
                            if commit_num > 0 {
                                Ok((chan.get_per_commitment_point(commit_num + 1)?, None))
                            } else {
                                // Commitment 0 is special because it doesn't
                                // have a previous commitment.  Since the
                                // revocation of the previous commitment normally
                                // makes a new commitment "current" this final
                                // step must be invoked explicitly.
                                Ok((chan.activate_initial_commitment()?, None))
                            }
                        }
                    })?;
                let old_secret_reply =
                    old_secret.map(|s| DisclosedSecret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::ValidateCommitmentTxReply {
                    next_per_commitment_point: PubKey(next_per_commitment_point.serialize()),
                    old_commitment_secret: old_secret_reply,
                }))
            }
            Message::ValidateCommitmentTx2(m) => {
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                let (received_htlcs, offered_htlcs) = extract_htlcs(&m.htlcs);
                let commit_sig =
                    ecdsa::Signature::from_compact(&m.signature.signature.0).expect("signature");
                assert_eq!(m.signature.sighash, EcdsaSighashType::All as u8);
                let htlc_sigs: Vec<_> = m
                    .htlc_signatures
                    .iter()
                    .map(|s| {
                        assert!(
                            s.sighash == EcdsaSighashType::All as u8
                                || s.sighash == EcdsaSighashType::SinglePlusAnyoneCanPay as u8
                        );
                        ecdsa::Signature::from_compact(&s.signature.0).expect("signature")
                    })
                    .collect();
                let (next_per_commitment_point, old_secret) =
                    self.node.with_channel(&self.channel_id, |chan| {
                        chan.validate_holder_commitment_tx_phase2(
                            commit_num,
                            feerate_sat_per_kw,
                            m.to_local_value_sat,
                            m.to_remote_value_sat,
                            offered_htlcs.clone(),
                            received_htlcs.clone(),
                            &commit_sig,
                            &htlc_sigs,
                        )?;
                        if self.protocol_version < PROTOCOL_VERSION_REVOKE {
                            // The older protcol presumes the previous is immediately revoked
                            chan.revoke_previous_holder_commitment(commit_num)
                        } else {
                            // The newer protocol defers until an explicit `RevokeCommitmentTx`
                            if commit_num > 0 {
                                Ok((chan.get_per_commitment_point(commit_num + 1)?, None))
                            } else {
                                // Commitment 0 is special because it doesn't
                                // have a previous commitment.  Since the
                                // revocation of the previous commitment normally
                                // makes a new commitment "current" this final
                                // step must be invoked explicitly.
                                Ok((chan.activate_initial_commitment()?, None))
                            }
                        }
                    })?;
                let old_secret_reply =
                    old_secret.map(|s| DisclosedSecret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::ValidateCommitmentTxReply {
                    next_per_commitment_point: PubKey(next_per_commitment_point.serialize()),
                    old_commitment_secret: old_secret_reply,
                }))
            }
            Message::RevokeCommitmentTx(m) => {
                if self.protocol_version < PROTOCOL_VERSION_REVOKE {
                    return Err(Status::invalid_argument(format!(
                        "RevokeCommitmentTx called with hsmd_protocol_version {} < {}",
                        self.protocol_version, PROTOCOL_VERSION_REVOKE,
                    )))?;
                }
                let commit_num = m.commitment_number;
                let (next_per_commitment_point, old_secret) =
                    self.node.with_channel(&self.channel_id, |chan| {
                        chan.revoke_previous_holder_commitment(commit_num + 1)
                    })?;
                let old_secret_reply =
                    old_secret.map(|s| DisclosedSecret(s[..].try_into().unwrap()));
                let next_per_commitment_point = PubKey(next_per_commitment_point.serialize());
                let old_commitment_secret = old_secret_reply.ok_or_else(|| {
                    Status::invalid_argument(format!("no old secret for commitment {}", commit_num))
                })?;
                Ok(Box::new(msgs::RevokeCommitmentTxReply {
                    next_per_commitment_point,
                    old_commitment_secret,
                }))
            }

            Message::SignLocalCommitmentTx2(m) => {
                let (sig, htlc_sigs) = self.node.with_channel(&self.channel_id, |chan| {
                    chan.sign_holder_commitment_tx_phase2(m.commitment_number)
                })?;
                Ok(Box::new(msgs::SignCommitmentTxWithHtlcsReply {
                    signature: to_bitcoin_sig(sig),
                    htlc_signatures: Array(
                        htlc_sigs.into_iter().map(|s| to_bitcoin_sig(s)).collect(),
                    ),
                }))
            }
            Message::ValidateRevocation(m) => {
                let revoke_num = m.commitment_number;
                let old_secret = SecretKey::from_slice(&m.commitment_secret.0).expect("secret");
                self.node.with_channel(&self.channel_id, |chan| {
                    chan.validate_counterparty_revocation(revoke_num, &old_secret)
                })?;
                Ok(Box::new(msgs::ValidateRevocationReply {}))
            }
            Message::SignPenaltyToUs(m) => sign_penalty_to_us(
                &self.node,
                &self.channel_id,
                &m.revocation_secret,
                &m.tx,
                &m.psbt.inner,
                &m.wscript,
                0,
            ),
            Message::SignChannelAnnouncement(m) => {
                let (node_signature, bitcoin_signature) =
                    sign_channel_announcement(&self.node, &self.channel_id, &m.announcement)?;
                Ok(Box::new(msgs::SignChannelAnnouncementReply {
                    node_signature,
                    bitcoin_signature,
                }))
            }
            Message::Unknown(u) => {
                unimplemented!("cloop {}: unknown message type {}", self.id, u.message_type)
            }
            m => unimplemented!("cloop {}: unimplemented message {:?}", self.id, m),
        }
    }

    fn client_id(&self) -> u64 {
        self.id
    }

    fn for_new_client(&self, _client_id: u64, _peer_id: PubKey, _dbid: u64) -> ChannelHandler {
        unimplemented!("cannot create a sub-handler from a channel handler");
    }

    fn node(&self) -> &Arc<Node> {
        &self.node
    }
}

fn sign_delayed_payment_to_us(
    node: &Node,
    channel_id: &ChannelId,
    commitment_number: u64,
    tx: &Transaction,
    psbt: &PartiallySignedTransaction,
    wscript: &Octets,
    input: u32,
) -> Result<Box<dyn SerBolt>> {
    // FIXME CLN is sending an incorrect tx in the psbt, so use the outer one in the message instead
    let commitment_number = commitment_number;
    let redeemscript = ScriptBuf::from(wscript.0.clone());
    let input = input as usize;
    let htlc_amount_sat =
        psbt.inputs[input].witness_utxo.as_ref().expect("will only spend witness UTXOs").value;
    let wallet_paths = extract_psbt_output_paths(&psbt);
    let sig = node.with_channel(channel_id, |chan| {
        chan.sign_delayed_sweep(
            &tx,
            input,
            commitment_number,
            &redeemscript,
            htlc_amount_sat,
            &wallet_paths[0],
        )
    })?;
    Ok(Box::new(msgs::SignTxReply {
        signature: BitcoinSignature {
            signature: Signature(sig.serialize_compact()),
            sighash: EcdsaSighashType::All as u8,
        },
    }))
}

fn sign_remote_htlc_to_us(
    node: &Node,
    channel_id: &ChannelId,
    remote_per_commitment_point: &PubKey,
    tx: &Transaction,
    psbt: &PartiallySignedTransaction,
    wscript: &Octets,
    _option_anchors: bool,
    input: u32,
) -> Result<Box<dyn SerBolt>> {
    let remote_per_commitment_point =
        PublicKey::from_slice(&remote_per_commitment_point.0).expect("pubkey");
    let redeemscript = ScriptBuf::from(wscript.0.clone());
    let input = input as usize;
    let htlc_amount_sat =
        psbt.inputs[input].witness_utxo.as_ref().expect("will only spend witness UTXOs").value;
    let wallet_paths = extract_psbt_output_paths(&psbt);
    let sig = node.with_channel(channel_id, |chan| {
        chan.sign_counterparty_htlc_sweep(
            &tx,
            input,
            &remote_per_commitment_point,
            &redeemscript,
            htlc_amount_sat,
            &wallet_paths[0],
        )
    })?;
    Ok(Box::new(msgs::SignTxReply {
        signature: BitcoinSignature {
            signature: Signature(sig.serialize_compact()),
            sighash: EcdsaSighashType::All as u8,
        },
    }))
}

fn sign_local_htlc_tx(
    node: &Node,
    channel_id: &ChannelId,
    commitment_number: u64,
    tx: &Transaction,
    psbt: &PartiallySignedTransaction,
    wscript: &Octets,
    _option_anchors: bool,
    input: u32,
) -> Result<Box<dyn SerBolt>> {
    let commitment_number = commitment_number;
    let redeemscript = ScriptBuf::from(wscript.0.clone());
    let input = input as usize;
    let htlc_amount_sat =
        psbt.inputs[input].witness_utxo.as_ref().expect("will only spend witness UTXOs").value;
    let output_witscript = psbt.outputs[0].witness_script.as_ref().expect("output witscript");
    let sig = node.with_channel(channel_id, |chan| {
        chan.sign_holder_htlc_tx(
            &tx,
            commitment_number,
            None,
            &redeemscript,
            htlc_amount_sat,
            output_witscript,
        )
    })?;
    Ok(Box::new(msgs::SignTxReply {
        signature: BitcoinSignature {
            signature: Signature(sig.sig.serialize_compact()),
            sighash: sig.typ as u8,
        },
    }))
}

fn sign_penalty_to_us(
    node: &Node,
    channel_id: &ChannelId,
    revocation_secret: &DisclosedSecret,
    tx: &Transaction,
    psbt: &PartiallySignedTransaction,
    wscript: &Octets,
    input: u32,
) -> Result<Box<dyn SerBolt>> {
    let revocation_secret = SecretKey::from_slice(&revocation_secret.0).expect("secret");
    let redeemscript = ScriptBuf::from(wscript.0.clone());
    let input = input as usize;
    let htlc_amount_sat =
        psbt.inputs[input].witness_utxo.as_ref().expect("will only spend witness UTXOs").value;
    let wallet_paths = extract_psbt_output_paths(&psbt);
    let sig = node.with_channel(&channel_id, |chan| {
        chan.sign_justice_sweep(
            &tx,
            input,
            &revocation_secret,
            &redeemscript,
            htlc_amount_sat,
            &wallet_paths[0],
        )
    })?;
    Ok(Box::new(msgs::SignTxReply {
        signature: BitcoinSignature {
            signature: Signature(sig.serialize_compact()),
            sighash: EcdsaSighashType::All as u8,
        },
    }))
}

fn sign_channel_announcement(
    node: &Node,
    channel_id: &ChannelId,
    announcement: &Octets,
) -> Result<(Signature, Signature)> {
    let message = announcement[256 + 2..].to_vec();
    let bitcoin_sig = node.with_channel(channel_id, |chan| {
        Ok(chan.sign_channel_announcement_with_funding_key(&message))
    })?;
    let node_sig = node.sign_channel_update(&message)?;
    Ok((Signature(node_sig.serialize_compact()), Signature(bitcoin_sig.serialize_compact())))
}

fn extract_pubkey(key: &PubKey) -> PublicKey {
    PublicKey::from_slice(&key.0).expect("pubkey")
}

fn extract_psbt_witscripts(psbt: &PartiallySignedTransaction) -> Vec<Vec<u8>> {
    psbt.outputs
        .iter()
        .map(|o| o.witness_script.clone().unwrap_or(ScriptBuf::new()))
        .map(|s| s[..].to_bytes())
        .collect()
}

fn extract_htlcs(htlcs: &Vec<Htlc>) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
    let offered_htlcs: Vec<HTLCInfo2> = htlcs
        .iter()
        .filter(|h| h.side == Htlc::LOCAL)
        .map(|h| HTLCInfo2 {
            value_sat: h.amount / 1000,
            payment_hash: PaymentHash(h.payment_hash.0),
            cltv_expiry: h.ctlv_expiry,
        })
        .collect();
    let received_htlcs: Vec<HTLCInfo2> = htlcs
        .iter()
        .filter(|h| h.side == Htlc::REMOTE)
        .map(|h| HTLCInfo2 {
            value_sat: h.amount / 1000,
            payment_hash: PaymentHash(h.payment_hash.0),
            cltv_expiry: h.ctlv_expiry,
        })
        .collect();
    (received_htlcs, offered_htlcs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning_signer::channel::CommitmentType;

    #[test]
    fn test_der() {
        let sig = [
            83, 1, 22, 118, 14, 225, 143, 45, 119, 59, 51, 81, 117, 109, 12, 76, 141, 142, 137,
            167, 117, 28, 98, 150, 245, 134, 254, 105, 172, 236, 170, 4, 24, 195, 101, 175, 186,
            97, 224, 127, 128, 202, 94, 58, 56, 171, 51, 106, 153, 217, 229, 22, 217, 94, 169, 47,
            55, 71, 237, 36, 128, 102, 148, 61,
        ];
        ecdsa::Signature::from_compact(&sig).expect("signature");
    }

    #[test]
    fn test_channel_type_to_commitment_type() {
        assert_eq!(
            channel_type_to_commitment_type(&vec![0x10_u8, 0x10_u8, 0x00_u8]),
            CommitmentType::Anchors
        );
        assert_eq!(
            channel_type_to_commitment_type(&vec![0x10_u8, 0x00_u8]),
            CommitmentType::StaticRemoteKey
        );
        assert_eq!(
            channel_type_to_commitment_type(&vec![0x00_u8, 0x00_u8]),
            CommitmentType::Legacy
        );
    }

    #[test]
    #[should_panic]
    fn test_channel_type_to_commitment_type_panic() {
        channel_type_to_commitment_type(&vec![0x10_u8, 0x00_u8, 0x00_u8]);
    }
}
