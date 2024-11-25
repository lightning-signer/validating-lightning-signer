use core::any::Any;
use core::fmt;
use core::fmt::{Debug, Error, Formatter};

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, ecdsa::Signature, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::sighash::SighashCache;
use bitcoin::{Network, OutPoint, Script, ScriptBuf, Transaction};
use lightning::chain;
use lightning::ln::chan_utils::{
    build_htlc_transaction, derive_private_key, get_htlc_redeemscript, make_funding_redeemscript,
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    CounterpartyChannelTransactionParameters, HTLCOutputInCommitment, HolderCommitmentTransaction,
    TxCreationKeys,
};
use lightning::ln::channel_keys::{DelayedPaymentKey, RevocationKey};
use lightning::ln::features::ChannelTypeFeatures;
use lightning::ln::{chan_utils, PaymentHash, PaymentPreimage};
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::{ChannelSigner, EntropySource, InMemorySigner, SignerProvider};
use serde_derive::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as, Bytes, IfIsHumanReadable};
use tracing::*;
use vls_common::HexEncode;

use crate::monitor::ChainMonitorBase;
use crate::node::{Node, RoutedPayment, CHANNEL_STUB_PRUNE_BLOCKS};
use crate::policy::error::policy_error;
use crate::policy::validator::{ChainState, CommitmentSignatures, EnforcementState, Validator};
use crate::prelude::*;
use crate::signer::derive::KeyDerivationStyle;
use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
use crate::util::crypto_utils::derive_public_key;
use crate::util::crypto_utils::derive_public_revocation_key;
use crate::util::debug_utils::{DebugHTLCOutputInCommitment, DebugInMemorySigner, DebugVecVecU8};
use crate::util::ser_util::{ChannelPublicKeysDef, OutPointReversedDef, ScriptDef};
use crate::util::status::{internal_error, invalid_argument, Status};
use crate::util::transaction_utils::add_holder_sig;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::wallet::Wallet;
use crate::{catch_panic, policy_err, Arc, CommitmentPointProvider, Weak};

/// Channel identifier
///
/// This ID is not related to the channel IDs in the Lightning protocol.
///
/// A channel may have more than one ID.
///
/// The channel keys are derived from this and a base key.
#[serde_as]
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChannelId(#[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")] Vec<u8>);

impl ChannelId {
    /// Create an ID
    pub fn new(inner: &[u8]) -> Self {
        Self(inner.to_vec())
    }

    /// Convert to a byte slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Get a reference to the byte vector
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", self.0.to_hex())
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

/// Bitcoin Signature which specifies EcdsaSighashType
#[derive(Debug)]
pub struct TypedSignature {
    /// The signature
    pub sig: Signature,
    /// The sighash type
    pub typ: EcdsaSighashType,
}

impl TypedSignature {
    /// Serialize the signature and append the sighash type byte.
    pub fn serialize(&self) -> Vec<u8> {
        let mut ss = self.sig.serialize_der().to_vec();
        ss.push(self.typ as u8);
        ss
    }

    /// A TypedSignature with SIGHASH_ALL
    pub fn all(sig: Signature) -> Self {
        Self { sig, typ: EcdsaSighashType::All }
    }
}

/// The commitment type, based on the negotiated option
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommitmentType {
    /// No longer used - dynamic to-remote key
    /// DEPRECATED
    Legacy,
    /// Static to-remote key
    StaticRemoteKey,
    /// Anchors
    /// DEPRECATED
    Anchors,
    /// Anchors, zero fee htlc
    AnchorsZeroFeeHtlc,
}

/// The negotiated parameters for the [Channel]
#[serde_as]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelSetup {
    /// Whether the channel is outbound
    pub is_outbound: bool,
    /// The total the channel was funded with
    pub channel_value_sat: u64,
    // DUP keys.inner.channel_value_satoshis
    /// How much was pushed to the counterparty
    pub push_value_msat: u64,
    /// The funding outpoint
    #[serde_as(as = "IfIsHumanReadable<OutPointReversedDef>")]
    pub funding_outpoint: OutPoint,
    /// locally imposed requirement on the remote commitment transaction to_self_delay
    pub holder_selected_contest_delay: u16,
    /// The holder's optional upfront shutdown script
    #[serde_as(as = "IfIsHumanReadable<Option<ScriptDef>>")]
    pub holder_shutdown_script: Option<ScriptBuf>,
    /// The counterparty's basepoints and pubkeys
    #[serde_as(as = "ChannelPublicKeysDef")]
    pub counterparty_points: ChannelPublicKeys,
    // DUP keys.inner.remote_channel_pubkeys
    /// remotely imposed requirement on the local commitment transaction to_self_delay
    pub counterparty_selected_contest_delay: u16,
    /// The counterparty's optional upfront shutdown script
    #[serde_as(as = "IfIsHumanReadable<Option<ScriptDef>>")]
    pub counterparty_shutdown_script: Option<ScriptBuf>,
    /// The negotiated commitment type
    pub commitment_type: CommitmentType,
}

// Need to define manually because ChannelPublicKeys doesn't derive Debug.
impl fmt::Debug for ChannelSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelSetup")
            .field("is_outbound", &self.is_outbound)
            .field("channel_value_sat", &self.channel_value_sat)
            .field("push_value_msat", &self.push_value_msat)
            .field("funding_outpoint", &self.funding_outpoint)
            .field("holder_selected_contest_delay", &self.holder_selected_contest_delay)
            .field("holder_shutdown_script", &self.holder_shutdown_script)
            .field("counterparty_points", log_channel_public_keys!(&self.counterparty_points))
            .field("counterparty_selected_contest_delay", &self.counterparty_selected_contest_delay)
            .field("counterparty_shutdown_script", &self.counterparty_shutdown_script)
            .field("commitment_type", &self.commitment_type)
            .finish()
    }
}

impl ChannelSetup {
    /// True if this channel uses static to_remote key
    pub fn is_static_remotekey(&self) -> bool {
        self.commitment_type != CommitmentType::Legacy
    }

    /// True if this channel uses anchors
    pub fn is_anchors(&self) -> bool {
        self.commitment_type == CommitmentType::Anchors
            || self.commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    }

    /// True if this channel uses zero fee htlc with anchors
    pub fn is_zero_fee_htlc(&self) -> bool {
        self.commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    }

    /// Convert the channel type to a ChannelTypeFeatures
    pub fn features(&self) -> ChannelTypeFeatures {
        let mut features = ChannelTypeFeatures::empty();
        features.set_static_remote_key_required();
        if self.is_anchors() {
            if self.is_zero_fee_htlc() {
                features.set_anchors_zero_fee_htlc_tx_optional();
            } else {
                features.set_anchors_nonzero_fee_htlc_tx_optional();
            }
        }
        features
    }
}

#[derive(Debug)]
/// Channel slot information for stubs and channels.
pub enum SlotInfoVariant {
    /// Information for stubs
    StubInfo {
        /// The blockheight that the stub will be pruned
        pruneheight: u32,
    },
    /// Information for channels
    ChannelInfo {
        /// The channel's funding outpoint
        funding: Option<OutPoint>,
        /// The channel balance
        balance: ChannelBalance,
        /// Has the node has forgotten this channel?
        forget_seen: bool,
        /// Description of the state of this channel
        diagnostic: String,
    },
}

#[derive(Debug)]
/// Per-channel-slot summary information for system monitoring
pub struct SlotInfo {
    /// An ordinal identifier
    pub oid: u64,
    /// The channel id
    pub id: ChannelId,
    /// Stub and Channel specific data
    pub slot: SlotInfoVariant,
}

/// A trait implemented by both channel states.  See [ChannelSlot]
pub trait ChannelBase: Any {
    /// Get the channel basepoints and public keys
    fn get_channel_basepoints(&self) -> ChannelPublicKeys;
    /// Get the per-commitment point for a holder commitment transaction.
    /// Errors if the commitment number is too high given the current state.
    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status>;
    /// Get the per-commitment secret for a holder commitment transaction
    /// Errors if the commitment number is not ready to be revoked given the current state.
    fn get_per_commitment_secret(&self, commitment_number: u64) -> Result<SecretKey, Status>;
    /// Get the per-commitment secret or None if the arg is out of range
    fn get_per_commitment_secret_or_none(&self, commitment_number: u64) -> Option<SecretKey>;
    /// Check a future secret to support `option_data_loss_protect`
    fn check_future_secret(&self, commit_num: u64, suggested: &SecretKey) -> Result<bool, Status>;
    /// Returns the validator for this channel
    fn validator(&self) -> Arc<dyn Validator>;
    /// Channel information for logging
    fn chaninfo(&self) -> SlotInfo;

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    fn set_next_holder_commit_num_for_testing(&mut self, _num: u64) {
        // Do nothing for ChannelStub.  Channel will override.
    }
}

/// A channel can be in two states - before [Node::setup_channel] it's a
/// [ChannelStub], afterwards it's a [Channel].  This enum keeps track
/// of the two different states.
#[derive(Debug, Clone)]
pub enum ChannelSlot {
    /// Initial state, not ready
    Stub(ChannelStub),
    /// Ready after negotiation is complete
    Ready(Channel),
}

impl ChannelSlot {
    /// The initial channel ID
    pub fn id(&self) -> ChannelId {
        match self {
            ChannelSlot::Stub(stub) => stub.id0.clone(),
            ChannelSlot::Ready(chan) => chan.id0.clone(),
        }
    }

    /// The basepoints
    pub fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        match self {
            ChannelSlot::Stub(stub) => stub.get_channel_basepoints(),
            ChannelSlot::Ready(chan) => chan.get_channel_basepoints(),
        }
    }

    /// Assume this is a channel stub, and return it.
    /// Panics if it's not.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn unwrap_stub(&self) -> &ChannelStub {
        match self {
            ChannelSlot::Stub(stub) => stub,
            ChannelSlot::Ready(_) => panic!("unwrap_stub called on ChannelSlot::Ready"),
        }
    }

    /// Log channel information
    pub fn chaninfo(&self) -> SlotInfo {
        match self {
            ChannelSlot::Stub(stub) => stub.chaninfo(),
            ChannelSlot::Ready(chan) => chan.chaninfo(),
        }
    }
}

/// A channel takes this form after [Node::new_channel], and before [Node::setup_channel]
#[derive(Clone)]
pub struct ChannelStub {
    /// A backpointer to the node
    pub node: Weak<Node>,
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: InMemorySigner,
    // Incomplete, channel_value_sat is placeholder.
    /// The initial channel ID, used to find the channel in the node
    pub id0: ChannelId,
    /// Blockheight when created
    pub blockheight: u32,
}

// Need to define manually because InMemorySigner doesn't derive Debug.
impl fmt::Debug for ChannelStub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelStub")
            .field("keys", &DebugInMemorySigner(&self.keys))
            .field("id0", &self.id0)
            .finish()
    }
}

impl ChannelBase for ChannelStub {
    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys().clone()
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status> {
        if ![0, 1].contains(&commitment_number) {
            return Err(policy_error(format!(
                "channel stub can only return point for commitment number zero or one",
            ))
            .into());
        }
        Ok(self.keys.get_per_commitment_point(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            &self.secp_ctx,
        ))
    }

    fn get_per_commitment_secret(&self, _commitment_number: u64) -> Result<SecretKey, Status> {
        // We can't release a commitment_secret from a ChannelStub ever.
        Err(policy_error(format!("channel stub cannot release commitment secret")).into())
    }

    fn get_per_commitment_secret_or_none(&self, _commitment_number: u64) -> Option<SecretKey> {
        None
    }

    fn check_future_secret(
        &self,
        commitment_number: u64,
        suggested: &SecretKey,
    ) -> Result<bool, Status> {
        let secret_data =
            self.keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        Ok(suggested[..] == secret_data)
    }

    fn validator(&self) -> Arc<dyn Validator> {
        let node = self.get_node();
        let v = node.validator_factory().make_validator(
            node.network(),
            node.get_id(),
            Some(self.id0.clone()),
        );
        v
    }

    fn chaninfo(&self) -> SlotInfo {
        SlotInfo {
            oid: self.oid(),
            id: self.id0.clone(),
            slot: SlotInfoVariant::StubInfo {
                pruneheight: self.blockheight + CHANNEL_STUB_PRUNE_BLOCKS,
            },
        }
    }
}

/// The CLN original id is encoded in little-endian in the last 8 bytes of the ChannelId
pub fn oid_from_native_channel_id(cid: &ChannelId) -> u64 {
    let chanidvec = &cid.0;
    assert!(chanidvec.len() >= 8);
    let bytes_slice = &chanidvec[chanidvec.len() - 8..];
    let mut bytes_array = [0u8; 8];
    bytes_array.copy_from_slice(bytes_slice);
    u64::from_le_bytes(bytes_array)
}

/// The CLN channel id is formed from a original seed id (called dbid) joined with
/// 33 bytes of the peer node id
// FIXME the peer node id should be properly typed
pub fn native_channel_id_from_oid(oid: u64, peer_id: &[u8; 33]) -> ChannelId {
    let mut nonce = [0u8; 33 + 8];
    nonce[0..33].copy_from_slice(peer_id);
    nonce[33..].copy_from_slice(&oid.to_le_bytes());
    ChannelId::new(&nonce)
}

/// The LDK original id is encoded in big endian in the first 8 bytes of the ChannelId
pub fn oid_from_ldk_channel_id(channel_id: &[u8]) -> u64 {
    assert!(channel_id.len() >= 8);
    let mut oid_slice = [0; 8];
    oid_slice.copy_from_slice(&channel_id[0..8]);
    u64::from_be_bytes(oid_slice)
}

/// The LDK channel id is formed from 8 bytes of an original id followed by zeroed out bytes
pub fn ldk_channel_id_from_oid(oid: u64) -> [u8; 32] {
    let mut channel_id = [0u8; 32];
    let oid_slice = oid.to_be_bytes();
    channel_id[..8].copy_from_slice(&oid_slice);
    channel_id
}

impl ChannelStub {
    pub(crate) fn channel_keys_with_channel_value(&self, channel_value_sat: u64) -> InMemorySigner {
        let secp_ctx = Secp256k1::signing_only();
        let keys = &self.keys;
        InMemorySigner::new(
            &secp_ctx,
            keys.funding_key,
            keys.revocation_base_key,
            keys.payment_key,
            keys.delayed_payment_base_key,
            keys.htlc_base_key,
            keys.commitment_seed,
            channel_value_sat,
            keys.channel_keys_id(),
            keys.get_secure_random_bytes(),
        )
    }

    /// Return the original id used to create the channel
    pub fn oid(&self) -> u64 {
        match self.get_node().node_config.key_derivation_style {
            KeyDerivationStyle::Native => oid_from_native_channel_id(&self.id0),
            KeyDerivationStyle::Ldk => oid_from_ldk_channel_id(&self.id0.inner()),
            // add other derivation styles here
            _ => 0,
        }
    }

    fn get_node(&self) -> Arc<Node> {
        // this is safe because the node holds the channel, so it can't be dropped before it
        self.node.upgrade().unwrap()
    }
}

/// After [Node::setup_channel]
#[derive(Clone)]
pub struct Channel {
    /// A backpointer to the node
    pub node: Weak<Node>,
    /// The logger
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: InMemorySigner,
    /// Channel state for policy enforcement purposes
    pub enforcement_state: EnforcementState,
    /// The negotiated channel setup
    pub setup: ChannelSetup,
    /// The initial channel ID
    pub id0: ChannelId,
    /// The optional permanent channel ID
    pub id: Option<ChannelId>,
    /// The chain monitor base
    pub monitor: ChainMonitorBase,
}

impl Debug for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("channel")
    }
}

impl ChannelBase for Channel {
    // TODO move out to impl Channel {} once LDK workaround is removed
    #[cfg(any(test, feature = "test_utils"))]
    fn set_next_holder_commit_num_for_testing(&mut self, num: u64) {
        self.enforcement_state.set_next_holder_commit_num_for_testing(num);
    }

    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys().clone()
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> Result<PublicKey, Status> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        // The following check is relaxed by +1 because LDK fetches the next commitment point
        // before it calls validate_holder_commitment_tx.
        if commitment_number > next_holder_commit_num + 1 {
            return Err(policy_error(format!(
                "get_per_commitment_point: \
                 commitment_number {} invalid when next_holder_commit_num is {}",
                commitment_number, next_holder_commit_num,
            ))
            .into());
        }
        Ok(self.get_per_commitment_point_unchecked(commitment_number))
    }

    fn get_per_commitment_secret(&self, commitment_number: u64) -> Result<SecretKey, Status> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        // When we try to release commitment number n, we must have a signature
        // for commitment number `n+1`, so `next_holder_commit_num` must be at least
        // `n+2`.
        // Also, given that we previous validated the commitment tx when we
        // got the counterparty signature for it, then we must have fulfilled
        // policy-revoke-new-commitment-valid
        if commitment_number + 2 > next_holder_commit_num {
            let validator = self.validator();
            policy_err!(
                validator,
                "policy-revoke-new-commitment-signed",
                "cannot revoke commitment_number {} when next_holder_commit_num is {}",
                commitment_number,
                next_holder_commit_num,
            )
        }
        let secret =
            self.keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        Ok(SecretKey::from_slice(&secret).unwrap())
    }

    // Like get_per_commitment_secret but just returns None instead of a
    // policy error if the request is out of range
    fn get_per_commitment_secret_or_none(&self, commitment_number: u64) -> Option<SecretKey> {
        let next_holder_commit_num = self.enforcement_state.next_holder_commit_num;
        if commitment_number + 2 > next_holder_commit_num {
            warn!(
                "get_per_commitment_secret_or_none: called past current revoked holder commitment \
                 implied by next_holder_commit_num: {} + 2 > {}",
                commitment_number, next_holder_commit_num
            );
            None
        } else {
            Some(
                SecretKey::from_slice(
                    &self
                        .keys
                        .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number),
                )
                .unwrap(),
            )
        }
    }

    fn check_future_secret(
        &self,
        commitment_number: u64,
        suggested: &SecretKey,
    ) -> Result<bool, Status> {
        let secret_data =
            self.keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        Ok(suggested[..] == secret_data)
    }

    fn validator(&self) -> Arc<dyn Validator> {
        let node = self.get_node();
        let v = node.validator_factory().make_validator(
            self.network(),
            node.get_id(),
            Some(self.id0.clone()),
        );
        v
    }

    fn chaninfo(&self) -> SlotInfo {
        SlotInfo {
            oid: self.oid(),
            id: self.id(),
            slot: SlotInfoVariant::ChannelInfo {
                funding: self.monitor.funding_outpoint(),
                balance: self.balance(),
                forget_seen: self.monitor.forget_seen(),
                diagnostic: self.monitor.diagnostic(self.enforcement_state.channel_closed),
            },
        }
    }
}

impl Channel {
    /// The channel ID
    pub fn id(&self) -> ChannelId {
        self.id.clone().unwrap_or(self.id0.clone())
    }

    /// Return the original id used to create the channel
    pub fn oid(&self) -> u64 {
        match self.get_node().node_config.key_derivation_style {
            KeyDerivationStyle::Native => oid_from_native_channel_id(&self.id0),
            KeyDerivationStyle::Ldk => oid_from_ldk_channel_id(&self.id0.inner()),
            // add other derivation styles here
            _ => 0,
        }
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_commit_num_for_testing(
        &mut self,
        num: u64,
        current_point: PublicKey,
    ) {
        self.enforcement_state.set_next_counterparty_commit_num_for_testing(num, current_point);
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_revoke_num_for_testing(&mut self, num: u64) {
        self.enforcement_state.set_next_counterparty_revoke_num_for_testing(num);
    }

    pub(crate) fn get_chain_state(&self) -> ChainState {
        self.monitor.as_chain_state()
    }

    /// Get the counterparty's public keys
    pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys {
        // this is safe because the channel was readied
        self.keys.counterparty_pubkeys().expect("counterparty_pubkeys")
    }

    fn get_per_commitment_point_unchecked(&self, commitment_number: u64) -> PublicKey {
        self.keys
            .get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - commitment_number, &self.secp_ctx)
    }

    pub(crate) fn get_counterparty_commitment_point(
        &self,
        commitment_number: u64,
    ) -> Option<PublicKey> {
        let state = &self.enforcement_state;

        let next_commit_num = state.next_counterparty_commit_num;

        // we can supply the counterparty's commitment point for the following cases:
        // - the commitment number is the current or previous one the counterparty signed (we received the point)
        // - the commitment number is older than that (the commitment was revoked and we received the secret)

        if next_commit_num < commitment_number + 1 {
            // in the future, we don't have it
            warn!("asked for counterparty commitment point {} but our next counterparty commitment number is {}",
                commitment_number, next_commit_num);
            None
        } else if next_commit_num == commitment_number + 1 {
            state.current_counterparty_point
        } else if next_commit_num == commitment_number {
            state.previous_counterparty_point
        } else if let Some(secrets) = state.counterparty_secrets.as_ref() {
            let secret = secrets.get_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
            secret.map(|s| {
                PublicKey::from_secret_key(
                    &self.secp_ctx,
                    &SecretKey::from_slice(&s).expect("secret from storage"),
                )
            })
        } else {
            warn!(
                "asked for counterparty commitment point {} but we don't have secrets storage",
                commitment_number
            );
            None
        }
    }
}

// Phase 2
impl Channel {
    // Phase 2
    /// Public for testing purposes
    pub fn make_counterparty_tx_keys(&self, per_commitment_point: &PublicKey) -> TxCreationKeys {
        let holder_points = self.keys.pubkeys();
        let counterparty_points = self.counterparty_pubkeys();

        self.make_tx_keys(per_commitment_point, counterparty_points, holder_points)
    }

    pub(crate) fn make_holder_tx_keys(&self, per_commitment_point: &PublicKey) -> TxCreationKeys {
        let holder_points = self.keys.pubkeys();
        let counterparty_points = self.counterparty_pubkeys();

        self.make_tx_keys(per_commitment_point, holder_points, counterparty_points)
    }

    fn make_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
        a_points: &ChannelPublicKeys,
        b_points: &ChannelPublicKeys,
    ) -> TxCreationKeys {
        TxCreationKeys::derive_new(
            &self.secp_ctx,
            &per_commitment_point,
            &a_points.delayed_payment_basepoint,
            &a_points.htlc_basepoint,
            &b_points.revocation_basepoint,
            &b_points.htlc_basepoint,
        )
    }

    /// Sign a counterparty commitment transaction after rebuilding it
    /// from the supplied arguments.
    #[instrument(skip(self))]
    pub fn sign_counterparty_commitment_tx_phase2(
        &mut self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(Signature, Vec<Signature>), Status> {
        // Since we didn't have the value at the real open, validate it now.
        let validator = self.validator();
        validator.validate_channel_value(&self.setup)?;

        let info2 = self.build_counterparty_commitment_info(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs.clone(),
            received_htlcs.clone(),
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let mut state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, None, Some(&info2), &self.setup);

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(None, Some(&info2));

        validator.validate_counterparty_commitment_tx(
            &self.enforcement_state,
            commitment_number,
            &remote_per_commitment_point,
            &self.setup,
            &self.get_chain_state(),
            &info2,
        )?;

        let htlcs = Self::htlcs_info2_to_oic(offered_htlcs, received_htlcs);

        #[cfg(fuzzing)]
        let htlcs_len = htlcs.len();

        // since we independently re-create the tx, this also performs the
        // policy-commitment-* controls
        let commitment_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );

        #[cfg(not(fuzzing))]
        let (sig, htlc_sigs) = catch_panic!(
            self.keys.sign_counterparty_commitment(
                &commitment_tx,
                Vec::new(),
                Vec::new(),
                &self.secp_ctx
            ),
            "sign_counterparty_commitment panic {} chantype={:?}",
            self.setup.commitment_type,
        )
        .map_err(|_| internal_error("failed to sign"))?;

        #[cfg(fuzzing)]
        let (sig, htlc_sigs, _) = (
            Signature::from_compact(&[0; 64]).unwrap(),
            vec![Signature::from_compact(&[0; 64]).unwrap(); htlcs_len],
            commitment_tx,
        );

        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, Some(&info2));
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        // Only advance the state if nothing goes wrong.
        validator.set_next_counterparty_commit_num(
            &mut self.enforcement_state,
            commitment_number + 1,
            *remote_per_commitment_point,
            info2,
        )?;

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
        );

        trace_enforcement_state!(self);
        self.persist()?;
        Ok((sig, htlc_sigs))
    }

    // restore node state payments from the current commitment transactions
    pub(crate) fn restore_payments(&self) {
        let node = self.get_node();

        let incoming_payment_summary = self.enforcement_state.incoming_payments_summary(None, None);
        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, None);

        let mut hashes: UnorderedSet<&PaymentHash> = UnorderedSet::new();
        hashes.extend(incoming_payment_summary.keys());
        hashes.extend(outgoing_payment_summary.keys());

        let mut state = node.get_state();

        for hash in hashes {
            let payment = state.payments.entry(*hash).or_insert_with(|| RoutedPayment::new());
            let incoming_sat = incoming_payment_summary.get(hash).map(|a| *a).unwrap_or(0);
            let outgoing_sat = outgoing_payment_summary.get(hash).map(|a| *a).unwrap_or(0);
            payment.apply(&self.id0, incoming_sat, outgoing_sat);
        }
    }

    // This function is needed for testing with mutated keys.
    /// Public for testing purposes
    pub fn make_counterparty_commitment_tx_with_keys(
        &self,
        keys: TxCreationKeys,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let mut htlcs_with_aux = htlcs.iter().map(|h| (h.clone(), ())).collect();
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            to_counterparty_value_sat,
            to_holder_value_sat,
            self.counterparty_pubkeys().funding_pubkey,
            self.keys.pubkeys().funding_pubkey,
            keys,
            feerate_per_kw,
            &mut htlcs_with_aux,
            &parameters,
        );
        commitment_tx
    }

    /// Public for testing purposes
    pub fn make_counterparty_commitment_tx(
        &self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let keys = self.make_counterparty_tx_keys(remote_per_commitment_point);
        self.make_counterparty_commitment_tx_with_keys(
            keys,
            commitment_number,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        )
    }

    #[instrument(skip(self))]
    fn check_holder_tx_signatures(
        &self,
        per_commitment_point: &PublicKey,
        txkeys: &TxCreationKeys,
        feerate_per_kw: u32,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
        recomposed_tx: CommitmentTransaction,
    ) -> Result<(), Status> {
        let redeemscript = make_funding_redeemscript(
            &self.keys.pubkeys().funding_pubkey,
            &self.setup.counterparty_points.funding_pubkey,
        );

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_slice(
            &SighashCache::new(&recomposed_tx.trust().built_transaction().transaction)
                .segwit_signature_hash(
                    0,
                    &redeemscript,
                    self.setup.channel_value_sat,
                    EcdsaSighashType::All,
                )
                .unwrap()[..],
        )
        .map_err(|ve| internal_error(format!("sighash failed: {}", ve)))?;

        self.secp_ctx
            .verify_ecdsa(
                &sighash,
                &counterparty_commit_sig,
                &self.setup.counterparty_points.funding_pubkey,
            )
            .map_err(|ve| policy_error(format!("commit sig verify failed: {}", ve)))?;

        let commitment_txid = recomposed_tx.trust().txid();
        let to_self_delay = self.setup.counterparty_selected_contest_delay;

        let htlc_pubkey = derive_public_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.counterparty_pubkeys().htlc_basepoint.0,
        )
        .map_err(|err| internal_error(format!("derive_public_key failed: {}", err)))?;

        let sig_hash_type = if self.setup.is_anchors() {
            EcdsaSighashType::SinglePlusAnyoneCanPay
        } else {
            EcdsaSighashType::All
        };

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { feerate_per_kw };

        let features = self.setup.features();

        for ndx in 0..recomposed_tx.htlcs().len() {
            let htlc = &recomposed_tx.htlcs()[ndx];

            let htlc_redeemscript = get_htlc_redeemscript(htlc, &features, &txkeys);

            let features = self.setup.features();

            // policy-onchain-format-standard
            let recomposed_htlc_tx = catch_panic!(
                build_htlc_transaction(
                    &commitment_txid,
                    build_feerate,
                    to_self_delay,
                    htlc,
                    &features,
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                ),
                "build_htlc_transaction panic {} chantype={:?}",
                self.setup.commitment_type
            );

            // unwrap is safe because we just created the tx and it's well formed
            let recomposed_tx_sighash = Message::from_slice(
                &SighashCache::new(&recomposed_htlc_tx)
                    .segwit_signature_hash(
                        0,
                        &htlc_redeemscript,
                        htlc.amount_msat / 1000,
                        sig_hash_type,
                    )
                    .unwrap()[..],
            )
            .map_err(|err| invalid_argument(format!("sighash failed for htlc {}: {}", ndx, err)))?;

            self.secp_ctx
                .verify_ecdsa(&recomposed_tx_sighash, &counterparty_htlc_sigs[ndx], &htlc_pubkey)
                .map_err(|err| {
                    policy_error(format!("commit sig verify failed for htlc {}: {}", ndx, err))
                })?;
        }
        Ok(())
    }

    // Advance the holder commitment state so that `N + 1` is the next
    // and `N - 1` is revoked, where N is `new_current_commitment_number`.
    fn advance_holder_commitment_state(
        &mut self,
        validator: Arc<dyn Validator>,
        new_current_commitment_number: u64,
        info2: CommitmentInfo2,
        counterparty_signatures: CommitmentSignatures,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        // Advance the local commitment number state.
        validator.set_next_holder_commit_num(
            &mut self.enforcement_state,
            new_current_commitment_number + 1,
            info2,
            counterparty_signatures,
        )?;

        self.release_commitment_secret(new_current_commitment_number)
    }

    // Gets the revocation return values for a previous commitments which are
    // ready to be released (fails on future commitments)
    fn release_commitment_secret(
        &mut self,
        commitment_number: u64,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        let next_holder_commitment_point = self.get_per_commitment_point(commitment_number + 1)?;
        let maybe_old_secret = if commitment_number >= 1 {
            // this will fail if the secret is not ready to be released
            Some(self.get_per_commitment_secret(commitment_number - 1)?)
        } else {
            None
        };
        Ok((next_holder_commitment_point, maybe_old_secret))
    }

    /// Validate the counterparty's signatures on the holder's
    /// commitment and HTLCs when the commitment_signed message is
    /// received.
    pub fn validate_holder_commitment_tx_phase2(
        &mut self,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
    ) -> Result<(), Status> {
        let per_commitment_point = &self.get_per_commitment_point(commitment_number)?;
        let info2 = self.build_holder_commitment_info(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &self.setup);

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);

        let validator = self.validator();
        validator
            .validate_holder_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                warn!(
                    "VALIDATION FAILED: {} setup={:?} state={:?} info={:?}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                warn!(
                    "VALIDATION FAILED: {}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs =
            Self::htlcs_info2_to_oic(info2.offered_htlcs.clone(), info2.received_htlcs.clone());

        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        // policy-commitment-*
        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &txkeys,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );

        #[cfg(not(fuzzing))]
        self.check_holder_tx_signatures(
            &per_commitment_point,
            &txkeys,
            feerate_per_kw,
            counterparty_commit_sig,
            counterparty_htlc_sigs,
            recomposed_tx,
        )?;

        #[cfg(fuzzing)]
        let _ = recomposed_tx;

        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        if commitment_number == self.enforcement_state.next_holder_commit_num {
            let counterparty_signatures = CommitmentSignatures(
                counterparty_commit_sig.clone(),
                counterparty_htlc_sigs.to_vec(),
            );
            self.enforcement_state.next_holder_commit_info = Some((info2, counterparty_signatures));
        }

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(())
    }

    /// Revoke holder commitment `N - 1` by disclosing its commitment secret.
    /// After this, `N` is the current holder commitment and `N + 1`
    /// is the next holder commitment.
    ///
    /// Returns the per_commitment_point for commitment `N + 1` and the
    /// holder's revocation secret for commitment `N - 1` if `N > 0`.
    ///
    /// [`validate_holder_commitment_tx`] (or the phase2 version) must be called
    /// before this method.
    ///
    /// The node should have persisted this state change first, because we cannot
    /// safely roll back a revocation.
    pub fn revoke_previous_holder_commitment(
        &mut self,
        new_current_commitment_number: u64,
    ) -> Result<(PublicKey, Option<SecretKey>), Status> {
        // If we are called on anything other than the next_holder_commit_num
        // with existing next_holder_commit_info we must not change any state
        if new_current_commitment_number != self.enforcement_state.next_holder_commit_num {
            return Ok(self.release_commitment_secret(new_current_commitment_number)?);
            // don't persist, this case doesn't change state
        }

        let validator = self.validator();

        if self.enforcement_state.next_holder_commit_info.is_none() {
            // the caller failed to call validate_holder_commitment_tx
            policy_err!(
                validator,
                "policy-revoke-new-commitment-signed",
                "new_current_commitment == next_holder_commit_num {} \
                 but next_holder_commit_info.is_none",
                new_current_commitment_number,
            );
            // `policy_err!` will not return an error in permissive mode, so we need to return
            // something plausible here.  The node will likely crash soon after, because we will
            // not return a revocation secret (`None` below).
            // That's OK, because the node should have called `validate_holder_commitment_tx` first
            // so the logic error is in the node.
            let holder_commitment_point =
                self.get_per_commitment_point(new_current_commitment_number)?;
            return Ok((holder_commitment_point, None));
        }

        // checked above
        let (info2, sigs) = self.enforcement_state.next_holder_commit_info.take().unwrap();
        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);
        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);

        let node = self.get_node();
        let mut state = node.get_state();

        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &self.setup);

        let (next_holder_commitment_point, maybe_old_secret) = self
            .advance_holder_commitment_state(
                validator.clone(),
                new_current_commitment_number,
                info2,
                sigs,
            )?;

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
        );

        trace_enforcement_state!(self);
        self.persist()?;
        Ok((next_holder_commitment_point, maybe_old_secret))
    }

    /// Sign a holder commitment when force-closing
    pub fn sign_holder_commitment_tx_phase2(
        &mut self,
        commitment_number: u64,
    ) -> Result<(Signature, Vec<Signature>), Status> {
        // We are just signing the latest commitment info that we previously
        // stored in the enforcement state, while checking that the commitment
        // number supplied by the caller matches the one we expect.
        //
        // policy-commitment-holder-not-revoked is implicitly checked by
        // the fact that the current holder commitment info in the enforcement
        // state cannot have been revoked.
        let validator = self.validator();
        let info2 = validator
            .get_current_holder_commitment_info(&mut self.enforcement_state, commitment_number)?;

        let htlcs = Self::htlcs_info2_to_oic(info2.offered_htlcs, info2.received_htlcs);
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { info2.feerate_per_kw };
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        // policy-onchain-format-standard
        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &txkeys,
            build_feerate,
            info2.to_broadcaster_value_sat,
            info2.to_countersigner_value_sat,
            htlcs,
        );

        // We provide a dummy signature for the remote, since we don't require that sig
        // to be passed in to this call.  It would have been better if HolderCommitmentTransaction
        // didn't require the remote sig.
        // TODO(516) remove dummy sigs here and in phase 2 protocol
        let htlcs_len = recomposed_tx.htlcs().len();
        let mut htlc_dummy_sigs = Vec::with_capacity(htlcs_len);
        htlc_dummy_sigs.resize(htlcs_len, Self::dummy_sig());

        // Holder commitments need an extra wrapper for the LDK signature routine.
        let recomposed_holder_tx = HolderCommitmentTransaction::new(
            recomposed_tx,
            Self::dummy_sig(),
            htlc_dummy_sigs,
            &self.keys.pubkeys().funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );

        // Sign the recomposed commitment.
        let sig = self
            .keys
            .sign_holder_commitment(&recomposed_holder_tx, &self.secp_ctx)
            .map_err(|_| internal_error("failed to sign"))?;

        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok((sig, vec![]))
    }

    /// Sign a holder commitment and HTLCs when recovering from node failure
    /// Also returns the revocable scriptPubKey so we can identify our outputs
    /// Also returns the unilateral close key material
    pub fn sign_holder_commitment_tx_for_recovery(
        &mut self,
    ) -> Result<
        (Transaction, Vec<Transaction>, ScriptBuf, (SecretKey, Vec<Vec<u8>>), PublicKey),
        Status,
    > {
        let info2 = self
            .enforcement_state
            .current_holder_commit_info
            .as_ref()
            .ok_or_else(|| internal_error("channel was not open - commit info"))?;
        let cp_sigs = self
            .enforcement_state
            .current_counterparty_signatures
            .as_ref()
            .ok_or_else(|| internal_error("channel was not open - counterparty sigs"))?;
        let commitment_number = self.enforcement_state.next_holder_commit_num - 1;
        warn!("force-closing channel for recovery at commitment number {}", commitment_number);

        let htlcs =
            Self::htlcs_info2_to_oic(info2.offered_htlcs.clone(), info2.received_htlcs.clone());
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { info2.feerate_per_kw };
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        // policy-onchain-format-standard
        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            &txkeys,
            build_feerate,
            info2.to_broadcaster_value_sat,
            info2.to_countersigner_value_sat,
            htlcs,
        );

        // We provide a dummy signature for the remote, since we don't require that sig
        // to be passed in to this call.  It would have been better if HolderCommitmentTransaction
        // didn't require the remote sig.
        // TODO consider if we actually want the sig for policy checks
        let htlcs_len = recomposed_tx.htlcs().len();
        let mut htlc_dummy_sigs = Vec::with_capacity(htlcs_len);
        htlc_dummy_sigs.resize(htlcs_len, Self::dummy_sig());

        // Holder commitments need an extra wrapper for the LDK signature routine.
        let recomposed_holder_tx = HolderCommitmentTransaction::new(
            recomposed_tx,
            Self::dummy_sig(),
            htlc_dummy_sigs,
            &self.keys.pubkeys().funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );

        // Sign the recomposed commitment.
        let sig = self
            .keys
            .sign_holder_commitment(&recomposed_holder_tx, &self.secp_ctx)
            .map_err(|_| internal_error("failed to sign"))?;

        let holder_tx = recomposed_holder_tx.trust();
        let mut tx = holder_tx.built_transaction().transaction.clone();
        let holder_funding_key = self.keys.pubkeys().funding_pubkey;
        let counterparty_funding_key = self.counterparty_pubkeys().funding_pubkey;

        let tx_keys = holder_tx.keys();
        let revocable_redeemscript = chan_utils::get_revokeable_redeemscript(
            &tx_keys.revocation_key,
            self.setup.counterparty_selected_contest_delay,
            &tx_keys.broadcaster_delayed_payment_key,
        );

        add_holder_sig(&mut tx, sig, cp_sigs.0, &holder_funding_key, &counterparty_funding_key);
        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);

        let revocation_basepoint = self.counterparty_pubkeys().revocation_basepoint;
        let revocation_pubkey = derive_public_revocation_key(
            &self.secp_ctx,
            &per_commitment_point,
            &revocation_basepoint,
        )
        .map_err(|_| internal_error("failure during derive_public_revocation_key"))?;
        let ck =
            self.get_unilateral_close_key(&Some(per_commitment_point), &Some(revocation_pubkey))?;

        self.persist()?;
        Ok((tx, Vec::new(), revocable_redeemscript.to_v0_p2wsh(), ck, revocation_pubkey.0))
    }

    /// Sign a holder commitment transaction after rebuilding it
    /// from the supplied arguments.
    /// Use [Channel::sign_counterparty_commitment_tx_phase2()] instead of this,
    /// since that one uses the last counter-signed holder tx, which is simpler
    /// and doesn't require re-validation of the holder tx.
    // TODO(517) remove this method
    pub fn sign_holder_commitment_tx_phase2_redundant(
        &mut self,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(Signature, Vec<Signature>), Status> {
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        let info2 = self.build_holder_commitment_info(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs.clone(),
            received_htlcs.clone(),
            feerate_per_kw,
        )?;

        self.validator().validate_holder_commitment_tx(
            &self.enforcement_state,
            commitment_number,
            &per_commitment_point,
            &self.setup,
            &self.get_chain_state(),
            &info2,
        )?;

        let htlcs = Self::htlcs_info2_to_oic(offered_htlcs, received_htlcs);

        // We provide a dummy signature for the remote, since we don't require that sig
        // to be passed in to this call.  It would have been better if HolderCommitmentTransaction
        // didn't require the remote sig.
        // TODO consider if we actually want the sig for policy checks
        let mut htlc_dummy_sigs = Vec::with_capacity(htlcs.len());
        htlc_dummy_sigs.resize(htlcs.len(), Self::dummy_sig());

        let build_feerate = if self.setup.is_zero_fee_htlc() { 0 } else { feerate_per_kw };
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);
        let commitment_tx = self.make_holder_commitment_tx(
            commitment_number,
            &txkeys,
            build_feerate,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );
        debug!("channel: sign holder txid {}", commitment_tx.trust().built_transaction().txid);

        let holder_commitment_tx = HolderCommitmentTransaction::new(
            commitment_tx,
            Self::dummy_sig(),
            htlc_dummy_sigs,
            &self.keys.pubkeys().funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );

        let sig = self
            .keys
            .sign_holder_commitment(&holder_commitment_tx, &self.secp_ctx)
            .map_err(|_| internal_error("failed to sign"))?;

        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok((sig, vec![]))
    }

    pub(crate) fn make_holder_commitment_tx(
        &self,
        commitment_number: u64,
        keys: &TxCreationKeys,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let mut htlcs_with_aux = htlcs.into_iter().map(|h| (h, ())).collect();
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();
        let mut commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            to_holder_value_sat,
            to_counterparty_value_sat,
            self.keys.pubkeys().funding_pubkey,
            self.counterparty_pubkeys().funding_pubkey,
            keys.clone(),
            feerate_per_kw,
            &mut htlcs_with_aux,
            &parameters,
        );
        if self.setup.is_anchors() {
            commitment_tx = commitment_tx.with_non_zero_fee_anchors();
        }
        commitment_tx
    }

    /// Public for testing purposes
    pub fn htlcs_info2_to_oic(
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Vec<HTLCOutputInCommitment> {
        let mut htlcs = Vec::new();
        for htlc in offered_htlcs {
            htlcs.push(HTLCOutputInCommitment {
                offered: true,
                amount_msat: htlc.value_sat * 1000,
                cltv_expiry: htlc.cltv_expiry,
                payment_hash: htlc.payment_hash,
                transaction_output_index: None,
            });
        }
        for htlc in received_htlcs {
            htlcs.push(HTLCOutputInCommitment {
                offered: false,
                amount_msat: htlc.value_sat * 1000,
                cltv_expiry: htlc.cltv_expiry,
                payment_hash: htlc.payment_hash,
                transaction_output_index: None,
            });
        }
        htlcs
    }

    /// Build channel parameters, used to further build a commitment transaction
    pub fn make_channel_parameters(&self) -> ChannelTransactionParameters {
        let funding_outpoint = chain::transaction::OutPoint {
            txid: self.setup.funding_outpoint.txid,
            index: self.setup.funding_outpoint.vout as u16,
        };
        let channel_parameters = ChannelTransactionParameters {
            holder_pubkeys: self.get_channel_basepoints(),
            holder_selected_contest_delay: self.setup.holder_selected_contest_delay,
            is_outbound_from_holder: self.setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: self.setup.counterparty_points.clone(),
                selected_contest_delay: self.setup.counterparty_selected_contest_delay,
            }),
            funding_outpoint: Some(funding_outpoint),
            channel_type_features: self.setup.features(),
        };
        channel_parameters
    }

    /// Get the shutdown script where our funds will go when we mutual-close
    // TODO(75) this method is deprecated
    pub fn get_ldk_shutdown_script(&self) -> ScriptBuf {
        self.setup.holder_shutdown_script.clone().unwrap_or_else(|| {
            self.get_node().keys_manager.get_shutdown_scriptpubkey().unwrap().into()
        })
    }

    fn get_node(&self) -> Arc<Node> {
        self.node.upgrade().unwrap()
    }

    /// Sign a mutual close transaction after rebuilding it from the supplied arguments
    pub fn sign_mutual_close_tx_phase2(
        &mut self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<ScriptBuf>,
        counterparty_script: &Option<ScriptBuf>,
        holder_wallet_path_hint: &[u32],
    ) -> Result<Signature, Status> {
        self.validator().validate_mutual_close_tx(
            &*self.get_node(),
            &self.setup,
            &self.enforcement_state,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script,
            counterparty_script,
            holder_wallet_path_hint,
        )?;

        let tx = ClosingTransaction::new(
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script.clone().unwrap_or_else(|| ScriptBuf::new()),
            counterparty_script.clone().unwrap_or_else(|| ScriptBuf::new()),
            self.setup.funding_outpoint,
        );

        let sig = self
            .keys
            .sign_closing_transaction(&tx, &self.secp_ctx)
            .map_err(|_| Status::internal("failed to sign"))?;
        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok(sig)
    }

    /// Sign a delayed output that goes to us while sweeping a transaction we broadcast
    pub fn sign_delayed_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        commitment_number: u64,
        redeemscript: &Script,
        amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_delayed_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;

        self.validator().validate_delayed_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            input,
            amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_slice(
            &SighashCache::new(tx)
                .segwit_signature_hash(input, &redeemscript, amount_sat, EcdsaSighashType::All)
                .unwrap()[..],
        )
        .map_err(|_| Status::internal("failed to sighash"))?;

        let privkey = derive_private_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.keys.delayed_payment_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&sighash, &privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign an offered or received HTLC output from a commitment the counterparty broadcast.
    pub fn sign_counterparty_htlc_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_counterparty_htlc_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }

        self.validator().validate_counterparty_htlc_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            redeemscript,
            input,
            htlc_amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let htlc_sighash = Message::from_slice(
            &SighashCache::new(tx)
                .segwit_signature_hash(input, &redeemscript, htlc_amount_sat, EcdsaSighashType::All)
                .unwrap()[..],
        )
        .map_err(|_| Status::internal("failed to sighash"))?;

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &remote_per_commitment_point,
            &self.keys.htlc_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&htlc_sighash, &htlc_privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign a justice transaction on an old state that the counterparty broadcast
    pub fn sign_justice_sweep(
        &self,
        tx: &Transaction,
        input: usize,
        revocation_secret: &SecretKey,
        redeemscript: &Script,
        amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<Signature, Status> {
        if input >= tx.input.len() {
            return Err(invalid_argument(format!(
                "sign_justice_sweep: bad input index: {} >= {}",
                input,
                tx.input.len()
            )));
        }
        self.validator().validate_justice_sweep(
            &*self.get_node(),
            &self.setup,
            &self.get_chain_state(),
            tx,
            input,
            amount_sat,
            wallet_path,
        )?;

        // unwrap is safe because we just created the tx and it's well formed
        let sighash = Message::from_slice(
            &SighashCache::new(tx)
                .segwit_signature_hash(input, &redeemscript, amount_sat, EcdsaSighashType::All)
                .unwrap()[..],
        )
        .map_err(|_| Status::internal("failed to sighash"))?;

        let privkey = chan_utils::derive_private_revocation_key(
            &self.secp_ctx,
            revocation_secret,
            &self.keys.revocation_base_key,
        );

        let sig = self.secp_ctx.sign_ecdsa(&sighash, &privkey);
        trace_enforcement_state!(self);
        Ok(sig)
    }

    /// Sign a channel announcement with both the node key and the funding key
    pub fn sign_channel_announcement_with_funding_key(&self, announcement: &[u8]) -> Signature {
        let ann_hash = Sha256dHash::hash(announcement);
        let encmsg = secp256k1::Message::from(ann_hash);

        self.secp_ctx.sign_ecdsa(&encmsg, &self.keys.funding_key)
    }

    fn persist(&self) -> Result<(), Status> {
        let node_id = self.get_node().get_id();
        self.get_node()
            .persister
            .update_channel(&node_id, &self)
            .map_err(|_| Status::internal("persist failed"))
    }

    /// The node's network
    pub fn network(&self) -> Network {
        self.get_node().network()
    }

    /// The node has signed our funding transaction
    pub fn funding_signed(&self, tx: &Transaction, _vout: u32) {
        // Start tracking funding inputs, in case an input is double-spent.
        // The tracker was already informed of the inputs by the node.

        // Note that the fundee won't detect double-spends this way, because
        // they never see the details of the funding transaction.
        // But the fundee doesn't care about double-spends, because they don't
        // have any funds in the channel yet.

        // the lock order is backwards (monitor -> tracker), but we release
        // the monitor lock, so it's OK

        self.monitor.add_funding_inputs(tx);
    }

    /// Mark this channel as forgotten by the node allowing it to be pruned
    pub fn forget(&self) -> Result<(), Status> {
        self.monitor.forget_channel();
        self.persist()?;
        Ok(())
    }

    /// Return channel balances
    pub fn balance(&self) -> ChannelBalance {
        let node = self.get_node();
        let state = node.get_state();
        let is_ready = self.validator().is_ready(&self.get_chain_state());
        self.enforcement_state.balance(&*state, &self.setup, is_ready)
    }

    /// advance the holder commitment in an arbitrary way for testing
    #[cfg(feature = "test_utils")]
    pub fn advance_holder_commitment(
        &mut self,
        counterparty_key: &SecretKey,
        counterparty_htlc_key: &SecretKey,
        offered_htlcs: Vec<HTLCInfo2>,
        value_to_holder: u64,
        commit_num: u64,
    ) -> Result<(), Status> {
        let feerate = 1000;
        let funding_redeemscript = make_funding_redeemscript(
            &self.keys.pubkeys().funding_pubkey,
            &self.counterparty_pubkeys().funding_pubkey,
        );
        let per_commitment_point = self.get_per_commitment_point(commit_num)?;
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        let tx = self.make_holder_commitment_tx(
            commit_num,
            &txkeys,
            feerate,
            value_to_holder,
            0,
            Channel::htlcs_info2_to_oic(offered_htlcs.clone(), vec![]),
        );

        let trusted_tx = tx.trust();
        let built_tx = trusted_tx.built_transaction();
        let counterparty_sig = built_tx.sign_counterparty_commitment(
            &counterparty_key,
            &funding_redeemscript,
            self.setup.channel_value_sat,
            &self.secp_ctx,
        );

        let counterparty_htlc_key =
            derive_private_key(&self.secp_ctx, &per_commitment_point, &counterparty_htlc_key);

        let features = self.setup.features();

        let mut htlc_sigs = Vec::with_capacity(tx.htlcs().len());
        for htlc in tx.htlcs() {
            let htlc_tx = catch_panic!(
                build_htlc_transaction(
                    &trusted_tx.txid(),
                    feerate,
                    self.setup.counterparty_selected_contest_delay,
                    htlc,
                    &features,
                    &txkeys.broadcaster_delayed_payment_key,
                    &txkeys.revocation_key,
                ),
                "build_htlc_transaction panic {} chantype={:?} htlc={:?}",
                self.setup.commitment_type,
                htlc
            );
            let htlc_redeemscript = get_htlc_redeemscript(&htlc, &features, &txkeys);
            let sig_hash_type = if self.setup.is_anchors() {
                EcdsaSighashType::SinglePlusAnyoneCanPay
            } else {
                EcdsaSighashType::All
            };

            // unwrap is safe because we just created the tx and it's well formed
            let htlc_sighash = Message::from(
                SighashCache::new(&htlc_tx)
                    .segwit_signature_hash(
                        0,
                        &htlc_redeemscript,
                        htlc.amount_msat / 1000,
                        sig_hash_type,
                    )
                    .unwrap(),
            );
            htlc_sigs.push(self.secp_ctx.sign_ecdsa(&htlc_sighash, &counterparty_htlc_key));
        }

        // add an HTLC
        self.validate_holder_commitment_tx_phase2(
            commit_num,
            feerate,
            value_to_holder,
            0,
            offered_htlcs,
            vec![],
            &counterparty_sig,
            &htlc_sigs,
        )?;

        self.revoke_previous_holder_commitment(commit_num)?;
        Ok(())
    }

    /// Sign a transaction that spends the anchor output
    pub fn sign_holder_anchor_input(
        &self,
        anchor_tx: &Transaction,
        input: usize,
    ) -> Result<Signature, Status> {
        self.keys
            .sign_holder_anchor_input(anchor_tx, input, &self.secp_ctx)
            .map_err(|()| internal_error(format!("sign_holder_anchor_input failed")))
    }

    /// Get the anchor redeemscript
    pub fn get_anchor_redeemscript(&self) -> ScriptBuf {
        chan_utils::get_anchor_redeemscript(&self.keys.pubkeys().funding_pubkey)
    }
}

/// Balances associated with a channel
/// See: <https://gitlab.com/lightning-signer/docs/-/wikis/Proposed-L1-and-Channel-Balance-Reconciliation>
///
/// All channels that VLS knows about are in one of the four categories:
/// 1. channel stubs: assigned channelid and can generate points, keys, ...
/// 2. unconfirmed channels: negotiated channels prior to `channel_ready`
/// 3. channels: active channels in their normal operating mode
/// 4. closing channels: closed channels being swept or aged prior to pruning
///
#[derive(Debug, PartialEq)]
pub struct ChannelBalance {
    /// Claimable balance on open channel
    pub claimable: u64,
    /// Sum of htlcs offered to us
    pub received_htlc: u64,
    /// Sum of htlcs we offered
    pub offered_htlc: u64,
    /// Sweeping to wallet
    pub sweeping: u64,
    /// Current number of channel stubs
    pub stub_count: u32,
    /// Current number of unconfirmed channels
    pub unconfirmed_count: u32,
    /// Current number of active channels
    pub channel_count: u32,
    /// Current number of closing channels
    pub closing_count: u32,
    /// Current number of received htlcs
    pub received_htlc_count: u32,
    /// Current number of offered htlcs
    pub offered_htlc_count: u32,
}

impl ChannelBalance {
    /// Create a ChannelBalance with specific values
    pub fn new(
        claimable: u64,
        received_htlc: u64,
        offered_htlc: u64,
        sweeping: u64,
        stub_count: u32,
        unconfirmed_count: u32,
        channel_count: u32,
        closing_count: u32,
        received_htlc_count: u32,
        offered_htlc_count: u32,
    ) -> ChannelBalance {
        ChannelBalance {
            claimable,
            received_htlc,
            offered_htlc,
            sweeping,
            stub_count,
            unconfirmed_count,
            channel_count,
            closing_count,
            received_htlc_count,
            offered_htlc_count,
        }
    }

    /// Create a ChannelBalance with zero values
    pub fn zero() -> ChannelBalance {
        ChannelBalance {
            claimable: 0,
            received_htlc: 0,
            offered_htlc: 0,
            sweeping: 0,
            stub_count: 0,
            unconfirmed_count: 0,
            channel_count: 0,
            closing_count: 0,
            received_htlc_count: 0,
            offered_htlc_count: 0,
        }
    }

    /// Create a ChannelBalance for a stub
    pub fn stub() -> ChannelBalance {
        let mut bal = ChannelBalance::zero();
        bal.stub_count = 1;
        bal
    }

    /// Sum channel balances
    pub fn accumulate(&mut self, other: &ChannelBalance) {
        self.claimable += other.claimable;
        self.received_htlc += other.received_htlc;
        self.offered_htlc += other.offered_htlc;
        self.sweeping += other.sweeping;
        self.stub_count += other.stub_count;
        self.unconfirmed_count += other.unconfirmed_count;
        self.channel_count += other.channel_count;
        self.closing_count += other.closing_count;
        self.received_htlc_count += other.received_htlc_count;
        self.offered_htlc_count += other.offered_htlc_count;
    }
}

// Phase 1
impl Channel {
    pub(crate) fn build_counterparty_commitment_info(
        &self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> Result<CommitmentInfo2, Status> {
        Ok(CommitmentInfo2::new(
            true,
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        ))
    }

    fn build_holder_commitment_info(
        &self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> Result<CommitmentInfo2, Status> {
        Ok(CommitmentInfo2::new(
            false,
            to_counterparty_value_sat,
            to_holder_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        ))
    }

    /// Phase 1
    pub fn sign_counterparty_commitment_tx(
        &mut self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<Signature, Status> {
        if tx.output.len() != output_witscripts.len() {
            return Err(invalid_argument("len(tx.output) != len(witscripts)"));
        }

        // Since we didn't have the value at the real open, validate it now.
        let validator = self.validator();
        validator.validate_channel_value(&self.setup)?;

        // Derive a CommitmentInfo first, convert to CommitmentInfo2 below ...
        let is_counterparty = true;
        let info = validator.decode_commitment_tx(
            &self.keys,
            &self.setup,
            is_counterparty,
            tx,
            output_witscripts,
        )?;

        let info2 = self.build_counterparty_commitment_info(
            info.to_countersigner_value_sat,
            info.to_broadcaster_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )?;

        let node = self.get_node();
        let mut state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, None, Some(&info2), &self.setup);

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(None, Some(&info2));

        validator
            .validate_counterparty_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &remote_per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                debug!(
                    "VALIDATION FAILED: {} tx={:?} setup={:?} cstate={:?} info={:?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                debug!(
                    "VALIDATION FAILED: {}\ntx={:#?}\nsetup={:#?}\ncstate={:#?}\ninfo={:#?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs =
            Self::htlcs_info2_to_oic(info2.offered_htlcs.clone(), info2.received_htlcs.clone());

        let recomposed_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            info2.to_countersigner_value_sat,
            info2.to_broadcaster_value_sat,
            htlcs,
        );

        if recomposed_tx.trust().built_transaction().transaction != *tx {
            #[cfg(not(feature = "log_pretty_print"))]
            {
                debug!("ORIGINAL_TX={:?}", &tx);
                debug!(
                    "RECOMPOSED_TX={:?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            #[cfg(feature = "log_pretty_print")]
            {
                debug!("ORIGINAL_TX={:#?}", &tx);
                debug!(
                    "RECOMPOSED_TX={:#?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            policy_err!(validator, "policy-commitment", "recomposed tx mismatch");
        }

        // The comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-commitment-version
        // - policy-commitment-locktime
        // - policy-commitment-sequence
        // - policy-commitment-input-single
        // - policy-commitment-input-match-funding
        // - policy-commitment-revocation-pubkey
        // - policy-commitment-broadcaster-pubkey
        // - policy-commitment-countersignatory-pubkey
        // - policy-commitment-htlc-revocation-pubkey
        // - policy-commitment-htlc-counterparty-htlc-pubkey
        // - policy-commitment-htlc-holder-htlc-pubkey
        // - policy-commitment-singular
        // - policy-commitment-to-self-delay
        // - policy-commitment-no-unrecognized-outputs

        // Convert from backwards counting.
        let commit_num = INITIAL_COMMITMENT_NUMBER - recomposed_tx.trust().commitment_number();

        let point = recomposed_tx.trust().keys().per_commitment_point;

        // we don't use keys.sign_counterparty_commitment here because it also signs HTLCs
        let trusted_tx = recomposed_tx.trust();

        let funding_pubkey = &self.keys.pubkeys().funding_pubkey;
        let counterparty_funding_pubkey = &self.setup.counterparty_points.funding_pubkey;
        let channel_funding_redeemscript =
            make_funding_redeemscript(funding_pubkey, counterparty_funding_pubkey);

        let built_tx = trusted_tx.built_transaction();
        let sig = catch_panic!(
            built_tx.sign_counterparty_commitment(
                &self.keys.funding_key,
                &channel_funding_redeemscript,
                self.setup.channel_value_sat,
                &self.secp_ctx,
            ),
            "sign_counterparty_commitment panic {} chantype={:?}",
            self.setup.commitment_type
        );

        let outgoing_payment_summary = self.enforcement_state.payments_summary(None, Some(&info2));
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        // Only advance the state if nothing goes wrong.
        validator.set_next_counterparty_commit_num(
            &mut self.enforcement_state,
            commit_num + 1,
            point,
            info2,
        )?;

        state.apply_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator,
        );

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(sig)
    }

    fn make_validated_recomposed_holder_commitment_tx(
        &self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        commitment_number: u64,
        per_commitment_point: PublicKey,
        txkeys: &TxCreationKeys,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(CommitmentTransaction, CommitmentInfo2, Map<PaymentHash, u64>), Status> {
        if tx.output.len() != output_witscripts.len() {
            return Err(invalid_argument(format!(
                "len(tx.output):{} != len(witscripts):{}",
                tx.output.len(),
                output_witscripts.len()
            )));
        }

        let validator = self.validator();

        // Since we didn't have the value at the real open, validate it now.
        validator.validate_channel_value(&self.setup)?;

        // Derive a CommitmentInfo first, convert to CommitmentInfo2 below ...
        let is_counterparty = false;
        let info = validator.decode_commitment_tx(
            &self.keys,
            &self.setup,
            is_counterparty,
            tx,
            output_witscripts,
        )?;

        let info2 = self.build_holder_commitment_info(
            info.to_broadcaster_value_sat,
            info.to_countersigner_value_sat,
            offered_htlcs.clone(),
            received_htlcs.clone(),
            feerate_per_kw,
        )?;

        let incoming_payment_summary =
            self.enforcement_state.incoming_payments_summary(Some(&info2), None);

        validator
            .validate_holder_commitment_tx(
                &self.enforcement_state,
                commitment_number,
                &per_commitment_point,
                &self.setup,
                &self.get_chain_state(),
                &info2,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                warn!(
                    "VALIDATION FAILED: {} tx={:?} setup={:?} state={:?} info={:?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                #[cfg(feature = "log_pretty_print")]
                warn!(
                    "VALIDATION FAILED: {}\ntx={:#?}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}",
                    ve,
                    &tx,
                    &self.setup,
                    &self.get_chain_state(),
                    &info2,
                );
                ve
            })?;

        let htlcs =
            Self::htlcs_info2_to_oic(info2.offered_htlcs.clone(), info2.received_htlcs.clone());

        let recomposed_tx = self.make_holder_commitment_tx(
            commitment_number,
            txkeys,
            feerate_per_kw,
            info.to_broadcaster_value_sat,
            info.to_countersigner_value_sat,
            htlcs.clone(),
        );

        if recomposed_tx.trust().built_transaction().transaction != *tx {
            dbgvals!(
                &self.setup,
                &self.enforcement_state,
                tx,
                DebugVecVecU8(output_witscripts),
                commitment_number,
                feerate_per_kw,
                &offered_htlcs,
                &received_htlcs
            );
            #[cfg(not(feature = "log_pretty_print"))]
            {
                warn!("RECOMPOSITION FAILED");
                warn!("ORIGINAL_TX={:?}", &tx);
                warn!("RECOMPOSED_TX={:?}", &recomposed_tx.trust().built_transaction().transaction);
            }
            #[cfg(feature = "log_pretty_print")]
            {
                warn!("RECOMPOSITION FAILED");
                warn!("ORIGINAL_TX={:#?}", &tx);
                warn!(
                    "RECOMPOSED_TX={:#?}",
                    &recomposed_tx.trust().built_transaction().transaction
                );
            }
            policy_err!(validator, "policy-commitment", "recomposed tx mismatch");
        }

        // The comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-commitment-version
        // - policy-commitment-locktime
        // - policy-commitment-sequence
        // - policy-commitment-input-single
        // - policy-commitment-input-match-funding
        // - policy-commitment-revocation-pubkey
        // - policy-commitment-broadcaster-pubkey
        // - policy-commitment-htlc-revocation-pubkey
        // - policy-commitment-htlc-counterparty-htlc-pubkey
        // - policy-commitment-htlc-holder-htlc-pubkey
        // - policy-revoke-new-commitment-valid

        Ok((recomposed_tx, info2, incoming_payment_summary))
    }

    /// Validate the counterparty's signatures on the holder's
    /// commitment and HTLCs when the commitment_signed message is
    /// received.  Returns the next per_commitment_point and the
    /// holder's revocation secret for the prior commitment.  This
    /// method advances the expected next holder commitment number in
    /// the signer's state.
    pub fn validate_holder_commitment_tx(
        &mut self,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
        commitment_number: u64,
        feerate_per_kw: u32,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        counterparty_commit_sig: &Signature,
        counterparty_htlc_sigs: &[Signature],
    ) -> Result<(), Status> {
        let validator = self.validator();
        let per_commitment_point = self.get_per_commitment_point(commitment_number)?;
        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        // policy-onchain-format-standard
        let (recomposed_tx, info2, incoming_payment_summary) = self
            .make_validated_recomposed_holder_commitment_tx(
                tx,
                output_witscripts,
                commitment_number,
                per_commitment_point,
                &txkeys,
                feerate_per_kw,
                offered_htlcs,
                received_htlcs,
            )?;

        let node = self.get_node();
        let state = node.get_state();
        let delta =
            self.enforcement_state.claimable_balances(&*state, Some(&info2), None, &self.setup);

        #[cfg(not(fuzzing))]
        self.check_holder_tx_signatures(
            &per_commitment_point,
            &txkeys,
            feerate_per_kw,
            counterparty_commit_sig,
            counterparty_htlc_sigs,
            recomposed_tx,
        )?;

        #[cfg(fuzzing)]
        let _ = recomposed_tx;

        let outgoing_payment_summary = self.enforcement_state.payments_summary(Some(&info2), None);
        state.validate_payments(
            &self.id0,
            &incoming_payment_summary,
            &outgoing_payment_summary,
            &delta,
            validator.clone(),
        )?;

        if commitment_number == self.enforcement_state.next_holder_commit_num {
            let counterparty_signatures = CommitmentSignatures(
                counterparty_commit_sig.clone(),
                counterparty_htlc_sigs.to_vec(),
            );
            self.enforcement_state.next_holder_commit_info = Some((info2, counterparty_signatures));
        }

        trace_enforcement_state!(self);
        self.persist()?;

        Ok(())
    }

    /// Activate commitment 0 explicitly
    ///
    /// Commitment 0 is special because it doesn't have a predecessor
    /// commitment.  Since the revocation of the prior commitment normally makes
    /// a new commitment "current" this final step must be invoked explicitly.
    ///
    /// Returns the next per_commitment_point.
    pub fn activate_initial_commitment(&mut self) -> Result<PublicKey, Status> {
        debug!("activate_initial_commitment");

        if self.enforcement_state.next_holder_commit_num != 0 {
            return Err(invalid_argument(format!(
                "activate_initial_commitment called with next_holder_commit_num {}",
                self.enforcement_state.next_holder_commit_num
            )));
        }

        // Remove the info and sigs from next holder and make current
        if let Some((info2, sigs)) = self.enforcement_state.next_holder_commit_info.take() {
            self.enforcement_state.set_next_holder_commit_num(1, info2, sigs);
        } else {
            return Err(invalid_argument(format!(
                "activate_initial_commitment called before validation of the initial commitment"
            )));
        }

        trace_enforcement_state!(self);
        self.persist()?;
        Ok(self.get_per_commitment_point_unchecked(1))
    }

    /// Process the counterparty's revocation
    ///
    /// When this is provided, we know that the counterparty has committed to
    /// the next state.
    pub fn validate_counterparty_revocation(
        &mut self,
        revoke_num: u64,
        old_secret: &SecretKey,
    ) -> Result<(), Status> {
        let validator = self.validator();
        validator.validate_counterparty_revocation(
            &self.enforcement_state,
            revoke_num,
            old_secret,
        )?;

        if let Some(secrets) = self.enforcement_state.counterparty_secrets.as_mut() {
            let backwards_num = INITIAL_COMMITMENT_NUMBER - revoke_num;
            if secrets.provide_secret(backwards_num, old_secret.secret_bytes()).is_err() {
                error!(
                    "secret does not chain: {} ({}) {} into {:?}",
                    revoke_num,
                    backwards_num,
                    old_secret.display_secret(),
                    secrets
                );
                policy_err!(
                    validator,
                    "policy-commitment-previous-revoked",
                    "counterparty secret does not chain"
                )
            }
        }

        validator.set_next_counterparty_revoke_num(&mut self.enforcement_state, revoke_num + 1)?;

        trace_enforcement_state!(self);
        self.persist()?;
        Ok(())
    }

    /// Phase 1
    pub fn sign_mutual_close_tx(
        &mut self,
        tx: &Transaction,
        opaths: &[Vec<u32>],
    ) -> Result<Signature, Status> {
        dbgvals!(tx.txid(), self.get_node().allowlist());
        if opaths.len() != tx.output.len() {
            return Err(invalid_argument(format!(
                "{}: bad opath len {} with tx.output len {}",
                short_function!(),
                opaths.len(),
                tx.output.len()
            )));
        }

        let recomposed_tx = self.validator().decode_and_validate_mutual_close_tx(
            &*self.get_node(),
            &self.setup,
            &self.enforcement_state,
            tx,
            opaths,
        )?;

        let sig = self
            .keys
            .sign_closing_transaction(&recomposed_tx, &self.secp_ctx)
            .map_err(|_| Status::internal("failed to sign"))?;
        self.enforcement_state.channel_closed = true;
        trace_enforcement_state!(self);
        self.persist()?;
        Ok(sig)
    }

    /// Phase 1
    pub fn sign_holder_htlc_tx(
        &self,
        tx: &Transaction,
        commitment_number: u64,
        opt_per_commitment_point: Option<PublicKey>,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
    ) -> Result<TypedSignature, Status> {
        let per_commitment_point = if opt_per_commitment_point.is_some() {
            opt_per_commitment_point.unwrap()
        } else {
            self.get_per_commitment_point(commitment_number)?
        };

        let txkeys = self.make_holder_tx_keys(&per_commitment_point);

        self.sign_htlc_tx(
            tx,
            &per_commitment_point,
            redeemscript,
            htlc_amount_sat,
            output_witscript,
            false, // is_counterparty
            txkeys,
        )
    }

    /// Phase 1
    pub fn sign_counterparty_htlc_tx(
        &self,
        tx: &Transaction,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
    ) -> Result<TypedSignature, Status> {
        let txkeys = self.make_counterparty_tx_keys(&remote_per_commitment_point);

        self.sign_htlc_tx(
            tx,
            remote_per_commitment_point,
            redeemscript,
            htlc_amount_sat,
            output_witscript,
            true, // is_counterparty
            txkeys,
        )
    }

    /// Sign a 2nd level HTLC transaction hanging off a commitment transaction
    pub fn sign_htlc_tx(
        &self,
        tx: &Transaction,
        per_commitment_point: &PublicKey,
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
        is_counterparty: bool,
        txkeys: TxCreationKeys,
    ) -> Result<TypedSignature, Status> {
        let (feerate_per_kw, htlc, recomposed_tx_sighash, sighash_type) =
            self.validator().decode_and_validate_htlc_tx(
                is_counterparty,
                &self.setup,
                &txkeys,
                tx,
                &redeemscript,
                htlc_amount_sat,
                output_witscript,
            )?;

        self.validator()
            .validate_htlc_tx(
                &self.setup,
                &self.get_chain_state(),
                is_counterparty,
                &htlc,
                feerate_per_kw,
            )
            .map_err(|ve| {
                #[cfg(not(feature = "log_pretty_print"))]
                debug!(
                    "VALIDATION FAILED: {} setup={:?} state={:?} is_counterparty={} \
                     tx={:?} htlc={:?} feerate_per_kw={}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    is_counterparty,
                    &tx,
                    DebugHTLCOutputInCommitment(&htlc),
                    feerate_per_kw,
                );
                #[cfg(feature = "log_pretty_print")]
                debug!(
                    "VALIDATION FAILED: {}\n\
                     setup={:#?}\n\
                     state={:#?}\n\
                     is_counterparty={}\n\
                     tx={:#?}\n\
                     htlc={:#?}\n\
                     feerate_per_kw={}",
                    ve,
                    &self.setup,
                    &self.get_chain_state(),
                    is_counterparty,
                    &tx,
                    DebugHTLCOutputInCommitment(&htlc),
                    feerate_per_kw,
                );
                ve
            })?;

        let htlc_privkey =
            derive_private_key(&self.secp_ctx, &per_commitment_point, &self.keys.htlc_base_key);

        let htlc_sighash = Message::from_slice(&recomposed_tx_sighash[..])
            .map_err(|_| Status::internal("failed to sighash recomposed"))?;

        Ok(TypedSignature {
            sig: self.secp_ctx.sign_ecdsa(&htlc_sighash, &htlc_privkey),
            typ: sighash_type,
        })
    }

    /// Get the unilateral close key and the witness stack suffix,
    /// for sweeping our main output from a commitment transaction.
    /// If the revocation_pubkey is Some, then we are sweeping a
    /// holder commitment transaction, otherwise we are sweeping a
    /// counterparty commitment transaction.
    /// commitment_point is used to derive the key if it is Some.
    /// Since we don't support legacy channels, commitment_point must
    /// be Some iff revocation_pubkey is Some.
    pub fn get_unilateral_close_key(
        &self,
        commitment_point: &Option<PublicKey>,
        revocation_pubkey: &Option<RevocationKey>,
    ) -> Result<(SecretKey, Vec<Vec<u8>>), Status> {
        if let Some(commitment_point) = commitment_point {
            // The key is rotated via the commitment point.  Since we removed support
            // for rotating the to-remote key (legacy channel type), we enforce below that
            // this is the to-local case.
            let base_key = if revocation_pubkey.is_some() {
                &self.keys.delayed_payment_base_key
            } else {
                &self.keys.payment_key
            };
            let key = derive_private_key(&self.secp_ctx, &commitment_point, base_key);
            let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &key);

            let witness_stack_prefix = if let Some(r) = revocation_pubkey {
                // p2wsh
                let contest_delay = self.setup.counterparty_selected_contest_delay;
                let redeemscript = chan_utils::get_revokeable_redeemscript(
                    r,
                    contest_delay,
                    &DelayedPaymentKey(pubkey),
                )
                .to_bytes();
                vec![vec![], redeemscript]
            } else {
                return Err(invalid_argument(
                    "no support for legacy rotated to-remote, commitment point is provided and revocation_pubkey is not"
                ));
            };
            Ok((key, witness_stack_prefix))
        } else {
            // The key is not rotated, so we use the base key.  This must be the to-remote case
            // because the to-local is always rotated.
            if revocation_pubkey.is_some() {
                return Err(invalid_argument(
                    "delayed to-local output must be rotated, but no commitment point provided",
                ));
            }

            let key = self.keys.payment_key.clone();
            let pubkey = PublicKey::from_secret_key(&self.secp_ctx, &key);
            let witness_stack_prefix = if self.setup.is_anchors() {
                // p2wsh
                let redeemscript =
                    chan_utils::get_to_countersignatory_with_anchors_redeemscript(&pubkey)
                        .to_bytes();
                vec![redeemscript]
            } else {
                // p2wpkh
                vec![pubkey.serialize().to_vec()]
            };
            Ok((key, witness_stack_prefix))
        }
    }

    /// Mark any in-flight payments (outgoing HTLCs) on this channel with the
    /// given preimage as filled.
    /// Any such payments adjust our expected balance downwards.
    pub fn htlcs_fulfilled(&mut self, preimages: Vec<PaymentPreimage>) {
        let validator = self.validator();
        let node = self.get_node();
        node.htlcs_fulfilled(&self.id0, preimages, validator);
    }

    fn dummy_sig() -> Signature {
        Signature::from_compact(&Vec::from_hex("eb299947b140c0e902243ee839ca58c71291f4cce49ac0367fb4617c4b6e890f18bc08b9be6726c090af4c6b49b2277e134b34078f710a72a5752e39f0139149").unwrap()).unwrap()
    }
}

#[derive(Clone)]
pub(crate) struct ChannelCommitmentPointProvider {
    chan: Arc<Mutex<ChannelSlot>>,
}

impl ChannelCommitmentPointProvider {
    /// Will panic on a channel stub
    pub(crate) fn new(chan: Arc<Mutex<ChannelSlot>>) -> Self {
        match &*chan.lock().unwrap() {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(_) => {}
        }
        Self { chan }
    }

    fn get_channel(&self) -> MutexGuard<ChannelSlot> {
        self.chan.lock().unwrap()
    }
}

impl SendSync for ChannelCommitmentPointProvider {}

impl CommitmentPointProvider for ChannelCommitmentPointProvider {
    fn get_holder_commitment_point(&self, commitment_number: u64) -> PublicKey {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };
        chan.get_per_commitment_point_unchecked(commitment_number)
    }

    fn get_counterparty_commitment_point(&self, commitment_number: u64) -> Option<PublicKey> {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };

        chan.get_counterparty_commitment_point(commitment_number)
    }

    fn get_transaction_parameters(&self) -> ChannelTransactionParameters {
        let slot = self.get_channel();
        let chan = match &*slot {
            ChannelSlot::Stub(_) => panic!("unexpected stub"),
            ChannelSlot::Ready(c) => c,
        };

        chan.make_channel_parameters()
    }

    fn clone_box(&self) -> Box<dyn CommitmentPointProvider> {
        Box::new(ChannelCommitmentPointProvider { chan: self.chan.clone() })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
    use lightning::ln::chan_utils::HTLCOutputInCommitment;
    use lightning::ln::PaymentHash;
    use lightning::util::ser::Writeable;

    use crate::channel::{ldk_channel_id_from_oid, oid_from_ldk_channel_id, ChannelBase};
    use crate::util::test_utils::{
        init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
    };

    use super::ChannelId;

    #[test]
    fn test_dummy_sig() {
        let dummy_sig = Secp256k1::new().sign_ecdsa(
            &secp256k1::Message::from_slice(&[42; 32]).unwrap(),
            &SecretKey::from_slice(&[42; 32]).unwrap(),
        );
        let ser = dummy_sig.serialize_compact();
        assert_eq!("eb299947b140c0e902243ee839ca58c71291f4cce49ac0367fb4617c4b6e890f18bc08b9be6726c090af4c6b49b2277e134b34078f710a72a5752e39f0139149", hex::encode(ser));
    }

    #[test]
    fn tx_size_test() {
        let (node, channel_id) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[1], make_test_channel_setup());
        node.with_channel(&channel_id, |chan| {
            let n = 1;
            let commitment_point = chan.get_per_commitment_point(n).unwrap();
            let txkeys = chan.make_holder_tx_keys(&commitment_point);
            let htlcs = (0..583)
                .map(|i| HTLCOutputInCommitment {
                    offered: true,
                    amount_msat: 1000000,
                    cltv_expiry: 100,
                    payment_hash: PaymentHash([0; 32]),
                    transaction_output_index: Some(i),
                })
                .collect();
            let tx = chan.make_holder_commitment_tx(n, &txkeys, 1, 1, 1, htlcs);
            let tx_size = tx.trust().built_transaction().transaction.serialized_length();
            assert_eq!(tx_size, 25196);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_ldk_oid() {
        let oid: u64 = 42;
        let mut channel_id_inner = [0u8; 32];
        channel_id_inner[..8].copy_from_slice(&oid.to_be_bytes());
        let channel_id = ChannelId(channel_id_inner.to_vec());

        assert_eq!(oid, oid_from_ldk_channel_id(&channel_id.inner()));
        assert_eq!(channel_id, ChannelId(ldk_channel_id_from_oid(oid).to_vec()));
    }
}
