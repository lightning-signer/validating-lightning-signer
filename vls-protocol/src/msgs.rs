#![allow(missing_docs)]
#![allow(deprecated)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use as_any::AsAny;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use core::fmt::{Debug, Formatter};
use core::ops::Deref;
use serde_bolt::{bitcoin, ReadBigEndian};
use txoo::bitcoin::hash_types::FilterHeader;

use crate::error::{Error, Result};
use crate::model::*;
use crate::psbt::{PsbtWrapper, StreamedPSBT};
use bitcoin_consensus_derive::{Decodable, Encodable};
#[cfg(feature = "developer")]
use bolt_derive::SerBoltTlvOptions;
use bolt_derive::{ReadMessage, SerBolt};
#[cfg(feature = "developer")]
use lightning_signer::lightning;
use lightning_signer::prelude::*;
use serde_bolt::{
    io, io::Read, io::Write, take::Take, to_vec, Array, ArrayBE, LargeOctets, Octets, WireString,
    WithSize,
};
use txoo::proof::{ProofType, TxoProof};

use log::error;

const MAX_MESSAGE_SIZE: u32 = 128 * 1024;

// Error codes used to demarcate Message::SignerError instances
pub const CODE_ORPHAN_BLOCK: u16 = 401;

// Notable hsmd protocol versions
pub const PROTOCOL_VERSION_REVOKE: u32 = 5; // RevokeCommitmentTx was split from ValidateCommitmentTx
pub const PROTOCOL_VERSION_NO_SECRET: u32 = 6; // GetPerCommitmentPoint no longer returns secret

/// Our default protcol version
/// (see also [`HsmdInit::hsm_wire_min_version`], etc.)
pub const DEFAULT_MAX_PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_NO_SECRET;

/// Our minimum protcol version
pub const MIN_PROTOCOL_VERSION: u32 = 2;

/// Serialize a message with a type prefix, in BOLT style
pub trait SerBolt: Debug + AsAny + Send {
    fn as_vec(&self) -> Vec<u8>;
    fn name(&self) -> &'static str;
}

pub trait DeBolt: Debug + Sized + Encodable + Decodable {
    const TYPE: u16;
    fn from_vec(ser: Vec<u8>) -> Result<Self>;
}

/// An unknown message
#[derive(Debug, Decodable)]
pub struct Unknown {
    /// Message type
    pub message_type: u16,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1)]
pub struct Ecdh {
    pub point: PubKey,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(100)]
pub struct EcdhReply {
    pub secret: Secret,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2)]
pub struct SignChannelAnnouncement {
    pub announcement: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(102)]
pub struct SignChannelAnnouncementReply {
    pub node_signature: Signature,
    pub bitcoin_signature: Signature,
}

/// Sign channel update
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(3)]
pub struct SignChannelUpdate {
    pub update: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(103)]
pub struct SignChannelUpdateReply {
    pub update: Octets,
}

/// CLN only
/// Same as [SignChannelAnnouncement] but called from lightningd
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(4)]
pub struct SignAnyChannelAnnouncement {
    pub announcement: Octets,
    pub peer_id: PubKey,
    pub dbid: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(104)]
pub struct SignAnyChannelAnnouncementReply {
    pub node_signature: Signature,
    pub bitcoin_signature: Signature,
}

///
/// CLN only
#[derive(SerBolt, Encodable, Decodable)]
#[message_id(5)]
pub struct SignCommitmentTx {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub remote_funding_key: PubKey,
    pub commitment_number: u64,
}

impl Debug for SignCommitmentTx {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // Sometimes c-lightning calls handle_sign_commitment_tx with mutual
        // close transactions.  We can tell the difference because the locktime
        // field will be set to 0 for a mutual close.
        let name = if self.tx.0.lock_time.to_consensus_u32() == 0 {
            "SignMutualCloseTx as a SignCommitmentTx"
        } else {
            "SignCommitmentTx"
        };
        f.debug_struct(name)
            .field("peer_id", &self.peer_id)
            .field("dbid", &self.dbid)
            .field("tx", &self.tx)
            .field("psbt", &self.psbt)
            .field("remote_funding_key", &self.remote_funding_key)
            .field("commitment_number", &self.commitment_number)
            .finish()
    }
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(105)]
pub struct SignCommitmentTxReply {
    pub signature: BitcoinSignature,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(6)]
pub struct SignNodeAnnouncement {
    pub announcement: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(106)]
pub struct SignNodeAnnouncementReply {
    pub signature: Signature,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(7)]
pub struct SignWithdrawal {
    pub utxos: Array<Utxo>,
    pub psbt: WithSize<StreamedPSBT>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(107)]
pub struct SignWithdrawalReply {
    pub psbt: WithSize<PsbtWrapper>,
}

/// Sign invoice
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(8)]
pub struct SignInvoice {
    pub u5bytes: Octets,
    pub hrp: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(108)]
pub struct SignInvoiceReply {
    pub signature: RecoverableSignature,
}

/// Connect a new client
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(9)]
pub struct ClientHsmFd {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub capabilities: u64,
}

/// TODO fd handling
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(109)]
pub struct ClientHsmFdReply {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(10)]
pub struct GetChannelBasepoints {
    pub node_id: PubKey,
    pub dbid: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(110)]
pub struct GetChannelBasepointsReply {
    pub basepoints: Basepoints,
    pub funding: PubKey,
}

/// hsmd Init
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(11)]
pub struct HsmdInit {
    pub key_version: Bip32KeyVersion,
    pub chain_params: BlockHash,
    pub encryption_key: Option<DevSecret>,
    pub dev_privkey: Option<DevPrivKey>,
    pub dev_bip32_seed: Option<DevSecret>,
    pub dev_channel_secrets: Option<Array<DevSecret>>,
    pub dev_channel_secrets_shaseed: Option<Sha256>,
    pub hsm_wire_min_version: u32,
    pub hsm_wire_max_version: u32,
}

/// deprecated after CLN v23.05
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(113)]
pub struct HsmdInitReplyV2 {
    pub node_id: PubKey,
    pub bip32: ExtKey,
    pub bolt12: PubKey,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(114)]
pub struct HsmdInitReplyV4 {
    /// This gets upgraded when the wire protocol changes in incompatible ways:
    pub hsm_version: u32,
    /// Capabilities, by convention are message numbers, indicating that the HSM
    /// supports you sending this message.
    pub hsm_capabilities: ArrayBE<u32>,
    pub node_id: PubKey,
    pub bip32: ExtKey,
    pub bolt12: PubKey,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(12)]
pub struct SignDelayedPaymentToUs {
    pub commitment_number: u64,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(112)]
pub struct SignTxReply {
    pub signature: BitcoinSignature,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(13)]
pub struct SignRemoteHtlcToUs {
    pub remote_per_commitment_point: PubKey,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub option_anchors: bool,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(14)]
pub struct SignPenaltyToUs {
    pub revocation_secret: DisclosedSecret,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(16)]
pub struct SignLocalHtlcTx {
    pub commitment_number: u64,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub option_anchors: bool,
}

/// Get per-commitment point n and optionally revoke a point n-2 by releasing the secret
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(18)]
pub struct GetPerCommitmentPoint {
    pub commitment_number: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(118)]
pub struct GetPerCommitmentPointReply {
    pub point: PubKey,
    pub secret: Option<DisclosedSecret>,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(19)]
pub struct SignRemoteCommitmentTx {
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub remote_funding_key: PubKey,
    pub remote_per_commitment_point: PubKey,
    pub option_static_remotekey: bool,
    pub commitment_number: u64,
    pub htlcs: Array<Htlc>,
    pub feerate: u32,
}

/// LDK message to sign a local HTLC transaction.
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(20)]
pub struct SignLocalHtlcTx2 {
    pub tx: WithSize<Transaction>,
    pub input: u32,
    pub per_commitment_number: u64,
    pub offered: bool,
    pub cltv_expiry: u32,
    pub htlc_amount_msat: u64,
    pub payment_hash: Sha256,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(20)]
pub struct SignRemoteHtlcTx {
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub remote_per_commitment_point: PubKey,
    pub option_anchors: bool,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(21)]
pub struct SignMutualCloseTx {
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub remote_funding_key: PubKey,
}

/// CheckFutureSecret
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(22)]
pub struct CheckFutureSecret {
    pub commitment_number: u64,
    pub secret: DisclosedSecret,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(122)]
pub struct CheckFutureSecretReply {
    pub result: bool,
}

/// SignMessage
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(23)]
pub struct SignMessage {
    pub message: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(123)]
pub struct SignMessageReply {
    pub signature: RecoverableSignature,
}

/// SignBolt12
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(25)]
pub struct SignBolt12 {
    pub message_name: WireString,
    pub field_name: WireString,
    pub merkle_root: Sha256,
    pub public_tweak: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(125)]
pub struct SignBolt12Reply {
    pub signature: Signature,
}

/// DeriveSecret
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(27)]
pub struct DeriveSecret {
    pub info: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(127)]
pub struct DeriveSecretReply {
    pub secret: Secret,
}

/// CheckPubKey
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(28)]
pub struct CheckPubKey {
    pub index: u32,
    pub pubkey: PubKey,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(128)]
pub struct CheckPubKeyReply {
    pub ok: bool,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(29)]
pub struct SignSpliceTx {
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub remote_funding_key: PubKey,
    pub input_index: u32,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(30)]
pub struct NewChannel {
    pub peer_id: PubKey,
    pub dbid: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(130)]
pub struct NewChannelReply {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(31)]
pub struct SetupChannel {
    pub is_outbound: bool,
    pub channel_value: u64,
    pub push_value: u64,
    pub funding_txid: Txid,
    pub funding_txout: u16,
    pub to_self_delay: u16,
    pub local_shutdown_script: Octets,
    pub local_shutdown_wallet_index: Option<u32>,
    pub remote_basepoints: Basepoints,
    pub remote_funding_pubkey: PubKey,
    pub remote_to_self_delay: u16,
    pub remote_shutdown_script: Octets,
    pub channel_type: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(131)]
pub struct SetupChannelReply {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(32)]
pub struct CheckOutpoint {
    pub funding_txid: Txid,
    pub funding_txout: u16,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(132)]
pub struct CheckOutpointReply {
    pub is_buried: bool,
}

/// Memleak
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(33)]
pub struct Memleak {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(133)]
pub struct MemleakReply {
    pub result: bool,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(34)]
pub struct ForgetChannel {
    pub node_id: PubKey,
    pub dbid: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(134)]
pub struct ForgetChannelReply {}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(35)]
pub struct ValidateCommitmentTx {
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub htlcs: Array<Htlc>,
    pub commitment_number: u64,
    pub feerate: u32,
    pub signature: BitcoinSignature,
    pub htlc_signatures: Array<BitcoinSignature>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(135)]
pub struct ValidateCommitmentTxReply {
    pub old_commitment_secret: Option<DisclosedSecret>,
    pub next_per_commitment_point: PubKey,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(36)]
pub struct ValidateRevocation {
    pub commitment_number: u64,
    pub commitment_secret: DisclosedSecret,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(136)]
pub struct ValidateRevocationReply {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(37)]
pub struct LockOutpoint {
    pub funding_txid: Txid,
    pub funding_txout: u16,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(137)]
pub struct LockOutpointReply {}

/// PreapproveInvoice {
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(38)]
pub struct PreapproveInvoice {
    pub invstring: WireString,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(138)]
pub struct PreapproveInvoiceReply {
    pub result: bool,
}

/// PreapproveKeysend {
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(39)]
pub struct PreapproveKeysend {
    pub destination: PubKey,
    pub payment_hash: Sha256,
    pub amount_msat: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(139)]
pub struct PreapproveKeysendReply {
    pub result: bool,
}

///
/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(40)]
pub struct RevokeCommitmentTx {
    pub commitment_number: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(140)]
pub struct RevokeCommitmentTxReply {
    pub old_commitment_secret: DisclosedSecret,
    pub next_per_commitment_point: PubKey,
}

// SignBolt12V2
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(41)]
pub struct SignBolt12V2 {
    pub message_name: WireString,
    pub field_name: WireString,
    pub merkle_root: Sha256,
    pub info: Octets,
    pub public_tweak: Octets,
}

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(141)]
pub struct SignBolt12V2Reply {
    pub signature: Signature,
}

/// Developer setup for testing
/// Must preceed `HsmdInit{,2}` message
#[cfg(feature = "developer")]
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(90)]
pub struct HsmdDevPreinit {
    pub derivation_style: u8,
    pub network_name: WireString,
    pub seed: Option<DevSecret>,
    pub allowlist: Array<WireString>,
}

/// TLV encoded options for HsmdDevPreinit2
#[cfg(feature = "developer")]
#[derive(SerBoltTlvOptions, Default, Debug, Clone)]
pub struct HsmdDevPreinit2Options {
    // CLN: allocates from 1 ascending
    #[tlv_tag = 1]
    pub fail_preapprove: Option<bool>,
    #[tlv_tag = 3]
    pub no_preapprove_check: Option<bool>,

    // VLS: allocates from 252 descending (largest single byte tag value is 252)
    #[tlv_tag = 252]
    pub derivation_style: Option<u8>,
    #[tlv_tag = 251]
    pub network_name: Option<WireString>,
    #[tlv_tag = 250]
    pub seed: Option<DevSecret>,
    #[tlv_tag = 249]
    pub allowlist: Option<Array<WireString>>,
}

/// Developer setup for testing
/// Must preceed `HsmdInit{,2}` message
#[cfg(feature = "developer")]
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(99)]
pub struct HsmdDevPreinit2 {
    pub options: HsmdDevPreinit2Options,
}

/// HsmdDevPreinit2 does not return a reply

#[cfg(feature = "developer")]
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(190)]
pub struct HsmdDevPreinitReply {
    /// The derived nodeid (or generated if none was supplied)
    pub node_id: PubKey,
}

/// CLN only
/// Same as [SignDelayedPaymentToUs] but called from lightningd
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(142)]
pub struct SignAnyDelayedPaymentToUs {
    pub commitment_number: u64,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub input: u32,
    pub peer_id: PubKey,
    pub dbid: u64,
}

/// CLN only
/// Same as [SignRemoteHtlcToUs] but called from lightningd
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(143)]
pub struct SignAnyRemoteHtlcToUs {
    pub remote_per_commitment_point: PubKey,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub option_anchors: bool,
    pub input: u32,
    pub peer_id: PubKey,
    pub dbid: u64,
}

/// Same as [SignPenaltyToUs] but called from lightningd
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(144)]
pub struct SignAnyPenaltyToUs {
    pub revocation_secret: DisclosedSecret,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub input: u32,
    pub peer_id: PubKey,
    pub dbid: u64,
}

/// CLN only
/// Same as [SignLocalHtlcTx] but called from lightningd
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(146)]
pub struct SignAnyLocalHtlcTx {
    pub commitment_number: u64,
    pub tx: WithSize<Transaction>,
    pub psbt: WithSize<PsbtWrapper>,
    pub wscript: Octets,
    pub option_anchors: bool,
    pub input: u32,
    pub peer_id: PubKey,
    pub dbid: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(147)]
pub struct SignAnchorspend {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub utxos: Array<Utxo>,
    pub psbt: WithSize<StreamedPSBT>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(148)]
pub struct SignAnchorspendReply {
    pub psbt: WithSize<PsbtWrapper>,
}

/// CLN only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(149)]
pub struct SignHtlcTxMingle {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub utxos: Array<Utxo>,
    pub psbt: WithSize<StreamedPSBT>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(150)]
pub struct SignHtlcTxMingleReply {
    pub psbt: WithSize<PsbtWrapper>,
}

/// Ping request
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1000)]
pub struct Ping {
    pub id: u16,
    pub message: WireString,
}

/// Ping reply
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1100)]
pub struct Pong {
    pub id: u16,
    pub message: WireString,
}

///
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1005)]
pub struct SignLocalCommitmentTx2 {
    pub commitment_number: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1006)]
pub struct SignGossipMessage {
    pub message: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1106)]
pub struct SignGossipMessageReply {
    pub signature: Signature,
}

/// Signer Init for LDK
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1011)]
pub struct HsmdInit2 {
    pub derivation_style: u8,
    pub network_name: WireString,
    pub dev_seed: Option<DevSecret>,
    pub dev_allowlist: Array<WireString>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1111)]
pub struct HsmdInit2Reply {
    pub node_id: PubKey,
    pub bip32: ExtKey,
    pub bolt12: PubKey,
}

/// Get node public keys.
/// Used by the frontend
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1012)]
pub struct NodeInfo {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1112)]
pub struct NodeInfoReply {
    pub network_name: WireString,
    pub node_id: PubKey,
    pub bip32: ExtKey,
}

/// Get per-commitment point
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1018)]
pub struct GetPerCommitmentPoint2 {
    pub commitment_number: u64,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1118)]
pub struct GetPerCommitmentPoint2Reply {
    pub point: PubKey,
}

///
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1019)]
pub struct SignRemoteCommitmentTx2 {
    pub remote_per_commitment_point: PubKey,
    pub commitment_number: u64,
    pub feerate: u32,
    pub to_local_value_sat: u64,
    pub to_remote_value_sat: u64,
    pub htlcs: Array<Htlc>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1119)]
pub struct SignCommitmentTxWithHtlcsReply {
    pub signature: BitcoinSignature,
    pub htlc_signatures: Array<BitcoinSignature>,
}

///
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1021)]
pub struct SignMutualCloseTx2 {
    pub to_local_value_sat: u64,
    pub to_remote_value_sat: u64,
    pub local_script: Octets,
    pub remote_script: Octets,
    pub local_wallet_path_hint: ArrayBE<u32>,
}

///
/// LDK only
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(1035)]
pub struct ValidateCommitmentTx2 {
    pub commitment_number: u64,
    pub feerate: u32,
    pub to_local_value_sat: u64,
    pub to_remote_value_sat: u64,
    pub htlcs: Array<Htlc>,
    pub signature: BitcoinSignature,
    pub htlc_signatures: Array<BitcoinSignature>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2002)]
pub struct TipInfo {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2102)]
pub struct TipInfoReply {
    pub height: u32,
    pub block_hash: BlockHash,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2003)]
pub struct ForwardWatches {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2103)]
pub struct ForwardWatchesReply {
    pub txids: Array<Txid>,
    pub outpoints: Array<OutPoint>,
}

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2004)]
pub struct ReverseWatches {}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2104)]
pub struct ReverseWatchesReply {
    pub txids: Array<Txid>,
    pub outpoints: Array<OutPoint>,
}

/// A debug wrapper around a TxoProof
pub struct DebugTxoProof(pub TxoProof);

impl Debug for DebugTxoProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match &self.0.proof {
            ProofType::Filter(filt, _) => write!(f, "TxoProof filter len={}", filt.len()),
            ProofType::Block(_) => write!(f, "TxoProof block"),
            ProofType::ExternalBlock() => write!(f, "TxoProof external block"),
        }
    }
}

impl Deref for DebugTxoProof {
    type Target = TxoProof;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Decodable for DebugTxoProof {
    fn consensus_decode<D: Read + ?Sized>(
        d: &mut D,
    ) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
        let proof = TxoProof::consensus_decode(d)?;
        Ok(DebugTxoProof(proof))
    }
}

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2005)]
pub struct AddBlock {
    /// Bitcoin consensus encoded
    pub header: Octets,
    /// Bitcoin consensus encoded TXOO TxoProof
    pub unspent_proof: Option<DebugTxoProof>,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2105)]
pub struct AddBlockReply {}

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2006)]
pub struct RemoveBlock {
    /// Bitcoin consensus encoded TXOO TxoProof
    // FIXME do we need the option?
    pub unspent_proof: Option<LargeOctets>,
    pub prev_block_header: BlockHeader,
    pub prev_filter_header: FilterHeader,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2106)]
pub struct RemoveBlockReply {}

/// Get a serialized signed heartbeat
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2008)]
pub struct GetHeartbeat {}

/// A serialized signed heartbeat
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2108)]
pub struct GetHeartbeatReply {
    pub heartbeat: Octets,
}

/// Start or continue streaming a full block.
/// Used when the compact proof has a false positive.
/// The hash and the offset are provided to fail fast
/// if there is a communication error.
/// The stream of messages is always followed by an `AddBlock` with
/// a proof type `ExternalBlock`.
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2009)]
pub struct BlockChunk {
    pub hash: BlockHash,
    pub offset: u32,
    pub content: Octets,
}

///
#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(2109)]
pub struct BlockChunkReply {}

// Watcher reply struct declarations moved next to their requests above.

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(3000)]
pub struct SignerError {
    // Error code
    pub code: u16,
    // Error message
    pub message: WireString,
}

#[derive(SerBolt, Debug, Encodable, Decodable)]
#[message_id(65535)]
pub struct UnknownPlaceholder {}

pub const UNKNOWN_PLACEHOLDER: UnknownPlaceholder = UnknownPlaceholder {};

/// An enum representing all messages we can read and write
#[derive(ReadMessage, Debug)]
pub enum Message {
    Ecdh(Ecdh),
    EcdhReply(EcdhReply),
    SignChannelAnnouncement(SignChannelAnnouncement),
    SignChannelAnnouncementReply(SignChannelAnnouncementReply),
    SignChannelUpdate(SignChannelUpdate),
    SignChannelUpdateReply(SignChannelUpdateReply),
    SignAnyChannelAnnouncement(SignAnyChannelAnnouncement),
    SignAnyChannelAnnouncementReply(SignAnyChannelAnnouncementReply),
    SignCommitmentTx(SignCommitmentTx),
    SignCommitmentTxReply(SignCommitmentTxReply),
    SignNodeAnnouncement(SignNodeAnnouncement),
    SignNodeAnnouncementReply(SignNodeAnnouncementReply),
    SignWithdrawal(SignWithdrawal),
    SignWithdrawalReply(SignWithdrawalReply),
    SignInvoice(SignInvoice),
    SignInvoiceReply(SignInvoiceReply),
    ClientHsmFd(ClientHsmFd),
    ClientHsmFdReply(ClientHsmFdReply),
    GetChannelBasepoints(GetChannelBasepoints),
    GetChannelBasepointsReply(GetChannelBasepointsReply),
    HsmdInit(HsmdInit),
    #[allow(deprecated)]
    HsmdInitReplyV2(HsmdInitReplyV2),
    HsmdInitReplyV4(HsmdInitReplyV4),

    SignDelayedPaymentToUs(SignDelayedPaymentToUs),
    SignTxReply(SignTxReply),
    SignRemoteHtlcToUs(SignRemoteHtlcToUs),
    SignPenaltyToUs(SignPenaltyToUs),
    SignLocalHtlcTx(SignLocalHtlcTx),
    GetPerCommitmentPoint(GetPerCommitmentPoint),
    GetPerCommitmentPointReply(GetPerCommitmentPointReply),
    SignRemoteCommitmentTx(SignRemoteCommitmentTx),
    SignRemoteHtlcTx(SignRemoteHtlcTx),
    SignLocalHtlcTx2(SignLocalHtlcTx2),
    SignMutualCloseTx(SignMutualCloseTx),
    CheckFutureSecret(CheckFutureSecret),
    CheckFutureSecretReply(CheckFutureSecretReply),
    SignMessage(SignMessage),
    SignMessageReply(SignMessageReply),
    SignBolt12(SignBolt12),
    SignBolt12Reply(SignBolt12Reply),
    DeriveSecret(DeriveSecret),
    DeriveSecretReply(DeriveSecretReply),
    CheckPubKey(CheckPubKey),
    CheckPubKeyReply(CheckPubKeyReply),
    SignSpliceTx(SignSpliceTx),
    NewChannel(NewChannel),
    NewChannelReply(NewChannelReply),
    SetupChannel(SetupChannel),
    SetupChannelReply(SetupChannelReply),
    CheckOutpoint(CheckOutpoint),
    CheckOutpointReply(CheckOutpointReply),
    Memleak(Memleak),
    MemleakReply(MemleakReply),
    ForgetChannel(ForgetChannel),
    ForgetChannelReply(ForgetChannelReply),
    ValidateCommitmentTx(ValidateCommitmentTx),
    ValidateCommitmentTxReply(ValidateCommitmentTxReply),
    ValidateRevocation(ValidateRevocation),
    ValidateRevocationReply(ValidateRevocationReply),
    LockOutpoint(LockOutpoint),
    LockOutpointReply(LockOutpointReply),
    PreapproveInvoice(PreapproveInvoice),
    PreapproveInvoiceReply(PreapproveInvoiceReply),
    PreapproveKeysend(PreapproveKeysend),
    PreapproveKeysendReply(PreapproveKeysendReply),
    RevokeCommitmentTx(RevokeCommitmentTx),
    RevokeCommitmentTxReply(RevokeCommitmentTxReply),
    SignBolt12V2(SignBolt12V2),
    SignBolt12V2Reply(SignBolt12V2Reply),
    SignAnyDelayedPaymentToUs(SignAnyDelayedPaymentToUs),
    SignAnyRemoteHtlcToUs(SignAnyRemoteHtlcToUs),
    SignAnyPenaltyToUs(SignAnyPenaltyToUs),
    SignAnyLocalHtlcTx(SignAnyLocalHtlcTx),
    SignAnchorspend(SignAnchorspend),
    SignAnchorspendReply(SignAnchorspendReply),
    SignHtlcTxMingle(SignHtlcTxMingle),
    SignHtlcTxMingleReply(SignHtlcTxMingleReply),
    #[cfg(feature = "developer")]
    HsmdDevPreinit(HsmdDevPreinit),
    #[cfg(feature = "developer")]
    HsmdDevPreinit2(HsmdDevPreinit2),
    #[cfg(feature = "developer")]
    HsmdDevPreinitReply(HsmdDevPreinitReply),
    Ping(Ping),
    Pong(Pong),
    SignLocalCommitmentTx2(SignLocalCommitmentTx2),
    SignGossipMessage(SignGossipMessage),
    SignGossipMessageReply(SignGossipMessageReply),
    HsmdInit2(HsmdInit2),
    HsmdInit2Reply(HsmdInit2Reply),
    NodeInfo(NodeInfo),
    NodeInfoReply(NodeInfoReply),
    GetPerCommitmentPoint2(GetPerCommitmentPoint2),
    GetPerCommitmentPoint2Reply(GetPerCommitmentPoint2Reply),
    SignRemoteCommitmentTx2(SignRemoteCommitmentTx2),
    SignCommitmentTxWithHtlcsReply(SignCommitmentTxWithHtlcsReply),
    SignMutualCloseTx2(SignMutualCloseTx2),
    ValidateCommitmentTx2(ValidateCommitmentTx2),
    TipInfo(TipInfo),
    TipInfoReply(TipInfoReply),
    ForwardWatches(ForwardWatches),
    ForwardWatchesReply(ForwardWatchesReply),
    ReverseWatches(ReverseWatches),
    ReverseWatchesReply(ReverseWatchesReply),
    AddBlock(AddBlock),
    AddBlockReply(AddBlockReply),
    RemoveBlock(RemoveBlock),
    RemoveBlockReply(RemoveBlockReply),
    GetHeartbeat(GetHeartbeat),
    GetHeartbeatReply(GetHeartbeatReply),
    BlockChunk(BlockChunk),
    BlockChunkReply(BlockChunkReply),
    SignerError(SignerError),
    Unknown(Unknown),
}

/// Read a length framed BOLT message of any type:
///
/// - u32 packet length
/// - u16 packet type
/// - data
pub fn read<R: Read>(reader: &mut R) -> Result<Message> {
    let len = reader.read_u32_be()?;
    from_reader(reader, len)
}

/// Read a specific message type from a length framed BOLT message:
///
/// - u32 packet length
/// - u16 packet type
/// - data
pub fn read_message<R: Read, T: DeBolt>(reader: &mut R) -> Result<T> {
    let len = reader.read_u32_be()?;
    check_message_length(len)?;

    let mut take = Take::new(Box::new(reader), len as u64);
    let message_type = take.read_u16_be()?;
    if message_type != T::TYPE {
        return Err(Error::UnexpectedType(message_type));
    }

    let res = T::consensus_decode(&mut take)?;
    if !take.is_empty() {
        return Err(Error::TrailingBytes(take.remaining() as usize, T::TYPE));
    }
    Ok(res)
}

/// Read a raw message from a length framed BOLT message:
///
/// - u32 packet length (not returned in the result)
/// - u16 packet type
/// - data
pub fn read_raw<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u32_be()?;
    let mut data = Vec::new();
    data.resize(len as usize, 0);
    reader.read_exact(&mut data)?;
    Ok(data)
}

/// Read a BOLT message from a vector:
///
/// - u16 packet type
/// - data
pub fn from_vec(mut v: Vec<u8>) -> Result<Message> {
    let len = v.len();
    let mut cursor = io::Cursor::new(&mut v);
    from_reader(&mut cursor, len as u32)
}

pub fn message_name_from_vec(v: &[u8]) -> String {
    if v.len() < 2 {
        return "ShortRead".to_owned();
    }
    let message_type = u16::from_be_bytes([v[0], v[1]]);
    Message::message_name(message_type).to_owned()
}

/// Read a BOLT message from a reader:
///
/// - u16 packet type
/// - data
pub fn from_reader<R: Read>(reader: &mut R, len: u32) -> Result<Message> {
    check_message_length(len)?;
    let mut take = Take::new(Box::new(reader), len as u64);

    let message_type = take.read_u16_be()?;
    let message = Message::read_message(&mut take, message_type)?;
    if !take.is_empty() {
        return Err(Error::TrailingBytes(take.remaining() as usize, message_type));
    }
    Ok(message)
}

fn check_message_length(len: u32) -> Result<()> {
    if len < 2 {
        return Err(Error::ShortRead);
    }
    if len > MAX_MESSAGE_SIZE {
        error!("message too large {}", len);
        return Err(Error::MessageTooLarge);
    }
    Ok(())
}

pub fn write<W: Write, T: DeBolt>(writer: &mut W, value: T) -> Result<()> {
    let message_type = T::TYPE;
    let mut buf = message_type.to_be_bytes().to_vec();
    let mut val_buf = to_vec(&value)?;
    buf.append(&mut val_buf);
    write_vec(writer, buf)
}

pub fn write_vec<W: Write>(writer: &mut W, buf: Vec<u8>) -> Result<()> {
    let len: u32 = buf.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&buf)?;
    Ok(())
}

/// A serial request header
#[derive(Debug)]
pub struct SerialRequestHeader {
    pub sequence: u16,
    pub peer_id: [u8; 33],
    pub dbid: u64,
}

/// Write a serial request header prefixed by two magic bytes
pub fn write_serial_request_header<W: Write>(
    writer: &mut W,
    srh: &SerialRequestHeader,
) -> Result<()> {
    writer.write_all(&0xaa55u16.to_be_bytes())?;
    writer.write_all(&srh.sequence.to_be_bytes())?;
    writer.write_all(&srh.peer_id)?;
    writer.write_all(&srh.dbid.to_be_bytes())?;
    Ok(())
}

/// Write a serial response header that includes two magic bytes and two sequence bytes
pub fn write_serial_response_header<W: Write>(writer: &mut W, sequence: u16) -> Result<()> {
    writer.write_all(&0x5aa5u16.to_be_bytes())?;
    writer.write_all(&sequence.to_be_bytes())?;
    Ok(())
}

/// Read and return the serial request header
/// Returns BadFraming if the magic is wrong.
pub fn read_serial_request_header<R: Read>(reader: &mut R) -> Result<SerialRequestHeader> {
    let magic = reader.read_u16_be()?;
    if magic != 0xaa55 {
        error!("bad magic {:02x}", magic);
        return Err(Error::BadFraming);
    }
    let sequence = reader.read_u16_be()?;
    let mut peer_id = [0u8; 33];
    reader.read_exact(&mut peer_id)?;
    let dbid = reader.read_u64_be()?;
    Ok(SerialRequestHeader { sequence, peer_id, dbid })
}

/// Read the serial response header and match the expected sequence number
/// Returns BadFraming if the magic or sequence are wrong.
pub fn read_serial_response_header<R: Read>(reader: &mut R, expected_sequence: u16) -> Result<()> {
    let magic = reader.read_u16_be()?;
    if magic != 0x5aa5u16 {
        error!("bad magic {:02x}", magic);
        return Err(Error::BadFraming);
    }
    let sequence = reader.read_u16_be()?;
    if sequence != expected_sequence {
        error!("sequence {} != expected {}", sequence, expected_sequence);
        return Err(Error::BadFraming);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec::Vec};
    use bitcoin::consensus::Encodable;
    use core::fmt::Debug;
    use serde_bolt::{io::Cursor, Array, WireString};
    use test_log::test;

    fn sample_array<T: Encodable + Decodable + Debug + Clone>(item: T, count: usize) -> Array<T> {
        Array(vec![item; count])
    }

    fn roundtrip<T: SerBolt + DeBolt>(msg: T) -> T {
        let ser = msg.as_vec();
        T::from_vec(ser).unwrap()
    }

    #[test]
    fn message_name_from_vec_test() {
        // Test with a short vector
        let short_vec = vec![0x01];
        assert_eq!(message_name_from_vec(&short_vec), "ShortRead");

        // Test with a valid message type
        let valid_vec = vec![0x00, 11];
        assert_eq!(message_name_from_vec(&valid_vec), "HsmdInit");

        // Test with an unknown message type
        let unknown_vec = vec![0xFF, 0xFF];
        assert_eq!(message_name_from_vec(&unknown_vec), "Unknown");
    }

    #[test]
    fn roundtrip_test() {
        let msg = SignChannelAnnouncementReply {
            node_signature: Signature([0; 64]),
            bitcoin_signature: Signature([1; 64]),
        };

        let ser = msg.as_vec();
        let dmsg = from_vec(ser).unwrap();
        if let Message::SignChannelAnnouncementReply(dmsg) = dmsg {
            assert_eq!(dmsg.node_signature.0, msg.node_signature.0);
            assert_eq!(dmsg.bitcoin_signature.0, msg.bitcoin_signature.0);
        } else {
            panic!("bad deser type")
        }
    }

    #[test]
    fn name_test() {
        assert_eq!(Message::NodeInfo(NodeInfo {}).inner().name(), "NodeInfo");
        assert_eq!(
            Message::Unknown(Unknown { message_type: 0 }).inner().name(),
            "UnknownPlaceholder"
        );
    }

    #[test]
    fn tlv_roundtrip_test() {
        #[cfg(feature = "developer")]
        {
            let mut options = HsmdDevPreinit2Options::default();
            options.network_name = Some(WireString("testnet".as_bytes().to_vec()));
            options.seed = Some(DevSecret([42u8; 32]));
            options.fail_preapprove = Some(true);
            options.no_preapprove_check = Some(false);
            options.derivation_style = Some(1);
            options.allowlist = Some(sample_array(WireString("test".as_bytes().to_vec()), 1));
            let msg = HsmdDevPreinit2 { options };
            let dmsg = roundtrip(msg);
            assert_eq!(dmsg.options.network_name, Some(WireString("testnet".as_bytes().to_vec())));
            assert_eq!(dmsg.options.seed, Some(DevSecret([42u8; 32])));
            assert_eq!(dmsg.options.fail_preapprove, Some(true));
            assert_eq!(dmsg.options.no_preapprove_check, Some(false));
            assert_eq!(dmsg.options.derivation_style, Some(1));
            assert_eq!(
                dmsg.options.allowlist,
                Some(sample_array(WireString("test".as_bytes().to_vec()), 1))
            );
        }
    }

    #[test]
    fn read_write_functions_test() {
        let msg = SignChannelAnnouncementReply {
            node_signature: Signature([0x48; 64]),
            bitcoin_signature: Signature([0x48; 64]),
        };
        let ser = msg.as_vec();
        let len = (ser.len() as u32).to_be_bytes().to_vec();
        let mut buf = len;
        buf.extend(ser.clone());

        let expected_node_signature = "48484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848";
        let expected_bitcoin_signature = "48484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848";
        let expexted_raw = vec![
            0, 102, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
            72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
            72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
            72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
            72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
            72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72,
        ];

        // Test read
        let mut cursor = Cursor::new(buf.clone());
        let dmsg = read(&mut cursor).unwrap();
        if let Message::SignChannelAnnouncementReply(dmsg) = dmsg {
            assert_eq!(format!("{:?}", dmsg.node_signature), expected_node_signature);
            assert_eq!(format!("{:?}", dmsg.bitcoin_signature), expected_bitcoin_signature);
        } else {
            panic!("bad deser type")
        }

        // Test read_message
        let mut cursor = Cursor::new(buf.clone());
        let dmsg: SignChannelAnnouncementReply = read_message(&mut cursor).unwrap();
        assert_eq!(format!("{:?}", dmsg.node_signature), expected_node_signature);
        assert_eq!(format!("{:?}", dmsg.bitcoin_signature), expected_bitcoin_signature);

        // Test read_raw
        let mut cursor = Cursor::new(buf.clone());
        let raw = read_raw(&mut cursor).unwrap();
        assert_eq!(raw, expexted_raw);

        // Test write
        let mut write_buf = Vec::new();
        write(&mut write_buf, msg).unwrap();
        let mut cursor = Cursor::new(write_buf);
        let dmsg: SignChannelAnnouncementReply = read_message(&mut cursor).unwrap();
        assert_eq!(format!("{:?}", dmsg.node_signature), expected_node_signature);
        assert_eq!(format!("{:?}", dmsg.bitcoin_signature), expected_bitcoin_signature);

        // Test write_vec
        let mut write_buf = Vec::new();
        write_vec(&mut write_buf, ser.clone()).unwrap();
        let mut cursor = Cursor::new(write_buf);
        let raw = read_raw(&mut cursor).unwrap();
        assert_eq!(raw, expexted_raw);
    }

    #[test]
    fn serial_header_tests() {
        let srh = SerialRequestHeader { sequence: 123, peer_id: [2u8; 33], dbid: 456 };
        let mut buf = Vec::new();
        write_serial_request_header(&mut buf, &srh).unwrap();
        let mut cursor = Cursor::new(buf);
        let read_srh = read_serial_request_header(&mut cursor).unwrap();
        assert_eq!(read_srh.sequence, 123);
        assert_eq!(read_srh.dbid, 456);

        let mut buf = Vec::new();
        write_serial_response_header(&mut buf, 123).unwrap();
        let mut cursor = Cursor::new(buf);
        read_serial_response_header(&mut cursor, 123).unwrap();

        // Test invalid magic
        let mut buf = vec![0x00, 0x00];
        buf.extend(123u16.to_be_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(read_serial_request_header(&mut cursor), Err(Error::BadFraming)));

        // Test invalid sequence
        let mut buf = Vec::new();
        write_serial_response_header(&mut buf, 123).unwrap();
        let mut cursor = Cursor::new(buf);
        assert!(matches!(read_serial_response_header(&mut cursor, 124), Err(Error::BadFraming)));
    }

    #[test]
    fn error_cases_test() {
        // Short read
        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x01]);
        assert!(matches!(read(&mut cursor), Err(Error::ShortRead)));

        // Message too large
        let mut cursor = Cursor::new((MAX_MESSAGE_SIZE + 1).to_be_bytes().to_vec());
        assert!(matches!(read(&mut cursor), Err(Error::MessageTooLarge)));

        // Trailing bytes
        let msg = SignChannelAnnouncementReply {
            node_signature: Signature([0x48; 64]),
            bitcoin_signature: Signature([0x48; 64]),
        };
        let mut ser = msg.as_vec();
        ser.push(0x00); // Extra byte
        let len = (ser.len() as u32).to_be_bytes().to_vec();
        let mut buf = len;
        buf.extend(ser);
        let mut cursor = Cursor::new(buf.clone());
        assert!(matches!(read(&mut cursor), Err(Error::TrailingBytes(1, 102))));

        // Wrong message type
        let mut cursor = Cursor::new(buf.clone());
        let result: Result<SignInvoiceReply> = read_message(&mut cursor);
        assert!(matches!(result, Err(Error::UnexpectedType(102))));
    }

    #[derive(SerBolt, Debug, Encodable, Decodable)]
    #[message_id(9999)]
    pub struct TestTlvWithDupTags {
        pub options: TestTlvOptionsWithDupTags,
    }

    // duplicate tag val!  This should fail
    #[derive(SerBoltTlvOptions, Default, Debug)]
    pub struct TestTlvOptionsWithDupTags {
        #[tlv_tag = 9]
        pub field1: Option<bool>,
        #[tlv_tag = 10]
        pub field2: Option<bool>,
        #[tlv_tag = 10]
        pub field3: Option<bool>,
        #[tlv_tag = 12]
        pub field4: Option<bool>,
    }

    #[test]
    #[should_panic(expected = "assertion failed: t < 10u64")]
    fn ser_bolt_tlv_options_dup_tags_test() {
        let mut options = TestTlvOptionsWithDupTags::default();
        options.field3 = Some(true);
        options.field2 = Some(false);
        let msg = TestTlvWithDupTags { options };
        let _ser = msg.as_vec();
    }

    #[derive(SerBolt, Debug, Encodable, Decodable)]
    #[message_id(9999)]
    pub struct TestTlvWithDescTags {
        pub options: TestTlvOptionsWithDescTags,
    }

    // descending tag order! This should be reordered internally and should work
    #[derive(SerBoltTlvOptions, Default, Debug)]
    pub struct TestTlvOptionsWithDescTags {
        #[tlv_tag = 12]
        pub field1: Option<bool>,
        #[tlv_tag = 11]
        pub field2: Option<bool>,
        #[tlv_tag = 10]
        pub field3: Option<bool>,
    }

    #[test]
    fn ser_bolt_tlv_options_desc_tags_test() {
        let mut options = TestTlvOptionsWithDescTags::default();
        options.field3 = Some(true);
        options.field2 = Some(false);
        let msg = TestTlvWithDescTags { options };
        let _ser = msg.as_vec();
    }

    // Test sending an even tag when the receiver doesn't know it

    #[derive(SerBoltTlvOptions, Default, Debug)]
    pub struct TestTlvOptionsEvenSender {
        #[tlv_tag = 12]
        pub field1: Option<bool>,
        #[tlv_tag = 11]
        pub field2: Option<bool>,
        #[tlv_tag = 10]
        pub field3: Option<bool>,
        #[tlv_tag = 42]
        pub mandatory: Option<bool>,
    }

    #[derive(SerBoltTlvOptions, Default, Debug)]
    pub struct TestTlvOptionsOddOnlyReceiver {
        #[tlv_tag = 12]
        pub field1: Option<bool>,
        #[tlv_tag = 11]
        pub field2: Option<bool>,
        #[tlv_tag = 10]
        pub field3: Option<bool>,
    }

    #[test]
    fn ser_bolt_tlv_even_is_mandatory_test() {
        // it's ok if you don't send the even tag
        let mut options = TestTlvOptionsEvenSender::default();
        options.field1 = Some(true);
        let tlvdata = crate::msgs::bitcoin::consensus::serialize(&options);
        let dmsg: TestTlvOptionsOddOnlyReceiver =
            crate::msgs::bitcoin::consensus::deserialize(&tlvdata).unwrap();
        assert_eq!(dmsg.field1, Some(true));
        assert_eq!(dmsg.field2, None);

        // but if the sender turns on an even tag ...
        options.mandatory = Some(true);
        let tlvdata = crate::msgs::bitcoin::consensus::serialize(&options);
        let rv =
            crate::msgs::bitcoin::consensus::deserialize::<TestTlvOptionsOddOnlyReceiver>(&tlvdata);
        match rv {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(e) => match e {
                bitcoin::consensus::encode::Error::ParseFailed(expected_msg) => {
                    assert_eq!(expected_msg, "decode_tlv_stream failed")
                }
                _ => panic!("Unexpected error type"),
            },
        }
    }
}
