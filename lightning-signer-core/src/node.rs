use core::fmt::{self, Debug, Error, Formatter};
use core::time::Duration;
use core::convert::TryFrom;
use core::str::FromStr;

#[cfg(feature = "backtrace")]
use backtrace::Backtrace;
use bitcoin;
use bitcoin::{Network, OutPoint, Script, SigHashType};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use lightning::chain;
use lightning::chain::keysinterface::{BaseSign, InMemorySigner, KeysInterface};
use lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters, CommitmentTransaction, CounterpartyChannelTransactionParameters, derive_private_key, HolderCommitmentTransaction, HTLCOutputInCommitment, make_funding_redeemscript, TxCreationKeys};
use lightning::ln::PaymentHash;

use crate::{Weak, Arc, Mutex, MutexGuard};
use crate::Map;
use crate::persist::model::NodeEntry;
use crate::persist::Persist;
use crate::policy::error::ValidationError;
use crate::policy::validator::{SimpleValidatorFactory, ValidatorFactory, ValidatorState};
use crate::signer::multi_signer::SyncLogger;
use crate::signer::my_keys_manager::{KeyDerivationStyle, MyKeysManager};
use crate::tx::tx::{build_close_tx, build_commitment_tx, CommitmentInfo2, get_commitment_transaction_number_obscure_factor, HTLCInfo, HTLCInfo2, sign_commitment};
use crate::util::{INITIAL_COMMITMENT_NUMBER, invoice_utils};
use crate::util::crypto_utils::{derive_private_revocation_key, derive_public_key, derive_revocation_pubkey, payload_for_p2wpkh};
use crate::util::enforcing_trait_impls::{EnforcementState, EnforcingSigner};
use crate::util::status::Status;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ChannelId(pub [u8; 32]);
// NOTE - this "ChannelId" does *not* correspond to the "channel_id"
// defined in BOLT #2.

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(hex::encode(self.0).as_str())
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(hex::encode(self.0).as_str())
    }
}

/// The commitment type, based on the negotiated option
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommitmentType {
    Legacy,
    StaticRemoteKey,
    Anchors,
}

/// The negotiated parameters for the [Channel]
#[derive(Clone)]
pub struct ChannelSetup {
    /// Whether the channel is outbound
    pub is_outbound: bool,
    /// The total the channel was funded with
    pub channel_value_sat: u64, // DUP keys.inner.channel_value_satoshis
    /// How much was pushed to the counterparty
    pub push_value_msat: u64,
    /// The funding outpoint
    pub funding_outpoint: OutPoint,
    /// locally imposed requirement on the remote commitment transaction to_self_delay
    pub holder_to_self_delay: u16,
    /// Maybe be None if we should generate it inside the signer
    pub holder_shutdown_script: Option<Script>,
    /// The counterparty's basepoints and pubkeys
    pub counterparty_points: ChannelPublicKeys, // DUP keys.inner.remote_channel_pubkeys
    /// remotely imposed requirement on the local commitment transaction to_self_delay
    pub counterparty_to_self_delay: u16,
    /// The counterparty's shutdown script, for mutual close
    pub counterparty_shutdown_script: Script,
    /// The negotiated commitment type
    pub commitment_type: CommitmentType,
}

// Need to define manually because ChannelPublicKeys doesn't derive Debug.
// BEGIN NOT TESTED
impl fmt::Debug for ChannelSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelSetup")
            .field("is_outbound", &self.is_outbound)
            .field("channel_value_sat", &self.channel_value_sat)
            .field("push_value_msat", &self.push_value_msat)
            .field("funding_outpoint", &self.funding_outpoint)
            .field("holder_to_self_delay", &self.holder_to_self_delay)
            .field("holder_shutdown_script", &self.holder_shutdown_script)
            .field(
                "counterparty_points",
                log_channel_public_keys!(&self.counterparty_points),
            )
            .field(
                "counterparty_to_self_delay",
                &self.counterparty_to_self_delay,
            )
            .field(
                "counterparty_shutdown_script",
                &self.counterparty_shutdown_script,
            )
            .field("commitment_type", &self.commitment_type)
            .finish()
    }
}
// END NOT TESTED

impl ChannelSetup {
    pub(crate) fn option_static_remotekey(&self) -> bool {
        self.commitment_type != CommitmentType::Legacy
    }

    pub(crate) fn option_anchor_outputs(&self) -> bool {
        self.commitment_type == CommitmentType::Anchors
    }
}

/// A channel takes this form after [Node::new_channel], and before [Node::ready_channel]
#[derive(Clone)]
pub struct ChannelStub {
    /// A backpointer to the node
    pub node: Weak<Node>,
    /// The channel nonce, used to derive keys
    pub nonce: Vec<u8>,
    /// The logger
    pub logger: Arc<SyncLogger>,
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: EnforcingSigner, // Incomplete, channel_value_sat is placeholder.
    /// The initial channel ID, used to find the channel in the node
    pub id0: ChannelId,
}

/// After [Node::ready_channel]
#[derive(Clone)]
pub struct Channel {
    /// A backpointer to the node
    pub node: Weak<Node>,
    /// The channel nonce, used to derive keys
    pub nonce: Vec<u8>,
    /// The logger
    pub logger: Arc<SyncLogger>,
    pub(crate) secp_ctx: Secp256k1<All>,
    /// The signer for this channel
    pub keys: EnforcingSigner,
    /// The negotiated channel setup
    pub setup: ChannelSetup,
    /// The initial channel ID
    pub id0: ChannelId,
    /// The optional permanent channel ID
    pub id: Option<ChannelId>,
}

/// A channel can be in two states - before [Node::ready_channel] it's a
/// [ChannelStub], afterwards it's a [Channel].  This enum keeps track
/// of the two different states.
pub enum ChannelSlot {
    Stub(ChannelStub),
    Ready(Channel),
}

impl ChannelSlot {
    // BEGIN NOT TESTED
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
    // END NOT TESTED
}

/// A trait implemented by both channel states.  See [ChannelSlot]
pub trait ChannelBase {
    /// Get the channel basepoints and public keys
    fn get_channel_basepoints(&self) -> ChannelPublicKeys;
    /// Get the per-commitment point for a holder commitment transaction
    fn get_per_commitment_point(&self, commitment_number: u64) -> PublicKey;
    /// Get the per-commitment secret for a holder commitment transaction
    // TODO leaking secret
    fn get_per_commitment_secret(&self, commitment_number: u64) -> SecretKey;
    /// Get the channel nonce, used to derive the channel keys
    // TODO should this be exposed?
    fn nonce(&self) -> Vec<u8>;
}

impl Debug for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("channel")
    }
}

impl ChannelBase for ChannelStub {
    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys().clone()
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> PublicKey {
        self.keys.get_per_commitment_point(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            &self.secp_ctx,
        )
    }

    fn get_per_commitment_secret(&self, commitment_number: u64) -> SecretKey {
        let secret = self
            .keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        SecretKey::from_slice(&secret).unwrap()
    }

    // BEGIN NOT TESTED
    fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
    // END NOT TESTED
}

impl ChannelBase for Channel {
    fn get_channel_basepoints(&self) -> ChannelPublicKeys {
        self.keys.pubkeys().clone()
    }

    fn get_per_commitment_point(&self, commitment_number: u64) -> PublicKey {
        self.keys.get_per_commitment_point(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            &self.secp_ctx,
        )
    }

    fn get_per_commitment_secret(&self, commitment_number: u64) -> SecretKey {
        let secret = self.keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        self.persist().unwrap();
        SecretKey::from_slice(&secret).unwrap()
    }

    // BEGIN NOT TESTED
    fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
    // END NOT TESTED
}

impl ChannelStub {
    pub(crate) fn channel_keys_with_channel_value(&self, channel_value_sat: u64) -> InMemorySigner {
        let secp_ctx = Secp256k1::signing_only();
        let keys0 = self.keys.inner();
        InMemorySigner::new(
            &secp_ctx,
            keys0.funding_key,
            keys0.revocation_base_key,
            keys0.payment_key,
            keys0.delayed_payment_base_key,
            keys0.htlc_base_key,
            keys0.commitment_seed,
            channel_value_sat,
            keys0.channel_keys_id(),
        )
    }
}

// Phase 2
impl Channel {
    pub(crate) fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    pub(crate) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }

    pub(crate) fn validation_error(&self, ve: ValidationError) -> Status {
        let s: String = ve.into();
        log_error!(self, "VALIDATION ERROR: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    // Phase 2
    pub(crate) fn make_counterparty_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
    ) -> Result<TxCreationKeys, Status> {
        let holder_points = self.keys.pubkeys();

        let counterparty_points = self.keys.counterparty_pubkeys();

        Ok(self.make_tx_keys(per_commitment_point, counterparty_points, holder_points))
    }

    pub(crate) fn make_holder_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
    ) -> Result<TxCreationKeys, Status> {
        let holder_points = self.keys.pubkeys();

        let counterparty_points = self.keys.counterparty_pubkeys();

        Ok(self.make_tx_keys(per_commitment_point, holder_points, counterparty_points))
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
            .expect("failed to derive keys")
    }

    fn derive_counterparty_payment_pubkey(
        &self,
        remote_per_commitment_point: &PublicKey,
    ) -> Result<PublicKey, Status> {
        let holder_points = self.keys.pubkeys();
        let counterparty_key = if self.setup.option_static_remotekey() {
            holder_points.payment_point
        } else {
            // BEGIN NOT TESTED
            derive_public_key(
                &self.secp_ctx,
                &remote_per_commitment_point,
                &holder_points.payment_point,
            )
                .map_err(|err| {
                    self.internal_error(format!("could not derive counterparty_key: {}", err))
                })?
            // END NOT TESTED
        };
        Ok(counterparty_key)
    }

    // BEGIN NOT TESTED
    fn get_commitment_transaction_number_obscure_factor(&self) -> u64 {
        get_commitment_transaction_number_obscure_factor(
            &self.keys.pubkeys().payment_point,
            &self.keys.counterparty_pubkeys().payment_point,
            self.setup.is_outbound,
        )
    }

    // forward counting commitment number
    #[allow(dead_code)]
    pub(crate) fn build_commitment_tx(
        &self,
        per_commitment_point: &PublicKey,
        commitment_number: u64,
        info: &CommitmentInfo2,
    ) -> Result<
        (
            bitcoin::Transaction,
            Vec<Script>,
            Vec<HTLCOutputInCommitment>,
        ),
        Status,
    > {
        let keys = if !info.is_counterparty_broadcaster {
            self.make_holder_tx_keys(per_commitment_point)?
        } else {
            self.make_counterparty_tx_keys(per_commitment_point)?
        };

        // TODO - consider if we can get LDK to put funding pubkeys in TxCreationKeys
        let (workaround_local_funding_pubkey, workaround_remote_funding_pubkey) =
            if !info.is_counterparty_broadcaster {
                (
                    &self.keys.pubkeys().funding_pubkey,
                    &self.keys.counterparty_pubkeys().funding_pubkey,
                )
            } else {
                (
                    &self.keys.counterparty_pubkeys().funding_pubkey,
                    &self.keys.pubkeys().funding_pubkey,
                )
            };

        let obscured_commitment_transaction_number =
            self.get_commitment_transaction_number_obscure_factor() ^ commitment_number;
        Ok(build_commitment_tx(
            &keys,
            info,
            obscured_commitment_transaction_number,
            self.setup.funding_outpoint,
            self.setup.option_anchor_outputs(),
            workaround_local_funding_pubkey,
            workaround_remote_funding_pubkey,
        ))
    }

    // END NOT TESTED

    /// Sign a counterparty commitment transaction after rebuilding it
    /// from the supplied arguments.
    // TODO anchors support once LDK supports it
    pub fn sign_counterparty_commitment_tx_phase2(
        &self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), Status> {
        let htlcs = Self::htlcs_info2_to_oic(offered_htlcs, received_htlcs);

        let commitment_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );

        log_debug!(
            self,
            "channel: sign counterparty txid {}",
            commitment_tx.trust().built_transaction().txid
        );

        let sigs = self
            .keys
            .sign_counterparty_commitment(&commitment_tx, &self.secp_ctx)
            .map_err(|_| self.internal_error("failed to sign"))?;
        let mut sig = sigs.0.serialize_der().to_vec();
        sig.push(SigHashType::All as u8);
        let mut htlc_sigs = Vec::new();
        for htlc_signature in sigs.1 {
            let mut htlc_sig = htlc_signature.serialize_der().to_vec();
            htlc_sig.push(SigHashType::All as u8);
            htlc_sigs.push(htlc_sig);
        }
        Ok((sig, htlc_sigs))
    }

    pub(crate) fn make_counterparty_commitment_tx(
        &self,
        remote_per_commitment_point: &PublicKey,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let keys = self
            .make_counterparty_tx_keys(remote_per_commitment_point)
            .unwrap();

        let mut htlcs_with_aux = htlcs.iter().map(|h| (h.clone(), ())).collect();
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_counterparty_broadcastable();
        let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            to_counterparty_value_sat,
            to_holder_value_sat,
            keys,
            feerate_per_kw,
            &mut htlcs_with_aux,
            &parameters,
        );
        commitment_tx
    }

    /// Sign a holder commitment transaction after rebuilding it
    /// from the supplied arguments.
    // TODO anchors support once upstream supports it
    pub fn sign_holder_commitment_tx_phase2(
        &self,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), Status> {
        let htlcs = Self::htlcs_info2_to_oic(offered_htlcs, received_htlcs);

        // We provide a dummy signature for the remote, since we don't require that sig
        // to be passed in to this call.  It would have been better if HolderCommitmentTransaction
        // didn't require the remote sig.
        // TODO consider if we actually want the sig for policy checks
        let dummy_sig = Secp256k1::new().sign(
            &secp256k1::Message::from_slice(&[42; 32]).unwrap(),
            &SecretKey::from_slice(&[42; 32]).unwrap(),
        );
        let mut htlc_dummy_sigs = Vec::with_capacity(htlcs.len());
        htlc_dummy_sigs.resize(htlcs.len(), dummy_sig);

        let commitment_tx = self.make_holder_commitment_tx(
            commitment_number,
            feerate_per_kw,
            to_holder_value_sat,
            to_counterparty_value_sat,
            htlcs,
        );
        log_debug!(
            self,
            "channel: sign holder txid {}",
            commitment_tx.trust().built_transaction().txid
        );

        let holder_commitment_tx = HolderCommitmentTransaction::new(
            commitment_tx,
            dummy_sig,
            htlc_dummy_sigs,
            &self.keys.pubkeys().funding_pubkey,
            &self.keys.counterparty_pubkeys().funding_pubkey,
        );

        let (sig, htlc_sigs) = self
            .keys
            .sign_holder_commitment_and_htlcs(&holder_commitment_tx, &self.secp_ctx)
            .map_err(|_| self.internal_error("failed to sign"))?;
        let mut sig_vec = sig.serialize_der().to_vec();
        sig_vec.push(SigHashType::All as u8);

        let mut htlc_sig_vecs = Vec::new();
        for htlc_sig in htlc_sigs {
            let mut htlc_sig_vec = htlc_sig.serialize_der().to_vec();
            htlc_sig_vec.push(SigHashType::All as u8);
            htlc_sig_vecs.push(htlc_sig_vec);
        }
        self.persist()?;
        Ok((sig_vec, htlc_sig_vecs))
    }

    pub(crate) fn make_holder_commitment_tx(
        &self,
        commitment_number: u64,
        feerate_per_kw: u32,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        htlcs: Vec<HTLCOutputInCommitment>,
    ) -> CommitmentTransaction {
        let per_commitment_point = self.get_per_commitment_point(commitment_number);
        let keys = self.make_holder_tx_keys(&per_commitment_point).unwrap();

        let mut htlcs_with_aux = htlcs.iter().map(|h| (h.clone(), ())).collect();
        let channel_parameters = self.make_channel_parameters();
        let parameters = channel_parameters.as_holder_broadcastable();
        let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
            INITIAL_COMMITMENT_NUMBER - commitment_number,
            to_holder_value_sat,
            to_counterparty_value_sat,
            keys,
            feerate_per_kw,
            &mut htlcs_with_aux,
            &parameters,
        );
        commitment_tx
    }

    fn htlcs_info2_to_oic(
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
            holder_selected_contest_delay: self.setup.holder_to_self_delay,
            is_outbound_from_holder: self.setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: self.setup.counterparty_points.clone(),
                selected_contest_delay: self.setup.counterparty_to_self_delay,
            }),
            funding_outpoint: Some(funding_outpoint),
        };
        channel_parameters
    }

    /// Get the shutdown script where our funds will go when we mutual-close
    pub fn get_shutdown_script(&self) -> Script {
        self.setup.holder_shutdown_script
            .clone()
            .unwrap_or_else(
                || payload_for_p2wpkh(&self.get_node().keys_manager.get_shutdown_pubkey())
                    .script_pubkey(),
            )
    }

    fn get_node(&self) -> Arc<Node> {
        self.node.upgrade().unwrap()
    }

    /// Sign a mutual close transaction after rebuilding it from the supplied arguments
    pub fn sign_mutual_close_tx_phase2(
        &self,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        counterparty_shutdown_script: Option<Script>
    ) -> Result<Signature, Status> {
        let holder_script = self.get_shutdown_script();

        let counterparty_script = counterparty_shutdown_script
            .as_ref()
            .unwrap_or(&self.setup.counterparty_shutdown_script);

        let tx = build_close_tx(
            to_holder_value_sat,
            to_counterparty_value_sat,
            &holder_script,
            counterparty_script,
            self.setup.funding_outpoint,
        );

        let res = self.keys.sign_closing_transaction(&tx, &self.secp_ctx)
            .map_err(|_| Status::internal("failed to sign"));
        self.persist()?;
        res
    }

    /// Sign a delayed output that goes to us while sweeping a transaction we broadcast
    pub fn sign_delayed_sweep(
        &self,
        tx: &bitcoin::Transaction,
        input: usize,
        commitment_number: u64,
        redeemscript: &Script,
        htlc_amount_sat: u64,
    ) -> Result<Signature, Status> {
        let per_commitment_point = self.get_per_commitment_point(commitment_number);

        let htlc_sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                input,
                &redeemscript,
                htlc_amount_sat,
                SigHashType::All,
            )[..],
        ).map_err(|_| Status::internal("failed to sighash"))?;

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.keys.delayed_payment_base_key(),
        ).map_err(|_| Status::internal("failed to derive key"))?;

        let sig = self.secp_ctx.sign(&htlc_sighash, &htlc_privkey);
        self.persist()?;
        Ok(sig)
    }

    /// Sign TODO
    pub fn sign_counterparty_htlc_sweep(
        &self,
        tx: &bitcoin::Transaction,
        input: usize,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &Script,
        htlc_amount_sat: u64,
    ) -> Result<Signature, Status> {
        let htlc_sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                input,
                &redeemscript,
                htlc_amount_sat,
                SigHashType::All,
            )[..],
        ).map_err(|_| Status::internal("failed to sighash"))?;

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &remote_per_commitment_point,
            &self.keys.htlc_base_key(),
        ).map_err(|_| Status::internal("failed to derive key"))?;

        let sig = self.secp_ctx.sign(&htlc_sighash, &htlc_privkey);
        self.persist()?;
        Ok(sig)
    }

    /// Sign a justice transaction on an old state that the counterparty broadcast
    pub fn sign_justice_sweep(
        &self,
        tx: &bitcoin::Transaction,
        input: usize,
        revocation_secret: &SecretKey,
        redeemscript: &Script,
        htlc_amount_sat: u64,
    ) -> Result<Signature, Status> {
        let sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                input,
                &redeemscript,
                htlc_amount_sat,
                SigHashType::All,
            )[..],
        ).map_err(|_| Status::internal("failed to sighash"))?;

        let privkey = derive_private_revocation_key(
            &self.secp_ctx,
            revocation_secret,
            self.keys.revocation_base_key(),
        ).map_err(|_| Status::internal("failed to derive key"))?;

        let sig = self.secp_ctx.sign(&sighash, &privkey);
        self.persist()?;
        Ok(sig)
    }

    /// Sign a channel announcement with both the node key and the funding key
    pub fn sign_channel_announcement(&self, announcement: &Vec<u8>) -> (Signature, Signature) {
        let ann_hash = Sha256dHash::hash(announcement);
        let encmsg = secp256k1::Message::from_slice(&ann_hash[..])
            .expect("encmsg failed");

        (self.secp_ctx.sign(&encmsg, &self.get_node().get_node_secret()),
         self.secp_ctx.sign(&encmsg, &self.keys.funding_key()))
    }

    fn persist(&self) -> Result<(), Status> {
        let node_id = self.get_node().get_id();
        self.get_node().persister.update_channel(&node_id, &self)
            .map_err(|_| Status::internal("persist failed"))
    }

    pub fn network(&self) -> Network {
        self.get_node().network
    }
}

// Phase 1
impl Channel {
    pub(crate) fn build_counterparty_commitment_info(
        &self,
        remote_per_commitment_point: &PublicKey,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<CommitmentInfo2, Status> {
        let holder_points = self.keys.pubkeys();
        let secp_ctx = &self.secp_ctx;

        let to_counterparty_delayed_pubkey = derive_public_key(
            secp_ctx,
            &remote_per_commitment_point,
            &self.setup.counterparty_points.delayed_payment_basepoint,
        )
            .map_err(|err| {
                // BEGIN NOT TESTED
                self.internal_error(format!("could not derive to_holder_delayed_key: {}", err))
                // END NOT TESTED
            })?;
        let counterparty_payment_pubkey =
            self.derive_counterparty_payment_pubkey(remote_per_commitment_point)?;
        let revocation_pubkey = derive_revocation_pubkey(
            secp_ctx,
            &remote_per_commitment_point,
            &holder_points.revocation_basepoint,
        )
            .map_err(|err| self.internal_error(format!("could not derive revocation key: {}", err)))?;
        let to_holder_pubkey = counterparty_payment_pubkey.clone();
        Ok(CommitmentInfo2 {
            is_counterparty_broadcaster: true,
            to_countersigner_pubkey: to_holder_pubkey,
            to_countersigner_value_sat: to_holder_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_counterparty_delayed_pubkey,
            to_broadcaster_value_sat: to_counterparty_value_sat,
            to_self_delay: self.setup.holder_to_self_delay,
            offered_htlcs,
            received_htlcs,
        })
    }

    // TODO dead code
    // BEGIN NOT TESTED
    #[allow(dead_code)]
    pub fn build_holder_commitment_info(
        &self,
        per_commitment_point: &PublicKey,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<CommitmentInfo2, Status> {
        let holder_points = self.keys.pubkeys();
        let counterparty_points = self.keys.counterparty_pubkeys();
        let secp_ctx = &self.secp_ctx;

        let to_holder_delayed_pubkey = derive_public_key(
            secp_ctx,
            &per_commitment_point,
            &holder_points.delayed_payment_basepoint,
        )
            .map_err(|err| {
                self.internal_error(format!(
                    "could not derive to_holder_delayed_pubkey: {}",
                    err
                ))
            })?;

        let counterparty_pubkey = if self.setup.option_static_remotekey() {
            counterparty_points.payment_point
        } else {
            derive_public_key(
                &self.secp_ctx,
                &per_commitment_point,
                &counterparty_points.payment_point,
            )
                .map_err(|err| {
                    self.internal_error(format!("could not derive counterparty_pubkey: {}", err))
                })?
        };

        let revocation_pubkey = derive_revocation_pubkey(
            secp_ctx,
            &per_commitment_point,
            &counterparty_points.revocation_basepoint,
        )
            .map_err(|err| {
                self.internal_error(format!("could not derive revocation_pubkey: {}", err))
            })?;
        let to_counterparty_pubkey = counterparty_pubkey.clone();
        Ok(CommitmentInfo2 {
            is_counterparty_broadcaster: false,
            to_countersigner_pubkey: to_counterparty_pubkey,
            to_countersigner_value_sat: to_counterparty_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_holder_delayed_pubkey,
            to_broadcaster_value_sat: to_holder_value_sat,
            to_self_delay: self.setup.counterparty_to_self_delay,
            offered_htlcs,
            received_htlcs,
        })
    }
    // END NOT TESTED

    /// Phase 1
    pub fn sign_counterparty_commitment_tx(
        &self,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
        remote_per_commitment_point: &PublicKey,
        channel_value_sat: u64,
        payment_hashmap: &Map<[u8; 20], PaymentHash>,
        commitment_number: u64,
    ) -> Result<Vec<u8>, Status> {
        // Set the feerate_per_kw to 0 because it is only used to
        // generate the htlc success/timeout tx signatures and these
        // signatures are discarded.
        let feerate_per_kw = 0;

        if tx.output.len() != output_witscripts.len() {
            // BEGIN NOT TESTED
            return Err(self.invalid_argument("len(tx.output) != len(witscripts)"));
            // END NOT TESTED
        }

        let validator = self
            .node.upgrade().unwrap()
            .validator_factory
            .make_validator_phase1(self, channel_value_sat);

        // Since we didn't have the value at the real open, validate it now.
        validator
            .validate_channel_open()
            .map_err(|ve| self.validation_error(ve))?;

        // Derive a CommitmentInfo first, convert to CommitmentInfo2 below ...
        let is_counterparty = true;
        let info = validator
            .make_info(
                &self.keys,
                &self.setup,
                is_counterparty,
                tx,
                output_witscripts,
            )
            .map_err(|err| self.validation_error(err))?;

        let offered_htlcs = Self::htlcs_info1_to_info2(payment_hashmap, &info.offered_htlcs)?;
        let received_htlcs = Self::htlcs_info1_to_info2(payment_hashmap, &info.received_htlcs)?;

        let info2 = self.build_counterparty_commitment_info(
            remote_per_commitment_point,
            info.to_broadcaster_value_sat,
            info.to_countersigner_value_sat,
            offered_htlcs,
            received_htlcs,
        )?;

        // TODO(devrandom) - obtain current_height so that we can validate the HTLC CLTV
        let state = ValidatorState { current_height: 0 };
        validator
            .validate_remote_tx(&self.setup, &state, &info2)
            .map_err(|ve| {
                // BEGIN NOT TESTED
                log_debug!(
                    self,
                    "VALIDATION FAILED:\ntx={:#?}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}",
                    &tx,
                    &self.setup,
                    &state,
                    &info2,
                );
                self.validation_error(ve)
                // END NOT TESTED
            })?;

        let htlcs = Self::htlcs_info2_to_oic(info2.offered_htlcs, info2.received_htlcs);

        let commitment_tx = self.make_counterparty_commitment_tx(
            remote_per_commitment_point,
            commitment_number,
            feerate_per_kw,
            info.to_countersigner_value_sat,
            info.to_broadcaster_value_sat,
            htlcs,
        );

        let funding_redeemscript = make_funding_redeemscript(
            &self.keys.pubkeys().funding_pubkey,
            &self.keys.counterparty_pubkeys().funding_pubkey,
        );
        let original_tx_sighash =
            tx.signature_hash(0, &funding_redeemscript, SigHashType::All as u32);
        let recomposed_tx_sighash = commitment_tx
            .trust()
            .built_transaction()
            .transaction
            .signature_hash(0, &funding_redeemscript, SigHashType::All as u32);
        if recomposed_tx_sighash != original_tx_sighash {
            // BEGIN NOT TESTED
            log_debug!(self, "ORIGINAL_TX={:#?}", &tx);
            log_debug!(
                self,
                "RECOMPOSED_TX={:#?}",
                &commitment_tx.trust().built_transaction().transaction
            );
            return Err(
                self.validation_error(ValidationError::Policy("sighash mismatch".to_string()))
            );
            // END NOT TESTED
        }

        // Sign the commitment.  Discard the htlc signatures for now.
        let sigs = self
            .keys
            .sign_counterparty_commitment(&commitment_tx, &self.secp_ctx)
            .map_err(|_| self.internal_error("failed to sign"))?;
        let mut sig = sigs.0.serialize_der().to_vec();
        sig.push(SigHashType::All as u8);

        self.persist()?;

        Ok(sig)
    }

    fn htlcs_info1_to_info2(
        payment_hashmap: &Map<[u8; 20], PaymentHash>,
        htlcs: &Vec<HTLCInfo>,
    ) -> Result<Vec<HTLCInfo2>, Status> {
        let mut htlcs2 = Vec::new();
        for htlc in htlcs.iter() {
            let payment_hash = payment_hashmap
                .get(&htlc.payment_hash_hash)
                .ok_or_else(|| Status::invalid_argument("unmappable htlc payment_hash"))?;
            htlcs2.push(HTLCInfo2 {
                value_sat: htlc.value_sat,
                payment_hash: payment_hash.clone(),
                cltv_expiry: htlc.cltv_expiry,
            });
        }
        Ok(htlcs2)
    }

    pub fn sign_holder_commitment_tx(
        &self,
        tx: &bitcoin::Transaction,
        funding_amount_sat: u64,
    ) -> Result<Signature, Status> {
        sign_commitment(
            &self.secp_ctx,
            &self.keys,
            &self.setup.counterparty_points.funding_pubkey,
            &tx,
            funding_amount_sat,
        ).map_err(|_| Status::internal("failed to sign"))
    }

    /// Phase 1
    pub fn sign_mutual_close_tx(
        &self,
        tx: &bitcoin::Transaction,
        funding_amount_sat: u64,
    ) -> Result<Signature, Status> {
        sign_commitment(
            &self.secp_ctx,
            &self.keys,
            &self.setup.counterparty_points.funding_pubkey,
            &tx,
            funding_amount_sat,
        ).map_err(|_| Status::internal("failed to sign"))
    }

    /// Phase 1
    pub fn sign_holder_htlc_tx(
        &self,
        tx: &bitcoin::Transaction,
        commitment_number: u64,
        opt_per_commitment_point: Option<PublicKey>,
        redeemscript: &Script,
        htlc_amount_sat: u64,
    ) -> Result<Signature, Status> {
        let per_commitment_point = opt_per_commitment_point
            .unwrap_or_else(|| self.get_per_commitment_point(commitment_number));

        let htlc_sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                0,
                redeemscript,
                htlc_amount_sat,
                SigHashType::All,
            )[..],
        ).map_err(|_| Status::internal("failed to sighash"))?;

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &per_commitment_point,
            &self.keys.htlc_base_key(),
        ).map_err(|_| Status::internal("failed to derive key"))?;

        let sig = self.secp_ctx.sign(&htlc_sighash, &htlc_privkey);

        self.persist()?;

        Ok(sig)
    }

    /// Phase 1
    pub fn sign_counterparty_htlc_tx(
        &self,
        tx: &bitcoin::Transaction,
        remote_per_commitment_point: &PublicKey,
        redeemscript: &Script,
        htlc_amount_sat: u64,
    ) -> Result<Signature, Status> {
        let sighash_type = if self.setup.option_anchor_outputs() {
            SigHashType::SinglePlusAnyoneCanPay
        } else {
            SigHashType::All
        };

        let htlc_sighash = Message::from_slice(
            &SigHashCache::new(tx).signature_hash(
                0,
                redeemscript,
                htlc_amount_sat,
                sighash_type,
            )[..],
        ).map_err(|_| Status::internal("failed to sighash"))?;

        let htlc_privkey = derive_private_key(
            &self.secp_ctx,
            &remote_per_commitment_point,
            &self.keys.htlc_base_key(),
        ).map_err(|_| Status::internal("failed to derive key"))?;

        Ok(self.secp_ctx.sign(&htlc_sighash, &htlc_privkey))
    }

    // TODO(devrandom) key leaking from this layer
    pub fn get_unilateral_close_key(&self, commitment_point: &Option<PublicKey>) -> Result<SecretKey, Status> {
        Ok(match commitment_point {
            Some(commitment_point) => derive_private_key(
                &self.secp_ctx,
                &commitment_point,
                &self.keys.payment_key(),
            ).map_err(|err| {
                Status::internal(format!("derive_private_key failed: {}", err))
            })?,
            None => {
                // option_static_remotekey in effect
                self.keys.payment_key().clone()
            }
        })
    }
}

#[derive(Copy, Clone)] // NOT TESTED
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
/// let logger: Arc<dyn SyncLogger> = Arc::new(TestLogger::new());
/// let node = Arc::new(Node::new(&logger, config, &seed, network, &persister));
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
    pub logger: Arc<SyncLogger>,
    pub(crate) node_config: NodeConfig,
    pub(crate) keys_manager: MyKeysManager,
    channels: Mutex<Map<ChannelId, Arc<Mutex<ChannelSlot>>>>,
    pub(crate) network: Network,
    validator_factory: Box<dyn ValidatorFactory>,
    pub(crate) persister: Arc<dyn Persist>,
}

impl Node {
    /// Create a node.
    ///
    /// NOTE: you must persist the node yourself if it is new.
    pub fn new(
        logger: &Arc<SyncLogger>,
        node_config: NodeConfig,
        seed: &[u8],
        network: Network,
        persister: &Arc<Persist>
    ) -> Node {
        let now = Duration::from_secs(genesis_block(network).header.time as u64);

        Node {
            logger: Arc::clone(logger),
            keys_manager: MyKeysManager::new(
                node_config.key_derivation_style,
                seed,
                network,
                Arc::clone(logger),
                now.as_secs(),
                now.subsec_nanos(),
            ),
            node_config,
            channels: Mutex::new(Map::new()),
            network,
            validator_factory: Box::new(SimpleValidatorFactory {}),
            persister: Arc::clone(persister)
        }
    }

    /// Get the node ID, which is the same as the node public key
    pub fn get_id(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret())
    }

    /// Get the [Mutex] protected channel slot
    pub fn get_channel(&self, channel_id: &ChannelId) -> Result<Arc<Mutex<ChannelSlot>>, Status> {
        let mut guard = self.channels();
        let elem = guard.get_mut(channel_id);
        let slot_arc = elem.ok_or_else(|| {
            Status::invalid_argument("no such channel")
        })?;
        Ok(Arc::clone(slot_arc))
    }

    #[allow(dead_code)]
    pub(crate) fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    pub(crate) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        #[cfg(feature = "backtrace")]
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }

    /// Create a new channel, which starts out as a stub.
    ///
    /// The initial channel ID may be specified in `opt_channel_id`.  If the channel
    /// with this ID already exists, no stub is returned.
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
        let channel_nonce0 =
            opt_channel_nonce0.unwrap_or_else(|| channel_id.0.to_vec());
        let mut channels = self.channels.lock().unwrap();
        if channels.contains_key(&channel_id) {
            // BEGIN NOT TESTED
            let msg = format!("channel already exists: {}", &channel_id);
            log_info!(self, "{}", &msg);
            // return Err(self.invalid_argument(&msg));
            return Ok((channel_id, None));
            // END NOT TESTED
        }
        let channel_value_sat = 0; // Placeholder value, not known yet.
        let inmem_keys = self.keys_manager.get_channel_keys_with_id(
            channel_id,
            channel_nonce0.as_slice(),
            channel_value_sat,
        );
        let stub = ChannelStub {
            node: Arc::downgrade(arc_self),
            nonce: channel_nonce0,
            logger: Arc::clone(&self.logger),
            secp_ctx: Secp256k1::new(),
            keys: EnforcingSigner::new(inmem_keys),
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
        let signer = self.keys_manager.get_channel_keys_with_id(
            channel_id0,
            nonce.as_slice(),
            channel_value_sat,
        );
        let mut enforcing_signer = EnforcingSigner::new_with_state(signer, enforcement_state);

        let slot = match channel_setup {
            None => {
                let stub = ChannelStub {
                    node: Arc::downgrade(arc_self),
                    nonce,
                    logger: Arc::clone(&self.logger),
                    secp_ctx: Secp256k1::new(),
                    keys: enforcing_signer,
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
                    Node::channel_setup_to_channel_transaction_parameters(
                        &setup,
                        enforcing_signer.inner().pubkeys(),
                    );
                enforcing_signer.ready_channel(&channel_transaction_parameters);
                let channel = Channel {
                    node: Arc::downgrade(arc_self),
                    nonce,
                    logger: Arc::clone(&self.logger),
                    secp_ctx: Secp256k1::new(),
                    keys: enforcing_signer,
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
    pub fn restore_node(node_id: &PublicKey,
                        node_entry: NodeEntry,
                        persister: Arc<dyn Persist>,
                        logger: Arc<dyn SyncLogger>) -> Arc<Node> {
        // BEGIN NOT TESTED
        let config = NodeConfig {
            key_derivation_style: KeyDerivationStyle::try_from(node_entry.key_derivation_style)
                .unwrap(),
        };
        let network = Network::from_str(node_entry.network.as_str()).expect("bad network");
        let node = Arc::new(Node::new(
            &logger,
            config,
            node_entry.seed.as_slice(),
            network,
            &persister
        ));
        assert_eq!(&node.get_id(), node_id);
        log_info!(node, "Restore node {}", node_id);
        for (channel_id0, channel_entry) in persister.get_node_channels(node_id) {
            log_info!(node, "  Restore channel {}", channel_id0);
            node.restore_channel(
                channel_id0,
                channel_entry.id,
                channel_entry.nonce,
                channel_entry.channel_value_satoshis,
                channel_entry.channel_setup,
                channel_entry.enforcement_state,
                &node,
            ).expect("restore channel");
        }
        node
    }

    /// Restore all nodes from `persister`.
    ///
    /// The channels of each node are also restored.
    pub fn restore_nodes(persister: Arc<dyn Persist>,
                         logger: Arc<dyn SyncLogger>) -> Map<PublicKey, Arc<Node>> {
        let mut nodes = Map::new();
        for (node_id, node_entry) in persister.get_nodes() {
            let node =
                Node::restore_node(&node_id,
                                   node_entry,
                                   Arc::clone(&persister),
                                   Arc::clone(&logger));
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
                self.invalid_argument(format!("channel does not exist: {}", channel_id0))
            })?;
            let slot = arcobj.lock().unwrap();
            let stub = match &*slot {
                ChannelSlot::Stub(stub) => Ok(stub),
                ChannelSlot::Ready(_) => {
                    Err(self.invalid_argument(format!("channel already ready: {}", channel_id0)))
                }
            }?;
            let mut inmem_keys = stub.channel_keys_with_channel_value(setup.channel_value_sat);
            let holder_pubkeys = inmem_keys.pubkeys();
            let channel_transaction_parameters =
                Node::channel_setup_to_channel_transaction_parameters(&setup, holder_pubkeys);
            inmem_keys.ready_channel(&channel_transaction_parameters);
            Channel {
                node: Weak::clone(&stub.node),
                nonce: stub.nonce.clone(),
                logger: Arc::clone(&stub.logger),
                secp_ctx: stub.secp_ctx.clone(),
                keys: EnforcingSigner::new(inmem_keys),
                setup,
                id0: channel_id0,
                id: opt_channel_id,
            }
        };
        let validator = self.validator_factory.make_validator(&chan);
        validator
            .validate_channel_open()
            .map_err(|ve| chan.validation_error(ve))?;

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

        self.persister.update_channel(&self.get_id(), &chan)
            .map_err(|_| Status::internal("persist failed"))?;

        Ok(chan)
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
            holder_selected_contest_delay: setup.holder_to_self_delay,
            is_outbound_from_holder: setup.is_outbound,
            counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
                pubkeys: setup.counterparty_points.clone(),
                selected_contest_delay: setup.counterparty_to_self_delay,
            }),
            funding_outpoint,
        };
        channel_transaction_parameters
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
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign(&encmsg, &self.get_node_secret());
        let res = sig.serialize_der().to_vec();
        Ok(res)
    }

    /// Sign a channel update using the node key
    pub fn sign_channel_update(&self, cu: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let cu_hash = Sha256dHash::hash(cu);
        let encmsg = secp256k1::Message::from_slice(&cu_hash[..])
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
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
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
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
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
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
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}
