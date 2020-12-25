use core::fmt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use backtrace::Backtrace;
use bitcoin;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{Network, OutPoint, Script, SigHashType};
use bitcoin_hashes::core::fmt::{Error, Formatter};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use lightning::chain::keysinterface::{ChannelKeys, InMemoryChannelKeys, KeysInterface};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, HTLCOutputInCommitment, PreCalculatedTxCreationKeys, TxCreationKeys,
};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::util::logger::Logger;
use secp256k1 as secp256k1_recoverable;
use secp256k1::Secp256k1 as Secp256k1_recoverable;
use tonic::Status;

use crate::policy::error::ValidationError;
use crate::policy::validator::{SimpleValidatorFactory, ValidatorFactory, ValidatorState};
use crate::server::my_keys_manager::{
    KeyDerivationStyle, MyKeysManager, INITIAL_COMMITMENT_NUMBER,
};
use crate::tx::tx::{
    build_commitment_tx, get_commitment_transaction_number_obscure_factor, sign_commitment,
    CommitmentInfo, CommitmentInfo2, HTLCInfo2,
};
use crate::util::crypto_utils::{derive_public_key, derive_revocation_pubkey, payload_for_p2wpkh};
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;
use crate::util::invoice_utils;

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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommitmentType {
    Legacy,
    StaticRemoteKey,
    Anchors,
}

#[derive(Clone)]
pub struct ChannelSetup {
    pub is_outbound: bool,
    pub channel_value_sat: u64, // DUP keys.inner.channel_value_satoshis
    pub push_value_msat: u64,
    pub funding_outpoint: OutPoint,
    /// locally imposed requirement on the remote commitment transaction to_self_delay
    pub holder_to_self_delay: u16,
    /// Maybe be None if we should generate it inside the signer
    pub holder_shutdown_script: Option<Script>,
    pub counterparty_points: ChannelPublicKeys, // DUP keys.inner.remote_channel_pubkeys
    /// remotely imposed requirement on the local commitment transaction to_self_delay
    pub counterparty_to_self_delay: u16,
    pub counterparty_shutdown_script: Script,
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

// After NewChannel, before ReadyChannel
pub struct ChannelStub {
    pub node: Arc<Node>,
    pub logger: Arc<Logger>,
    pub secp_ctx: Secp256k1<All>,
    pub keys: EnforcingChannelKeys, // Incomplete, channel_value_sat is placeholder.
}

// After ReadyChannel
pub struct Channel {
    pub node: Arc<Node>,
    pub logger: Arc<Logger>,
    pub secp_ctx: Secp256k1<All>,
    pub keys: EnforcingChannelKeys,
    pub setup: ChannelSetup,
}

pub enum ChannelSlot {
    Stub(ChannelStub),
    Ready(Channel),
}

pub trait ChannelBase {
    // Both ChannelStub and ready Channels can handle these.
    fn get_channel_basepoints(&self) -> ChannelPublicKeys;
    fn get_per_commitment_point(&self, commitment_number: u64) -> PublicKey;
    fn get_per_commitment_secret(&self, commitment_number: u64) -> SecretKey;
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
        let secret = self
            .keys
            .release_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number);
        SecretKey::from_slice(&secret).unwrap()
    }
}

impl ChannelStub {
    pub(crate) fn channel_keys_with_channel_value(
        &self,
        channel_value_sat: u64,
    ) -> InMemoryChannelKeys {
        let secp_ctx = Secp256k1::signing_only();
        let keys0 = self.keys.inner();
        InMemoryChannelKeys::new(
            &secp_ctx,
            keys0.funding_key,
            keys0.revocation_base_key,
            keys0.payment_key,
            keys0.delayed_payment_base_key,
            keys0.htlc_base_key,
            keys0.commitment_seed,
            channel_value_sat,
            MyKeysManager::derivation_params(),
        )
    }
}

impl Channel {
    pub(crate) fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    pub(crate) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }

    pub(crate) fn validation_error(&self, ve: ValidationError) -> Status {
        let s: String = ve.into();
        log_error!(self, "VALIDATION ERROR: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    // Phase 2
    fn make_counterparty_tx_keys(
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
            derive_public_key(
                &self.secp_ctx,
                &remote_per_commitment_point,
                &holder_points.payment_point,
            )
            .map_err(|err| {
                // BEGIN NOT TESTED
                self.internal_error(format!("could not derive counterparty_key: {}", err))
                // END NOT TESTED
            })?
        };
        Ok(counterparty_key)
    }

    /// Phase 1
    pub fn sign_counterparty_commitment_tx(
        &self,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
        remote_per_commitment_point: &PublicKey,
        channel_value_sat: u64,
    ) -> Result<Vec<u8>, Status> {
        if tx.output.len() != output_witscripts.len() {
            // BEGIN NOT TESTED
            return Err(self.invalid_argument("len(tx.output) != len(witscripts)"));
            // END NOT TESTED
        }

        // The CommitmentInfo will be used to check policy
        // assertions.
        let mut info = CommitmentInfo::new_for_counterparty();
        for ind in 0..tx.output.len() {
            log_debug!(self, "pkscript[{}] {:?}", ind, tx.output[ind].script_pubkey);
            info.handle_output(
                &self.keys,
                &self.setup,
                &tx.output[ind],
                output_witscripts[ind].as_slice(),
            )
            .map_err(|ve| self.invalid_argument(format!("output[{}]: {}", ind, ve)))?;
        }

        // Our key (remote from the point of view of the tx)
        let counterparty_payment_pubkey =
            self.derive_counterparty_payment_pubkey(remote_per_commitment_point)?;
        let validator = self
            .node
            .validator_factory
            .make_validator_phase1(self, channel_value_sat);
        // since we didn't have the value at the real open, validate it now
        validator
            .validate_channel_open()
            .map_err(|ve| self.validation_error(ve))?;

        // TODO(devrandom) - obtain current_height so that we can validate the HTLC CLTV
        let state = ValidatorState { current_height: 0 };
        let our_address = payload_for_p2wpkh(&counterparty_payment_pubkey);
        validator
            .validate_remote_tx_phase1(&self.setup, &state, &info, &our_address)
            .map_err(|ve| {
                // BEGIN NOT TESTED
                log_debug!(
                    self,
                    "VALIDATION FAILED:\ntx={:#?}\nsetup={:#?}\nstate={:#?}\ninfo={:#?}\nour_address={:#?}",
                    &tx,
                    &self.setup,
                    &state,
                    &info,
                    log_payload!(our_address),
                );
                self.validation_error(ve)
                // END NOT TESTED
            })?;

        let commitment_sig = sign_commitment(
            &self.secp_ctx,
            &self.keys,
            &self.setup.counterparty_points.funding_pubkey,
            &tx,
            channel_value_sat,
        )
        .map_err(|err| self.internal_error(format!("sign_commitment failed: {}", err)))?;

        let mut sig = commitment_sig.serialize_der().to_vec();
        sig.push(SigHashType::All as u8);
        Ok(sig)
    }

    // Not tested because loopback test is currently ignored.
    // TODO phase 2
    // BEGIN NOT TESTED
    pub fn sign_counterparty_commitment(
        &self,
        feerate_per_kw: u32,
        commitment_tx: &bitcoin::Transaction,
        per_commitment_point: &PublicKey,
        htlcs: &[&HTLCOutputInCommitment],
    ) -> Result<(Signature, Vec<Signature>), Status> {
        let tx_keys =
            PreCalculatedTxCreationKeys::new(self.make_counterparty_tx_keys(per_commitment_point)?);
        let pubkey = self.keys.pubkeys().funding_pubkey;
        log_trace!(
            self,
            "sign_counterparty_commitment with pubkey {}",
            log_bytes!(pubkey.serialize())
        );
        self.keys
            .sign_counterparty_commitment(
                feerate_per_kw,
                commitment_tx,
                &tx_keys,
                htlcs,
                &self.secp_ctx,
            )
            .map_err(|_| self.internal_error("sign_counterparty_commitment failed"))
    }
    // END NOT TESTED

    // BEGIN NOT TESTED
    // Not tested because loopback test is currently ignored.
    pub fn sign_channel_announcement(
        &self,
        msg: &UnsignedChannelAnnouncement,
    ) -> Result<Signature, ()> {
        self.keys.sign_channel_announcement(msg, &self.secp_ctx)
    }
    // END NOT TESTED

    fn get_commitment_transaction_number_obscure_factor(&self) -> u64 {
        get_commitment_transaction_number_obscure_factor(
            &self.keys.pubkeys().payment_point,
            &self.keys.counterparty_pubkeys().payment_point,
            self.setup.is_outbound,
        )
    }

    // forward counting commitment number
    pub fn build_commitment_tx(
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

        // FIXME, WORKAROUND - These should be in `keys` above.
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

    pub fn build_counterparty_commitment_info(
        &self,
        remote_per_commitment_point: &PublicKey,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> Result<CommitmentInfo2, Status> {
        let holder_points = self.keys.pubkeys();
        let secp_ctx = &self.secp_ctx;

        let to_holder_delayed_pubkey = derive_public_key(
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
        let to_counterparty_pubkey = counterparty_payment_pubkey.clone();
        Ok(CommitmentInfo2 {
            is_counterparty_broadcaster: true,
            to_countersigner_pubkey: to_counterparty_pubkey,
            to_countersigner_value_sat: to_counterparty_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_holder_delayed_pubkey,
            to_broadcaster_value_sat: to_holder_value_sat,
            to_self_delay: self.setup.holder_to_self_delay,
            offered_htlcs,
            received_htlcs,
        })
    }

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
            // BEGIN NOT TESTED
            self.internal_error(format!(
                "could not derive to_holder_delayed_pubkey: {}",
                err
            ))
            // END NOT TESTED
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
                // BEGIN NOT TESTED
                self.internal_error(format!("could not derive counterparty_pubkey: {}", err))
                // END NOT TESTED
            })?
        };

        let revocation_pubkey = derive_revocation_pubkey(
            secp_ctx,
            &per_commitment_point,
            &counterparty_points.revocation_basepoint,
        )
        .map_err(|err| {
            // BEGIN NOT TESTED
            self.internal_error(format!("could not derive revocation_pubkey: {}", err))
            // END NOT TESTED
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
        let info = self.build_counterparty_commitment_info(
            remote_per_commitment_point,
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs.clone(),
            received_htlcs.clone(),
        )?;

        let (tx, _scripts, htlcs) =
            self.build_commitment_tx(remote_per_commitment_point, commitment_number, &info)?;

        for out in &tx.output {
            println!("channel: remote script {:?}", out.script_pubkey);
        }
        println!("txid {}", tx.txid());

        let keys = PreCalculatedTxCreationKeys::new(
            self.make_counterparty_tx_keys(remote_per_commitment_point)?,
        ); // NOT TESTED

        let mut htlc_refs = Vec::new();
        for htlc in htlcs.iter() {
            htlc_refs.push(htlc);
        }
        let sigs = self
            .keys
            .sign_counterparty_commitment(
                feerate_per_kw,
                &tx,
                &keys,
                htlc_refs.as_slice(),
                &self.secp_ctx,
            )
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

    pub fn network(&self) -> Network {
        self.node.network
    }
}

pub struct NodeConfig {
    pub key_derivation_style: KeyDerivationStyle,
}

pub struct Node {
    pub logger: Arc<Logger>,
    pub node_config: NodeConfig,
    pub(crate) keys_manager: MyKeysManager,
    channels: Mutex<HashMap<ChannelId, Arc<Mutex<ChannelSlot>>>>,
    pub network: Network,
    validator_factory: Box<dyn ValidatorFactory>,
}

impl Node {
    pub fn new(
        logger: &Arc<Logger>,
        node_config: NodeConfig,
        seed: &[u8],
        network: Network,
    ) -> Node {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

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
            channels: Mutex::new(HashMap::new()),
            network,
            validator_factory: Box::new(SimpleValidatorFactory {}),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    pub(crate) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }

    pub fn new_channel(
        &self,
        channel_id: ChannelId,
        channel_nonce0: Vec<u8>,
        arc_self: &Arc<Node>,
    ) -> Result<(), Status> {
        let mut channels = self.channels.lock().unwrap();
        if channels.contains_key(&channel_id) {
            // BEGIN NOT TESTED
            let msg = format!("channel already exists: {}", &channel_id);
            log_info!(self, "{}", &msg);
            // return Err(self.invalid_argument(&msg));
            return Ok(());
            // END NOT TESTED
        }
        let channel_value_sat = 0; // Placeholder value, not known yet.
        let inmem_keys = self
            .keys_manager
            .get_channel_keys_with_nonce(channel_nonce0.as_slice(), channel_value_sat);
        let stub = ChannelStub {
            node: Arc::clone(arc_self),
            logger: Arc::clone(&self.logger),
            secp_ctx: Secp256k1::new(),
            keys: EnforcingChannelKeys::new(inmem_keys),
        };
        channels.insert(channel_id, Arc::new(Mutex::new(ChannelSlot::Stub(stub))));
        Ok(())
    }

    pub fn ready_channel(
        &self,
        channel_id0: ChannelId,
        opt_channel_id: Option<ChannelId>,
        setup: ChannelSetup,
    ) -> Result<(), Status> {
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
            inmem_keys.on_accept(
                &setup.counterparty_points,
                setup.counterparty_to_self_delay,
                setup.holder_to_self_delay,
            ); // DUP VALUE
            Channel {
                node: Arc::clone(&stub.node),
                logger: Arc::clone(&stub.logger),
                secp_ctx: stub.secp_ctx.clone(),
                keys: EnforcingChannelKeys::new(inmem_keys),
                setup,
            }
        };
        let validator = self.validator_factory.make_validator(&chan);
        validator
            .validate_channel_open()
            .map_err(|ve| chan.validation_error(ve))?;

        let mut channels = self.channels.lock().unwrap();

        // Wrap the ready channel with an arc so we can potentially
        // refer to it multiple times.
        let arcobj = Arc::new(Mutex::new(ChannelSlot::Ready(chan)));

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

        Ok(())
    }

    /// TODO leaking secret
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

    pub fn get_account_extended_key(&self) -> &ExtendedPrivKey {
        self.keys_manager.get_account_extended_key()
    }

    pub fn sign_node_announcement(&self, na: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let na_hash = Sha256dHash::hash(na);
        let encmsg = secp256k1::Message::from_slice(&na_hash[..])
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign(&encmsg, &self.get_node_secret());
        let res = sig.serialize_der().to_vec();
        Ok(res)
    }

    pub fn sign_channel_update(&self, cu: &Vec<u8>) -> Result<Vec<u8>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let cu_hash = Sha256dHash::hash(cu);
        let encmsg = secp256k1::Message::from_slice(&cu_hash[..])
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign(&encmsg, &self.get_node_secret());
        let res = sig.serialize_der().to_vec();
        Ok(res)
    }

    pub fn sign_invoice(
        &self,
        data_part: &Vec<u8>,
        human_readable_part: &String,
    ) -> Result<Vec<u8>, Status> {
        use bech32::CheckBase32;

        let hash = invoice_utils::hash_from_parts(
            human_readable_part.as_bytes(),
            &data_part.check_base32().expect("needs to be base32 data"),
        );

        let secp_ctx = Secp256k1_recoverable::signing_only();
        let encmsg = secp256k1_recoverable::Message::from_slice(&hash[..])
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
        let sig = secp_ctx.sign_recoverable(&encmsg, &self.get_node_secret());
        let (rid, sig) = sig.serialize_compact();
        let mut res = sig.to_vec();
        res.push(rid.to_i32() as u8);
        Ok(res)
    }

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

    pub fn channels(&self) -> MutexGuard<HashMap<ChannelId, Arc<Mutex<ChannelSlot>>>> {
        self.channels.lock().unwrap()
    }
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("node")
    }
}
