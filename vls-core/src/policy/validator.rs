extern crate scopeguard;

use core::cmp::{max, min};
use core::fmt::{self, Debug, Formatter};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{
    self, BlockHash, BlockHeader, EcdsaSighashType, FilterHeader, Network, OutPoint, Script,
    Sighash, Transaction,
};
use core::time::Duration;
use lightning::chain::keysinterface::InMemorySigner;
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};
use lightning::ln::PaymentHash;
use log::{debug, error};
use serde_derive::{Deserialize, Serialize};
use txoo::proof::{TxoProof, VerifyError};

use crate::channel::{ChannelBalance, ChannelId, ChannelSetup, ChannelSlot};
use crate::invoice::{Invoice, InvoiceAttributes};
use crate::policy::{Policy, MAX_CLOCK_SKEW, MIN_INVOICE_EXPIRY};
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2, HTLCInfo2, PreimageMap};
use crate::util::debug_utils::DebugBytes;
use crate::wallet::Wallet;

use super::error::ValidationError;

/// A policy checker
///
/// Called by Node / Channel as needed.
pub trait Validator {
    /// Validate ready channel parameters.
    /// The holder_shutdown_key_path should be an empty vector if the
    /// setup.holder_shutdown_script is not set or the address is in
    /// the allowlist.
    fn validate_ready_channel(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &[u32],
    ) -> Result<(), ValidationError>;

    /// Validate channel value after it is late-filled
    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError>;

    /// Validate an onchain transaction (funding tx, simple sweeps).
    /// This transaction may fund multiple channels at the same time.
    ///
    /// * `channels` the funded channel for each funding output, or
    ///   None for change outputs
    /// * `input_txs` - previous tx for inputs when funding channel
    /// * `values_sat` - the amount in satoshi per input
    /// * `opaths` - derivation path per output.  Empty for non-wallet/non-xpub-whitelist
    ///   outputs.
    /// * `weight_lower_bound` - lower bound of tx size, for feerate checking
    ///
    /// Returns the total "non-beneficial value" (i.e. fees) in satoshi
    fn validate_onchain_tx(
        &self,
        wallet: &dyn Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        tx: &Transaction,
        input_txs: &[&Transaction],
        values_sat: &[u64],
        opaths: &[Vec<u32>],
        weight_lower_bound: usize,
    ) -> Result<u64, ValidationError>;

    /// Phase 1 CommitmentInfo
    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
    ) -> Result<CommitmentInfo, ValidationError>;

    /// Validate a counterparty commitment
    fn validate_counterparty_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError>;

    /// Validate a holder commitment
    fn validate_holder_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError>;

    /// Check a counterparty's revocation of an old state.
    /// This also makes a note that the counterparty has committed to their
    /// current commitment transaction.
    fn validate_counterparty_revocation(
        &self,
        state: &EnforcementState,
        revoke_num: u64,
        commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError>;

    /// Phase 1 decoding of 2nd level HTLC tx and validation by recomposition
    fn decode_and_validate_htlc_tx(
        &self,
        is_counterparty: bool,
        setup: &ChannelSetup,
        txkeys: &TxCreationKeys,
        tx: &Transaction,
        redeemscript: &Script,
        htlc_amount_sat: u64,
        output_witscript: &Script,
    ) -> Result<(u32, HTLCOutputInCommitment, Sighash, EcdsaSighashType), ValidationError>;

    /// Phase 2 validation of 2nd level HTLC tx
    fn validate_htlc_tx(
        &self,
        setup: &ChannelSetup,
        cstate: &ChainState,
        is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError>;

    /// Phase 1 decoding and recomposition of mutual_close
    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        tx: &Transaction,
        opaths: &[Vec<u32>],
    ) -> Result<ClosingTransaction, ValidationError>;

    /// Phase 2 Validatation of mutual_close
    fn validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_shutdown_script: &Option<Script>,
        counterparty_shutdown_script: &Option<Script>,
        holder_wallet_path_hint: &[u32],
    ) -> Result<(), ValidationError>;

    /// Validation of delayed sweep transaction
    fn validate_delayed_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &[u32],
    ) -> Result<(), ValidationError>;

    /// Validation of counterparty htlc sweep transaction (first level
    /// commitment htlc outputs)
    fn validate_counterparty_htlc_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        redeemscript: &Script,
        input: usize,
        amount_sat: u64,
        key_path: &[u32],
    ) -> Result<(), ValidationError>;

    /// Validation of justice sweep transaction
    fn validate_justice_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &[u32],
    ) -> Result<(), ValidationError>;

    /// Validation of the payment state for a payment hash.
    /// This could include a payment routed through us, or a payment we
    /// are making, or both.  If we are not making a payment, then the incoming
    /// must be greater or equal to the outgoing.  Otherwise, the incoming
    /// minus outgoing should be enough to pay for the invoice and routing fees,
    /// but no larger.
    fn validate_payment_balance(
        &self,
        incoming_msat: u64,
        outgoing_msat: u64,
        invoiced_amount_msat: Option<u64>,
    ) -> Result<(), ValidationError>;

    /// Whether the policy specifies that holder balance should be tracked and
    /// enforced.
    fn enforce_balance(&self) -> bool {
        false
    }

    /// The minimum initial commitment transaction balance to us, given
    /// the funding amount.
    /// The result is in satoshi.
    fn minimum_initial_balance(&self, holder_value_msat: u64) -> u64;

    /// The associated policy
    fn policy(&self) -> Box<&dyn Policy>;

    /// Set next holder commitment number
    fn set_next_holder_commit_num(
        &self,
        estate: &mut EnforcementState,
        num: u64,
        current_commitment_info: CommitmentInfo2,
        counterparty_signatures: CommitmentSignatures,
    ) -> Result<(), ValidationError> {
        let current = estate.next_holder_commit_num;
        if num != current && num != current + 1 {
            // the tag is non-obvious, but jumping to an incorrect commitment number can mean that signing and revocation are out of sync
            policy_err!(
                self,
                "policy-revoke-new-commitment-signed",
                "invalid progression: {} to {}",
                current,
                num
            );
        }
        estate.set_next_holder_commit_num(num, current_commitment_info, counterparty_signatures);
        Ok(())
    }

    /// Get the current commitment info
    fn get_current_holder_commitment_info(
        &self,
        estate: &mut EnforcementState,
        commitment_number: u64,
    ) -> Result<CommitmentInfo2, ValidationError> {
        // Make sure they are asking for the correct commitment (in sync).
        if commitment_number + 1 != estate.next_holder_commit_num {
            policy_err!(
                self,
                "policy-other",
                "invalid next holder commitment number: {} != {}",
                commitment_number + 1,
                estate.next_holder_commit_num
            );
        }
        Ok(estate.get_current_holder_commitment_info())
    }

    /// Set next counterparty commitment number
    fn set_next_counterparty_commit_num(
        &self,
        estate: &mut EnforcementState,
        num: u64,
        current_point: PublicKey,
        current_commitment_info: CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        if num == 0 {
            policy_err!(self, "policy-commitment-previous-revoked", "can't set next to 0");
        }

        // The initial commitment is special, it can advance even though next_revoke is 0.
        let delta = if num == 1 { 1 } else { 2 };

        // Ensure that next_commit is ok relative to next_revoke
        if num < estate.next_counterparty_revoke_num + delta {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "{} too small relative to next_counterparty_revoke_num {}",
                num,
                estate.next_counterparty_revoke_num
            );
        }
        if num > estate.next_counterparty_revoke_num + 2 {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "{} too large relative to next_counterparty_revoke_num {}",
                num,
                estate.next_counterparty_revoke_num
            );
        }

        let current = estate.next_counterparty_commit_num;
        if num == current {
            // This is a retry.
            assert!(
                estate.current_counterparty_point.is_some(),
                "retry {}: current_counterparty_point not set, this shouldn't be possible",
                num
            );
            // FIXME - need to compare current_commitment_info with current_counterparty_commit_info
            if current_point != estate.current_counterparty_point.unwrap() {
                debug!(
                    "current_point {} != prior {}",
                    current_point,
                    estate.current_counterparty_point.unwrap()
                );
                policy_err!(
                    self,
                    "policy-commitment-retry-same",
                    "retry {}: point different than prior",
                    num
                );
            }
        } else if num == current + 1 {
        } else {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "invalid progression: {} to {}",
                current,
                num
            );
        }

        estate.set_next_counterparty_commit_num(num, current_point, current_commitment_info);
        Ok(())
    }

    /// Set next counterparty revoked commitment number
    fn set_next_counterparty_revoke_num(
        &self,
        estate: &mut EnforcementState,
        num: u64,
    ) -> Result<(), ValidationError> {
        if num == 0 {
            policy_err!(self, "policy-other", "can't set next to 0");
        }

        // Ensure that next_revoke is ok relative to next_commit.
        if num + 2 < estate.next_counterparty_commit_num {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "{} too small relative to next_counterparty_commit_num {}",
                num,
                estate.next_counterparty_commit_num
            );
        }
        if num + 1 > estate.next_counterparty_commit_num {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "{} too large relative to next_counterparty_commit_num {}",
                num,
                estate.next_counterparty_commit_num
            );
        }

        let current = estate.next_counterparty_revoke_num;
        if num != current && num != current + 1 {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "invalid progression: {} to {}",
                current,
                num
            );
        }

        estate.set_next_counterparty_revoke_num(num);
        debug!("next_counterparty_revoke_num {} -> {}", current, num);
        Ok(())
    }

    /// Validate a block and a TXOO proof for spent/unspent watched outputs
    fn validate_block(
        &self,
        proof: &TxoProof,
        height: u32,
        header: &BlockHeader,
        external_block_hash: Option<&BlockHash>,
        prev_filter_header: &FilterHeader,
        outpoint_watches: &[OutPoint],
    ) -> Result<(), ValidationError> {
        let secp = Secp256k1::new();
        let result = proof.verify(
            height,
            header,
            external_block_hash,
            prev_filter_header,
            outpoint_watches,
            &secp,
        );
        match result {
            Ok(()) => {}
            Err(VerifyError::InvalidAttestation) => {
                for (pubkey, attestation) in &proof.attestations {
                    error!(
                        "invalid attestation for oracle {} at height {} block hash {} - {:?}",
                        pubkey,
                        height,
                        header.block_hash(),
                        &attestation.attestation
                    );
                }
                policy_err!(self, "policy-chain-validated", "invalid attestation");
            }
            Err(_) => {
                policy_err!(self, "policy-chain-validated", "invalid proof {:?}", result);
            }
        }
        // TODO validate attestation is by configured oracle
        // TODO validate filter header chain
        Ok(())
    }

    /// Validate an invoice
    fn validate_invoice(&self, invoice: &Invoice, now: Duration) -> Result<(), ValidationError> {
        // When we are using block headers our now() may be 1 hour behind or 2 hours ahead
        #[cfg(not(feature = "timeless_workaround"))]
        let (behind_tolerance, ahead_tolerance) = (Duration::from_secs(0), Duration::from_secs(0));
        #[cfg(feature = "timeless_workaround")]
        let (behind_tolerance, ahead_tolerance) =
            (Duration::from_secs(1 * 60 * 60), Duration::from_secs(2 * 60 * 60));

        // invoice must not have been created in the future
        if now + MAX_CLOCK_SKEW + behind_tolerance < invoice.duration_since_epoch() {
            policy_err!(
                self,
                "policy-invoice-not-expired",
                "invoice is not yet valid ({} + {} (skew) + {} (tolerance) < {})",
                now.as_secs(),
                MAX_CLOCK_SKEW.as_secs(),
                behind_tolerance.as_secs(),
                invoice.duration_since_epoch().as_secs()
            );
        }

        // new invoices must not expire too soon
        if now + MIN_INVOICE_EXPIRY
            > (invoice.duration_since_epoch() + invoice.expiry_duration())
                + MAX_CLOCK_SKEW
                + ahead_tolerance
        {
            policy_err!(
                self,
                "policy-invoice-not-expired",
                "invoice is expired ({} + {} (buffer) > {} + {} (skew) + {} (tolerance))",
                now.as_secs(),
                MIN_INVOICE_EXPIRY.as_secs(),
                (invoice.duration_since_epoch() + invoice.expiry_duration()).as_secs(),
                MAX_CLOCK_SKEW.as_secs(),
                ahead_tolerance.as_secs()
            );
        }

        Ok(())
    }
}

/// Blockchain state used by the validator
#[derive(Debug)]
pub struct ChainState {
    /// The current blockchain height
    pub current_height: u32,
    /// Zero or the number of confirmation of the funding tx
    pub funding_depth: u32,
    /// Zero or the number of confirmation of a double-spend of the funding tx
    pub funding_double_spent_depth: u32,
    /// Zero or the number of confirmations of a closing tx
    pub closing_depth: u32,
}

/// A factory for validators
pub trait ValidatorFactory: Send + Sync {
    /// Construct a validator
    fn make_validator(
        &self,
        network: Network,
        node_id: PublicKey,
        channel_id: Option<ChannelId>,
    ) -> Arc<dyn Validator>;

    /// Get the policy
    fn policy(&self, network: Network) -> Box<dyn Policy>;
}

/// Signatures for a commitment transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSignatures(pub Signature, pub Vec<Signature>);

/// Copied from LDK because we need to serialize it
#[derive(Clone, Serialize, Deserialize)]
pub struct CounterpartyCommitmentSecrets {
    old_secrets: Vec<([u8; 32], u64)>,
}

impl Debug for CounterpartyCommitmentSecrets {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("CounterpartyCommitmentSecrets")
            .field("old_secrets", &DebugOldSecrets(&self.old_secrets))
            .finish()
    }
}

struct DebugOldSecrets<'a>(pub &'a Vec<([u8; 32], u64)>);
impl<'a> core::fmt::Debug for DebugOldSecrets<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list().entries(self.0.iter().map(|os| DebugOldSecret(os))).finish()
    }
}

struct DebugOldSecret<'a>(pub &'a ([u8; 32], u64));
impl<'a> core::fmt::Debug for DebugOldSecret<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("OldSecret").field(&DebugBytes(&self.0 .0)).field(&self.0 .1).finish()
    }
}

impl CounterpartyCommitmentSecrets {
    /// Creates a new empty `CounterpartyCommitmentSecrets` structure.
    pub fn new() -> Self {
        let old_secrets = (0..49).map(|_| ([0; 32], 1 << 48)).collect::<Vec<_>>();
        Self { old_secrets }
    }

    #[inline]
    fn place_secret(idx: u64) -> u8 {
        for i in 0..48 {
            if idx & (1 << i) == (1 << i) {
                return i;
            }
        }
        48
    }

    /// Returns the minimum index of all stored secrets. Note that indexes start
    /// at 1 << 48 and get decremented by one for each new secret.
    pub fn get_min_seen_secret(&self) -> u64 {
        //TODO This can be optimized?
        let mut min = 1 << 48;
        for &(_, idx) in self.old_secrets.iter() {
            if idx < min {
                min = idx;
            }
        }
        min
    }

    #[inline]
    fn derive_secret(secret: [u8; 32], bits: u8, idx: u64) -> [u8; 32] {
        let mut res: [u8; 32] = secret;
        for i in 0..bits {
            let bitpos = bits - 1 - i;
            if idx & (1 << bitpos) == (1 << bitpos) {
                res[(bitpos / 8) as usize] ^= 1 << (bitpos & 7);
                res = Sha256::hash(&res).into_inner();
            }
        }
        res
    }

    /// Inserts the `secret` at `idx`. Returns `Ok(())` if the secret
    /// was generated in accordance with BOLT 3 and is consistent with previous secrets.
    pub fn provide_secret(&mut self, idx: u64, secret: [u8; 32]) -> Result<(), ()> {
        let pos = Self::place_secret(idx);
        for i in 0..pos {
            let (old_secret, old_idx) = self.old_secrets[i as usize];
            if Self::derive_secret(secret, pos, old_idx) != old_secret {
                return Err(());
            }
        }
        if self.get_min_seen_secret() <= idx {
            return Ok(());
        }
        self.old_secrets[pos as usize] = (secret, idx);
        Ok(())
    }

    /// Returns the secret at `idx`.
    /// Returns `None` if `idx` is < [`CounterpartyCommitmentSecrets::get_min_seen_secret`].
    pub fn get_secret(&self, idx: u64) -> Option<[u8; 32]> {
        for i in 0..self.old_secrets.len() {
            if (idx & (!((1 << i) - 1))) == self.old_secrets[i].1 {
                return Some(Self::derive_secret(self.old_secrets[i].0, i as u8, idx));
            }
        }
        assert!(idx < self.get_min_seen_secret());
        None
    }
}

/// Enforcement state for a channel
///
/// This keeps track of commitments on both sides and whether the channel
/// was closed.
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnforcementState {
    // the next commitment number we expect to see signed by the counterparty
    // (set by validate_holder_commitment_tx)
    pub next_holder_commit_num: u64,
    // the next commitment number we expect to sign
    // (set by sign_counterparty_commitment_tx)
    pub next_counterparty_commit_num: u64,
    // the next commitment number we expect the counterparty to revoke
    // (set by validate_counterparty_revocation)
    pub next_counterparty_revoke_num: u64,

    // (set by sign_counterparty_commitment_tx)
    pub current_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 1
    // (set by sign_counterparty_commitment_tx)
    pub previous_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 2

    // (set by validate_holder_commitment_tx)
    pub current_holder_commit_info: Option<CommitmentInfo2>,
    /// Counterparty signatures on holder's commitment
    pub current_counterparty_signatures: Option<CommitmentSignatures>,

    // (set by sign_counterparty_commitment_tx)
    pub current_counterparty_commit_info: Option<CommitmentInfo2>,
    // (set by sign_counterparty_commitment_tx)
    pub previous_counterparty_commit_info: Option<CommitmentInfo2>,

    pub channel_closed: bool,
    pub initial_holder_value: u64,

    /// Counterparty revocation secrets.
    /// This is an Option for backwards compatibility with old databases.
    pub counterparty_secrets: Option<CounterpartyCommitmentSecrets>,
}

impl EnforcementState {
    /// Create state for a new channel.
    ///
    /// `initial_holder_value` is in satoshi and represents the lowest value
    /// that we expect the initial commitment to send to us.
    pub fn new(initial_holder_value: u64) -> EnforcementState {
        EnforcementState {
            next_holder_commit_num: 0,
            next_counterparty_commit_num: 0,
            next_counterparty_revoke_num: 0,
            current_counterparty_point: None,
            previous_counterparty_point: None,
            current_holder_commit_info: None,
            current_counterparty_signatures: None,
            current_counterparty_commit_info: None,
            previous_counterparty_commit_info: None,
            channel_closed: false,
            initial_holder_value,
            counterparty_secrets: Some(CounterpartyCommitmentSecrets::new()),
        }
    }

    /// Returns the minimum amount to_holder from both commitments or
    /// None if the amounts are not within epsilon_sat.
    pub fn minimum_to_holder_value(&self, epsilon_sat: u64) -> Option<u64> {
        if let Some(hinfo) = &self.current_holder_commit_info {
            if let Some(cinfo) = &self.current_counterparty_commit_info {
                let hval = hinfo.to_broadcaster_value_sat;
                let cval = cinfo.to_countersigner_value_sat;
                debug!("min to_holder: hval={}, cval={}", hval, cval);
                if hval > cval {
                    if hval - cval <= epsilon_sat {
                        return Some(cval);
                    }
                } else
                /* cval >= hval */
                {
                    if cval - hval <= epsilon_sat {
                        return Some(hval);
                    }
                }
            }
        }
        None
    }

    /// Returns the minimum amount to_counterparty from both commitments or
    /// None if the amounts are not within epsilon_sat.
    pub fn minimum_to_counterparty_value(&self, epsilon_sat: u64) -> Option<u64> {
        if let Some(hinfo) = &self.current_holder_commit_info {
            if let Some(cinfo) = &self.current_counterparty_commit_info {
                let hval = hinfo.to_countersigner_value_sat;
                let cval = cinfo.to_broadcaster_value_sat;
                debug!("min to_cparty: hval={}, cval={}", hval, cval);
                if hval > cval {
                    if hval - cval <= epsilon_sat {
                        return Some(cval);
                    }
                } else
                /* cval >= hval */
                {
                    if cval - hval <= epsilon_sat {
                        return Some(hval);
                    }
                }
            }
        }
        None
    }

    /// Set next holder commitment number
    /// Policy enforcement must be performed by the caller
    pub fn set_next_holder_commit_num(
        &mut self,
        num: u64,
        current_commitment_info: CommitmentInfo2,
        counterparty_signatures: CommitmentSignatures,
    ) {
        let current = self.next_holder_commit_num;
        // TODO - should we enforce policy-v2-commitment-retry-same here?
        debug!("next_holder_commit_num {} -> {}", current, num);
        self.next_holder_commit_num = num;
        self.current_holder_commit_info = Some(current_commitment_info);
        self.current_counterparty_signatures = Some(counterparty_signatures);
    }

    /// Get the current commitment info
    pub fn get_current_holder_commitment_info(&self) -> CommitmentInfo2 {
        self.current_holder_commit_info.as_ref().unwrap().clone()
    }

    /// Set next counterparty commitment number
    pub fn set_next_counterparty_commit_num(
        &mut self,
        num: u64,
        current_point: PublicKey,
        current_commitment_info: CommitmentInfo2,
    ) {
        assert!(num > 0);
        let current = self.next_counterparty_commit_num;

        if num == current + 1 {
            // normal progression, move current to previous
            self.previous_counterparty_point = self.current_counterparty_point;
            self.previous_counterparty_commit_info = self.current_counterparty_commit_info.take();
        } else if num > current + 1 || num < current {
            // we jumped ahead or back, clear out previous info
            self.previous_counterparty_point = None;
            self.previous_counterparty_commit_info = None;
        }

        if num >= current + 1 {
            // we progressed, set current
            self.current_counterparty_point = Some(current_point);
            self.current_counterparty_commit_info = Some(current_commitment_info);
        }

        self.next_counterparty_commit_num = num;
        debug!("next_counterparty_commit_num {} -> {} current {}", current, num, current_point);
    }

    /// Previous counterparty commitment point, or None if unknown
    pub fn get_previous_counterparty_point(&self, num: u64) -> Option<PublicKey> {
        if num + 1 == self.next_counterparty_commit_num {
            self.current_counterparty_point
        } else if num + 2 == self.next_counterparty_commit_num {
            self.previous_counterparty_point
        } else {
            None
        }
    }

    /// Previous counterparty commitment info
    pub fn get_previous_counterparty_commit_info(&self, num: u64) -> Option<CommitmentInfo2> {
        if num + 1 == self.next_counterparty_commit_num {
            self.current_counterparty_commit_info.clone()
        } else if num + 2 == self.next_counterparty_commit_num {
            self.previous_counterparty_commit_info.clone()
        } else {
            None
        }
    }

    /// Set next counterparty revoked commitment number
    pub fn set_next_counterparty_revoke_num(&mut self, num: u64) {
        assert_ne!(num, 0);
        let current = self.next_counterparty_revoke_num;

        // Remove any revoked commitment state.
        if num + 1 >= self.next_counterparty_commit_num {
            // We can't remove the previous_counterparty_point, needed for retries.
            self.previous_counterparty_commit_info = None;
        }

        self.next_counterparty_revoke_num = num;
        debug!("next_counterparty_revoke_num {} -> {}", current, num);
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_holder_commit_num_for_testing(&mut self, num: u64) {
        debug!(
            "set_next_holder_commit_num_for_testing: {} -> {}",
            self.next_holder_commit_num, num
        );
        self.next_holder_commit_num = num;
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_commit_num_for_testing(
        &mut self,
        num: u64,
        current_point: PublicKey,
    ) {
        debug!(
            "set_next_counterparty_commit_num_for_testing: {} -> {}",
            self.next_counterparty_commit_num, num
        );
        self.previous_counterparty_point = self.current_counterparty_point;
        self.current_counterparty_point = Some(current_point);
        self.next_counterparty_commit_num = num;
    }

    #[allow(missing_docs)]
    #[cfg(any(test, feature = "test_utils"))]
    pub fn set_next_counterparty_revoke_num_for_testing(&mut self, num: u64) {
        debug!(
            "set_next_counterparty_revoke_num_for_testing: {} -> {}",
            self.next_counterparty_revoke_num, num
        );
        self.next_counterparty_revoke_num = num;
    }

    /// Summarize in-flight outgoing payments, possibly with new
    /// holder offered or counterparty received commitment tx.
    /// The amounts are in satoshi.
    /// HTLCs belonging to a payment are summed for each of the
    /// holder and counterparty txs. The greater value is taken as the actual
    /// in-flight value.
    pub fn payments_summary(
        &self,
        new_holder_tx: Option<&CommitmentInfo2>,
        new_counterparty_tx: Option<&CommitmentInfo2>,
    ) -> Map<PaymentHash, u64> {
        let holder_offered =
            new_holder_tx.or(self.current_holder_commit_info.as_ref()).map(|h| &h.offered_htlcs);
        let counterparty_received = new_counterparty_tx
            .or(self.current_counterparty_commit_info.as_ref())
            .map(|c| &c.received_htlcs);
        let holder_summary =
            holder_offered.map(|h| Self::summarize_payments(h)).unwrap_or_else(|| Map::new());
        let counterparty_summary = counterparty_received
            .map(|h| Self::summarize_payments(h))
            .unwrap_or_else(|| Map::new());
        // Union the two summaries
        let mut summary = holder_summary;
        for (k, v) in counterparty_summary {
            // Choose higher amount if already there, or insert if not
            summary.entry(k).and_modify(|e| *e = max(*e, v)).or_insert(v);
        }

        if let Some(holder_tx) = self.current_holder_commit_info.as_ref() {
            for h in holder_tx.offered_htlcs.iter() {
                summary.entry(h.payment_hash).or_insert(0);
            }
        }

        if let Some(counterparty_tx) = self.current_counterparty_commit_info.as_ref() {
            for h in counterparty_tx.received_htlcs.iter() {
                summary.entry(h.payment_hash).or_insert(0);
            }
        }
        summary
    }

    /// Summarize in-flight incoming payments, possibly with new
    /// holder offered or counterparty received commitment tx.
    /// The amounts are in satoshi.
    /// HTLCs belonging to a payment are summed for each of the
    /// holder and counterparty txs. The smaller value is taken as the actual
    /// in-flight value.
    //
    // The smaller value is taken because we should only consider an invoice paid
    // when both txs contain the payment.
    pub fn incoming_payments_summary(
        &self,
        new_holder_tx: Option<&CommitmentInfo2>,
        new_counterparty_tx: Option<&CommitmentInfo2>,
    ) -> Map<PaymentHash, u64> {
        let holder_received =
            new_holder_tx.or(self.current_holder_commit_info.as_ref()).map(|h| &h.received_htlcs);
        let counterparty_offered = new_counterparty_tx
            .or(self.current_counterparty_commit_info.as_ref())
            .map(|c| &c.offered_htlcs);
        let holder_summary =
            holder_received.map(|h| Self::summarize_payments(h)).unwrap_or_else(|| Map::new());
        let counterparty_summary =
            counterparty_offered.map(|h| Self::summarize_payments(h)).unwrap_or_else(|| Map::new());
        // Intersect the holder and counterparty summaries, because we don't
        // consider a payment until it is present in both commitment transactions.
        let mut summary = holder_summary;
        summary.retain(|k, _| counterparty_summary.contains_key(k));
        for (k, v) in counterparty_summary {
            // Choose lower amount
            summary.entry(k).and_modify(|e| *e = min(*e, v));
        }

        if let Some(holder_tx) = self.current_holder_commit_info.as_ref() {
            for h in holder_tx.received_htlcs.iter() {
                summary.entry(h.payment_hash).or_insert(0);
            }
        }

        if let Some(counterparty_tx) = self.current_counterparty_commit_info.as_ref() {
            for h in counterparty_tx.offered_htlcs.iter() {
                summary.entry(h.payment_hash).or_insert(0);
            }
        }
        summary
    }

    fn summarize_payments(htlcs: &[HTLCInfo2]) -> Map<PaymentHash, u64> {
        let mut summary = Map::new();
        for h in htlcs {
            // If there are multiple HTLCs for the same payment, sum them
            summary.entry(h.payment_hash).and_modify(|e| *e += h.value_sat).or_insert(h.value_sat);
        }
        summary
    }

    /// The claimable balance before and after a new commitment tx
    ///
    /// See [`CommitmentInfo2::claimable_balance`]
    pub fn claimable_balances<T: PreimageMap>(
        &self,
        preimage_map: &T,
        new_holder_tx: Option<&CommitmentInfo2>,
        new_counterparty_tx: Option<&CommitmentInfo2>,
        channel_setup: &ChannelSetup,
    ) -> BalanceDelta {
        assert!(
            new_holder_tx.is_some() || new_counterparty_tx.is_some(),
            "must have at least one new tx"
        );
        assert!(
            new_holder_tx.is_none() || new_counterparty_tx.is_none(),
            "must have at most one new tx"
        );
        // Our balance in the holder commitment tx
        let cur_holder_bal = self.current_holder_commit_info.as_ref().map(|tx| {
            tx.claimable_balance(
                preimage_map,
                channel_setup.is_outbound,
                channel_setup.channel_value_sat,
            )
        });
        // Our balance in the counterparty commitment tx
        let cur_cp_bal = self.current_counterparty_commit_info.as_ref().map(|tx| {
            tx.claimable_balance(
                preimage_map,
                channel_setup.is_outbound,
                channel_setup.channel_value_sat,
            )
        });
        // Our overall balance is the lower of the two
        let cur_bal_opt = min_opt(cur_holder_bal, cur_cp_bal);

        // Perform balance calculations given the new transaction
        let new_holder_bal = new_holder_tx.or(self.current_holder_commit_info.as_ref()).map(|tx| {
            tx.claimable_balance(
                preimage_map,
                channel_setup.is_outbound,
                channel_setup.channel_value_sat,
            )
        });
        let new_cp_bal =
            new_counterparty_tx.or(self.current_counterparty_commit_info.as_ref()).map(|tx| {
                tx.claimable_balance(
                    preimage_map,
                    channel_setup.is_outbound,
                    channel_setup.channel_value_sat,
                )
            });
        let new_bal =
            min_opt(new_holder_bal, new_cp_bal).expect("already checked that we have a new tx");

        // If this is the first commitment, we will have no current balance.
        // We will use our funding amount, or zero if we are not the funder.
        let cur_bal = cur_bal_opt.unwrap_or_else(|| self.initial_holder_value);

        debug!(
            "balance {} -> {} --- cur h {} c {} new h {} c {}",
            cur_bal,
            new_bal,
            self.current_holder_commit_info.is_some(),
            self.current_counterparty_commit_info.is_some(),
            new_holder_tx.is_some(),
            new_counterparty_tx.is_some()
        );

        BalanceDelta(cur_bal, new_bal)
    }

    /// Return channel balances
    pub fn balance<T: PreimageMap + core::fmt::Debug>(
        &self,
        preimage_map: &T,
        channel_setup: &ChannelSetup,
    ) -> ChannelBalance {
        debug!("{:#?}", preimage_map);

        // If either of commitments is missing, return 0.
        if self.current_holder_commit_info.is_none()
            || self.current_counterparty_commit_info.is_none()
        {
            return ChannelBalance::zero();
        }

        // Our balance in the holder commitment tx
        let cur_holder_bal = self.current_holder_commit_info.as_ref().unwrap().claimable_balance(
            preimage_map,
            channel_setup.is_outbound,
            channel_setup.channel_value_sat,
        );
        // Our balance in the counterparty commitment tx
        let cur_cp_bal = self.current_counterparty_commit_info.as_ref().unwrap().claimable_balance(
            preimage_map,
            channel_setup.is_outbound,
            channel_setup.channel_value_sat,
        );
        // Our overall balance is the lower of the two.  Use the htlc values from the same.
        // TODO - might be more correct to check the HTLC value for each payment hash, and do
        // Math.min on each one, then sum that.  If an htlc exists in one commitment but not the
        // other if we offered, then it would be -value, if we are receiving, it would be
        // 0. i.e. Math.min(0, value)
        let (cur_bal, received_htlc, offered_htlc, received_htlc_count, offered_htlc_count) =
            if cur_holder_bal < cur_cp_bal {
                let (received_htlc, offered_htlc, received_count, offered_count) =
                    self.current_holder_commit_info.as_ref().unwrap().htlc_balance();
                (cur_holder_bal, received_htlc, offered_htlc, received_count, offered_count)
            } else {
                let (received_htlc, offered_htlc, received_count, offered_count) =
                    self.current_counterparty_commit_info.as_ref().unwrap().htlc_balance();
                (cur_cp_bal, received_htlc, offered_htlc, received_count, offered_count)
            };

        let (claimable, sweeping) = if self.channel_closed { (0, cur_bal) } else { (cur_bal, 0) };

        let balance = ChannelBalance {
            claimable,
            received_htlc,
            offered_htlc,
            sweeping,
            channel_count: 1,
            received_htlc_count,
            offered_htlc_count,
        };
        balance
    }
}

/// Claimable balance before and after a new commitment tx, in satoshi
pub struct BalanceDelta(pub u64, pub u64);

impl Default for BalanceDelta {
    fn default() -> Self {
        BalanceDelta(0, 0)
    }
}

// The minimum of two optional values.  If both are None, the result is None.
fn min_opt(a_opt: Option<u64>, b_opt: Option<u64>) -> Option<u64> {
    if let Some(a) = a_opt {
        if let Some(b) = b_opt {
            Some(a.min(b))
        } else {
            a_opt
        }
    } else {
        b_opt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::tx::{CommitmentInfo2, HTLCInfo2};
    use crate::util::test_utils::make_dummy_pubkey;
    use bitcoin::secp256k1::PublicKey;
    use lightning::ln::PaymentHash;

    #[test]
    fn test_per_commitment_storage() {
        // Test vectors from BOLT 3:
        let mut secrets: Vec<[u8; 32]> = Vec::new();
        let mut monitor;

        macro_rules! test_secrets {
            () => {
                let mut idx = 281474976710655;
                for secret in secrets.iter() {
                    assert_eq!(monitor.get_secret(idx).unwrap(), *secret);
                    idx -= 1;
                }
                assert_eq!(monitor.get_min_seen_secret(), idx + 1);
                assert!(monitor.get_secret(idx).is_none());
            };
        }

        {
            // insert_secret correct sequence
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710648, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();
        }

        {
            // insert_secret #1 incorrect
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710654, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #2 incorrect (#1 derived from incorrect)
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710652, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #3 incorrect
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710652, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #4 incorrect (1,2,3 derived from incorrect)
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710648, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #5 incorrect
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710650, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #6 incorrect (5 derived from incorrect)
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710648, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #7 incorrect
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710648, secrets.last().unwrap().clone())
                .is_err());
        }

        {
            // insert_secret #8 incorrect
            monitor = CounterpartyCommitmentSecrets::new();
            secrets.clear();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710655, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710654, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710653, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710652, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710651, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710650, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32")
                    .unwrap(),
            );
            monitor.provide_secret(281474976710649, secrets.last().unwrap().clone()).unwrap();
            test_secrets!();

            secrets.push([0; 32]);
            secrets.last_mut().unwrap()[0..32].clone_from_slice(
                &hex::decode("a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4")
                    .unwrap(),
            );
            assert!(monitor
                .provide_secret(281474976710648, secrets.last().unwrap().clone())
                .is_err());
        }
    }

    #[test]
    fn payments_summary_test() {
        let mut state = EnforcementState::new(1000000);
        let dummy_pubkey = make_dummy_pubkey(1);

        // COUNTERPARTY
        let payment_hash = PaymentHash([3; 32]);
        let htlcs = vec![HTLCInfo2 { value_sat: 1000, payment_hash, cltv_expiry: 100 }];

        let cp_tx = make_tx(true, dummy_pubkey, htlcs);

        // no payments yet
        assert!(state.payments_summary(None, None).is_empty());

        // pending add of outgoing HTLC
        let sum = state.payments_summary(None, Some(&cp_tx));
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // outgoing HTLC
        state.current_counterparty_commit_info = Some(cp_tx);
        let sum = state.payments_summary(None, None);
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // pending failed HTLC
        let cp_tx2 = make_tx(true, dummy_pubkey, vec![]);
        let sum = state.payments_summary(None, Some(&cp_tx2));
        assert_eq!(sum.get(&payment_hash), Some(&0));

        state.current_counterparty_commit_info = Some(cp_tx2);
        let sum = state.payments_summary(None, None);
        assert_eq!(sum.get(&payment_hash), None);

        // HOLDER
        let payment_hash = PaymentHash([4; 32]);
        let htlcs = vec![HTLCInfo2 { value_sat: 1000, payment_hash, cltv_expiry: 100 }];
        let holder_tx = make_tx(false, dummy_pubkey, htlcs);

        // no payments yet
        assert!(state.payments_summary(None, None).is_empty());

        // pending add of outgoing HTLC
        let sum = state.payments_summary(Some(&holder_tx), None);
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // outgoing HTLC
        state.current_holder_commit_info = Some(holder_tx);
        let sum = state.payments_summary(None, None);
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // pending failed HTLC
        let holder_tx2 = make_tx(false, dummy_pubkey, vec![]);
        let sum = state.payments_summary(Some(&holder_tx2), None);
        assert_eq!(sum.get(&payment_hash), Some(&0));

        state.current_holder_commit_info = Some(holder_tx2);
        let sum = state.payments_summary(None, None);
        assert_eq!(sum.get(&payment_hash), None);
    }

    #[test]
    fn incoming_payments_summary_test() {
        let mut state = EnforcementState::new(1000000);
        let dummy_pubkey = make_dummy_pubkey(1);

        let payment_hash = PaymentHash([3; 32]);
        let htlcs = vec![HTLCInfo2 { value_sat: 1000, payment_hash, cltv_expiry: 100 }];

        let cp_tx = make_tx(false, dummy_pubkey, htlcs.clone());
        let holder_tx = make_tx(true, dummy_pubkey, htlcs.clone());

        // no payments yet
        assert!(state.incoming_payments_summary(None, None).is_empty());

        // no payments with just one side
        assert!(state.incoming_payments_summary(Some(&holder_tx), None).is_empty());
        assert!(state.incoming_payments_summary(None, Some(&cp_tx)).is_empty());

        // pending add of outgoing HTLC
        let sum = state.incoming_payments_summary(Some(&holder_tx), Some(&cp_tx));
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // outgoing HTLC
        state.current_counterparty_commit_info = Some(cp_tx);
        state.current_holder_commit_info = Some(holder_tx);
        let sum = state.incoming_payments_summary(None, None);
        assert_eq!(sum.get(&payment_hash), Some(&1000));

        // pending failed HTLC
        let holder_tx2 = make_tx(true, dummy_pubkey, vec![]);
        let cp_tx2 = make_tx(false, dummy_pubkey, vec![]);

        let sum = state.incoming_payments_summary(None, Some(&cp_tx2));
        assert_eq!(sum.get(&payment_hash), Some(&0));

        let sum = state.incoming_payments_summary(Some(&holder_tx2), None);
        assert_eq!(sum.get(&payment_hash), Some(&0));
    }

    fn make_tx(
        is_received: bool,
        dummy_pubkey: PublicKey,
        htlcs: Vec<HTLCInfo2>,
    ) -> CommitmentInfo2 {
        CommitmentInfo2::new(
            is_received,
            dummy_pubkey,
            9000,
            dummy_pubkey,
            dummy_pubkey,
            10000,
            6,
            if is_received { vec![] } else { htlcs.clone() },
            if is_received { htlcs.clone() } else { vec![] },
            1000,
        )
    }
}
