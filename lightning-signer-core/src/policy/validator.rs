extern crate scopeguard;

use core::cmp::{max, min};

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{self, EcdsaSighashType, Network, Script, Sighash, Transaction};
use lightning::chain::keysinterface::InMemorySigner;
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};
use lightning::ln::PaymentHash;
use log::debug;

use crate::channel::{ChannelBalance, ChannelId, ChannelSetup, ChannelSlot};
use crate::policy::Policy;
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2, HTLCInfo2, PreimageMap};
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
        wallet: &Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &Vec<u32>,
    ) -> Result<(), ValidationError>;

    /// Validate channel value after it is late-filled
    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError>;

    /// Validate an onchain transaction (funding tx, simple sweeps).
    /// This transaction may fund multiple channels at the same time.
    ///
    /// * `channels` the funded channel for each funding output, or
    ///   None for change outputs
    /// * `values_sat` - the amount in satoshi per input
    /// * `opaths` - derivation path for change, one per output,
    ///   empty for non-change or allowlisted outputs
    /// * `weight_lower_bound` - lower bound of tx size, for feerate checking
    fn validate_onchain_tx(
        &self,
        wallet: &Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        tx: &Transaction,
        values_sat: &Vec<u64>,
        opaths: &Vec<Vec<u32>>,
        weight_lower_bound: usize,
    ) -> Result<(), ValidationError>;

    /// Phase 1 CommitmentInfo
    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
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
        wallet: &Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        tx: &Transaction,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<ClosingTransaction, ValidationError>;

    /// Phase 2 Validatation of mutual_close
    fn validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_shutdown_script: &Option<Script>,
        counterparty_shutdown_script: &Option<Script>,
        holder_wallet_path_hint: &Vec<u32>,
    ) -> Result<(), ValidationError>;

    /// Validation of delayed sweep transaction
    fn validate_delayed_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &Vec<u32>,
    ) -> Result<(), ValidationError>;

    /// Validation of counterparty htlc sweep transaction (first level
    /// commitment htlc outputs)
    fn validate_counterparty_htlc_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        redeemscript: &Script,
        input: usize,
        amount_sat: u64,
        key_path: &Vec<u32>,
    ) -> Result<(), ValidationError>;

    /// Validation of justice sweep transaction
    fn validate_justice_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &Vec<u32>,
    ) -> Result<(), ValidationError>;

    /// Validation of the payment state for a payment hash.
    /// This could include a payment routed through us, or a payment we
    /// are making, or both.  If we are not making a payment, then the incoming
    /// must be greater or equal to the outgoing.  Otherwise, the incoming
    /// minus outgoing should be enough to pay for the invoice and routing fees,
    /// but no larger.
    fn validate_payment_balance(
        &self,
        incoming: u64,
        outgoing: u64,
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
        estate.set_next_holder_commit_num(num, current_commitment_info);
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

/// Enforcement state for a channel
///
/// This keeps track of commitments on both sides and whether the channel
/// was closed.
#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct EnforcementState {
    pub next_holder_commit_num: u64,
    pub next_counterparty_commit_num: u64,
    pub next_counterparty_revoke_num: u64,
    pub current_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 1
    pub previous_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 2
    pub current_holder_commit_info: Option<CommitmentInfo2>,
    pub current_counterparty_commit_info: Option<CommitmentInfo2>,
    pub previous_counterparty_commit_info: Option<CommitmentInfo2>,
    pub channel_closed: bool,
    pub initial_holder_value: u64,
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
            current_counterparty_commit_info: None,
            previous_counterparty_commit_info: None,
            channel_closed: false,
            initial_holder_value,
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
    ) {
        let current = self.next_holder_commit_num;
        // TODO - should we enforce policy-v2-commitment-retry-same here?
        debug!("next_holder_commit_num {} -> {}", current, num);
        self.next_holder_commit_num = num;
        self.current_holder_commit_info = Some(current_commitment_info);
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
    #[cfg(feature = "test_utils")]
    pub fn set_next_holder_commit_num_for_testing(&mut self, num: u64) {
        debug!(
            "set_next_holder_commit_num_for_testing: {} -> {}",
            self.next_holder_commit_num, num
        );
        self.next_holder_commit_num = num;
    }

    #[allow(missing_docs)]
    #[cfg(feature = "test_utils")]
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
    #[cfg(feature = "test_utils")]
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
        summary
    }

    fn summarize_payments(htlcs: &Vec<HTLCInfo2>) -> Map<PaymentHash, u64> {
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

        log::debug!(
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
    pub fn balance<T: PreimageMap>(
        &self,
        preimage_map: &T,
        channel_setup: &ChannelSetup,
    ) -> ChannelBalance {
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
        let (cur_bal, received_htlc, offered_htlc) = if cur_holder_bal < cur_cp_bal {
            let (received_htlc, offered_htlc) =
                self.current_holder_commit_info.as_ref().unwrap().htlc_balance();
            (cur_holder_bal, received_htlc, offered_htlc)
        } else {
            let (received_htlc, offered_htlc) =
                self.current_counterparty_commit_info.as_ref().unwrap().htlc_balance();
            (cur_cp_bal, received_htlc, offered_htlc)
        };

        let (claimable, sweeping) = if self.channel_closed { (0, cur_bal) } else { (cur_bal, 0) };

        let balance = ChannelBalance { claimable, received_htlc, offered_htlc, sweeping };
        debug!("balance: {:?}", balance);
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
