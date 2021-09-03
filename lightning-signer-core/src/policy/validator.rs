use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{self, Address, Network, OutPoint, Script, SigHash, SigHashType, Transaction};
use lightning::chain::keysinterface::{BaseSign, InMemorySigner};
use lightning::ln::chan_utils::{
    build_htlc_transaction, make_funding_redeemscript, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::ln::PaymentHash;
use log::{debug, info};

use crate::channel::{ChannelSetup, ChannelSlot};
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{
    build_close_tx, parse_offered_htlc_script, parse_received_htlc_script,
    parse_revokeable_redeemscript, CommitmentInfo, CommitmentInfo2, HTLC_SUCCESS_TX_WEIGHT,
    HTLC_TIMEOUT_TX_WEIGHT,
};
use crate::util::crypto_utils::payload_for_p2wsh;
use crate::wallet::Wallet;

use super::error::{policy_error, transaction_format_error, ValidationError};

/// A policy checker
///
/// Called by Node / Channel as needed.
pub trait Validator {
    /// Phase 1 CommitmentInfo
    fn make_info(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
    ) -> Result<CommitmentInfo, ValidationError>;

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

    /// General validation applicable to both holder and counterparty txs
    fn validate_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        vstate: &ValidatorState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError>;

    /// Ensures that signing a holder commitment is valid.
    fn validate_sign_holder_commitment_tx(
        &self,
        enforcement_state: &EnforcementState,
        commit_num: u64,
    ) -> Result<(), ValidationError>;

    /// Ensures that a counterparty signed holder commitment is valid.
    fn validate_holder_commitment_state(
        &self,
        enforcement_state: &EnforcementState,
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
    ) -> Result<(u32, HTLCOutputInCommitment, SigHash), ValidationError>;

    /// Phase 2 validation of 2nd level HTLC tx
    fn validate_htlc_tx(
        &self,
        setup: &ChannelSetup,
        state: &ValidatorState,
        is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError>;

    /// Validate a funding transaction, which may fund multiple channels
    ///
    /// * `channels` the funded channel for each funding output, or None for
    ///   change outputs
    /// * `values_sat` - the amount in satoshi per input
    /// * `opaths` - derivation path for change, one per output.  Empty for
    ///   non-change outputs.
    fn validate_funding_tx(
        &self,
        wallet: &Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        state: &ValidatorState,
        tx: &Transaction,
        values_sat: &Vec<u64>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<(), ValidationError>;

    /// Phase 1 decoding and recomposition of mutual_close
    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        tx: &Transaction,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<Transaction, ValidationError>;

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
}

/// Blockchain state used by the validator
#[derive(Debug)]
pub struct ValidatorState {
    /// The current blockchain height
    pub current_height: u32,
}

/// A factory for validators
pub trait ValidatorFactory: Send + Sync {
    /// Construct a validator
    fn make_validator(&self, network: Network) -> Box<dyn Validator>;
}

/// A factor for SimpleValidator
pub struct SimpleValidatorFactory {}

fn simple_validator(network: Network) -> SimpleValidator {
    SimpleValidator {
        policy: make_simple_policy(network),
    }
}

impl ValidatorFactory for SimpleValidatorFactory {
    fn make_validator(&self, network: Network) -> Box<dyn Validator> {
        Box::new(simple_validator(network))
    }
}

/// A simple policy to configure a SimpleValidator
#[derive(Clone)]
pub struct SimplePolicy {
    /// Minimum delay in blocks
    pub min_delay: u16,
    /// Maximum delay in blocks
    pub max_delay: u16,
    /// Maximum channel value in satoshi
    pub max_channel_size_sat: u64,
    /// Maximum amount allowed to be pushed
    pub max_push_sat: u64,
    /// amounts below this number of satoshi are not considered important
    pub epsilon_sat: u64,
    /// Maximum number of in-flight HTLCs
    pub max_htlcs: usize,
    /// Maximum value of in-flight HTLCs
    pub max_htlc_value_sat: u64,
    /// Whether to use knowledge of chain state (e.g. current_height)
    pub use_chain_state: bool,
    /// Minimum feerate
    pub min_feerate_per_kw: u32,
    /// Maximum feerate
    pub max_feerate_per_kw: u32,
    /// Minimum fee
    pub min_fee: u64,
    /// Maximum fee
    pub max_fee: u64,
}

/// A simple validator
pub struct SimpleValidator {
    policy: SimplePolicy,
}

impl SimpleValidator {
    fn validate_delay(&self, name: &str, delay: u32) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if delay < policy.min_delay as u32 {
            return policy_err!("{} too small", name);
        }
        if delay > policy.max_delay as u32 {
            return policy_err!("{} too large", name);
        }

        Ok(())
    }

    fn validate_expiry(
        &self,
        name: &str,
        expiry: u32,
        current_height: u32,
    ) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if policy.use_chain_state {
            if expiry < current_height + policy.min_delay as u32 {
                return policy_err!("{} expiry too early", name);
            }
            if expiry > current_height + policy.max_delay as u32 {
                return policy_err!("{} expiry too late", name);
            }
        }

        Ok(())
    }

    fn validate_fee(&self, name: &str, fee: u64, _tx: &Transaction) -> Result<(), ValidationError> {
        if fee < self.policy.min_fee {
            return policy_err!(
                "{}: fee below minimum: {} < {}",
                name,
                fee,
                self.policy.min_fee
            );
        }
        if fee > self.policy.max_fee {
            return policy_err!("{}: above maximum: {} > {}", name, fee, self.policy.max_fee);
        }
        // TODO - apply min/max fee rate heurustic (incorporating tx size) as well.
        Ok(())
    }

    fn outside_epsilon_range(&self, value0: u64, value1: u64) -> (bool, String) {
        if value0 > value1 {
            (
                value0 - value1 > self.policy.epsilon_sat,
                "larger".to_string(),
            )
        } else {
            (
                value1 - value0 > self.policy.epsilon_sat,
                "smaller".to_string(),
            )
        }
    }
}

// sign_commitment_tx has some, missing these
// TODO - policy-v1-commitment-anchor-static-remotekey
// TODO - policy-v1-commitment-anchor-to-local
// TODO - policy-v1-commitment-anchor-to-remote
// TODO - policy-v1-commitment-anchors-not-when-off
// TODO - policy-v1-commitment-htlc-cltv-range
// TODO - policy-v1-commitment-outputs-trimmed
// TODO - policy-v2-commitment-fee-range
// TODO - policy-v2-commitment-htlc-count-limit
// TODO - policy-v2-commitment-htlc-inflight-limit
// TODO - policy-v2-commitment-htlc-offered-hash-matches
// TODO - policy-v2-commitment-htlc-received-spends-active-utxo
// TODO - policy-v2-commitment-htlc-routing-balance
// TODO - policy-v2-commitment-previous-revoked (still need secret storage)
// TODO - policy-v2-commitment-spends-active-utxo

// not yet implemented
// TODO - policy-v2-htlc-cltv-range

// not yet implemented
// TODO - policy-v2-forced-destination-allowlisted
// TODO - policy-v2-forced-fee-range

// not yet implemented
// TODO - policy-v3-velocity-transferred
// TODO - policy-v3-merchant-no-sends
// TODO - policy-v3-routing-deltas-only-htlc
// TODO - policy-v3-velocity-funding

impl Validator for SimpleValidator {
    fn make_info(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
    ) -> Result<CommitmentInfo, ValidationError> {
        // policy-v1-commitment-version
        if tx.version != 2 {
            return policy_err!("bad commitment version: {}", tx.version);
        }

        let mut info = CommitmentInfo::new(is_counterparty);
        for ind in 0..tx.output.len() {
            info.handle_output(
                keys,
                setup,
                &tx.output[ind],
                output_witscripts[ind].as_slice(),
            )
            .map_err(|ve| policy_error(format!("tx output[{}]: {}", ind, ve)))?;
        }
        Ok(info)
    }

    fn validate_ready_channel(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        // NOTE - setup.channel_value_sat is not valid, set later on.

        if setup.push_value_msat / 1000 > self.policy.max_push_sat {
            return policy_err!(
                "push_value_msat {} greater than max_push_sat {}",
                setup.push_value_msat,
                self.policy.max_push_sat
            );
        }
        // policy-v1-commitment-to-self-delay-range
        self.validate_delay(
            "counterparty_selected_contest_delay",
            setup.counterparty_selected_contest_delay as u32,
        )?;
        // policy-v1-commitment-to-self-delay-range
        self.validate_delay(
            "holder_selected_contest_delay",
            setup.holder_selected_contest_delay as u32,
        )?;

        // policy-v2-mutual-destination-whitelisted
        if let Some(holder_shutdown_script) = &setup.holder_shutdown_script {
            if !wallet
                .can_spend(holder_shutdown_key_path, &holder_shutdown_script)
                .map_err(|err| policy_error(format!("wallet can_spend error: {}", err)))?
                && !wallet.allowlist_contains(&holder_shutdown_script)
            {
                info!(
                    "not matched: path={:?}, holder_shutdown_script={} regtest={}",
                    holder_shutdown_key_path,
                    Address::from_script(
                        &setup.holder_shutdown_script.as_ref().unwrap(),
                        wallet.network()
                    )
                    .unwrap()
                    .to_string(),
                    Address::from_script(
                        &setup.holder_shutdown_script.as_ref().unwrap(),
                        bitcoin::Network::Regtest
                    )
                    .unwrap()
                    .to_string()
                );
                return policy_err!("holder_shutdown_script is not in wallet or allowlist");
            }
        }
        Ok(())
    }

    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        if setup.channel_value_sat > self.policy.max_channel_size_sat {
            return policy_err!("channel value {} too large", setup.channel_value_sat);
        }
        Ok(())
    }

    fn validate_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        vstate: &ValidatorState,
        info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        let is_counterparty = info.is_counterparty_broadcaster;

        let policy = &self.policy;

        // policy-v1-commitment-to-self-delay-range
        if is_counterparty {
            if info.to_self_delay != setup.holder_selected_contest_delay {
                return Err(policy_error(
                    "holder_selected_contest_delay mismatch".to_string(),
                ));
            }
        } else {
            if info.to_self_delay != setup.counterparty_selected_contest_delay {
                return Err(policy_error(
                    "counterparty_selected_contest_delay mismatch".to_string(),
                ));
            }
        }

        // policy-v2-commitment-htlc-count-limit
        if info.offered_htlcs.len() + info.received_htlcs.len() > policy.max_htlcs {
            return Err(policy_error("too many HTLCs".to_string()));
        }

        let mut htlc_value_sat: u64 = 0;

        for htlc in &info.offered_htlcs {
            self.validate_expiry("offered HTLC", htlc.cltv_expiry, vstate.current_height)?;
            htlc_value_sat = htlc_value_sat
                .checked_add(htlc.value_sat)
                .ok_or_else(|| policy_error("offered HTLC value overflow".to_string()))?;
        }

        for htlc in &info.received_htlcs {
            self.validate_expiry("received HTLC", htlc.cltv_expiry, vstate.current_height)?;
            htlc_value_sat = htlc_value_sat
                .checked_add(htlc.value_sat)
                .ok_or_else(|| policy_error("received HTLC value overflow".to_string()))?;
        }

        // policy-v2-commitment-htlc-inflight-limit
        if htlc_value_sat > policy.max_htlc_value_sat {
            return policy_err!("sum of HTLC values {} too large", htlc_value_sat);
        }

        // policy-v2-commitment-fee-range
        let consumed = info
            .to_broadcaster_value_sat
            .checked_add(info.to_countersigner_value_sat)
            .ok_or_else(|| policy_error("channel value overflow".to_string()))?
            .checked_add(htlc_value_sat)
            .ok_or_else(|| policy_error("channel value overflow on HTLC".to_string()))?;
        let shortage = setup
            .channel_value_sat
            .checked_sub(consumed)
            .ok_or_else(|| {
                policy_error(format!(
                    "channel shortage underflow: {} - {}",
                    setup.channel_value_sat, consumed
                ))
            })?;
        if shortage > policy.epsilon_sat {
            return policy_err!(
                "channel value short by {} > {}",
                shortage,
                policy.epsilon_sat
            );
        }

        if is_counterparty {
            // policy-v2-commitment-previous-revoked
            // if next_counterparty_revoke_num is 20:
            // - commit_num 19 has been revoked
            // - commit_num 20 is current, previously signed, ok to resign
            // - commit_num 21 is ok to sign, advances the state
            // - commit_num 22 is not ok to sign
            if commit_num > estate.next_counterparty_revoke_num + 1 {
                return policy_err!(
                    "invalid attempt to sign counterparty commit_num {} \
                         with next_counterparty_revoke_num {}",
                    commit_num,
                    estate.next_counterparty_revoke_num
                );
            }

            // policy-v2-commitment-retry-same
            // If this is a retry the commit_point must be the same
            if commit_num + 1 == estate.next_counterparty_commit_num {
                let prev_commit_point = estate.get_previous_counterparty_point(commit_num)?;
                if *commitment_point != prev_commit_point {
                    return policy_err!(
                        "retry of sign_counterparty_commitment {} with changed point: \
                             prev {} != new {}",
                        commit_num,
                        &prev_commit_point,
                        &commitment_point
                    );
                }
            }
        }

        // Enforce additional requirements on initial commitments.
        if commit_num == 0 {
            if info.offered_htlcs.len() + info.received_htlcs.len() > 0 {
                return policy_err!("initial commitment may not have HTLCS");
            }

            // policy-v2-commitment-initial-funding-value
            // If we are the funder, the value to us of the initial
            // commitment transaction should be equal to our funding
            // value.
            if setup.is_outbound {
                // Ensure that no extra value is sent to fundee, the
                // no-initial-htlcs and fee checks above will ensure
                // that our share is valid.

                let fundee_value_sat = if is_counterparty {
                    info.to_broadcaster_value_sat
                } else {
                    info.to_countersigner_value_sat
                };

                // The fundee is only entitled to push_value
                if fundee_value_sat > setup.push_value_msat / 1000 {
                    return policy_err!(
                        "initial commitment may only send push_value_msat ({}) to fundee",
                        setup.push_value_msat
                    );
                }
            }
        }

        Ok(())
    }

    fn validate_sign_holder_commitment_tx(
        &self,
        enforcement_state: &EnforcementState,
        commit_num: u64,
    ) -> Result<(), ValidationError> {
        // policy-v2-commitment-local-not-revoked
        if commit_num + 2 <= enforcement_state.next_holder_commit_num {
            return policy_err!(
                "can't sign revoked commitment_number {}, \
                 next_holder_commit_num is {}",
                commit_num,
                enforcement_state.next_holder_commit_num
            );
        };
        Ok(())
    }

    fn validate_holder_commitment_state(
        &self,
        enforcement_state: &EnforcementState,
    ) -> Result<(), ValidationError> {
        // policy-v2-revoke-not-closed
        if enforcement_state.mutual_close_signed {
            return policy_err!("mutual close already signed");
        }
        Ok(())
    }

    fn validate_counterparty_revocation(
        &self,
        state: &EnforcementState,
        revoke_num: u64,
        commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError> {
        let secp_ctx = Secp256k1::signing_only();

        // Only allowed to revoke expected next or retry.
        if revoke_num != state.next_counterparty_revoke_num
            && revoke_num + 1 != state.next_counterparty_revoke_num
        {
            return policy_err!(
                "invalid counterparty revoke_num {} with next_counterparty_revoke_num {}",
                revoke_num,
                state.next_counterparty_revoke_num
            );
        }

        // policy-v2-commitment-previous-revoked (partial: secret validated, but not stored here)
        let supplied_commit_point = PublicKey::from_secret_key(&secp_ctx, &commitment_secret);
        let prev_commit_point = state.get_previous_counterparty_point(revoke_num)?;
        if supplied_commit_point != prev_commit_point {
            return policy_err!(
                "revocation commit point mismatch for commit_num {}: supplied {}, previous {}",
                revoke_num,
                supplied_commit_point,
                prev_commit_point
            );
        }
        Ok(())
    }

    // Phase 1
    // setup and txkeys must come from a trusted source
    fn decode_and_validate_htlc_tx(
        &self,
        is_counterparty: bool,
        setup: &ChannelSetup,
        txkeys: &TxCreationKeys,
        tx: &Transaction,
        redeemscript: &Script,
        htlc_amount_sat: u64,
        output_witscript: &Script,
    ) -> Result<(u32, HTLCOutputInCommitment, SigHash), ValidationError> {
        let to_self_delay = if is_counterparty {
            setup.holder_selected_contest_delay // the local side imposes this value
        } else {
            setup.counterparty_selected_contest_delay // the remote side imposes this value
        };
        let sighash_type = if setup.option_anchor_outputs() {
            SigHashType::SinglePlusAnyoneCanPay
        } else {
            SigHashType::All
        };
        let original_tx_sighash =
            SigHashCache::new(tx).signature_hash(0, &redeemscript, htlc_amount_sat, sighash_type);

        let offered = if parse_offered_htlc_script(redeemscript, setup.option_anchor_outputs())
            .is_ok()
        {
            true
        } else if parse_received_htlc_script(redeemscript, setup.option_anchor_outputs()).is_ok() {
            false
        } else {
            return Err(policy_error("invalid redeemscript".to_string()));
        };

        // Extract some parameters from the submitted transaction.
        let cltv_expiry = if offered { tx.lock_time } else { 0 };
        let transaction_output_index = tx.input[0].previous_output.vout;
        let commitment_txid = tx.input[0].previous_output.txid;
        let total_fee = htlc_amount_sat - tx.output[0].value;

        // Derive the feerate_per_kw used to generate this
        // transaction.  Compensate for the total_fee being rounded
        // down when computed.
        let weight = if offered {
            HTLC_TIMEOUT_TX_WEIGHT
        } else {
            HTLC_SUCCESS_TX_WEIGHT
        };
        let feerate_per_kw = (((total_fee * 1000) + weight - 1) / weight) as u32;

        let htlc = HTLCOutputInCommitment {
            offered,
            amount_msat: htlc_amount_sat * 1000,
            cltv_expiry,
            payment_hash: PaymentHash([0; 32]), // isn't used
            transaction_output_index: Some(transaction_output_index),
        };

        // Recompose the transaction.
        let recomposed_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &txkeys.broadcaster_delayed_payment_key,
            &txkeys.revocation_key,
        );

        let recomposed_tx_sighash = SigHashCache::new(&recomposed_tx).signature_hash(
            0,
            &redeemscript,
            htlc_amount_sat,
            SigHashType::All,
        );

        if recomposed_tx_sighash != original_tx_sighash {
            let (revocation_key, contest_delay, delayed_pubkey) =
                parse_revokeable_redeemscript(output_witscript, setup.option_anchor_outputs())
                    .unwrap_or_else(|_| (vec![], 0, vec![]));
            debug!(
                "ORIGINAL_TX={:#?}\n\
                     output witscript params: [\n\
                     \x20  revocation_pubkey: {},\n\
                     \x20  to_self_delay: {},\n\
                     \x20  delayed_pubkey: {},\n\
                     ]",
                &tx,
                revocation_key.to_hex(),
                contest_delay,
                delayed_pubkey.to_hex()
            );
            debug!(
                "RECOMPOSED_TX={:#?}\n\
                     output witscript params: [\n\
                     \x20  revocation_pubkey: {},\n\
                     \x20  to_self_delay: {},\n\
                     \x20  delayed_pubkey: {},\n\
                     ]",
                &recomposed_tx,
                &txkeys.revocation_key,
                to_self_delay,
                &txkeys.broadcaster_delayed_payment_key
            );
            return Err(policy_error("sighash mismatch".to_string()));
        }

        // The sighash comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-v1-htlc-version
        // - policy-v1-htlc-locktime (for received HTLC)
        // - policy-v1-htlc-nsequence
        // - policy-v1-htlc-to-self-delay
        // - policy-v1-htlc-revocation-pubkey
        // - policy-v1-htlc-payment-pubkey

        Ok((feerate_per_kw, htlc, recomposed_tx_sighash))
    }

    fn validate_htlc_tx(
        &self,
        _setup: &ChannelSetup,
        _state: &ValidatorState,
        _is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError> {
        // This must be further checked with policy-v2-htlc-cltv-range.
        // Note that we can't check cltv_expiry for non-offered 2nd level
        // HTLC txs in phase 1, because they don't mention the cltv_expiry
        // there, only in the commitment tx output.
        // policy-v1-htlc-locktime
        if htlc.offered && htlc.cltv_expiry == 0 {
            return policy_err!("offered lock_time must be non-zero");
        }

        // policy-v1-htlc-fee-range
        if feerate_per_kw < self.policy.min_feerate_per_kw {
            return policy_err!(
                "feerate_per_kw of {} is smaller than the minimum of {}",
                feerate_per_kw,
                self.policy.min_feerate_per_kw
            );
        }
        if feerate_per_kw > self.policy.max_feerate_per_kw {
            return policy_err!(
                "feerate_per_kw of {} is larger than the maximum of {}",
                feerate_per_kw,
                self.policy.max_feerate_per_kw
            );
        }

        Ok(())
    }

    fn validate_funding_tx(
        &self,
        wallet: &Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        _state: &ValidatorState,
        tx: &Transaction,
        values_sat: &Vec<u64>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<(), ValidationError> {
        // policy-v1-funding-fee-range
        let mut sum_inputs: u64 = 0;
        for val in values_sat {
            sum_inputs = sum_inputs
                .checked_add(*val)
                .ok_or_else(|| policy_error(format!("funding sum inputs overflow")))?;
        }
        let mut sum_outputs: u64 = 0;
        for outp in &tx.output {
            sum_outputs = sum_outputs
                .checked_add(outp.value)
                .ok_or_else(|| policy_error(format!("funding sum outputs overflow")))?;
        }
        let fee = sum_inputs
            .checked_sub(sum_outputs)
            .ok_or_else(|| policy_error(format!("funding fee overflow")))?;
        self.validate_fee("validate_funding_tx", fee, tx)?;

        // policy-v1-funding-format-standard
        if tx.version != 2 {
            return policy_err!("invalid version: {}", tx.version);
        }

        for outndx in 0..tx.output.len() {
            let output = &tx.output[outndx];
            let opath = &opaths[outndx];
            let channel_slot = channels[outndx].as_ref();

            // policy-v1-funding-output-match-commitment
            // policy-v2-funding-change-to-wallet
            // All outputs must either be wallet (change) or channel funding.
            if opath.len() > 0 {
                let spendable = wallet
                    .can_spend(opath, &output.script_pubkey)
                    .map_err(|err| {
                        policy_error(format!(
                            "output[{}]: wallet_can_spend error: {}",
                            outndx, err
                        ))
                    })?;
                if !spendable {
                    return policy_err!("wallet cannot spend output[{}]", outndx);
                }
            } else {
                let slot = channel_slot.ok_or_else(|| {
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: outndx as u32,
                    };
                    policy_error(format!("unknown output: {}", outpoint))
                })?;
                match &*slot.lock().unwrap() {
                    ChannelSlot::Ready(chan) => {
                        // policy-v1-funding-output-match-commitment
                        if output.value != chan.setup.channel_value_sat {
                            return policy_err!(
                                "funding output amount mismatch w/ channel: {} != {}",
                                output.value,
                                chan.setup.channel_value_sat
                            );
                        }

                        // policy-v1-funding-output-scriptpubkey
                        let funding_redeemscript = make_funding_redeemscript(
                            &chan.keys.pubkeys().funding_pubkey,
                            &chan.keys.counterparty_pubkeys().funding_pubkey,
                        );
                        let script_pubkey =
                            payload_for_p2wsh(&funding_redeemscript).script_pubkey();
                        if output.script_pubkey != script_pubkey {
                            return policy_err!(
                                "funding script_pubkey mismatch w/ channel: {} != {}",
                                output.script_pubkey,
                                script_pubkey
                            );
                        }

                        // policy-v1-funding-initial-commitment-countersigned
                        if chan.enforcement_state.next_holder_commit_num != 1 {
                            return policy_err!("initial holder commitment not validated",);
                        }
                    }
                    _ => panic!("this can't happen"),
                };
            }
        }
        Ok(())
    }

    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        tx: &Transaction,
        wallet_paths: &Vec<Vec<u32>>,
    ) -> Result<Transaction, ValidationError> {
        debug!("{}: setup:\n{:#?}", short_function!(), setup);
        debug!("{}: estate:\n{:#?}", short_function!(), estate);
        debug!("{}: tx:\n{:#?}", short_function!(), tx);
        debug!("{}: wallet_paths:\n{:#?}", short_function!(), wallet_paths);

        if tx.output.len() > 2 {
            return transaction_format_err!("invalid number of outputs: {}", tx.output.len(),);
        }

        // The caller checked, this shouldn't happen
        assert_eq!(wallet_paths.len(), tx.output.len());

        if estate.current_holder_commit_info.is_none() {
            return policy_err!("current_holder_commit_info missing");
        }
        if estate.current_counterparty_commit_info.is_none() {
            return policy_err!("current_counterparty_commit_info missing");
        }

        // Establish which output belongs to the holder by trying all possibilities

        // Guess which ordering is most likely based on commitment values.
        // - Makes it unlikely we'll have to call validate a second time.
        // - Allows us to return the "better" validation error.

        #[derive(Debug)]
        struct ValidateArgs {
            to_holder_value_sat: u64,
            to_counterparty_value_sat: u64,
            holder_script: Option<Script>,
            counterparty_script: Option<Script>,
            wallet_path: Vec<u32>,
        }

        // If the commitments are not in the expected state, or the values
        // are outside epsilon from each other the comparison won't be
        // meaningful and an arbitrary order will have to do ...
        //
        let holder_value = estate.minimum_to_holder_value(self.policy.epsilon_sat);
        let cparty_value = estate.minimum_to_counterparty_value(self.policy.epsilon_sat);
        debug!(
            "holder_value={:#?}, cparty_value={:#?}",
            holder_value, cparty_value
        );
        let holder_value_is_larger = holder_value > cparty_value;
        debug!("holder_value_is_larger={}", holder_value_is_larger);

        let (likely_args, unlikely_args) = if tx.output.len() == 1 {
            let holders_output = ValidateArgs {
                to_holder_value_sat: tx.output[0].value,
                to_counterparty_value_sat: 0,
                holder_script: Some(tx.output[0].script_pubkey.clone()),
                counterparty_script: None,
                wallet_path: wallet_paths[0].clone(),
            };
            let cpartys_output = ValidateArgs {
                to_holder_value_sat: 0,
                to_counterparty_value_sat: tx.output[0].value,
                holder_script: None,
                counterparty_script: Some(tx.output[0].script_pubkey.clone()),
                wallet_path: vec![],
            };
            if holder_value_is_larger {
                debug!("{}: likely the holder's output", short_function!());
                (holders_output, cpartys_output)
            } else {
                debug!("{}: likely the counterparty's output", short_function!());
                (cpartys_output, holders_output)
            }
        } else {
            let holder_first = ValidateArgs {
                to_holder_value_sat: tx.output[0].value,
                to_counterparty_value_sat: tx.output[1].value,
                holder_script: Some(tx.output[0].script_pubkey.clone()),
                counterparty_script: Some(tx.output[1].script_pubkey.clone()),
                wallet_path: wallet_paths[0].clone(),
            };
            let cparty_first = ValidateArgs {
                to_holder_value_sat: tx.output[1].value,
                to_counterparty_value_sat: tx.output[0].value,
                holder_script: Some(tx.output[1].script_pubkey.clone()),
                counterparty_script: Some(tx.output[0].script_pubkey.clone()),
                wallet_path: wallet_paths[1].clone(),
            };
            if holder_value_is_larger {
                debug!(
                    "{}: likely output[0] is counterparty, output[1] is holder",
                    short_function!()
                );
                (cparty_first, holder_first)
            } else {
                debug!(
                    "{}: likely output[0] is holder, output[1] is counterparty",
                    short_function!()
                );
                (holder_first, cparty_first)
            }
        };

        debug!(
            "{}: trying likely args: {:#?}",
            short_function!(),
            &likely_args
        );
        let likely_rv = self.validate_mutual_close_tx(
            wallet,
            setup,
            estate,
            likely_args.to_holder_value_sat,
            likely_args.to_counterparty_value_sat,
            &likely_args.holder_script,
            &likely_args.counterparty_script,
            &likely_args.wallet_path,
        );

        let good_args = if likely_rv.is_ok() {
            likely_args
        } else {
            // Try the other case
            debug!(
                "{}: trying unlikely args: {:#?}",
                short_function!(),
                &unlikely_args
            );
            let unlikely_rv = self.validate_mutual_close_tx(
                wallet,
                setup,
                estate,
                unlikely_args.to_holder_value_sat,
                unlikely_args.to_counterparty_value_sat,
                &unlikely_args.holder_script,
                &unlikely_args.counterparty_script,
                &unlikely_args.wallet_path,
            );
            if unlikely_rv.is_ok() {
                unlikely_args
            } else {
                // Return the error from the likely attempt, it's probably "better"
                return Err(likely_rv.unwrap_err());
            }
        };

        let recomposed_tx = build_close_tx(
            good_args.to_holder_value_sat,
            good_args.to_counterparty_value_sat,
            &good_args.holder_script,
            &good_args.counterparty_script,
            setup.funding_outpoint,
        )?;

        if recomposed_tx != *tx {
            debug!("ORIGINAL_TX={:#?}", &tx);
            debug!("RECOMPOSED_TX={:#?}", &recomposed_tx);
            return policy_err!("recomposed tx mismatch");
        }

        Ok(recomposed_tx)
    }

    fn validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<Script>,
        counterparty_script: &Option<Script>,
        holder_wallet_path_hint: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        debug!("{}: estate:\n{:#?}", short_function!(), estate);

        let holder_info = estate
            .current_holder_commit_info
            .as_ref()
            .ok_or_else(|| policy_error("current_holder_commit_info missing"))?;

        let counterparty_info = estate
            .current_counterparty_commit_info
            .as_ref()
            .ok_or_else(|| policy_error("current_counterparty_commit_info missing"))?;

        if to_holder_value_sat > 0 && holder_script.is_none() {
            return policy_err!(
                "missing holder_script with {} to_holder_value_sat",
                to_holder_value_sat
            );
        }

        if to_counterparty_value_sat > 0 && counterparty_script.is_none() {
            return policy_err!(
                "missing counterparty_script with {} to_counterparty_value_sat",
                to_counterparty_value_sat
            );
        }

        // If the upfront holder_shutdown_script was in effect, make sure the
        // holder script matches.
        if setup.holder_shutdown_script.is_some() && to_holder_value_sat > 0 {
            if *holder_script != setup.holder_shutdown_script {
                return policy_err!("holder_script doesn't match upfront holder_shutdown_script");
            }
        }

        // policy-v2-mutual-no-pending-htlcs
        if !holder_info.htlcs_is_empty() || !counterparty_info.htlcs_is_empty() {
            return policy_err!("cannot close with pending htlcs");
        }

        // policy-v2-mutual-fee-range
        let consumed = to_holder_value_sat
            .checked_add(to_counterparty_value_sat)
            .ok_or_else(|| policy_error("consumed overflow".to_string()))?;
        let fee = setup
            .channel_value_sat
            .checked_sub(consumed)
            .ok_or_else(|| {
                policy_error(format!(
                    "mutual_close_tx: fee underflow: {} - {}",
                    setup.channel_value_sat, consumed
                ))
            })?;
        if fee > self.policy.max_fee {
            return policy_err!("fee too large {} > {}", fee, self.policy.max_fee);
        }
        if fee < self.policy.min_fee {
            return policy_err!("fee too small {} < {}", fee, self.policy.min_fee);
        }

        // policy-v2-mutual-value-matches-commitment
        if let (true, descr) =
            self.outside_epsilon_range(to_holder_value_sat, holder_info.to_broadcaster_value_sat)
        {
            return policy_err!(
                "to_holder_value {} is {} than holder_info.broadcaster_value_sat {}",
                to_holder_value_sat,
                descr,
                holder_info.to_broadcaster_value_sat
            );
        }
        if let (true, descr) = self.outside_epsilon_range(
            to_holder_value_sat,
            counterparty_info.to_countersigner_value_sat,
        ) {
            return policy_err!(
                "to_holder_value {} is {} than counterparty_info.countersigner_value_sat {}",
                to_holder_value_sat,
                descr,
                counterparty_info.to_countersigner_value_sat
            );
        }

        // policy-v2-mutual-destination-allowlisted
        if let Some(script) = &holder_script {
            if !wallet
                .can_spend(holder_wallet_path_hint, script)
                .map_err(|err| policy_error(format!("wallet can_spend error: {}", err)))?
                && !wallet.allowlist_contains(script)
            {
                return policy_err!("holder output not to wallet or in allowlist");
            }
        }

        Ok(())
    }
}

/// Construct a default simple policy
pub fn make_simple_policy(network: Network) -> SimplePolicy {
    if network == Network::Bitcoin {
        SimplePolicy {
            min_delay: 60,
            max_delay: 1440,
            max_channel_size_sat: 1_000_000_001,
            max_push_sat: 0,
            epsilon_sat: 1_600_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216,
            use_chain_state: false,
            min_feerate_per_kw: 1000,
            max_feerate_per_kw: 1000 * 1000,
            min_fee: 100,
            max_fee: 1000,
        }
    } else {
        SimplePolicy {
            min_delay: 4,
            max_delay: 1440,
            max_channel_size_sat: 1_000_000_001, // lnd itest: wumbu default + 1
            max_push_sat: 20_000,
            // lnd itest: async_bidirectional_payments (large amount of dust HTLCs) 1_600_000
            epsilon_sat: 79641, // c-lighting integration
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216, // lnd itest: multi-hop_htlc_error_propagation
            use_chain_state: false,
            min_feerate_per_kw: 500,    // c-lightning integration
            max_feerate_per_kw: 16_000, // c-lightning integration
            min_fee: 100,
            max_fee: 21_000, // c-lightning integration 21000
        }
    }
}

/// Enforcement state for a signer
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
    pub mutual_close_signed: bool,
}

impl EnforcementState {
    /// Create state for a new channel
    pub fn new() -> EnforcementState {
        EnforcementState {
            next_holder_commit_num: 0,
            next_counterparty_commit_num: 0,
            next_counterparty_revoke_num: 0,
            current_counterparty_point: None,
            previous_counterparty_point: None,
            current_holder_commit_info: None,
            current_counterparty_commit_info: None,
            previous_counterparty_commit_info: None,
            mutual_close_signed: false,
        }
    }

    /// Returns the minimum amount to_holder from both commitments or
    /// None if the amounts are not within epsilon_sat.
    pub fn minimum_to_holder_value(&self, epsilon_sat: u64) -> Option<u64> {
        if let Some(hinfo) = &self.current_holder_commit_info {
            if let Some(cinfo) = &self.current_counterparty_commit_info {
                let hval = hinfo.to_broadcaster_value_sat;
                let cval = cinfo.to_countersigner_value_sat;
                debug!("hval={}, cval={}", hval, cval);
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
    pub fn set_next_holder_commit_num(
        &mut self,
        num: u64,
        current_commitment_info: CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        let current = self.next_holder_commit_num;
        if num != current && num != current + 1 {
            return policy_err!("invalid progression: {} to {}", current, num);
        }
        // TODO - should we enforce policy-v1-commitment-retry-same here?
        debug!("next_holder_commit_num {} -> {}", current, num);
        self.next_holder_commit_num = num;
        self.current_holder_commit_info = Some(current_commitment_info);
        Ok(())
    }

    /// Set next counterparty commitment number
    pub fn set_next_counterparty_commit_num(
        &mut self,
        num: u64,
        current_point: PublicKey,
        current_commitment_info: CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        if num == 0 {
            return policy_err!("can't set next to 0");
        }

        // The initial commitment is special, it can advance even though next_revoke is 0.
        let delta = if num == 1 { 1 } else { 2 };

        // Ensure that next_commit is ok relative to next_revoke
        if num < self.next_counterparty_revoke_num + delta {
            return policy_err!(
                "{} too small relative to next_counterparty_revoke_num {}",
                num,
                self.next_counterparty_revoke_num
            );
        }
        if num > self.next_counterparty_revoke_num + 2 {
            return policy_err!(
                "{} too large relative to next_counterparty_revoke_num {}",
                num,
                self.next_counterparty_revoke_num
            );
        }

        let current = self.next_counterparty_commit_num;
        if num == current {
            // This is a retry.
            assert!(
                self.current_counterparty_point.is_some(),
                "retry {}: current_counterparty_point not set, this shouldn't be possible",
                num
            );
            // policy-v2-commitment-retry-same (FIXME - not currently in policy-controls.md)
            // FIXME - need to compare current_commitment_info with current_counterparty_commit_info
            if current_point != self.current_counterparty_point.unwrap() {
                debug!(
                    "current_point {} != prior {}",
                    current_point,
                    self.current_counterparty_point.unwrap()
                );
                return policy_err!("retry {}: point different than prior", num);
            }
        } else if num == current + 1 {
            self.previous_counterparty_point = self.current_counterparty_point;
            self.previous_counterparty_commit_info = self.current_counterparty_commit_info.take();
            self.current_counterparty_point = Some(current_point);
            self.current_counterparty_commit_info = Some(current_commitment_info);
        } else {
            return policy_err!("invalid progression: {} to {}", current, num);
        }

        self.next_counterparty_commit_num = num;
        debug!(
            "next_counterparty_commit_num {} -> {} current {}",
            current, num, current_point
        );
        Ok(())
    }

    /// Previous counterparty commitment point
    pub fn get_previous_counterparty_point(&self, num: u64) -> Result<PublicKey, ValidationError> {
        let point = if num + 1 == self.next_counterparty_commit_num {
            &self.current_counterparty_point
        } else if num + 2 == self.next_counterparty_commit_num {
            &self.previous_counterparty_point
        } else {
            return policy_err!(
                "{} out of range, next is {}",
                num,
                self.next_counterparty_commit_num
            );
        }
        .unwrap_or_else(|| {
            panic!(
                "counterparty point for commit_num {} not set, \
                 next_commitment_number is {}",
                num, self.next_counterparty_commit_num
            );
        });
        Ok(point)
    }

    /// Set next counterparty revoked commitment number
    pub fn set_next_counterparty_revoke_num(&mut self, num: u64) -> Result<(), ValidationError> {
        if num == 0 {
            return policy_err!("can't set next to 0");
        }

        // Ensure that next_revoke is ok relative to next_commit.
        if num + 2 < self.next_counterparty_commit_num {
            return policy_err!(
                "{} too small relative to next_counterparty_commit_num {}",
                num,
                self.next_counterparty_commit_num
            );
        }
        if num + 1 > self.next_counterparty_commit_num {
            return policy_err!(
                "{} too large relative to next_counterparty_commit_num {}",
                num,
                self.next_counterparty_commit_num
            );
        }

        let current = self.next_counterparty_revoke_num;
        if num != current && num != current + 1 {
            return policy_err!("invalid progression: {} to {}", current, num);
        }

        // Remove any revoked commitment state.
        if num + 1 == self.next_counterparty_commit_num {
            // We can't remove the previous_counterparty_point, needed for retries.
            self.previous_counterparty_commit_info = None;
        }

        self.next_counterparty_revoke_num = num;
        debug!("next_counterparty_revoke_num {} -> {}", current, num);
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use lightning::ln::PaymentHash;
    use test_env_log::test;

    use crate::tx::tx::HTLCInfo2;
    use crate::util::test_utils::*;

    use super::*;

    fn make_test_validator() -> SimpleValidator {
        let policy = SimplePolicy {
            min_delay: 5,
            max_delay: 1440,
            max_channel_size_sat: 100_000_000,
            max_push_sat: 0,
            epsilon_sat: 100_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 10_000_000,
            use_chain_state: true,
            min_feerate_per_kw: 1000,
            max_feerate_per_kw: 1000 * 1000,
            min_fee: 100,
            max_fee: 1000,
        };

        SimpleValidator { policy }
    }

    #[test]
    fn make_info_test() {
        let validator = make_test_validator();
        let info = validator
            .make_info(
                &make_test_channel_keys(),
                &make_test_channel_setup(),
                true,
                &make_test_commitment_tx(),
                &vec![vec![]],
            )
            .unwrap();
        assert_eq!(info.is_counterparty_broadcaster, true);
    }

    #[test]
    fn validate_policy_commitment_version() {
        let validator = make_test_validator();
        let mut tx = make_test_commitment_tx();
        tx.version = 1;
        let res = validator.make_info(
            &make_test_channel_keys(),
            &make_test_channel_setup(),
            true,
            &tx,
            &vec![vec![]],
        );
        assert_policy_err!(res, "make_info: bad commitment version: 1");
    }

    #[test]
    fn validate_channel_value_test() {
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.channel_value_sat = 100_000_000;
        assert!(validator.validate_channel_value(&setup).is_ok());
        setup.channel_value_sat = 100_000_001;
        assert!(validator.validate_channel_value(&setup).is_err());
    }

    #[test]
    fn validate_channel_open_bad_push_val() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.push_value_msat = 0;
        assert!(validator
            .validate_ready_channel(&*node, &setup, &vec![])
            .is_ok());
        setup.push_value_msat = 1000;
        assert_policy_err!(
            validator.validate_ready_channel(&*node, &setup, &vec![]),
            "validate_ready_channel: push_value_msat 1000 greater than max_push_sat 0"
        );
    }

    fn make_counterparty_info(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        to_self_delay: u16,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> CommitmentInfo2 {
        let to_holder_pubkey = make_test_pubkey(1);
        let revocation_pubkey = make_test_pubkey(2);
        let to_broadcaster_delayed_pubkey = make_test_pubkey(3);
        CommitmentInfo2 {
            is_counterparty_broadcaster: true,
            to_countersigner_pubkey: to_holder_pubkey,
            to_countersigner_value_sat: to_holder_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey: to_broadcaster_delayed_pubkey,
            to_broadcaster_value_sat: to_counterparty_value_sat,
            to_self_delay,
            offered_htlcs,
            received_htlcs,
        }
    }

    fn make_test_validator_state() -> ValidatorState {
        ValidatorState {
            current_height: 1000,
        }
    }

    fn make_htlc_info2(expiry: u32) -> HTLCInfo2 {
        HTLCInfo2 {
            value_sat: 10,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: expiry,
        }
    }

    #[test]
    fn validate_commitment_tx_test() {
        let validator = make_test_validator();
        let mut enforcement_state = EnforcementState::new();
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let vstate = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info = make_counterparty_info(2_000_000, 900_000, delay, vec![], vec![]);
        assert!(validator
            .validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &vstate,
                &info,
            )
            .is_ok());
    }

    // policy-v1-commitment-to-self-delay-range
    #[test]
    fn validate_to_holder_min_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.holder_selected_contest_delay = 5;
        assert!(validator
            .validate_ready_channel(&*node, &setup, &vec![])
            .is_ok());
        setup.holder_selected_contest_delay = 4;
        assert_policy_err!(
            validator.validate_ready_channel(&*node, &setup, &vec![]),
            "validate_delay: holder_selected_contest_delay too small"
        );
    }

    // policy-v1-commitment-to-self-delay-range
    #[test]
    fn validate_to_holder_max_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.holder_selected_contest_delay = 1440;
        assert!(validator
            .validate_ready_channel(&*node, &setup, &vec![])
            .is_ok());
        setup.holder_selected_contest_delay = 1441;
        assert_policy_err!(
            validator.validate_ready_channel(&*node, &setup, &vec![]),
            "validate_delay: holder_selected_contest_delay too large"
        );
    }

    // policy-v1-commitment-to-self-delay-range
    #[test]
    fn validate_to_counterparty_min_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.counterparty_selected_contest_delay = 5;
        assert!(validator
            .validate_ready_channel(&*node, &setup, &vec![])
            .is_ok());
        setup.counterparty_selected_contest_delay = 4;
        assert_policy_err!(
            validator.validate_ready_channel(&*node, &setup, &vec![]),
            "validate_delay: counterparty_selected_contest_delay too small"
        );
    }

    // policy-v1-commitment-to-self-delay-range
    #[test]
    fn validate_to_counterparty_max_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.counterparty_selected_contest_delay = 1440;
        assert!(validator
            .validate_ready_channel(&*node, &setup, &vec![])
            .is_ok());
        setup.counterparty_selected_contest_delay = 1441;
        assert_policy_err!(
            validator.validate_ready_channel(&*node, &setup, &vec![]),
            "validate_delay: counterparty_selected_contest_delay too large"
        );
    }

    #[test]
    fn validate_commitment_tx_shortage_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new();
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info_bad = make_counterparty_info(2_000_000, 900_000 - 1, delay, vec![], vec![]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "validate_commitment_tx: channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_shortage_test() {
        let validator = make_test_validator();
        let htlc = HTLCInfo2 {
            value_sat: 100_000,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: 1005,
        };
        let mut enforcement_state = EnforcementState::new();
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info = make_counterparty_info(2_000_000, 800_000, delay, vec![htlc.clone()], vec![]);

        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &state,
            &info,
        );
        assert!(status.is_ok());
        let info_bad =
            make_counterparty_info(2_000_000, 800_000 - 1, delay, vec![htlc.clone()], vec![]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "validate_commitment_tx: channel value short by 100001 > 100000"
        );
    }

    #[test]
    fn validate_commitment_tx_initial_with_htlcs() {
        let validator = make_test_validator();
        let htlc = HTLCInfo2 {
            value_sat: 100_000,
            payment_hash: PaymentHash([0; 32]),
            cltv_expiry: 1005,
        };
        let enforcement_state = EnforcementState::new();
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info = make_counterparty_info(2_000_000, 800_000, delay, vec![htlc.clone()], vec![]);

        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &state,
            &info,
        );
        assert_policy_err!(
            status,
            "validate_commitment_tx: initial commitment may not have HTLCS"
        );
    }

    // policy-v2-commitment-initial-funding-value
    #[test]
    fn validate_commitment_tx_initial_with_bad_fundee_output() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new();
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info = make_counterparty_info(2_000_000, 950_000, delay, vec![], vec![]);

        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &state,
            &info,
        );
        assert_policy_err!(
            status,
            "validate_commitment_tx: initial commitment may only send push_value_msat (0) to fundee"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_count_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new();
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let htlcs = (0..1001).map(|_| make_htlc_info2(1100)).collect();
        let delay = setup.holder_selected_contest_delay;
        let info_bad = make_counterparty_info(99_000_000, 900_000, delay, vec![], htlcs);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "too many HTLCs"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_value_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new();
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let htlcs = (0..1000)
            .map(|_| HTLCInfo2 {
                value_sat: 10001,
                payment_hash: PaymentHash([0; 32]),
                cltv_expiry: 1100,
            })
            .collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, delay, vec![], htlcs);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "validate_commitment_tx: sum of HTLC values 10001000 too large"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_delay_test() {
        let validator = make_test_validator();
        let mut enforcement_state = EnforcementState::new();
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let state = make_test_validator_state();
        let setup = make_test_channel_setup();
        let delay = setup.holder_selected_contest_delay;
        let info_good = make_counterparty_info(
            2_000_000,
            990_000,
            delay,
            vec![],
            vec![make_htlc_info2(1005)],
        );
        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &state,
            &info_good,
        );
        assert!(status.is_ok());
        let info_good = make_counterparty_info(
            2_000_000,
            990_000,
            delay,
            vec![],
            vec![make_htlc_info2(2440)],
        );
        assert!(validator
            .validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_good,
            )
            .is_ok());
        let info_bad = make_counterparty_info(
            2_000_000,
            990_000,
            delay,
            vec![],
            vec![make_htlc_info2(1004)],
        );
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "validate_expiry: received HTLC expiry too early"
        );
        let info_bad = make_counterparty_info(
            2_000_000,
            990_000,
            delay,
            vec![],
            vec![make_htlc_info2(2441)],
        );
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &state,
                &info_bad,
            ),
            "validate_expiry: received HTLC expiry too late"
        );
    }

    #[test]
    fn enforcement_state_previous_counterparty_point_test() {
        let mut state = EnforcementState::new();

        let point0 = make_test_pubkey(0x12);
        let commit_info = make_test_commitment_info();

        // you can never set next to 0
        assert_policy_err!(
            state.set_next_counterparty_commit_num(0, point0.clone(), commit_info.clone()),
            "set_next_counterparty_commit_num: can\'t set next to 0"
        );

        // point for 0 is not set yet
        assert_policy_err!(
            state.get_previous_counterparty_point(0),
            "get_previous_counterparty_point: 0 out of range, next is 0"
        );

        // can't look forward either
        assert_policy_err!(
            state.get_previous_counterparty_point(1),
            "get_previous_counterparty_point: 1 out of range, next is 0"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(2, point0.clone(), commit_info.clone()),
            "set_next_counterparty_commit_num: invalid progression: 0 to 2"
        );

        // set point 0
        assert!(state
            .set_next_counterparty_commit_num(1, point0.clone(), commit_info.clone())
            .is_ok());

        // and now you can get it.
        assert_eq!(
            state.get_previous_counterparty_point(0).unwrap(),
            point0.clone()
        );

        // you can set it again to the same thing (retry)
        // policy-v2-commitment-retry-same
        assert!(state
            .set_next_counterparty_commit_num(1, point0.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 1);

        // but setting it to something else is an error
        // policy-v2-commitment-retry-same
        let point1 = make_test_pubkey(0x16);
        assert_policy_err!(
            state.set_next_counterparty_commit_num(1, point1.clone(), commit_info.clone()),
            "set_next_counterparty_commit_num: retry 1: point different than prior"
        );
        assert_eq!(state.next_counterparty_commit_num, 1);

        // can't get commit_num 1 yet
        assert_policy_err!(
            state.get_previous_counterparty_point(1),
            "get_previous_counterparty_point: 1 out of range, next is 1"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(3, point1.clone(), commit_info.clone()),
            "set_next_counterparty_commit_num: \
             3 too large relative to next_counterparty_revoke_num 0"
        );
        assert_eq!(state.next_counterparty_commit_num, 1);

        // set point 1
        assert!(state
            .set_next_counterparty_commit_num(2, point1.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 2);

        // you can still get commit_num 0
        assert_eq!(
            state.get_previous_counterparty_point(0).unwrap(),
            point0.clone()
        );

        // Now you can get commit_num 1
        assert_eq!(
            state.get_previous_counterparty_point(1).unwrap(),
            point1.clone()
        );

        // can't look forward
        assert_policy_err!(
            state.get_previous_counterparty_point(2),
            "get_previous_counterparty_point: 2 out of range, next is 2"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(4, point1.clone(), commit_info.clone()),
            "set_next_counterparty_commit_num: 4 too large \
             relative to next_counterparty_revoke_num 0"
        );
        assert_eq!(state.next_counterparty_commit_num, 2);

        assert!(state.set_next_counterparty_revoke_num(1).is_ok());

        // set point 2
        let point2 = make_test_pubkey(0x20);
        assert!(state
            .set_next_counterparty_commit_num(3, point2.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 3);

        // You can't get commit_num 0 anymore
        assert_policy_err!(
            state.get_previous_counterparty_point(0),
            "get_previous_counterparty_point: 0 out of range, next is 3"
        );

        // you can still get commit_num 1
        assert_eq!(
            state.get_previous_counterparty_point(1).unwrap(),
            point1.clone()
        );

        // now you can get commit_num 2
        assert_eq!(
            state.get_previous_counterparty_point(2).unwrap(),
            point2.clone()
        );

        // can't look forward
        assert_policy_err!(
            state.get_previous_counterparty_point(3),
            "get_previous_counterparty_point: 3 out of range, next is 3"
        );
    }
}
