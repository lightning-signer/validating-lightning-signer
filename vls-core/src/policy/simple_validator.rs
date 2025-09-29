use bitcoin::absolute::{Height, Time};
use bitcoin::bip32::DerivationPath;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SegwitV0Sighash, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction};
use lightning::ln::chan_utils::{
    build_htlc_transaction, htlc_success_tx_weight, htlc_timeout_tx_weight,
    make_funding_redeemscript, ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::sign::{ChannelSigner, InMemorySigner};
use lightning::types::payment::PaymentHash;
use log::*;
use serde::Deserialize;
use vls_common::HexEncode;
use vls_policy_derive::Optionized;

use super::error::{
    policy_error, transaction_format_error, unknown_destinations_error, ValidationError,
};
use super::filter::{FilterResult, PolicyFilter};
use super::validator::EnforcementState;
use super::validator::{ChainState, Validator, ValidatorFactory};
use super::{
    policy_error_with_filter, Policy, DEFAULT_FEE_VELOCITY_CONTROL, MAX_CHANNELS, MAX_INVOICES,
    MAX_ONCHAIN_TX_SIZE,
};
use crate::channel::{ChannelId, ChannelSetup, ChannelSlot, CommitmentType};
use crate::policy::temporary_policy_error_with_filter;
use crate::prelude::*;
use crate::tx::tx::{
    parse_offered_htlc_script, parse_received_htlc_script, parse_revokeable_redeemscript,
    CommitmentInfo, CommitmentInfo2,
};
use crate::util::debug_utils::{
    script_debug, DebugHTLCOutputInCommitment, DebugInMemorySigner, DebugTxCreationKeys,
    DebugVecVecU8,
};
use crate::util::transaction_utils::{
    estimate_feerate_per_kw, expected_commitment_tx_weight, is_tx_non_malleable,
    mutual_close_tx_weight, MIN_CHAN_DUST_LIMIT_SATOSHIS, MIN_DUST_LIMIT_SATOSHIS,
};
use crate::util::velocity::VelocityControlSpec;
use crate::wallet::Wallet;

extern crate scopeguard;

const SAFE_COMMITMENT_TYPE: &[CommitmentType] =
    &[CommitmentType::StaticRemoteKey, CommitmentType::AnchorsZeroFeeHtlc];

const MAX_CHAIN_LAG: u32 = 2;

/// A factory for SimpleValidator
pub struct SimpleValidatorFactory {
    pub(crate) policy: Option<SimplePolicy>,
}

impl SimpleValidatorFactory {
    /// Create a new simple validator factory with default policy settings
    pub fn new() -> Self {
        SimpleValidatorFactory { policy: None }
    }

    /// Create a new simple validator factory with a specified policy
    pub fn new_with_policy(policy: SimplePolicy) -> Self {
        SimpleValidatorFactory { policy: Some(policy) }
    }
}

impl ValidatorFactory for SimpleValidatorFactory {
    fn make_validator(
        &self,
        network: Network,
        node_id: PublicKey,
        channel_id: Option<ChannelId>,
    ) -> Arc<dyn Validator> {
        let validator = SimpleValidator {
            policy: self.policy.clone().unwrap_or_else(|| make_default_simple_policy(network)),
            node_id,
            channel_id,
        };

        Arc::new(validator)
    }

    fn policy(&self, network: Network) -> Box<dyn Policy> {
        Box::new(self.policy.clone().unwrap_or_else(|| make_default_simple_policy(network)))
    }
}

/// A simple policy to configure a SimpleValidator
#[derive(Clone, Debug, Optionized, Deserialize)]
pub struct SimplePolicy {
    /// Minimum delay in blocks
    pub min_delay: u16,
    /// Maximum delay in blocks
    pub max_delay: u16,
    /// Maximum channel value in satoshi
    pub max_channel_size_sat: u64,
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
    /// Enforce holder balance
    pub enforce_balance: bool,
    /// Maximum layer-2 fee
    pub max_routing_fee_msat: u64,
    /// Maximum layer-2 percentage fee, this is setting
    /// up the max fee percentage to pay for a payment.
    pub max_feerate_percentage: u8,
    /// Developer flags - DO NOT USE IN PRODUCTION
    pub dev_flags: Option<PolicyDevFlags>,
    /// Policy filter
    pub filter: PolicyFilter,
    /// Global velocity control specification
    pub global_velocity_control: VelocityControlSpec,
    /// Maximum number of channels
    pub max_channels: usize,
    /// Maximum number of invoices
    pub max_invoices: usize,
    /// Fee velocity control specification
    pub fee_velocity_control: VelocityControlSpec,
}

impl Policy for SimplePolicy {
    fn policy_error(&self, tag: String, msg: String) -> Result<(), ValidationError> {
        policy_error_with_filter(tag, msg, &self.filter)
    }

    fn temporary_policy_error(&self, tag: String, msg: String) -> Result<(), ValidationError> {
        temporary_policy_error_with_filter(tag, msg, &self.filter)
    }

    fn policy_log(&self, tag: String, msg: String) {
        if self.filter.filter(&tag) == FilterResult::Error {
            error!("{}", msg);
        } else {
            warn!("{}", msg);
        }
    }

    fn global_velocity_control(&self) -> VelocityControlSpec {
        self.global_velocity_control
    }

    fn max_channels(&self) -> usize {
        self.max_channels
    }

    fn max_invoices(&self) -> usize {
        self.max_invoices
    }

    fn fee_velocity_control(&self) -> VelocityControlSpec {
        self.fee_velocity_control
    }
}

/// Development flags included in SimplePolicy
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyDevFlags {
    /// Allow sending to unknown destinations
    pub disable_beneficial_balance_checks: bool,
}

const DEFAULT_DEV_FLAGS: PolicyDevFlags =
    PolicyDevFlags { disable_beneficial_balance_checks: false };

impl Default for PolicyDevFlags {
    fn default() -> Self {
        DEFAULT_DEV_FLAGS
    }
}

/// A simple validator.
/// See [`SimpleValidatorFactory`] for construction
pub struct SimpleValidator {
    policy: SimplePolicy,
    node_id: PublicKey,
    channel_id: Option<ChannelId>,
}

impl SimpleValidator {
    const ANCHOR_SEQS: [u32; 1] = [0x_0000_0001];
    const NON_ANCHOR_SEQS: [u32; 3] = [0x_0000_0000_u32, 0x_ffff_fffd_u32, 0x_ffff_ffff_u32];

    fn log_prefix(&self) -> String {
        let short_node_id = &self.node_id.to_string()[0..4];
        let short_channel_id = self
            .channel_id
            .as_ref()
            .map(|c| c.as_slice()[0..4].to_vec().to_hex())
            .unwrap_or("".to_string());
        format!("{}/{}", short_node_id, short_channel_id)
    }

    fn validate_delay(&self, name: &str, delay: u32) -> Result<(), ValidationError> {
        let policy = &self.policy;

        if delay < policy.min_delay as u32 {
            let tag = format!("policy-channel-contest-delay-range-{}", name);
            policy_err!(
                self,
                tag,
                "{} contest-delay too small: {} < {}",
                name,
                delay,
                policy.min_delay
            );
        }
        if delay > policy.max_delay as u32 {
            let tag = format!("policy-channel-contest-delay-range-{}", name);
            policy_err!(
                self,
                tag,
                "{} contest-delay too large: {} > {}",
                name,
                delay,
                policy.max_delay
            );
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
                policy_err!(
                    self,
                    "policy-commitment-htlc-cltv-range",
                    "{} expiry too early: {} < {}",
                    name,
                    expiry,
                    current_height + policy.min_delay as u32
                );
            }
            if expiry > current_height + policy.max_delay as u32 {
                policy_err!(
                    self,
                    "policy-commitment-htlc-cltv-range",
                    "{} expiry too late: {} > {}",
                    name,
                    expiry,
                    current_height + policy.max_delay as u32
                );
            }
        }

        Ok(())
    }

    fn validate_fee(
        &self,
        tag: &str,
        sum_inputs: u64,
        sum_outputs: u64,
        weight: usize,
    ) -> Result<(), ValidationError> {
        let fee = sum_inputs.checked_sub(sum_outputs).ok_or_else(|| {
            policy_error(tag, format!("fee underflow: {} - {}", sum_inputs, sum_outputs))
        })?;
        let feerate_perkw = estimate_feerate_per_kw(fee, weight as u64);
        debug!("validate_fee fee:{} / weight:{} = feerate_perkw:{}", fee, weight, feerate_perkw);
        if feerate_perkw < self.policy.min_feerate_per_kw {
            policy_err!(
                self,
                tag, // also policy-{commitment,mutual}-fee-range
                "feerate below minimum: {} < {}",
                feerate_perkw,
                self.policy.min_feerate_per_kw
            );
        }
        if feerate_perkw > self.policy.max_feerate_per_kw {
            policy_err!(
                self,
                tag, // also policy-{commitment,mutual}-fee-range
                "feerate above maximum: {} > {}",
                feerate_perkw,
                self.policy.max_feerate_per_kw
            );
        }
        Ok(())
    }

    fn validate_beneficial_value(
        &self,
        sum_our_inputs: u64,
        sum_our_outputs: u64,
        weight: usize,
    ) -> Result<u64, ValidationError> {
        let non_beneficial = sum_our_inputs.checked_sub(sum_our_outputs).ok_or_else(|| {
            policy_error(
                "policy-onchain-format-standard",
                format!(
                    "non-beneficial value underflow: sum of our inputs {} < sum of our outputs {}",
                    sum_our_inputs, sum_our_outputs
                ),
            )
        })?;
        let feerate_perkw = estimate_feerate_per_kw(non_beneficial, weight as u64);
        if feerate_perkw > self.policy.max_feerate_per_kw {
            let dev_flags = self.policy.dev_flags.as_ref().unwrap_or(&DEFAULT_DEV_FLAGS);
            if dev_flags.disable_beneficial_balance_checks {
                error!(
                    "DEV IGNORE \
                     non-beneficial value considered as fees is above maximum feerate: {} > {}",
                    feerate_perkw, self.policy.max_feerate_per_kw
                );
            } else {
                policy_err!(
                    self,
                    "policy-onchain-fee-range",
                    "non-beneficial value considered as fees is above maximum feerate: {} > {}",
                    feerate_perkw,
                    self.policy.max_feerate_per_kw
                );
            }
        }
        Ok(non_beneficial)
    }

    fn outside_epsilon_range(&self, value0: u64, value1: u64) -> (bool, String) {
        if value0 > value1 {
            (value0 - value1 > self.policy.epsilon_sat, "larger".to_string())
        } else {
            (value1 - value0 > self.policy.epsilon_sat, "smaller".to_string())
        }
    }

    // Common validation for validate_{delayed,counterparty_htlc,justice}_sweep
    fn validate_sweep(
        &self,
        wallet: &dyn Wallet,
        tx: &Transaction,
        _input: usize,
        _amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        if tx.version != Version::TWO {
            transaction_format_err!(self, "policy-sweep-version", "bad version: {}", tx.version);
        }

        // LDK now provides multi-input txs, and we can't easily validate fees securely
        // TODO(522) Since we see the tx on-chain, we should just get the input amount from there

        // // policy-sweep-fee-range
        // self.validate_fee(amount_sat, tx.output[0].value.to_sat())
        //     .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        for out in tx.output.iter() {
            let dest_script = &out.script_pubkey;
            let spendable = wallet.can_spend(wallet_path, dest_script).map_err(|err| {
                policy_error(
                    "policy-onchain-output-scriptpubkey",
                    format!("wallet can_spend error: {}", err),
                )
            })?;
            if !spendable && !wallet.allowlist_contains(dest_script, wallet_path) {
                info!(
                    "dest_script not matched: path={:?}, {}",
                    wallet_path,
                    script_debug(dest_script, wallet.network())
                );
                policy_err!(
                    self,
                    "policy-sweep-destination-allowlisted",
                    "destination is not in wallet or allowlist"
                );
            }
        }

        Ok(())
    }
}

impl Validator for SimpleValidator {
    fn validate_setup_channel(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return = scoped_debug_return!(setup, holder_shutdown_key_path);

        // NOTE - setup.channel_value_sat is not valid, set later on.

        // policy-channel-safe-type
        if !SAFE_COMMITMENT_TYPE.contains(&setup.commitment_type) {
            policy_err!(
                self,
                "policy-channel-safe-type",
                "unsafe commitment type: {:?}",
                setup.commitment_type
            );
        }

        // policy-channel-contest-delay-range-counterparty
        // policy-commitment-to-self-delay-range relies on this value
        self.validate_delay("holder", setup.counterparty_selected_contest_delay as u32)?;

        // policy-channel-contest-delay-range-holder
        // policy-commitment-to-self-delay-range relies on this value
        self.validate_delay("counterparty", setup.holder_selected_contest_delay as u32)?;

        if let Some(holder_shutdown_script) = &setup.holder_shutdown_script {
            let spendable = wallet
                .can_spend(holder_shutdown_key_path, holder_shutdown_script)
                .map_err(|err| {
                    policy_error(
                        "policy-onchain-output-scriptpubkey",
                        format!("wallet can_spend error: {}", err),
                    )
                })?;
            if !spendable
                && !wallet.allowlist_contains(holder_shutdown_script, holder_shutdown_key_path)
            {
                info!(
                    "holder_shutdown_script not matched: path={:?}, {}",
                    holder_shutdown_key_path,
                    script_debug(holder_shutdown_script, wallet.network())
                );
                policy_err!(
                    self,
                    "policy-mutual-destination-allowlisted",
                    "holder_shutdown_script is not in wallet or allowlist"
                );
            }
        }
        *debug_on_return = false;
        Ok(())
    }

    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        if setup.channel_value_sat > self.policy.max_channel_size_sat {
            policy_err!(
                self,
                "policy-funding-max",
                "channel value {} too large",
                setup.channel_value_sat
            );
        }
        Ok(())
    }

    fn validate_onchain_tx(
        &self,
        wallet: &dyn Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        tx: &Transaction,
        segwit_flags: &[bool],
        values_sat: &[u64],
        opaths: &[DerivationPath],
        weight_lower_bound: usize,
    ) -> Result<u64, ValidationError> {
        let mut debug_on_return = scoped_debug_return!(tx, values_sat, opaths);

        if tx.version != Version::TWO {
            policy_err!(self, "policy-onchain-format-standard", "invalid version: {}", tx.version);
        }

        if tx.base_size() > MAX_ONCHAIN_TX_SIZE {
            policy_err!(
                self,
                "policy-onchain-max-size",
                "tx too large: {} > {}",
                tx.base_size(),
                MAX_ONCHAIN_TX_SIZE
            );
        }

        if channels.iter().any(|c| c.is_some()) && !is_tx_non_malleable(tx, segwit_flags) {
            policy_err!(
                self,
                "policy-onchain-funding-non-malleable",
                "funding tx has non-segwit-native input"
            );
        }

        let mut unknowns = Vec::new();

        let mut beneficial_sum = 0u64;
        for outndx in 0..tx.output.len() {
            let output = &tx.output[outndx];
            let opath = &opaths[outndx];
            let channel_slot = channels[outndx].as_ref();

            macro_rules! add_beneficial_output {
                ($sum: expr, $val: expr, $which: expr) => {
                    $sum.checked_add($val).ok_or_else(|| {
                        policy_error(
                            "policy-onchain-fee-range",
                            format!(
                                "beneficial outputs overflow: sum {} + {} {}",
                                $sum, $which, $val
                            ),
                        )
                    })
                };
            }

            if opath.len() > 0 {
                // Possible change output to our wallet
                let mut spendable =
                    wallet.can_spend(opath, &output.script_pubkey).map_err(|err| {
                        policy_error(
                            "policy-onchain-output-scriptpubkey",
                            format!("output[{}]: wallet_can_spend error: {}", outndx, err),
                        )
                    })?;
                if spendable {
                    debug!("output {} ({}) is to our wallet", outndx, output.value.to_sat());
                    beneficial_sum =
                        add_beneficial_output!(beneficial_sum, output.value.to_sat(), "to wallet")?;
                }
                if !spendable {
                    // Possible output to allowlisted xpub
                    spendable = wallet.allowlist_contains(&output.script_pubkey, opath);
                    if spendable {
                        debug!(
                            "output {} ({}) is to allowlisted xpub",
                            outndx,
                            output.value.to_sat()
                        );
                        beneficial_sum = add_beneficial_output!(
                            beneficial_sum,
                            output.value.to_sat(),
                            "to allowlisted xpub"
                        )?;
                    }
                }
                if !spendable {
                    policy_err!(
                        self,
                        "policy-onchain-no-unknown-outputs",
                        "output[{}] is unknown",
                        outndx
                    );
                }
            } else if wallet.allowlist_contains(&output.script_pubkey, &DerivationPath::master()) {
                // Possible output to allowlisted address
                debug!("output {} ({}) is allowlisted", outndx, output.value.to_sat());
                beneficial_sum =
                    add_beneficial_output!(beneficial_sum, output.value.to_sat(), "allowlisted")?;
            } else if let Some(slot) = channel_slot {
                // Possible funded channel balance
                match &*slot.lock().unwrap() {
                    ChannelSlot::Ready(chan) => {
                        debug!(
                            "output {} ({}) matches channel {}",
                            outndx,
                            output.value.to_sat(),
                            chan.id()
                        );
                        dbgvals!(chan.setup, chan.enforcement_state);

                        if output.value.to_sat() != chan.setup.channel_value_sat {
                            policy_err!(
                                self,
                                "policy-onchain-output-match-commitment",
                                "funding output amount mismatch w/ channel: {} != {}",
                                output.value.to_sat(),
                                chan.setup.channel_value_sat
                            );
                        }

                        let funding_redeemscript = make_funding_redeemscript(
                            &chan.keys.pubkeys().funding_pubkey,
                            &chan.counterparty_pubkeys().funding_pubkey,
                        );
                        let address = Address::p2wsh(&funding_redeemscript, wallet.network());
                        let script_pubkey = address.script_pubkey();
                        if output.script_pubkey != script_pubkey {
                            policy_err!(
                                self,
                                "policy-onchain-output-scriptpubkey",
                                "funding script_pubkey mismatch w/ channel: {} != {}",
                                output.script_pubkey,
                                script_pubkey
                            );
                        }

                        if chan.enforcement_state.next_holder_commit_num != 1 {
                            policy_err!(
                                self,
                                "policy-onchain-initial-commitment-countersigned",
                                "initial holder commitment not validated",
                            );
                        }
                        if !chan.setup.is_outbound {
                            policy_err!(
                                self,
                                "policy-onchain-no-fund-inbound",
                                "can't sign for inbound channel: dual-funding not supported yet",
                            );
                        }
                        let push_val_sat = chan.setup.push_value_msat / 1000;
                        if push_val_sat > 0 {
                            policy_err!(
                                self,
                                "policy-onchain-no-channel-push",
                                "channel push not allowed: dual-funding not supported yet",
                            );
                        }
                        let our_value =
                            chan.setup.channel_value_sat.checked_sub(push_val_sat).ok_or_else(
                                || {
                                    policy_error(
                                        "policy-onchain-fee-range",
                                        format!(
                                            "channel value underflow: {} - {}",
                                            chan.setup.channel_value_sat, push_val_sat
                                        ),
                                    )
                                },
                            )?;
                        debug!(
                            "output {} ({}) funds channel {}",
                            outndx,
                            output.value.to_sat(),
                            chan.id()
                        );
                        beneficial_sum =
                            add_beneficial_output!(beneficial_sum, our_value, "channel value")?;
                    }
                    _ => panic!("this can't happen"),
                };
            } else {
                debug!("output {} ({}) is unknown", outndx, output.value.to_sat());
                // policy-onchain-no-unknown-outputs
                unknowns.push(outndx);
            }
        }

        if unknowns.len() > 0 {
            return Err(unknown_destinations_error(unknowns));
        }

        // policy-onchain-fee-range
        let mut sum_inputs: u64 = 0;
        for val in values_sat {
            sum_inputs = sum_inputs.checked_add(*val).ok_or_else(|| {
                policy_error("policy-onchain-fee-range", "funding sum inputs overflow")
            })?;
        }
        let non_beneficial = self
            .validate_beneficial_value(sum_inputs, beneficial_sum, weight_lower_bound)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        *debug_on_return = false;
        Ok(non_beneficial)
    }

    /// panics if `keys` doesn't have counterparty keys populated
    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &[Vec<u8>],
    ) -> Result<CommitmentInfo, ValidationError> {
        let mut debug_on_return = scoped_debug_return!(
            DebugInMemorySigner(keys),
            setup,
            is_counterparty,
            tx,
            DebugVecVecU8(output_witscripts)
        );

        if tx.version != Version::TWO {
            policy_err!(
                self,
                "policy-commitment-version",
                "bad commitment version: {}",
                tx.version
            );
        }

        let mut info = CommitmentInfo::new(is_counterparty);
        for ind in 0..tx.output.len() {
            info.handle_output(keys, setup, &tx.output[ind], output_witscripts[ind].as_slice())
                .map_err(|ve| {
                    ve.prepend_msg(format!("{}: tx output[{}]: ", containing_function!(), ind))
                })?;
        }

        *debug_on_return = false;
        Ok(info)
    }

    fn validate_counterparty_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        if let Some(current) = &estate.current_counterparty_commit_info {
            let (added, removed) = current.delta_offered_htlcs(info2);
            debug!(
                "{} counterparty offered delta outbound={} +{:?} -{:?}",
                self.log_prefix(),
                setup.is_outbound,
                added.collect::<Vec<_>>(),
                removed.collect::<Vec<_>>()
            );
            let (added, removed) = current.delta_received_htlcs(info2);
            debug!(
                "{} counterparty received delta outbound={} +{:?} -{:?}",
                self.log_prefix(),
                setup.is_outbound,
                added.collect::<Vec<_>>(),
                removed.collect::<Vec<_>>()
            );
        }
        // Validate common commitment constraints
        self.validate_commitment_tx(estate, commit_num, commitment_point, setup, cstate, info2)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        let mut debug_on_return =
            scoped_debug_return!(estate, commit_num, commitment_point, setup, cstate, info2);

        // if next_counterparty_revoke_num is 20:
        // - commit_num 19 has been revoked
        // - commit_num 20 is current, previously signed, ok to resign
        // - commit_num 21 is ok to sign, advances the state
        // - commit_num 22 is not ok to sign
        if commit_num > estate.next_counterparty_revoke_num + 1 {
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "invalid attempt to sign counterparty commit_num {} \
                         with next_counterparty_revoke_num {}",
                commit_num,
                estate.next_counterparty_revoke_num
            );
        }

        // Is this a retry?
        // not a security problem, because it's OK to re-sign an old commitment
        // that the *counterparty* revoked
        if commit_num + 1 == estate.next_counterparty_commit_num {
            // The commit_point must be the same as previous
            match estate.current_counterparty_point {
                None => {
                    policy_err!(
                        self,
                        "policy-commitment-retry-same",
                        "retry of sign_counterparty_commitment {} with no prev point: \
                             new {}",
                        commit_num,
                        commitment_point
                    );
                }
                Some(prev) =>
                    if *commitment_point != prev {
                        policy_err!(
                            self,
                            "policy-commitment-retry-same",
                            "retry of sign_counterparty_commitment {} with changed point: \
                             prev {} != new {}",
                            commit_num,
                            prev,
                            commitment_point
                        );
                    },
            }

            // The CommitmentInfo2 must be the same as previously
            let prev_commit_info = estate.get_previous_counterparty_commit_info(commit_num);
            if Some(info2) != prev_commit_info.as_ref() {
                #[cfg(not(feature = "log_pretty_print"))]
                policy_log!(
                    self,
                    "policy-commitment-retry-same",
                    "info2 != prev_commit_info\n{:?}\n{:?}",
                    info2,
                    prev_commit_info
                );
                #[cfg(feature = "log_pretty_print")]
                policy_log!(
                    self,
                    "policy-commitment-retry-same",
                    "info2 != prev_commit_info\n{:#?}\n{:#?}",
                    info2,
                    prev_commit_info
                );
                policy_err!(
                    self,
                    "policy-commitment-retry-same",
                    "retry of sign_counterparty_commitment {} with changed info",
                    commit_num,
                );
            }
        }

        *debug_on_return = false;
        Ok(())
    }

    fn validate_holder_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info2: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        if let Some(current) = &estate.current_holder_commit_info {
            let (added, removed) = current.delta_offered_htlcs(info2);
            debug!(
                "{} holder offered delta outbound={} +{:?} -{:?}",
                self.log_prefix(),
                setup.is_outbound,
                added.collect::<Vec<_>>(),
                removed.collect::<Vec<_>>()
            );
            let (added, removed) = current.delta_received_htlcs(info2);
            debug!(
                "{} holder received delta outbound={} +{:?} -{:?}",
                self.log_prefix(),
                setup.is_outbound,
                added.collect::<Vec<_>>(),
                removed.collect::<Vec<_>>()
            );
        }

        // Validate common commitment constraints
        self.validate_commitment_tx(estate, commit_num, commitment_point, setup, cstate, info2)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        let mut debug_on_return =
            scoped_debug_return!(estate, commit_num, commitment_point, setup, cstate, info2);

        // Is this a retry?
        if commit_num + 1 == estate.next_holder_commit_num {
            // The CommitmentInfo2 must be the same as previously
            // unwrap is safe, because commitment number can't be > 0 without a holder commitment_info
            let holder_commit_info =
                &estate.current_holder_commit_info.as_ref().expect("current_holder_commit_info");
            if info2 != *holder_commit_info {
                dbgvals!(*info2, holder_commit_info);
                policy_err!(
                    self,
                    "policy-commitment-retry-same",
                    "retry holder commitment {} with changed info",
                    commit_num
                );
            }
        }

        // This test overlaps the check in set_next_holder_commit_num but gives
        // better diagnostic.
        if commit_num + 2 <= estate.next_holder_commit_num {
            dbgvals!(estate, commit_num);
            policy_err!(
                self,
                "policy-commitment-holder-not-revoked",
                "can't validate revoked commitment_number {}, \
                 next_holder_commit_num is {}",
                commit_num,
                estate.next_holder_commit_num
            );
        };

        // It's ok to validate the current state when closed, but not ok to validate
        // a new state.
        if commit_num == estate.next_holder_commit_num && estate.channel_closed {
            dbgvals!(estate);
            policy_err!(self, "policy-commitment-spends-active-utxo", "channel is closing");
        }

        *debug_on_return = false;
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
            dbgvals!(state, revoke_num, commitment_secret);
            policy_err!(
                self,
                "policy-commitment-previous-revoked",
                "invalid counterparty revoke_num {} with next_counterparty_revoke_num {}",
                revoke_num,
                state.next_counterparty_revoke_num
            );
        }

        // policy-commitment-previous-revoked (partial: secret validated, but not stored here)
        let supplied_commit_point = PublicKey::from_secret_key(&secp_ctx, &commitment_secret);
        let prev_commit_point = state.get_previous_counterparty_point(revoke_num);
        match prev_commit_point {
            None => {
                dbgvals!(state, revoke_num, commitment_secret);
                policy_err!(
                    self,
                    "policy-commitment-previous-revoked",
                    "revocation commit point mismatch for commit_num {}: supplied {}, previous is None",
                    revoke_num,
                    supplied_commit_point
                );
            }
            Some(prev) =>
                if supplied_commit_point != prev {
                    dbgvals!(state, revoke_num, commitment_secret);
                    policy_err!(
                        self,
                        "policy-commitment-previous-revoked",
                        "revocation commit point mismatch for commit_num {}: supplied {}, previous {}",
                        revoke_num,
                        supplied_commit_point,
                        prev
                    );
                },
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
        redeemscript: &ScriptBuf,
        htlc_amount_sat: u64,
        output_witscript: &ScriptBuf,
    ) -> Result<(u32, HTLCOutputInCommitment, SegwitV0Sighash, EcdsaSighashType), ValidationError>
    {
        let to_self_delay = if is_counterparty {
            setup.holder_selected_contest_delay // the local side imposes this value
        } else {
            setup.counterparty_selected_contest_delay // the remote side imposes this value
        };
        let sighash_type = if setup.is_anchors() {
            EcdsaSighashType::SinglePlusAnyoneCanPay
        } else {
            EcdsaSighashType::All
        };
        let original_tx_sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(0, &redeemscript, Amount::from_sat(htlc_amount_sat), sighash_type)
            .map_err(|_| {
                policy_error(
                    "policy-commitment-other",
                    "could not compute sighash on provided HTLC tx",
                )
            })?;

        let offered = if parse_offered_htlc_script(redeemscript, setup.is_anchors()).is_ok() {
            true
        } else if parse_received_htlc_script(redeemscript, setup.is_anchors()).is_ok() {
            false
        } else {
            dbgvals!(
                is_counterparty,
                setup,
                DebugTxCreationKeys(txkeys),
                tx,
                redeemscript,
                htlc_amount_sat,
                output_witscript
            );
            return Err(policy_error("policy-commitment-scripts", "invalid redeemscript"));
        };

        // Extract some parameters from the submitted transaction.
        let cltv_expiry = if offered { tx.lock_time.to_consensus_u32() } else { 0 };
        let transaction_output_index = tx.input[0].previous_output.vout;
        let commitment_txid = tx.input[0].previous_output.txid;
        let total_fee = htlc_amount_sat
            .checked_sub(tx.output[0].value.to_sat())
            .ok_or_else(|| policy_error("policy-commitment-fee-range", "fee underflow"))?;

        let features = setup.features();
        let build_feerate = if setup.is_zero_fee_htlc() {
            0
        } else {
            let weight = if offered {
                htlc_timeout_tx_weight(&features)
            } else {
                htlc_success_tx_weight(&features)
            };
            estimate_feerate_per_kw(total_fee, weight)
        };

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
            build_feerate,
            to_self_delay,
            &htlc,
            &setup.features(),
            &txkeys.broadcaster_delayed_payment_key,
            &txkeys.revocation_key,
        );

        // unwrap is safe because we know the tx is valid
        let recomposed_tx_sighash = SighashCache::new(&recomposed_tx)
            .p2wsh_signature_hash(0, &redeemscript, Amount::from_sat(htlc_amount_sat), sighash_type)
            .unwrap();

        if recomposed_tx_sighash != original_tx_sighash {
            dbgvals!(
                is_counterparty,
                setup,
                DebugTxCreationKeys(txkeys),
                tx,
                redeemscript,
                htlc_amount_sat,
                output_witscript
            );
            let (revocation_key, contest_delay, delayed_pubkey) =
                parse_revokeable_redeemscript(output_witscript, setup.is_anchors())
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
                &txkeys.revocation_key.0,
                to_self_delay,
                &txkeys.broadcaster_delayed_payment_key.0
            );
            return Err(policy_error("policy-htlc-other", "sighash mismatch".to_string()));
        }

        // The sighash comparison in the previous block will fail if any of the
        // following policies are violated:
        // - policy-htlc-version
        // - policy-htlc-locktime
        // - policy-htlc-sequence
        // - policy-htlc-to-self-delay
        // - policy-htlc-revocation-pubkey
        // - policy-htlc-delayed-pubkey

        Ok((build_feerate, htlc, recomposed_tx_sighash, sighash_type))
    }

    fn validate_htlc_tx(
        &self,
        setup: &ChannelSetup,
        _cstate: &ChainState,
        _is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return =
            scoped_debug_return!(DebugHTLCOutputInCommitment(htlc), feerate_per_kw);

        // This must be further checked with policy-htlc-cltv-range.
        // Note that we can't check cltv_expiry for non-offered 2nd level
        // HTLC txs in phase 1, because they don't mention the cltv_expiry
        // there, only in the commitment tx output.
        if htlc.offered && htlc.cltv_expiry == 0 {
            policy_err!(self, "policy-htlc-locktime", "offered lock_time must be non-zero");
        }

        if !setup.is_zero_fee_htlc() {
            if feerate_per_kw < self.policy.min_feerate_per_kw {
                policy_err!(
                    self,
                    "policy-htlc-fee-range",
                    "feerate_per_kw of {} is smaller than the minimum of {}",
                    feerate_per_kw,
                    self.policy.min_feerate_per_kw
                );
            }
        }
        if feerate_per_kw > self.policy.max_feerate_per_kw {
            policy_err!(
                self,
                "policy-htlc-fee-range",
                "feerate_per_kw of {} is larger than the maximum of {}",
                feerate_per_kw,
                self.policy.max_feerate_per_kw
            );
        }

        *debug_on_return = false;
        Ok(())
    }

    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        tx: &Transaction,
        wallet_paths: &[DerivationPath],
    ) -> Result<ClosingTransaction, ValidationError> {
        // Log state and inputs if we don't succeed.
        let should_debug = true;
        let mut debug_on_return = scopeguard::guard(should_debug, |should_debug| {
            if should_debug {
                if log::log_enabled!(log::Level::Debug) {
                    debug!("{} failed:", containing_function!());
                    dbgvals!(setup, estate, tx, wallet_paths);

                    // Log the addresses associated with the outputs
                    let mut addrstrs = String::new();
                    for ndx in 0..tx.output.len() {
                        let script = &tx.output[ndx].script_pubkey;
                        addrstrs.push_str(
                            &format!(
                                "\ntxout[{}]: {}",
                                ndx,
                                &script_debug(script, wallet.network())
                            )[..],
                        );
                    }
                    debug!("output addresses: {}", &addrstrs);
                }
            }
        });

        if tx.output.len() > 2 {
            transaction_format_err!(
                self,
                "policy-mutual-other",
                "invalid number of outputs: {}",
                tx.output.len(),
            );
        }

        // The caller checked, this shouldn't happen
        assert_eq!(wallet_paths.len(), tx.output.len());

        if estate.current_holder_commit_info.is_none() {
            policy_err!(self, "policy-mutual-other", "current_holder_commit_info missing");
        }
        if estate.current_counterparty_commit_info.is_none() {
            policy_err!(self, "policy-mutual-other", "current_counterparty_commit_info missing");
        }

        // Establish which output belongs to the holder by trying all possibilities

        // Guess which ordering is most likely based on commitment values.
        // - Makes it unlikely we'll have to call validate a second time.
        // - Allows us to return the "better" validation error.

        #[derive(Debug)]
        struct ValidateArgs {
            to_holder_value_sat: u64,
            to_counterparty_value_sat: u64,
            holder_script: Option<ScriptBuf>,
            counterparty_script: Option<ScriptBuf>,
            wallet_path: DerivationPath,
        }

        // If the commitments are not in the expected state, or the values
        // are outside epsilon from each other the comparison won't be
        // meaningful and an arbitrary order will have to do ...
        //
        let holder_value = estate.minimum_to_holder_value(self.policy.epsilon_sat);
        let cparty_value = estate.minimum_to_counterparty_value(self.policy.epsilon_sat);
        #[cfg(not(feature = "log_pretty_print"))]
        debug!("holder_value={:?}, cparty_value={:?}", holder_value, cparty_value);
        #[cfg(feature = "log_pretty_print")]
        debug!("holder_value={:#?}, cparty_value={:#?}", holder_value, cparty_value);
        let holder_value_is_larger = holder_value > cparty_value;
        debug!("holder_value_is_larger={}", holder_value_is_larger);

        let (likely_args, unlikely_args) = if tx.output.len() == 1 {
            let holders_output = ValidateArgs {
                to_holder_value_sat: tx.output[0].value.to_sat(),
                to_counterparty_value_sat: 0,
                holder_script: Some(tx.output[0].script_pubkey.clone()),
                counterparty_script: None,
                wallet_path: wallet_paths[0].clone(),
            };
            let cpartys_output = ValidateArgs {
                to_holder_value_sat: 0,
                to_counterparty_value_sat: tx.output[0].value.to_sat(),
                holder_script: None,
                counterparty_script: Some(tx.output[0].script_pubkey.clone()),
                wallet_path: DerivationPath::master(),
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
                to_holder_value_sat: tx.output[0].value.to_sat(),
                to_counterparty_value_sat: tx.output[1].value.to_sat(),
                holder_script: Some(tx.output[0].script_pubkey.clone()),
                counterparty_script: Some(tx.output[1].script_pubkey.clone()),
                wallet_path: wallet_paths[0].clone(),
            };
            let cparty_first = ValidateArgs {
                to_holder_value_sat: tx.output[1].value.to_sat(),
                to_counterparty_value_sat: tx.output[0].value.to_sat(),
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

        #[cfg(not(feature = "log_pretty_print"))]
        debug!("{}: trying likely args: {:?}", short_function!(), &likely_args);
        #[cfg(feature = "log_pretty_print")]
        debug!("{}: trying likely args: {:#?}", short_function!(), &likely_args);
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
            debug!("{}: trying unlikely args: {:#?}", short_function!(), &unlikely_args);
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

        let closing_tx = ClosingTransaction::new(
            good_args.to_holder_value_sat,
            good_args.to_counterparty_value_sat,
            good_args.holder_script.unwrap_or_else(|| ScriptBuf::new()),
            good_args.counterparty_script.unwrap_or_else(|| ScriptBuf::new()),
            setup.funding_outpoint,
        );
        let trusted = closing_tx.trust();
        let recomposed_tx = trusted.built_transaction();

        if *recomposed_tx != *tx {
            debug!("ORIGINAL_TX={:#?}", &tx);
            debug!("RECOMPOSED_TX={:#?}", &recomposed_tx);
            // this actually covers a few policies, not just format
            policy_err!(self, "policy-onchain-format-standard", "recomposed tx mismatch");
        }

        *debug_on_return = false; // don't debug when we succeed
        Ok(closing_tx)
    }

    fn validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<ScriptBuf>,
        counterparty_script: &Option<ScriptBuf>,
        holder_wallet_path_hint: &DerivationPath,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return = scoped_debug_return!(
            setup,
            estate,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script,
            counterparty_script
        );

        let holder_info = estate.current_holder_commit_info.as_ref().ok_or_else(|| {
            policy_error(
                "policy-mutual-value-matches-commitment",
                "current_holder_commit_info missing",
            )
        })?;

        let counterparty_info =
            estate.current_counterparty_commit_info.as_ref().ok_or_else(|| {
                policy_error(
                    "policy-mutual-value-matches-commitment",
                    "current_counterparty_commit_info missing",
                )
            })?;

        if to_holder_value_sat > 0 && holder_script.is_none() {
            policy_err!(
                self,
                "policy-mutual-destination-allowlisted",
                "missing holder_script with {} to_holder_value_sat",
                to_holder_value_sat
            );
        }

        if to_counterparty_value_sat > 0 && counterparty_script.is_none() {
            policy_err!(
                self,
                "policy-mutual-destination-allowlisted",
                "missing counterparty_script with {} to_counterparty_value_sat",
                to_counterparty_value_sat
            );
        }

        // If the upfront holder_shutdown_script was in effect, make sure the
        // holder script matches.
        if setup.holder_shutdown_script.is_some() && to_holder_value_sat > 0 {
            if *holder_script != setup.holder_shutdown_script {
                policy_err!(
                    self,
                    "policy-mutual-destination-allowlisted",
                    "holder_script doesn't match upfront holder_shutdown_script"
                );
            }
        }

        if !holder_info.htlcs_is_empty() || !counterparty_info.htlcs_is_empty() {
            policy_err!(self, "policy-mutual-no-pending-htlcs", "cannot close with pending htlcs");
        }

        let weight = mutual_close_tx_weight(
            &ClosingTransaction::new(
                to_holder_value_sat,
                to_counterparty_value_sat,
                holder_script.clone().unwrap_or_else(|| ScriptBuf::new()),
                counterparty_script.clone().unwrap_or_else(|| ScriptBuf::new()),
                setup.funding_outpoint,
            )
            .trust()
            .built_transaction(),
        );

        // policy-mutual-fee-range
        let sum_outputs =
            to_holder_value_sat.checked_add(to_counterparty_value_sat).ok_or_else(|| {
                policy_error("policy-mutual-value-matches-commitment", "consumed overflow")
            })?;
        self.validate_fee("policy-mutual-fee-range", setup.channel_value_sat, sum_outputs, weight)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        // To make this test independent of variable fees we compare the side that
        // isn't paying the fees.
        if setup.is_outbound {
            // We are the funder and paying the fees, make sure the counterparty's output matches
            // the latest commitments.  Our value will then be enforced by the max-fee policy.
            if let (true, descr) = self.outside_epsilon_range(
                to_counterparty_value_sat,
                counterparty_info.to_broadcaster_value_sat,
            ) {
                policy_err!(
                    self,
                    "policy-mutual-value-matches-commitment",
                    "to_counterparty_value {} \
                     is {} than counterparty_info.broadcaster_value_sat {}",
                    to_counterparty_value_sat,
                    descr,
                    counterparty_info.to_broadcaster_value_sat
                );
            }
            if let (true, descr) = self.outside_epsilon_range(
                to_counterparty_value_sat,
                holder_info.to_countersigner_value_sat,
            ) {
                policy_err!(
                    self,
                    "policy-mutual-value-matches-commitment",
                    "to_counterparty_value {} \
                     is {} than holder_info.countersigner_value_sat {}",
                    to_counterparty_value_sat,
                    descr,
                    holder_info.to_countersigner_value_sat
                );
            }
        } else {
            // The counterparty is the funder, make sure the holder's
            // output matches the latest commitments.
            if let (true, descr) = self
                .outside_epsilon_range(to_holder_value_sat, holder_info.to_broadcaster_value_sat)
            {
                policy_err!(
                    self,
                    "policy-mutual-value-matches-commitment",
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
                policy_err!(
                    self,
                    "policy-mutual-value-matches-commitment",
                    "to_holder_value {} is {} than counterparty_info.countersigner_value_sat {}",
                    to_holder_value_sat,
                    descr,
                    counterparty_info.to_countersigner_value_sat
                );
            }
        }

        if let Some(script) = &holder_script {
            if !wallet.can_spend(holder_wallet_path_hint, script).map_err(|err| {
                policy_error("policy-mutual-scripts", format!("wallet can_spend error: {}", err))
            })? && !wallet.allowlist_contains(script, holder_wallet_path_hint)
            {
                policy_err!(
                    self,
                    "policy-mutual-destination-allowlisted",
                    "holder output not to wallet or in allowlist"
                );
            }
        }

        *debug_on_return = false; // don't debug when we succeed
        Ok(())
    }

    fn validate_delayed_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return =
            scoped_debug_return!(setup, cstate, tx, input, amount_sat, wallet_path);

        // Common sweep validation
        self.validate_sweep(wallet, tx, input, amount_sat, wallet_path)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        // this is safe because we know that the current height is reasonable
        if !tx.lock_time.is_satisfied_by(
            Height::from_consensus(cstate.current_height + MAX_CHAIN_LAG)
                .expect("Height::from_consensus"),
            // We are only interested in checking the height, and not the time. So we can put here any value.
            Time::MIN,
        ) {
            transaction_format_err!(
                self,
                "policy-sweep-locktime",
                "bad locktime: {} > {}",
                tx.lock_time,
                cstate.current_height + MAX_CHAIN_LAG
            );
        }

        let seq = tx.input[0].sequence.0;
        if seq != setup.counterparty_selected_contest_delay as u32 {
            transaction_format_err!(
                self,
                "policy-sweep-sequence",
                "bad sequence: {} != {}",
                seq,
                setup.counterparty_selected_contest_delay
            );
        }

        *debug_on_return = false;
        Ok(())
    }

    fn validate_counterparty_htlc_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        redeemscript: &ScriptBuf,
        input: usize,
        amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return =
            scoped_debug_return!(setup, cstate, tx, input, amount_sat, wallet_path);

        // Common sweep validation
        self.validate_sweep(wallet, tx, input, amount_sat, wallet_path)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        // Parse the redeemscript to determine the cltv_expiry
        if let Ok((
            _revocation_hash,
            _remote_htlc_pubkey,
            _payment_hash_vec,
            _local_htlc_pubkey,
            cltv_expiry,
        )) = parse_received_htlc_script(redeemscript, setup.is_anchors())
        {
            // It's a received htlc (counterparty perspective)
            if cltv_expiry < 0 || cltv_expiry > u32::MAX as i64 {
                transaction_format_err!(
                    self,
                    "policy-sweep-other",
                    "bad cltv_expiry: {}",
                    cltv_expiry
                );
            }

            if tx.lock_time.to_consensus_u32() > cltv_expiry as u32 {
                transaction_format_err!(
                    self,
                    "policy-sweep-locktime",
                    "bad locktime: {} > {}",
                    tx.lock_time,
                    cltv_expiry as u32
                );
            }
        } else if let Ok((
            _revocation_hash,
            _remote_htlc_pubkey,
            _local_htlc_pubkey,
            _payment_hash_vec,
        )) = parse_offered_htlc_script(redeemscript, setup.is_anchors())
        {
            // It's an offered htlc (counterparty perspective)
            if !tx.lock_time.is_satisfied_by(
                // this is safe because we know that the current height is reasonable
                Height::from_consensus(cstate.current_height + MAX_CHAIN_LAG)
                    .expect("Height::from_consensus"),
                // We are only interested in checking the height, and not the time. So we can put here any value.
                Time::MIN,
            ) {
                transaction_format_err!(
                    self,
                    "policy-sweep-locktime",
                    "bad locktime: {} > {}",
                    tx.lock_time,
                    cstate.current_height + MAX_CHAIN_LAG
                );
            }
        } else {
            // The redeemscript didn't parse as received or offered ...
            transaction_format_err!(
                self,
                "policy-sweep-other",
                "bad redeemscript: {}",
                &redeemscript
            );
        };

        let seq = tx.input[0].sequence.0;
        let valid_seqs = if setup.is_anchors() {
            SimpleValidator::ANCHOR_SEQS.to_vec()
        } else {
            SimpleValidator::NON_ANCHOR_SEQS.to_vec()
        };
        if !valid_seqs.contains(&seq) {
            transaction_format_err!(
                self,
                "policy-sweep-sequence",
                "bad sequence: {} not in {:?}",
                seq,
                valid_seqs,
            );
        }

        *debug_on_return = false;
        Ok(())
    }

    fn validate_justice_sweep(
        &self,
        wallet: &dyn Wallet,
        _setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return =
            scoped_debug_return!(_setup, cstate, tx, input, amount_sat, wallet_path);

        // Common sweep validation
        self.validate_sweep(wallet, tx, input, amount_sat, wallet_path)
            .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        if !tx.lock_time.is_satisfied_by(
            // this is safe because we know that the current height is reasonable
            Height::from_consensus(cstate.current_height + MAX_CHAIN_LAG)
                .expect("Height::from_consensus"),
            // We are only interested in checking the height, and not the time. So we can put here any value.
            Time::MIN,
        ) {
            transaction_format_err!(
                self,
                "policy-sweep-locktime",
                "bad locktime: {} > {}",
                tx.lock_time,
                cstate.current_height + MAX_CHAIN_LAG
            );
        }

        let seq = tx.input[0].sequence.0;
        let valid_seqs = SimpleValidator::NON_ANCHOR_SEQS.to_vec();
        if !valid_seqs.contains(&seq) {
            transaction_format_err!(
                self,
                "policy-sweep-sequence",
                "bad sequence: {} not in {:?}",
                seq,
                valid_seqs
            );
        }

        *debug_on_return = false;
        Ok(())
    }

    /// When thinking about payment routing and balance, it is
    /// useful to consider three cases:
    ///
    /// 1. When `invoiced_amount_msat` is specified and the `incoming_msat` is 0;
    /// e.g. we are paying an invoice and there is no loop in the routing through us
    /// 2. When `invoiced_amount_msat` is specified and the `incoming_msat` is not 0;
    /// e.g. we are paying an invoice and there is a loop in the routing that includes us
    /// 3. When no `invoiced_amount_msat` is specified and the `incoming_msat` is not 0;
    /// e.g forwarding a payment.
    fn validate_payment_balance(
        &self,
        incoming_msat: u64,
        outgoing_msat: u64,
        invoiced_amount_msat: Option<u64>,
    ) -> Result<(), ValidationError> {
        let max_to_invoice_msat = if let Some(a) = invoiced_amount_msat {
            a + self.policy.max_routing_fee_msat
        } else {
            0
        };

        // this also implicitly implements policy-commitment-payment-invoiced
        if incoming_msat + max_to_invoice_msat < outgoing_msat {
            policy_err!(
                self,
                "policy-routing-balanced",
                "incoming_msat + max_to_invoice_msat < outgoing_msat: {} + {} < {}",
                incoming_msat,
                max_to_invoice_msat,
                outgoing_msat
            );
        }

        if let Some(invoiced_amount_msat) = invoiced_amount_msat {
            // When we are underpaying the invoice or we are not paying fee,
            // there is no need to check the fee here.
            if invoiced_amount_msat + incoming_msat > outgoing_msat {
                return Ok(());
            }

            // check if the payment is payment an percentage of the fee
            let fee = outgoing_msat - invoiced_amount_msat - incoming_msat;
            let actual_fee_percentage = fee.checked_mul(100).ok_or(policy_error(
                "policy-commitment-payment-velocity",
                "policy-generic-error: invoice amount too big",
            ))? / core::cmp::max(invoiced_amount_msat, 1);
            if actual_fee_percentage > self.policy.max_feerate_percentage.into() {
                policy_err!(
                    self,
                    "policy-htlc-fee-range",
                    "fee_percentage > max_feerate_percentage: {actual_fee_percentage}% > {}%",
                    self.policy.max_feerate_percentage
                );
            }
        }

        Ok(())
    }

    fn enforce_balance(&self) -> bool {
        self.policy.enforce_balance
    }

    fn minimum_initial_balance(&self, holder_value_msat: u64) -> u64 {
        holder_value_msat / 1000
    }

    fn is_ready(&self, cstate: &ChainState) -> bool {
        cstate.funding_depth > 0 && cstate.closing_depth == 0
    }

    fn policy(&self) -> Box<&dyn Policy> {
        Box::new(&self.policy)
    }
}

impl SimpleValidator {
    // Common commitment validation applicable to both holder and counterparty txs
    fn validate_commitment_tx(
        &self,
        estate: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        let mut debug_on_return =
            scoped_debug_return!(estate, commit_num, commitment_point, setup, cstate, info);

        let policy = &self.policy;

        if info.to_broadcaster_value_sat > 0
            && info.to_broadcaster_value_sat < MIN_CHAN_DUST_LIMIT_SATOSHIS
        {
            policy_err!(
                self,
                "policy-commitment-outputs-trimmed",
                "to_broadcaster_value_sat {} less than dust limit {}",
                info.to_broadcaster_value_sat,
                MIN_CHAN_DUST_LIMIT_SATOSHIS
            );
        }
        if info.to_countersigner_value_sat > 0
            && info.to_countersigner_value_sat < MIN_CHAN_DUST_LIMIT_SATOSHIS
        {
            policy_err!(
                self,
                "policy-commitment-outputs-trimmed",
                "to_countersigner_value_sat {} less than dust limit {}",
                info.to_countersigner_value_sat,
                MIN_CHAN_DUST_LIMIT_SATOSHIS
            );
        }

        if info.offered_htlcs.len() + info.received_htlcs.len() > policy.max_htlcs {
            policy_err!(self, "policy-commitment-htlc-count-limit", "too many HTLCs");
        }

        let mut htlc_value_sat: u64 = 0;

        let offered_htlc_dust_limit = if setup.is_zero_fee_htlc() {
            MIN_CHAN_DUST_LIMIT_SATOSHIS
        } else {
            MIN_DUST_LIMIT_SATOSHIS
                + (info.feerate_per_kw as u64 * htlc_timeout_tx_weight(&setup.features()) / 1000)
        };
        for htlc in &info.offered_htlcs {
            // TODO(512) - this check should be converted into two checks, one the first time
            // the HTLC is introduced and the other every time it is encountered.
            //
            // policy-commitment-htlc-cltv-range
            self.validate_expiry("offered HTLC", htlc.cltv_expiry, cstate.current_height)?;

            htlc_value_sat = htlc_value_sat.checked_add(htlc.value_sat).ok_or_else(|| {
                policy_error(
                    "policy-commitment-payment-velocity",
                    "offered HTLC value overflow".to_string(),
                )
            })?;

            if htlc.value_sat < offered_htlc_dust_limit {
                policy_err!(
                    self,
                    "policy-commitment-outputs-trimmed",
                    "offered htlc.value_sat {} less than dust limit {}",
                    htlc.value_sat,
                    offered_htlc_dust_limit
                );
            }
        }

        let received_htlc_dust_limit = if setup.is_zero_fee_htlc() {
            MIN_CHAN_DUST_LIMIT_SATOSHIS
        } else {
            MIN_DUST_LIMIT_SATOSHIS
                + (info.feerate_per_kw as u64 * htlc_success_tx_weight(&setup.features()) / 1000)
        };
        for htlc in &info.received_htlcs {
            // TODO(512) - this check should be converted into two checks, one the first time
            // the HTLC is introduced and the other every time it is encountered.
            //
            // policy-commitment-htlc-cltv-range
            self.validate_expiry("received HTLC", htlc.cltv_expiry, cstate.current_height)?;

            htlc_value_sat = htlc_value_sat.checked_add(htlc.value_sat).ok_or_else(|| {
                policy_error(
                    "policy-commitment-payment-velocity",
                    "received HTLC value overflow".to_string(),
                )
            })?;

            if htlc.value_sat < received_htlc_dust_limit {
                policy_err!(
                    self,
                    "policy-commitment-outputs-trimmed",
                    "received htlc.value_sat {} less than dust limit {}",
                    htlc.value_sat,
                    received_htlc_dust_limit
                );
            }
        }

        if htlc_value_sat > policy.max_htlc_value_sat {
            policy_err!(
                self,
                "policy-commitment-htlc-inflight-limit",
                "sum of HTLC values {} too large",
                htlc_value_sat
            );
        }

        let expected_weight = expected_commitment_tx_weight(
            setup.is_anchors(),
            info.offered_htlcs.len() + info.received_htlcs.len(),
        );

        // policy-commitment-fee-range
        let sum_outputs = info
            .to_broadcaster_value_sat
            .checked_add(info.to_countersigner_value_sat)
            .ok_or_else(|| {
                policy_error(
                    "policy-commitment-payment-velocity",
                    "channel value overflow".to_string(),
                )
            })?
            .checked_add(htlc_value_sat)
            .ok_or_else(|| {
                policy_error(
                    "policy-commitment-payment-velocity",
                    "channel value overflow on HTLC".to_string(),
                )
            })?;
        self.validate_fee(
            "policy-commitment-fee-range",
            setup.channel_value_sat,
            sum_outputs,
            expected_weight,
        )
        .map_err(|ve| ve.prepend_msg(format!("{}: ", containing_function!())))?;

        let (_holder_value_sat, counterparty_value_sat) = info.value_to_parties();

        // Enforce additional requirements on initial commitments.
        if commit_num == 0 {
            if info.offered_htlcs.len() + info.received_htlcs.len() > 0 {
                policy_err!(
                    self,
                    "policy-commitment-first-no-htlcs",
                    "initial commitment may not have HTLCS"
                );
            }

            // If we are the funder, the value to us of the initial
            // commitment transaction should be equal to our funding
            // value.
            if setup.is_outbound {
                // Ensure that no extra value is sent to fundee, the
                // no-initial-htlcs and fee checks above will ensure
                // that our share is valid.

                // The fundee is only entitled to push_value
                if counterparty_value_sat > setup.push_value_msat / 1000 {
                    policy_err!(
                        self,
                        "policy-commitment-initial-funding-value",
                        "initial commitment may only send push_value_msat ({}) to fundee",
                        setup.push_value_msat
                    );
                }
            }
        }

        *debug_on_return = false;
        Ok(())
    }
}

/// Construct a simple policy
pub fn make_simple_policy(network: Network, config: OptionizedSimplePolicy) -> SimplePolicy {
    config.resolve_defaults(make_default_simple_policy(network))
}

/// Construct a default simple policy
pub fn make_default_simple_policy(network: Network) -> SimplePolicy {
    if network == Network::Bitcoin {
        SimplePolicy {
            min_delay: 144,  // LDK min
            max_delay: 2016, // LDK max
            max_channel_size_sat: 1_000_000_001,
            epsilon_sat: 10_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216,
            use_chain_state: false,
            min_feerate_per_kw: 253,    // mainnet observed
            max_feerate_per_kw: 25_000, // equiv to 100 sat/vb
            enforce_balance: false,
            max_routing_fee_msat: 10_000,
            max_feerate_percentage: 10,
            dev_flags: None,
            filter: PolicyFilter::default(),
            global_velocity_control: VelocityControlSpec::UNLIMITED,
            max_channels: MAX_CHANNELS,
            max_invoices: MAX_INVOICES,
            fee_velocity_control: DEFAULT_FEE_VELOCITY_CONTROL,
        }
    } else {
        SimplePolicy {
            min_delay: 4,
            max_delay: 2016,                     // Match LDK maximum and default
            max_channel_size_sat: 1_000_000_001, // lnd itest: wumbu default + 1
            // lnd itest: async_bidirectional_payments (large amount of dust HTLCs) 1_600_000
            epsilon_sat: 10_000, // c-lightning
            max_htlcs: 1000,
            max_htlc_value_sat: 16_777_216, // lnd itest: multi-hop_htlc_error_propagation
            use_chain_state: false,
            min_feerate_per_kw: 253,     // testnet/regtest observed
            max_feerate_per_kw: 333_333, // 301_096 observed in testnet
            enforce_balance: false,
            max_routing_fee_msat: 222_000, // CLN test_pay_avoid_low_fee_chan_1: 200_000
            max_feerate_percentage: 10,
            dev_flags: None,
            filter: PolicyFilter::default(),
            global_velocity_control: VelocityControlSpec::UNLIMITED,
            max_channels: MAX_CHANNELS,
            max_invoices: MAX_INVOICES,
            fee_velocity_control: DEFAULT_FEE_VELOCITY_CONTROL,
        }
    }
}

#[cfg(test)]
mod tests {
    use lightning::types::payment::PaymentHash;
    use test_log::test;

    use crate::policy::filter::FilterRule;
    use crate::tx::tx::HTLCInfo2;
    use crate::util::test_utils::key::*;
    use crate::util::test_utils::*;

    use super::*;

    fn make_test_validator() -> SimpleValidator {
        let policy = SimplePolicy {
            min_delay: 5,
            max_delay: 1440,
            max_channel_size_sat: 100_000_000,
            epsilon_sat: 100_000,
            max_htlcs: 1000,
            max_htlc_value_sat: 10_000_000,
            use_chain_state: true,
            min_feerate_per_kw: 1000,
            max_feerate_per_kw: 1000 * 1000,
            max_feerate_percentage: 10,
            enforce_balance: false,
            max_routing_fee_msat: 10000,
            dev_flags: None,
            filter: PolicyFilter::default(),
            global_velocity_control: VelocityControlSpec::UNLIMITED,
            max_channels: MAX_CHANNELS,
            max_invoices: MAX_INVOICES,
            fee_velocity_control: DEFAULT_FEE_VELOCITY_CONTROL,
        };

        SimpleValidator {
            policy,
            node_id: PublicKey::from_slice(&[2u8; 33]).unwrap(),
            channel_id: None,
        }
    }

    #[test]
    fn decode_commitment_test() {
        let validator = make_test_validator();
        let info = validator
            .decode_commitment_tx(
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
        tx.version = Version::ONE;
        let res = validator.decode_commitment_tx(
            &make_test_channel_keys(),
            &make_test_channel_setup(),
            true,
            &tx,
            &vec![vec![]],
        );
        assert_policy_err!(
            res,
            "policy-commitment-version",
            "decode_commitment_tx: bad commitment version: 1"
        );
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

    fn make_counterparty_info(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
    ) -> CommitmentInfo2 {
        make_counterparty_info_with_feerate(
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            6500,
        )
    }

    fn make_counterparty_info_with_feerate(
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        offered_htlcs: Vec<HTLCInfo2>,
        received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> CommitmentInfo2 {
        CommitmentInfo2::new(
            true,
            to_holder_value_sat,
            to_counterparty_value_sat,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        )
    }

    fn make_htlc_info2(expiry: u32) -> HTLCInfo2 {
        HTLCInfo2 { value_sat: 5010, payment_hash: PaymentHash([0; 32]), cltv_expiry: expiry }
    }

    #[test]
    fn validate_commitment_tx_test() {
        let validator = make_test_validator();
        let mut enforcement_state = EnforcementState::new(0);
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info = make_counterparty_info(2_000_000, 999_000, vec![], vec![]);
        assert_status_ok!(validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info,
        ));
    }

    // policy-channel-contest-delay-range-holder
    // policy-commitment-to-self-delay-range
    #[test]
    fn validate_to_holder_min_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.holder_selected_contest_delay = 5;
        let derivation_path = DerivationPath::master();
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());
        setup.holder_selected_contest_delay = 4;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-contest-delay-range-counterparty",
            "validate_delay: counterparty contest-delay too small: 4 < 5"
        );
    }

    // policy-channel-safe-type
    #[test]
    fn validate_safe_modes_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();

        let derivation_path = DerivationPath::master();
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());

        setup.commitment_type = CommitmentType::AnchorsZeroFeeHtlc;
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());

        setup.commitment_type = CommitmentType::Anchors;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-safe-type",
            "validate_setup_channel: unsafe commitment type: Anchors"
        );
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_err());

        setup.commitment_type = CommitmentType::Legacy;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-safe-type",
            "validate_setup_channel: unsafe commitment type: Legacy"
        );
    }

    // policy-channel-contest-delay-range-holder
    // policy-commitment-to-self-delay-range
    #[test]
    fn validate_to_holder_max_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.holder_selected_contest_delay = 1440;
        let derivation_path = DerivationPath::master();
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());
        setup.holder_selected_contest_delay = 1441;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-contest-delay-range-counterparty",
            "validate_delay: counterparty contest-delay too large: 1441 > 1440"
        );
    }

    // policy-channel-contest-delay-range-counterparty
    // policy-commitment-to-self-delay-range
    #[test]
    fn validate_to_counterparty_min_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.counterparty_selected_contest_delay = 5;
        let derivation_path = DerivationPath::master();
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());

        setup.counterparty_selected_contest_delay = 4;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-contest-delay-range-holder",
            "validate_delay: holder contest-delay too small: 4 < 5"
        );
    }

    // policy-channel-contest-delay-range-counterparty
    // policy-commitment-to-self-delay-range
    #[test]
    fn validate_to_counterparty_max_delay_test() {
        let node = init_node(TEST_NODE_CONFIG, TEST_SEED[1]);
        let mut setup = make_test_channel_setup();
        let validator = make_test_validator();
        setup.counterparty_selected_contest_delay = 1440;
        let derivation_path = DerivationPath::master();
        assert!(validator.validate_setup_channel(&*node, &setup, &derivation_path).is_ok());

        setup.counterparty_selected_contest_delay = 1441;
        assert_policy_err!(
            validator.validate_setup_channel(&*node, &setup, &derivation_path),
            "policy-channel-contest-delay-range-holder",
            "validate_delay: holder contest-delay too large: 1441 > 1440"
        );
    }

    // policy-commitment-fee-range
    #[test]
    fn validate_commitment_tx_shortage_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new(0);
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info_bad = make_counterparty_info(2_000_000, 1_000_001, vec![], vec![]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-fee-range",
            "validate_commitment_tx: fee underflow: 3000000 - 3000001"
        );
    }

    // policy-commitment-fee-range
    #[test]
    fn validate_commitment_tx_htlc_shortage_test() {
        let validator = make_test_validator();
        let htlc =
            HTLCInfo2 { value_sat: 100_000, payment_hash: PaymentHash([0; 32]), cltv_expiry: 1005 };
        let mut enforcement_state = EnforcementState::new(0);
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info = make_counterparty_info(2_000_000, 899_000, vec![htlc.clone()], vec![]);

        assert_status_ok!(validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info,
        ));

        let info_bad = make_counterparty_info(2_000_000, 1_000_000, vec![htlc.clone()], vec![]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-fee-range",
            "validate_commitment_tx: fee underflow: 3000000 - 3100000"
        );
    }

    // policy-commitment-first-no-htlcs
    #[test]
    fn validate_commitment_tx_initial_with_htlcs() {
        let validator = make_test_validator();
        let htlc =
            HTLCInfo2 { value_sat: 199_000, payment_hash: PaymentHash([0; 32]), cltv_expiry: 1005 };
        let enforcement_state = EnforcementState::new(0);
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info = make_counterparty_info(2_000_000, 800_000, vec![htlc.clone()], vec![]);

        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info,
        );
        assert_policy_err!(
            status,
            "policy-commitment-first-no-htlcs",
            "validate_commitment_tx: initial commitment may not have HTLCS"
        );
    }

    // policy-commitment-initial-funding-value
    #[test]
    fn validate_commitment_tx_initial_with_bad_fundee_output() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new(0);
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info = make_counterparty_info(2_000_000, 999_000, vec![], vec![]);

        let status = validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info,
        );
        assert_policy_err!(
            status,
            "policy-commitment-initial-funding-value",
            "validate_commitment_tx: initial commitment may only send push_value_msat (0) to fundee"
        );
    }

    // policy-commitment-htlc-count-limit
    #[test]
    fn validate_commitment_tx_htlc_count_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new(0);
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let htlcs = (0..1001).map(|_| make_htlc_info2(1100)).collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, vec![], htlcs);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-htlc-count-limit",
            "validate_commitment_tx: too many HTLCs"
        );
    }

    // policy-commitment-htlc-inflight-limit
    #[test]
    fn validate_commitment_tx_htlc_value_test() {
        let validator = make_test_validator();
        let enforcement_state = EnforcementState::new(0);
        let commit_num = 0;
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let htlcs = (0..1000)
            .map(|_| HTLCInfo2 {
                value_sat: 10001,
                payment_hash: PaymentHash([0; 32]),
                cltv_expiry: 1100,
            })
            .collect();
        let info_bad = make_counterparty_info(99_000_000, 900_000, vec![], htlcs);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-htlc-inflight-limit",
            "validate_commitment_tx: sum of HTLC values 10001000 too large"
        );
    }

    #[test]
    fn validate_commitment_tx_htlc_delay_test() {
        let validator = make_test_validator();
        let mut enforcement_state = EnforcementState::new(0);
        let commit_num = 23;
        enforcement_state
            .set_next_counterparty_commit_num_for_testing(commit_num, make_test_pubkey(0x10));
        enforcement_state.set_next_counterparty_revoke_num_for_testing(commit_num - 1);
        let commit_point = make_test_pubkey(0x12);
        let cstate = make_test_chain_state();
        let setup = make_test_channel_setup();
        let info_good =
            make_counterparty_info(2_000_000, 990_000, vec![], vec![make_htlc_info2(1005)]);
        assert_validation_ok!(validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info_good,
        ));
        let info_good =
            make_counterparty_info(2_000_000, 990_000, vec![], vec![make_htlc_info2(2440)]);
        assert_validation_ok!(validator.validate_commitment_tx(
            &enforcement_state,
            commit_num,
            &commit_point,
            &setup,
            &cstate,
            &info_good,
        ));
        let info_bad =
            make_counterparty_info(2_000_000, 990_000, vec![], vec![make_htlc_info2(1004)]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-htlc-cltv-range",
            "validate_expiry: received HTLC expiry too early: 1004 < 1005"
        );
        let info_bad =
            make_counterparty_info(2_000_000, 990_000, vec![], vec![make_htlc_info2(2441)]);
        assert_policy_err!(
            validator.validate_commitment_tx(
                &enforcement_state,
                commit_num,
                &commit_point,
                &setup,
                &cstate,
                &info_bad,
            ),
            "policy-commitment-htlc-cltv-range",
            "validate_expiry: received HTLC expiry too late: 2441 > 2440"
        );
    }

    #[test]
    fn enforcement_state_previous_counterparty_point_test() {
        let mut state = EnforcementState::new(0);
        let validator = make_test_validator();

        let point0 = make_test_pubkey(0x12);
        let commit_info = make_test_commitment_info();

        // you can never set next to 0
        assert_policy_err!(
            validator.set_next_counterparty_commit_num(
                &mut state,
                0,
                point0.clone(),
                commit_info.clone()
            ),
            "policy-other",
            "set_next_counterparty_commit_num: can\'t set next to 0"
        );

        // point for 0 is not set yet
        assert_eq!(state.get_previous_counterparty_point(0), None);

        // can't look forward either
        assert_eq!(state.get_previous_counterparty_point(1), None);

        // can't skip forward
        assert_policy_err!(
            validator.set_next_counterparty_commit_num(
                &mut state,
                2,
                point0.clone(),
                commit_info.clone()
            ),
            "policy-commitment-previous-revoked",
            "set_next_counterparty_commit_num: invalid progression: 0 to 2"
        );

        // set point 0
        assert!(validator
            .set_next_counterparty_commit_num(&mut state, 1, point0.clone(), commit_info.clone())
            .is_ok());

        // and now you can get it.
        assert_eq!(state.get_previous_counterparty_point(0).unwrap(), point0.clone());

        // you can set it again to the same thing (retry)
        // policy-v2-commitment-retry-same
        assert!(validator
            .set_next_counterparty_commit_num(&mut state, 1, point0.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 1);

        // can't get commit_num 1 yet
        assert_eq!(state.get_previous_counterparty_point(1), None);

        // can't skip forward
        let point1 = make_test_pubkey(0x16);
        assert_policy_err!(
            validator.set_next_counterparty_commit_num(
                &mut state,
                3,
                point1.clone(),
                commit_info.clone()
            ),
            "policy-commitment-previous-revoked",
            "set_next_counterparty_commit_num: \
             invalid progression: 1 to 3"
        );
        assert_eq!(state.next_counterparty_commit_num, 1);

        // set point 1
        assert!(validator
            .set_next_counterparty_commit_num(&mut state, 2, point1.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 2);

        // you can still get commit_num 0
        assert_eq!(state.get_previous_counterparty_point(0).unwrap(), point0.clone());

        // Now you can get commit_num 1
        assert_eq!(state.get_previous_counterparty_point(1).unwrap(), point1.clone());

        // can't look forward
        assert_eq!(state.get_previous_counterparty_point(2), None);

        // can't skip forward
        assert_policy_err!(
            validator.set_next_counterparty_commit_num(
                &mut state,
                4,
                point1.clone(),
                commit_info.clone()
            ),
            "policy-commitment-previous-revoked",
            "set_next_counterparty_commit_num: invalid progression: 2 to 4"
        );
        assert_eq!(state.next_counterparty_commit_num, 2);

        assert!(validator.set_next_counterparty_revoke_num(&mut state, 1).is_ok());

        // set point 2
        let point2 = make_test_pubkey(0x20);
        assert!(validator
            .set_next_counterparty_commit_num(&mut state, 3, point2.clone(), commit_info.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 3);

        // You can't get commit_num 0 anymore
        assert_eq!(state.get_previous_counterparty_point(0), None);

        // you can still get commit_num 1
        assert_eq!(state.get_previous_counterparty_point(1).unwrap(), point1.clone());

        // now you can get commit_num 2
        assert_eq!(state.get_previous_counterparty_point(2).unwrap(), point2.clone());

        // can't look forward
        assert_eq!(state.get_previous_counterparty_point(3), None);
    }

    #[test]
    fn validate_payment_balance_with_zero_invoiced_amount_test() {
        let validator = make_test_validator();
        let result = validator.validate_payment_balance(100, 100, Some(0));
        assert!(result.is_ok());
    }
}
