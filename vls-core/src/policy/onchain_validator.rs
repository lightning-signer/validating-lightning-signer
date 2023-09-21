use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{self, EcdsaSighashType, Network, Script, Sighash, Transaction};
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};
use lightning::sign::InMemorySigner;

use super::filter::PolicyFilter;
use super::simple_validator::SimpleValidatorFactory;
use super::validator::EnforcementState;
use super::validator::{ChainState, Validator, ValidatorFactory};
use super::{policy_error_with_filter, Policy, DEFAULT_FEE_VELOCITY_CONTROL};
use crate::channel::{ChannelId, ChannelSetup, ChannelSlot};
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::util::velocity::VelocityControlSpec;
use crate::wallet::Wallet;

use crate::policy::temporary_policy_error_with_filter;
use log::*;

extern crate scopeguard;

use super::error::ValidationError;

/// A factory for OnchainValidator
pub struct OnchainValidatorFactory {
    inner_factory: SimpleValidatorFactory,
}

impl OnchainValidatorFactory {
    /// Create a new onchain validator factory with default policy
    pub fn new() -> Self {
        Self { inner_factory: SimpleValidatorFactory::new() }
    }

    /// Create a new onchain validator factory with specific inner simple factory
    pub fn new_with_simple_factory(inner_factory: SimpleValidatorFactory) -> Self {
        Self { inner_factory }
    }
}

impl ValidatorFactory for OnchainValidatorFactory {
    fn make_validator(
        &self,
        network: Network,
        node_id: PublicKey,
        channel_id: Option<ChannelId>,
    ) -> Arc<dyn Validator> {
        // copy the filter from the inner
        let filter =
            self.inner_factory.policy.as_ref().map(|p| p.filter.clone()).unwrap_or_default();
        let validator = OnchainValidator {
            inner: self.inner_factory.make_validator(network, node_id, channel_id),
            policy: make_onchain_policy(network, filter),
        };
        Arc::new(validator)
    }

    fn policy(&self, network: Network) -> Box<dyn Policy> {
        self.inner_factory.policy(network)
    }
}

/// An on-chain validator, subsumes the policy checks of SimpleValidator
pub struct OnchainValidator {
    inner: Arc<dyn Validator>,
    policy: OnchainPolicy,
}

/// Policy to configure the onchain validator
pub struct OnchainPolicy {
    /// Policy filter
    pub filter: PolicyFilter,
    /// Minimum funding confirmations
    pub min_funding_depth: u16,
}

impl Policy for OnchainPolicy {
    fn policy_error(&self, tag: String, msg: String) -> Result<(), ValidationError> {
        policy_error_with_filter(tag, msg, &self.filter)
    }

    fn temporary_policy_error(&self, tag: String, msg: String) -> Result<(), ValidationError> {
        temporary_policy_error_with_filter(tag, msg, &self.filter)
    }

    fn policy_log(&self, _tag: String, msg: String) {
        error!("{}", msg);
    }

    fn global_velocity_control(&self) -> VelocityControlSpec {
        VelocityControlSpec::UNLIMITED
    }

    fn fee_velocity_control(&self) -> VelocityControlSpec {
        DEFAULT_FEE_VELOCITY_CONTROL
    }
}

fn make_onchain_policy(_network: Network, filter: PolicyFilter) -> OnchainPolicy {
    OnchainPolicy { filter, min_funding_depth: 1 }
}

impl Validator for OnchainValidator {
    fn validate_setup_channel(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &[u32],
    ) -> Result<(), ValidationError> {
        self.inner.validate_setup_channel(wallet, setup, holder_shutdown_key_path)
    }

    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        self.inner.validate_channel_value(setup)
    }

    fn validate_onchain_tx(
        &self,
        wallet: &dyn Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        tx: &Transaction,
        segwit_flags: &[bool],
        values_sat: &[u64],
        opaths: &[Vec<u32>],
        weight: usize,
    ) -> Result<u64, ValidationError> {
        self.inner.validate_onchain_tx(
            wallet,
            channels,
            tx,
            segwit_flags,
            values_sat,
            opaths,
            weight,
        )
    }

    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &[Vec<u8>],
    ) -> Result<CommitmentInfo, ValidationError> {
        // Delegate to SimplePolicy
        self.inner.decode_commitment_tx(keys, setup, is_counterparty, tx, output_witscripts)
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
        // Only allow state advancement if funding is buried and unspent
        self.ensure_funding_buried_and_unspent(commit_num, cstate)?;
        self.inner.validate_counterparty_commitment_tx(
            estate,
            commit_num,
            commitment_point,
            setup,
            cstate,
            info2,
        )
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
        // Only allow state advancement if funding is buried and unspent
        if estate.next_holder_commit_num <= commit_num {
            self.ensure_funding_buried_and_unspent(commit_num, cstate)?;
        }
        self.inner.validate_holder_commitment_tx(
            estate,
            commit_num,
            commitment_point,
            setup,
            cstate,
            info2,
        )
    }

    fn validate_counterparty_revocation(
        &self,
        state: &EnforcementState,
        revoke_num: u64,
        commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError> {
        self.inner.validate_counterparty_revocation(state, revoke_num, commitment_secret)
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
    ) -> Result<(u32, HTLCOutputInCommitment, Sighash, EcdsaSighashType), ValidationError> {
        // Delegate to SimplePolicy
        self.inner.decode_and_validate_htlc_tx(
            is_counterparty,
            setup,
            txkeys,
            tx,
            redeemscript,
            htlc_amount_sat,
            output_witscript,
        )
    }

    fn validate_htlc_tx(
        &self,
        setup: &ChannelSetup,
        cstate: &ChainState,
        is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError> {
        self.inner.validate_htlc_tx(setup, cstate, is_counterparty, htlc, feerate_per_kw)
    }

    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        tx: &Transaction,
        wallet_paths: &[Vec<u32>],
    ) -> Result<ClosingTransaction, ValidationError> {
        // Delegate to SimplePolicy
        self.inner.decode_and_validate_mutual_close_tx(wallet, setup, estate, tx, wallet_paths)
    }

    fn validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<Script>,
        counterparty_script: &Option<Script>,
        holder_wallet_path_hint: &[u32],
    ) -> Result<(), ValidationError> {
        self.inner.validate_mutual_close_tx(
            wallet,
            setup,
            state,
            to_holder_value_sat,
            to_counterparty_value_sat,
            holder_script,
            counterparty_script,
            holder_wallet_path_hint,
        )
    }

    fn validate_delayed_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<(), ValidationError> {
        self.inner.validate_delayed_sweep(wallet, setup, cstate, tx, input, amount_sat, wallet_path)
    }

    fn validate_counterparty_htlc_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        redeemscript: &Script,
        input: usize,
        amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<(), ValidationError> {
        self.inner.validate_counterparty_htlc_sweep(
            wallet,
            setup,
            cstate,
            tx,
            redeemscript,
            input,
            amount_sat,
            wallet_path,
        )
    }

    fn validate_justice_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &[u32],
    ) -> Result<(), ValidationError> {
        self.inner.validate_justice_sweep(wallet, setup, cstate, tx, input, amount_sat, wallet_path)
    }

    fn validate_payment_balance(
        &self,
        incoming_msat: u64,
        outgoing_msat: u64,
        invoiced_amount_msat: Option<u64>,
    ) -> Result<(), ValidationError> {
        self.inner.validate_payment_balance(incoming_msat, outgoing_msat, invoiced_amount_msat)
    }

    fn minimum_initial_balance(&self, holder_value_msat: u64) -> u64 {
        self.inner.minimum_initial_balance(holder_value_msat)
    }

    fn policy(&self) -> Box<&dyn Policy> {
        Box::new(&self.policy)
    }
}

impl OnchainValidator {
    fn ensure_funding_buried_and_unspent(
        &self,
        commit_num: u64,
        cstate: &ChainState,
    ) -> Result<(), ValidationError> {
        debug!(
            "ensure_funding_buried_and_unspent commit_num {} depth {} our height {}",
            commit_num, cstate.funding_depth, cstate.current_height
        );

        // If we are trying to move beyond the initial commitment, ensure funding is on-chain and
        // had enough confirmations.
        if commit_num > 0 {
            if cstate.funding_depth < self.policy.min_funding_depth as u32 {
                temporary_policy_err!(
                    self,
                    "policy-commitment-spends-active-utxo",
                    "tried commitment {} when funding is not buried at depth {}, our height {}",
                    commit_num,
                    cstate.funding_depth,
                    cstate.current_height,
                );
            }

            if cstate.closing_depth > 0 {
                policy_err!(
                    self,
                    "policy-commitment-spends-active-utxo",
                    "tried commitment {} after closed on-chain at depth {}",
                    commit_num,
                    cstate.closing_depth
                );
            }
        }
        Ok(())
    }
}
