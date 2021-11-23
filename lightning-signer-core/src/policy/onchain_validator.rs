use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{self, Network, Script, SigHash, Transaction};
use lightning::chain::keysinterface::InMemorySigner;
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};

use crate::channel::{ChannelSetup, ChannelSlot};
use crate::policy::simple_validator::{simple_validator, SimpleValidator};
use crate::policy::validator::EnforcementState;
use crate::policy::validator::{ChainState, Validator, ValidatorFactory};
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::wallet::Wallet;

extern crate scopeguard;

use super::error::ValidationError;

/// A factory for OnchainValidator
pub struct OnchainValidatorFactory {}

impl ValidatorFactory for OnchainValidatorFactory {
    fn make_validator(&self, network: Network) -> Box<dyn Validator> {
        let validator = OnchainValidator {
            0: simple_validator(network),
        };
        Box::new(validator)
    }
}

/// An on-chain validator, subsumes the policy checks of SimpleValidator
pub struct OnchainValidator(SimpleValidator);

impl Validator for OnchainValidator {
    fn validate_ready_channel(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        self.0.validate_ready_channel(wallet, setup, holder_shutdown_key_path)
    }

    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        self.0.validate_channel_value(setup)
    }

    fn validate_onchain_tx(
        &self,
        wallet: &Wallet,
        channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        tx: &Transaction,
        values_sat: &Vec<u64>,
        opaths: &Vec<Vec<u32>>,
    ) -> Result<(), ValidationError> {
        self.0.validate_onchain_tx(wallet, channels, tx, values_sat, opaths)
    }

    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &bitcoin::Transaction,
        output_witscripts: &Vec<Vec<u8>>,
    ) -> Result<CommitmentInfo, ValidationError> {
        // Delegate to SimplePolicy
        self.0
            .decode_commitment_tx(keys, setup, is_counterparty, tx, output_witscripts)
    }

    fn validate_counterparty_commitment_tx(
        &self,
        state: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        self.0.validate_counterparty_commitment_tx(state, commit_num, commitment_point, setup, cstate, info)
    }

    fn validate_holder_commitment_tx(
        &self,
        state: &EnforcementState,
        commit_num: u64,
        commitment_point: &PublicKey,
        setup: &ChannelSetup,
        cstate: &ChainState,
        info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        self.0.validate_holder_commitment_tx(state, commit_num, commitment_point, setup, cstate, info)
    }

    fn validate_counterparty_revocation(
        &self,
        state: &EnforcementState,
        revoke_num: u64,
        commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError> {
        self.0.validate_counterparty_revocation(state, revoke_num, commitment_secret)
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
        // Delegate to SimplePolicy
        self.0.decode_and_validate_htlc_tx(
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
        self.0.validate_htlc_tx(setup, cstate, is_counterparty, htlc, feerate_per_kw)
    }

    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        estate: &EnforcementState,
        tx: &Transaction,
        wallet_paths: &Vec<Vec<u32>>,
    ) -> Result<ClosingTransaction, ValidationError> {
        // Delegate to SimplePolicy
        self.0
            .decode_and_validate_mutual_close_tx(wallet, setup, estate, tx, wallet_paths)
    }

    fn validate_mutual_close_tx(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_script: &Option<Script>,
        counterparty_script: &Option<Script>,
        holder_wallet_path_hint: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        self.0.validate_mutual_close_tx(wallet, setup, state, to_holder_value_sat, to_counterparty_value_sat, holder_script, counterparty_script, holder_wallet_path_hint)
    }

    fn validate_delayed_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        self.0.validate_delayed_sweep(wallet, setup, cstate, tx, input, amount_sat, wallet_path)
    }

    fn validate_counterparty_htlc_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        redeemscript: &Script,
        input: usize,
        amount_sat: u64,
        wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        self.0.validate_counterparty_htlc_sweep(wallet, setup, cstate, tx, redeemscript, input, amount_sat, wallet_path)
    }

    fn validate_justice_sweep(
        &self,
        wallet: &Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        self.0.validate_justice_sweep(wallet, setup, cstate, tx, input, amount_sat, wallet_path)
    }
}
