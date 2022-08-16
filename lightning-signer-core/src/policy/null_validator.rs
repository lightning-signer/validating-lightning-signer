use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{self, EcdsaSighashType, Network, Script, Sighash, Transaction};
use lightning::chain::keysinterface::InMemorySigner;
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};

use crate::channel::{ChannelId, ChannelSetup, ChannelSlot};
use crate::policy::simple_validator::SimpleValidatorFactory;
use crate::policy::validator::EnforcementState;
use crate::policy::validator::{ChainState, Validator, ValidatorFactory};
use crate::policy::Policy;
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::wallet::Wallet;

extern crate scopeguard;

use super::error::ValidationError;

/// A factory for NullValidator
pub struct NullValidatorFactory {}

fn null_validator() -> NullValidator {
    let factory = SimpleValidatorFactory::new();
    NullValidator {
        0: factory.make_validator(
            Network::Regtest,
            PublicKey::from_slice(&[2u8; 33]).unwrap(),
            None,
        ),
    }
}

impl ValidatorFactory for NullValidatorFactory {
    fn make_validator(
        &self,
        _network: Network,
        _node_id: PublicKey,
        _channel_id: Option<ChannelId>,
    ) -> Arc<dyn Validator> {
        Arc::new(null_validator())
    }

    fn policy(&self, network: Network) -> Box<dyn Policy> {
        let factory = SimpleValidatorFactory::new();
        factory.policy(network)
    }
}

/// A null validator
pub struct NullValidator(Arc<dyn Validator>); // So we can DRY by borrowing its decode methods ...

impl Validator for NullValidator {
    fn validate_ready_channel(
        &self,
        _wallet: &Wallet,
        _setup: &ChannelSetup,
        _holder_shutdown_key_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_channel_value(&self, _setup: &ChannelSetup) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_onchain_tx(
        &self,
        _wallet: &Wallet,
        _channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        _tx: &Transaction,
        _values_sat: &Vec<u64>,
        _opaths: &Vec<Vec<u32>>,
        _weight: usize,
    ) -> Result<(), ValidationError> {
        Ok(())
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
        self.0.decode_commitment_tx(keys, setup, is_counterparty, tx, output_witscripts)
    }

    fn validate_counterparty_commitment_tx(
        &self,
        _estate: &EnforcementState,
        _commit_num: u64,
        _commitment_point: &PublicKey,
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_holder_commitment_tx(
        &self,
        _estate: &EnforcementState,
        _commit_num: u64,
        _commitment_point: &PublicKey,
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _info: &CommitmentInfo2,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_counterparty_revocation(
        &self,
        _state: &EnforcementState,
        _revoke_num: u64,
        _commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError> {
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
    ) -> Result<(u32, HTLCOutputInCommitment, Sighash, EcdsaSighashType), ValidationError> {
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
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _is_counterparty: bool,
        _htlc: &HTLCOutputInCommitment,
        _feerate_per_kw: u32,
    ) -> Result<(), ValidationError> {
        Ok(())
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
        self.0.decode_and_validate_mutual_close_tx(wallet, setup, estate, tx, wallet_paths)
    }

    fn validate_mutual_close_tx(
        &self,
        _wallet: &Wallet,
        _setup: &ChannelSetup,
        _estate: &EnforcementState,
        _to_holder_value_sat: u64,
        _to_counterparty_value_sat: u64,
        _holder_script: &Option<Script>,
        _counterparty_script: &Option<Script>,
        _holder_wallet_path_hint: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_delayed_sweep(
        &self,
        _wallet: &Wallet,
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _tx: &Transaction,
        _input: usize,
        _amount_sat: u64,
        _wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_counterparty_htlc_sweep(
        &self,
        _wallet: &Wallet,
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _tx: &Transaction,
        _redeemscript: &Script,
        _input: usize,
        _amount_sat: u64,
        _wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_justice_sweep(
        &self,
        _wallet: &Wallet,
        _setup: &ChannelSetup,
        _cstate: &ChainState,
        _tx: &Transaction,
        _input: usize,
        _amount_sat: u64,
        _wallet_path: &Vec<u32>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_payment_balance(
        &self,
        _incoming: u64,
        _outgoing: u64,
        _invoiced_amount: Option<u64>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn minimum_initial_balance(&self, _holder_value_msat: u64) -> u64 {
        0
    }

    fn policy(&self) -> Box<&dyn Policy> {
        self.0.policy()
    }
}
