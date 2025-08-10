#![allow(unused_variables)]

use crate::channel::{ChannelId, ChannelSetup, ChannelSlot};
use crate::policy::error::ValidationError;
use crate::policy::simple_validator::make_default_simple_policy;
use crate::policy::validator::{
    validate_block, ChainState, EnforcementState, Validator, ValidatorFactory,
};
use crate::policy::Policy;
use crate::prelude::{Arc, Mutex};
use crate::tx::tx::{CommitmentInfo, CommitmentInfo2};
use crate::wallet::Wallet;
use bitcoin::bip32::DerivationPath;
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::hash_types::FilterHeader;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SegwitV0Sighash};
use bitcoin::{BlockHash, Network, OutPoint, ScriptBuf, Transaction};
use lightning::ln::chan_utils::{ClosingTransaction, HTLCOutputInCommitment, TxCreationKeys};
use lightning::sign::InMemorySigner;
use txoo::proof::TxoProof;

#[derive(Clone)]
pub(crate) struct MockValidator {
    pub last_validated_watches: Arc<Mutex<Vec<OutPoint>>>,
    pub policy: Arc<dyn Policy>,
}

impl MockValidator {
    pub fn new() -> Self {
        MockValidator {
            last_validated_watches: Arc::new(Mutex::new(vec![])),
            policy: Arc::new(make_default_simple_policy(Network::Regtest)),
        }
    }
}

pub(crate) struct MockValidatorFactory {
    validator: Arc<MockValidator>,
}

impl MockValidatorFactory {
    pub fn new() -> Self {
        MockValidatorFactory { validator: Arc::new(MockValidator::new()) }
    }

    pub fn validator(&self) -> Arc<MockValidator> {
        self.validator.clone()
    }
}

impl ValidatorFactory for MockValidatorFactory {
    fn make_validator(
        &self,
        network: Network,
        node_id: PublicKey,
        channel_id: Option<ChannelId>,
    ) -> Arc<dyn Validator> {
        self.validator()
    }

    fn policy(&self, network: Network) -> Box<dyn Policy> {
        Box::new(make_default_simple_policy(Network::Regtest))
    }
}

impl Validator for MockValidator {
    fn validate_setup_channel(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        holder_shutdown_key_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_channel_value(&self, setup: &ChannelSetup) -> Result<(), ValidationError> {
        todo!()
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
        todo!()
    }

    fn decode_commitment_tx(
        &self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        is_counterparty: bool,
        tx: &Transaction,
        output_witscripts: &[Vec<u8>],
    ) -> Result<CommitmentInfo, ValidationError> {
        todo!()
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
        todo!()
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
        todo!()
    }

    fn validate_counterparty_revocation(
        &self,
        state: &EnforcementState,
        revoke_num: u64,
        commitment_secret: &SecretKey,
    ) -> Result<(), ValidationError> {
        todo!()
    }

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
        todo!()
    }

    fn validate_htlc_tx(
        &self,
        setup: &ChannelSetup,
        cstate: &ChainState,
        is_counterparty: bool,
        htlc: &HTLCOutputInCommitment,
        feerate_per_kw: u32,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn decode_and_validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        tx: &Transaction,
        opaths: &[DerivationPath],
    ) -> Result<ClosingTransaction, ValidationError> {
        todo!()
    }

    fn validate_mutual_close_tx(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        state: &EnforcementState,
        to_holder_value_sat: u64,
        to_counterparty_value_sat: u64,
        holder_shutdown_script: &Option<ScriptBuf>,
        counterparty_shutdown_script: &Option<ScriptBuf>,
        holder_wallet_path_hint: &DerivationPath,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_delayed_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        todo!()
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
        key_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_justice_sweep(
        &self,
        wallet: &dyn Wallet,
        setup: &ChannelSetup,
        cstate: &ChainState,
        tx: &Transaction,
        input: usize,
        amount_sat: u64,
        key_path: &DerivationPath,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payment_balance(
        &self,
        incoming: u64,
        outgoing: u64,
        invoiced_amount_msat: Option<u64>,
    ) -> Result<(), ValidationError> {
        todo!()
    }

    fn minimum_initial_balance(&self, holder_value_msat: u64) -> u64 {
        todo!()
    }

    fn is_ready(&self, _cstate: &ChainState) -> bool {
        todo!()
    }

    fn policy(&self) -> Box<&dyn Policy> {
        Box::new(self.policy.as_ref())
    }

    fn validate_block(
        &self,
        proof: &TxoProof,
        height: u32,
        header: &BlockHeader,
        external_block_hash: Option<&BlockHash>,
        prev_filter_header: &FilterHeader,
        outpoint_watches: &[OutPoint],
        trusted_oracle_pubkeys: &Vec<PublicKey>,
    ) -> Result<(), ValidationError> {
        *self.last_validated_watches.lock().unwrap() = outpoint_watches.to_vec();
        return validate_block(
            self,
            proof,
            height,
            header,
            external_block_hash,
            prev_filter_header,
            outpoint_watches,
            trusted_oracle_pubkeys,
        );
    }
}
