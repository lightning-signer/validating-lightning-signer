use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{self, Network, Script, SigHash, SigHashType, Transaction};
use lightning::chain::keysinterface::InMemorySigner;
use lightning::ln::chan_utils::{build_htlc_transaction, HTLCOutputInCommitment, TxCreationKeys};
use lightning::ln::PaymentHash;
use log::debug;

use crate::channel::{ChannelSetup, ChannelSlot};
use crate::policy::validator::EnforcementState;
use crate::policy::validator::{Validator, ValidatorFactory, ValidatorState};
use crate::prelude::*;
use crate::sync::Arc;
use crate::tx::tx::{
    build_close_tx, parse_offered_htlc_script, parse_received_htlc_script, CommitmentInfo,
    CommitmentInfo2, HTLC_SUCCESS_TX_WEIGHT, HTLC_TIMEOUT_TX_WEIGHT,
};
use crate::util::debug_utils::{
    script_debug, DebugInMemorySigner, DebugTxCreationKeys, DebugVecVecU8,
};
use crate::wallet::Wallet;

extern crate scopeguard;

use super::error::{policy_error, transaction_format_error, ValidationError};

/// A factory for NullValidator
pub struct NullValidatorFactory {}

const EPSILON_SAT: u64 = 80_000;

fn null_validator() -> NullValidator {
    NullValidator {}
}

impl ValidatorFactory for NullValidatorFactory {
    fn make_validator(&self, _network: Network) -> Box<dyn Validator> {
        Box::new(null_validator())
    }
}

/// A simple validator
pub struct NullValidator {}

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

    fn validate_funding_tx(
        &self,
        _wallet: &Wallet,
        _channels: Vec<Option<Arc<Mutex<ChannelSlot>>>>,
        _state: &ValidatorState,
        _tx: &Transaction,
        _values_sat: &Vec<u64>,
        _opaths: &Vec<Vec<u32>>,
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
        let mut debug_on_return = scoped_debug_return!(
            DebugInMemorySigner(keys),
            setup,
            is_counterparty,
            tx,
            DebugVecVecU8(output_witscripts)
        );

        let mut info = CommitmentInfo::new(is_counterparty);
        for ind in 0..tx.output.len() {
            info.handle_output(
                keys,
                setup,
                &tx.output[ind],
                output_witscripts[ind].as_slice(),
            )
            .map_err(|ve| {
                ve.prepend_msg(format!("{}: tx output[{}]: ", containing_function!(), ind))
            })?;
        }

        *debug_on_return = false;
        Ok(info)
    }

    fn validate_counterparty_commitment_tx(
        &self,
        _estate: &EnforcementState,
        _commit_num: u64,
        _commitment_point: &PublicKey,
        _setup: &ChannelSetup,
        _vstate: &ValidatorState,
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
        _vstate: &ValidatorState,
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
    ) -> Result<(u32, HTLCOutputInCommitment, SigHash), ValidationError> {
        let to_self_delay = if is_counterparty {
            setup.holder_selected_contest_delay // the local side imposes this value
        } else {
            setup.counterparty_selected_contest_delay // the remote side imposes this value
        };

        let offered = if parse_offered_htlc_script(redeemscript, setup.option_anchor_outputs())
            .is_ok()
        {
            true
        } else if parse_received_htlc_script(redeemscript, setup.option_anchor_outputs()).is_ok() {
            false
        } else {
            debug_failed_vals!(
                is_counterparty,
                setup,
                DebugTxCreationKeys(txkeys),
                tx,
                redeemscript,
                htlc_amount_sat,
                output_witscript
            );
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

        Ok((feerate_per_kw, htlc, recomposed_tx_sighash))
    }

    fn validate_htlc_tx(
        &self,
        _setup: &ChannelSetup,
        _state: &ValidatorState,
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
    ) -> Result<Transaction, ValidationError> {
        // Log state and inputs if we don't succeed.
        let should_debug = true;
        let mut debug_on_return = scopeguard::guard(should_debug, |should_debug| {
            if should_debug {
                if log::log_enabled!(log::Level::Debug) {
                    debug!(
                        "{} failed: {}",
                        containing_function!(),
                        vals_str!(setup, estate, tx, wallet_paths)
                    );

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
        let holder_value = estate.minimum_to_holder_value(EPSILON_SAT);
        let cparty_value = estate.minimum_to_counterparty_value(EPSILON_SAT);
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

        *debug_on_return = false; // don't debug when we succeed
        Ok(recomposed_tx)
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
}
