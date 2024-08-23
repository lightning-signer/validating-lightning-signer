use crate::node::{PaymentState, RoutedPayment};
use crate::prelude::*;
use bitcoin::address::Payload;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Network, ScriptBuf};
use lightning::ln::chan_utils::{
    BuiltCommitmentTransaction, ChannelPublicKeys, CommitmentTransaction, HTLCOutputInCommitment,
    TxCreationKeys,
};
use lightning::ln::PaymentHash;
use lightning::sign::InMemorySigner;
use vls_common::HexEncode;

/// Debug printer for ChannelPublicKeys which doesn't have one.
pub struct DebugChannelPublicKeys<'a>(pub &'a ChannelPublicKeys);
impl<'a> core::fmt::Debug for DebugChannelPublicKeys<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("ChannelPublicKeys")
            .field("funding_pubkey", &self.0.funding_pubkey)
            .field("revocation_basepoint", &self.0.revocation_basepoint)
            .field("payment_point", &self.0.payment_point)
            .field("delayed_payment_basepoint", &self.0.delayed_payment_basepoint)
            .field("htlc_basepoint", &self.0.htlc_basepoint)
            .finish()
    }
}

macro_rules! log_channel_public_keys {
    ($obj: expr) => {
        &crate::util::debug_utils::DebugChannelPublicKeys(&$obj)
    };
}

/// log the enforcement state
#[doc(hidden)]
#[macro_export]
macro_rules! trace_enforcement_state {
    ($chan: expr) => {
        #[cfg(not(feature = "debug_enforcement_state"))]
        {
            #[cfg(not(feature = "log_pretty_print"))]
            trace!("{}:{:?}{:?}", function!(), &$chan.enforcement_state, &$chan.get_chain_state());
            #[cfg(feature = "log_pretty_print")]
            trace!(
                "{}:\n{:#?}\n{:#?}",
                function!(),
                &$chan.enforcement_state,
                &$chan.get_chain_state()
            );
        }
        #[cfg(feature = "debug_enforcement_state")]
        {
            #[cfg(not(feature = "log_pretty_print"))]
            debug!("{}:{:?}{:?}", function!(), &$chan.enforcement_state, &$chan.get_chain_state());
            #[cfg(feature = "log_pretty_print")]
            debug!(
                "{}:\n{:#?}\n{:#?}",
                function!(),
                &$chan.enforcement_state,
                &$chan.get_chain_state()
            );
        }
    };
}

/// log the node state
#[doc(hidden)]
#[macro_export]
macro_rules! trace_node_state {
    ($nodestate: expr) => {
        #[cfg(not(feature = "debug_node_state"))]
        {
            #[cfg(not(feature = "log_pretty_print"))]
            trace!("{}:{:?}", function!(), &$nodestate);
            #[cfg(feature = "log_pretty_print")]
            trace!("{}:\n{#:?}", function!(), &$nodestate);
        }
        #[cfg(feature = "debug_node_state")]
        {
            #[cfg(not(feature = "log_pretty_print"))]
            debug!("{}:{:?}", function!(), &$nodestate);
            #[cfg(feature = "log_pretty_print")]
            debug!("{}:\n{:#?}", function!(), &$nodestate);
        }
        // log the summary if it changed
        let (summary, changed) = &$nodestate.summary();
        if *changed {
            info!("{}: {}", function!(), summary);
        }
    };
}

/// Debug printer for Payload which uses hex encoded strings.
pub struct DebugPayload<'a>(pub &'a Payload);
impl<'a> core::fmt::Debug for DebugPayload<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self.0 {
            Payload::PubkeyHash(ref hash) =>
                f.debug_struct("PubkeyHash").field("hash", &hex::encode(hash)).finish(),
            Payload::ScriptHash(ref hash) =>
                f.debug_struct("ScriptHash").field("hash", &hex::encode(hash)).finish(),
            Payload::WitnessProgram(ref program) => f
                .debug_struct("WitnessProgram")
                .field("version", &program.version())
                .field("program", &program.program().to_hex())
                .finish(),
            _ => unreachable!(),
        }
    }
}

/// Debug printer for HTLCOutputInCommitment which doesn't have one.
pub struct DebugHTLCOutputInCommitment<'a>(pub &'a HTLCOutputInCommitment);
impl<'a> core::fmt::Debug for DebugHTLCOutputInCommitment<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("HTLCOutputInCommitment")
            .field("offered", &self.0.offered)
            .field("amount_msat", &self.0.amount_msat)
            .field("cltv_expiry", &self.0.cltv_expiry)
            .field("payment_hash", &self.0.payment_hash.0.to_hex())
            .field("transaction_output_index", &self.0.transaction_output_index)
            .finish()
    }
}

/// Debug support for Vec<HTLCOutputInCommitment>
pub struct DebugVecHTLCOutputInCommitment<'a>(pub &'a Vec<HTLCOutputInCommitment>);
impl<'a> core::fmt::Debug for DebugVecHTLCOutputInCommitment<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list().entries(self.0.iter().map(|vv| DebugHTLCOutputInCommitment(&vv))).finish()
    }
}

/// Debug printer for TxCreationKeys which doesn't have one.
pub struct DebugTxCreationKeys<'a>(pub &'a TxCreationKeys);
impl<'a> core::fmt::Debug for DebugTxCreationKeys<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("TxCreationKeys")
            .field("per_commitment_point", &self.0.per_commitment_point)
            .field("revocation_key", &self.0.revocation_key)
            .field("broadcaster_htlc_key", &self.0.broadcaster_htlc_key)
            .field("countersignatory_htlc_key", &self.0.countersignatory_htlc_key)
            .field("broadcaster_delayed_payment_key", &self.0.broadcaster_delayed_payment_key)
            .finish()
    }
}

/// Debug printer for InMemorySigner which doesn't have one.
pub struct DebugInMemorySigner<'a>(pub &'a InMemorySigner);
impl<'a> core::fmt::Debug for DebugInMemorySigner<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("InMemorySigner")
            .field("funding_key", &self.0.funding_key)
            .field("revocation_base_key", &self.0.revocation_base_key)
            .field("payment_key", &self.0.payment_key)
            .field("delayed_payment_base_key", &self.0.delayed_payment_base_key)
            .field("htlc_base_key", &self.0.htlc_base_key)
            .field("commitment_seed", &DebugBytes(&self.0.commitment_seed))
            .finish()
    }
}

/// Debug printer for BuiltCommitmentTransaction which doesn't have one.
pub struct DebugBuiltCommitmentTransaction<'a>(pub &'a BuiltCommitmentTransaction);
impl<'a> core::fmt::Debug for DebugBuiltCommitmentTransaction<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("BuiltCommitmentTransaction")
            .field("transaction", &self.0.transaction)
            .field("txid", &self.0.txid)
            .finish()
    }
}

/// Debug printer for CommitmentTransaction which doesn't have one.
pub struct DebugCommitmentTransaction<'a>(pub &'a CommitmentTransaction);
impl<'a> core::fmt::Debug for DebugCommitmentTransaction<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("CommitmentTransaction")
            .field("commitment_number", &self.0.commitment_number())
            .field("to_broadcaster_value_sat", &self.0.to_broadcaster_value_sat())
            .field("to_countersignatory_value_sat", &self.0.to_countersignatory_value_sat())
            .field("feerate_per_kw", &self.0.feerate_per_kw())
            .field("htlcs", &DebugVecHTLCOutputInCommitment(&self.0.htlcs()))
            .field("keys", &DebugTxCreationKeys(&self.0.trust().keys()))
            .field("built", &DebugBuiltCommitmentTransaction(&self.0.trust().built_transaction()))
            .finish()
    }
}

/// Debug support for bytes
#[derive(Clone)]
pub struct DebugBytes<'a>(pub &'a [u8]);
impl<'a> core::fmt::Debug for DebugBytes<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        for i in self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

/// Debug support for Vec<Vec<u8>>
pub struct DebugVecVecU8<'a>(pub &'a [Vec<u8>]);
impl<'a> core::fmt::Debug for DebugVecVecU8<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list().entries(self.0.iter().map(|vv| DebugBytes(&vv[..]))).finish()
    }
}

/// Debug support for a two element witness stack
pub struct DebugWitness<'a>(pub &'a (Vec<u8>, Vec<u8>));
impl<'a> core::fmt::Debug for DebugWitness<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("Witness")
            .field(&DebugBytes(&self.0 .0))
            .field(&DebugBytes(&self.0 .1))
            .finish()
    }
}

/// Debug support for a collection of two-element witness stacks
pub struct DebugWitVec<'a>(pub &'a Vec<(Vec<u8>, Vec<u8>)>);
impl<'a> core::fmt::Debug for DebugWitVec<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list().entries(self.0.iter().map(|ww| DebugWitness(ww))).finish()
    }
}

/// Debug support for a unilateral close key
pub struct DebugUnilateralCloseKey<'a>(pub &'a (SecretKey, Vec<Vec<u8>>));
impl<'a> core::fmt::Debug for DebugUnilateralCloseKey<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("UnilateralCloseKey")
            .field(&self.0 .0)
            .field(&DebugVecVecU8(&self.0 .1))
            .finish()
    }
}

/// Debug support for unilateral close info
pub struct DebugUnilateralCloseInfo<'a>(pub &'a Vec<Option<(SecretKey, Vec<Vec<u8>>)>>);
impl<'a> core::fmt::Debug for DebugUnilateralCloseInfo<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list()
            .entries(self.0.iter().map(|o| o.as_ref().map(|vv| DebugUnilateralCloseKey(&vv))))
            .finish()
    }
}

/// Debug support for Map<PaymentHash, PaymentState>
pub struct DebugMapPaymentState<'a>(pub &'a Map<PaymentHash, PaymentState>);
impl<'a> core::fmt::Debug for DebugMapPaymentState<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_map().entries(self.0.iter().map(|(k, v)| (DebugBytes(&k.0), v))).finish()
    }
}

/// Debug support for Map<PaymentHash, RoutedPayment>
pub struct DebugMapRoutedPayment<'a>(pub &'a Map<PaymentHash, RoutedPayment>);
impl<'a> core::fmt::Debug for DebugMapRoutedPayment<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_map().entries(self.0.iter().map(|(k, v)| (DebugBytes(&k.0), v))).finish()
    }
}

/// Debug support for Map<PaymentHash, u64>
pub struct DebugMapPaymentSummary<'a>(pub &'a Map<PaymentHash, u64>);
impl<'a> core::fmt::Debug for DebugMapPaymentSummary<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_map().entries(self.0.iter().map(|(k, v)| (DebugBytes(&k.0), v))).finish()
    }
}

/// Return a debug string for a bitcoin::Script
pub fn script_debug(script: &ScriptBuf, network: Network) -> String {
    format!(
        "script={} {}={}",
        script.to_hex(),
        network,
        match Address::from_script(script, network) {
            Ok(addr) => addr.to_string(),
            Err(_) => "<bad-address>".to_string(),
        },
    )
}

/// Return a scopeguard which debugs args on return unless disabled.
#[doc(hidden)]
#[macro_export]
macro_rules! scoped_debug_return {
    ( $($arg:tt)* ) => {{
        let should_debug = true;
        scopeguard::guard(should_debug, |should_debug| {
            if should_debug {
                if log::log_enabled!(log::Level::Debug) {
                    debug!("{} failed:", containing_function!());
                    dbgvals!($($arg)*);
                }
            }
        })
    }};
}

#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "log_pretty_print"))]
macro_rules! dbgvals {
    ($($val:expr),* $(,)?) => {
        $(debug!("{:?}: {:?}", stringify!($val), $val);)*
    }
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "log_pretty_print")]
macro_rules! dbgvals {
    ($($val:expr),* $(,)?) => {
        $(debug!("{:?}: {:#?}", stringify!($val), $val);)*
    }
}
