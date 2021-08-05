use crate::prelude::*;
use bitcoin::hashes::hex;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::address::Payload;
use lightning::ln::chan_utils::{ChannelPublicKeys, HTLCOutputInCommitment};

// Debug printer for ChannelPublicKeys which doesn't have one.
// BEGIN NOT TESTED
pub struct DebugChannelPublicKeys<'a>(pub &'a ChannelPublicKeys);
impl<'a> core::fmt::Debug for DebugChannelPublicKeys<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("ChannelPublicKeys")
            .field("funding_pubkey", &self.0.funding_pubkey)
            .field("revocation_basepoint", &self.0.revocation_basepoint)
            .field("payment_point", &self.0.payment_point)
            .field(
                "delayed_payment_basepoint",
                &self.0.delayed_payment_basepoint,
            )
            .field("htlc_basepoint", &self.0.htlc_basepoint)
            .finish()
    }
}
// END NOT TESTED
macro_rules! log_channel_public_keys {
    ($obj: expr) => {
        &crate::util::debug_utils::DebugChannelPublicKeys(&$obj)
    };
}

// Debug printer for Payload which uses hex encoded strings.
// BEGIN NOT TESTED
pub struct DebugPayload<'a>(pub &'a Payload);
impl<'a> core::fmt::Debug for DebugPayload<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self.0 {
            Payload::PubkeyHash(ref hash) => hex::format_hex(hash, f),
            Payload::ScriptHash(ref hash) => hex::format_hex(hash, f),
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => f
                .debug_struct("WitnessProgram")
                .field("version", &ver.to_u8())
                .field("program", &prog.to_hex())
                .finish(),
        }
    }
}
// END NOT TESTED

// Debug printer for HTLCOutputInCommitment which doesn't have one.
pub struct DebugHTLCOutputInCommitment<'a>(pub &'a HTLCOutputInCommitment);
impl<'a> core::fmt::Debug for DebugHTLCOutputInCommitment<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("HTLCOutputInCommitment")
            .field("offered", &self.0.offered)
            .field("amount_msat", &self.0.amount_msat)
            .field("cltv_expiry", &self.0.cltv_expiry)
            .field("payment_hash", &self.0.payment_hash.0[..].to_hex())
            .field("transaction_output_index", &self.0.transaction_output_index)
            .finish()
    }
}

pub struct DebugBytes<'a>(pub &'a [u8]);
impl<'a> core::fmt::Debug for DebugBytes<'a> {
    // BEGIN NOT TESTED
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        for i in self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
    // END NOT TESTED
}

pub struct DebugWitness<'a>(pub &'a (Vec<u8>, Vec<u8>));
impl<'a> core::fmt::Debug for DebugWitness<'a> {
    // BEGIN NOT TESTED
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("Witness")
            .field(&DebugBytes(&self.0 .0))
            .field(&DebugBytes(&self.0 .1))
            .finish()
    }
    // END NOT TESTED
}

pub struct DebugWitVec<'a>(pub &'a Vec<(Vec<u8>, Vec<u8>)>);
impl<'a> core::fmt::Debug for DebugWitVec<'a> {
    // BEGIN NOT TESTED
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_list()
            .entries(self.0.iter().map(|ww| DebugWitness(ww)))
            .finish()
    }
    // END NOT TESTED
}
