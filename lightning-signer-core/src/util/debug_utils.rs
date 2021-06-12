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
            Payload::PubkeyHash(ref hash) => write!(f, "{}", hex::encode(&hash)),
            Payload::ScriptHash(ref hash) => write!(f, "{}", hex::encode(&hash)),
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => f
                .debug_struct("WitnessProgram")
                .field("version", &ver.to_u8())
                .field("program", &hex::encode(&prog))
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
            .field("payment_hash", &hex::encode(&self.0.payment_hash.0[..]))
            .field("transaction_output_index", &self.0.transaction_output_index)
            .finish()
    }
}
