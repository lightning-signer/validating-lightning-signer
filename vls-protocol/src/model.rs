use alloc::format;
use bitcoin::Txid;
use bitcoin_consensus_derive::{Decodable, Encodable};
use core::fmt::{self, Debug, Formatter};
use serde_bolt::bitcoin;
use serde_bolt::Octets;

macro_rules! secret_array_impl {
    ($ty:ident, $len:tt) => {
        #[derive(Clone, Encodable, Decodable)]
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            #[cfg(feature = "log-secrets")]
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
            #[cfg(not(feature = "log-secrets"))]
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "******")
            }
        }
    };
}

macro_rules! array_impl {
    ($ty:ident, $len:tt) => {
        #[derive(Clone, Encodable, Decodable)]
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

#[derive(Encodable, Decodable)]
pub struct Bip32KeyVersion {
    pub pubkey_version: u32,
    pub privkey_version: u32,
}

impl Debug for Bip32KeyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bip32KeyVersion")
            .field("pubkey_version", &format!("0x{:x?}", self.pubkey_version))
            .field("privkey_version", &format!("0x{:x?}", self.privkey_version))
            .finish()
    }
}

// A 32-byte secret that is sensitive
secret_array_impl!(Secret, 32);

// A 32-byte secret that is no longer sensitive, because it is known or will
// soon be known to our counterparty
array_impl!(DisclosedSecret, 32);

// A 32-byte secret that is not sensitive, because it is used for testing / development
array_impl!(DevSecret, 32);

// A 32-byte secret that is not sensitive, because it is used for testing / development
array_impl!(DevPrivKey, 32);

array_impl!(PubKey32, 32);

array_impl!(PubKey, 33);

array_impl!(ExtKey, 78);

array_impl!(Sha256, 32);

#[derive(Debug, Encodable, Decodable)]
pub struct Basepoints {
    pub revocation: PubKey,
    pub payment: PubKey,
    pub htlc: PubKey,
    pub delayed_payment: PubKey,
}

array_impl!(Signature, 64);
array_impl!(RecoverableSignature, 65);

array_impl!(OnionRoutingPacket, 1366);

#[derive(Debug, Encodable, Decodable)]
pub struct FailedHtlc {
    pub id: u64,
}

#[derive(Debug, Encodable, Decodable)]
pub struct BitcoinSignature {
    pub signature: Signature,
    pub sighash: u8,
}

#[derive(Debug, Encodable, Decodable)]
pub struct Htlc {
    pub side: u8, // 0 = local, 1 = remote
    pub amount: u64,
    pub payment_hash: Sha256,
    pub ctlv_expiry: u32,
}

impl Htlc {
    pub const LOCAL: u8 = 0;
    pub const REMOTE: u8 = 1;
}

#[derive(Debug, Encodable, Decodable)]
pub struct CloseInfo {
    pub channel_id: u64,
    pub peer_id: PubKey,
    pub commitment_point: Option<PubKey>,
    // TODO this is unused
    pub is_anchors: bool,
    pub csv: u32,
}

#[derive(Debug, Encodable, Decodable)]
pub struct Utxo {
    pub txid: Txid,
    pub outnum: u32,
    pub amount: u64,
    pub keyindex: u32,
    pub is_p2sh: bool,
    pub script: Octets,
    pub close_info: Option<CloseInfo>,
    pub is_in_coinbase: bool,
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_secret_test() {
        let secret = super::Secret([0; 32]);
        let debug = format!("{:?}", secret);
        #[cfg(feature = "log-secrets")]
        assert_eq!(debug, "0000000000000000000000000000000000000000000000000000000000000000");
        #[cfg(not(feature = "log-secrets"))]
        assert_eq!(debug, "******");
    }
}
