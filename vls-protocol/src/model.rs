use alloc::format;
use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;

use serde::ser::SerializeTuple;
use serde::{de, ser, Serializer};
use serde_bolt::Octets;
use serde_derive::{Deserialize, Serialize};

macro_rules! unprefixed_array_impl {
    ($ty:ident, $len:tt) => {
        #[derive(Clone, Serialize, Deserialize)]
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

macro_rules! unprefixed_secret_array_impl {
    ($ty:ident, $len:tt) => {
        #[derive(Clone, Serialize, Deserialize)]
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            #[cfg(feature = "log-secrets")]
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
            #[cfg(not(feature = "log-secrets"))]
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "******")
            }
        }
    };
}

macro_rules! array_impl {
    ($ty:ident, $len:tt) => {
        #[derive(Clone)]
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }

        impl<'de> de::Deserialize<'de> for $ty {
            fn deserialize<D>(d: D) -> core::result::Result<Self, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                struct Visitor {
                    marker: PhantomData<$ty>,
                }

                impl<'de> de::Visitor<'de> for Visitor {
                    type Value = $ty;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(concat!("an array of length {}", $len))
                    }

                    #[inline]
                    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
                    where
                        A: de::SeqAccess<'de>,
                    {
                        let mut buf = [0u8; $len];
                        for i in 0..buf.len() {
                            let next = seq.next_element()?;
                            buf[i] = match next {
                                None => return Err(de::Error::invalid_length($len, &self)),
                                Some(val) => val,
                            };
                        }
                        Ok($ty(buf))
                    }
                }

                impl Visitor {
                    fn new() -> Self {
                        Self { marker: PhantomData }
                    }
                }
                d.deserialize_tuple($len, Visitor::new())
            }
        }

        impl ser::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut tuple = serializer.serialize_tuple(self.0.len())?;
                for i in 0..self.0.len() {
                    tuple.serialize_element(&self.0[i])?;
                }
                tuple.end()
            }
        }
    };
}

#[derive(Serialize, Deserialize)]
pub struct Bip32KeyVersion {
    pub pubkey_version: u32,
    pub privkey_version: u32,
}

// kcov-ignore-start
impl Debug for Bip32KeyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bip32KeyVersion")
            .field("pubkey_version", &format!("0x{:x?}", self.pubkey_version))
            .field("privkey_version", &format!("0x{:x?}", self.privkey_version))
            .finish()
    }
}
// kcov-ignore-end

unprefixed_array_impl!(BlockId, 32);

// A 32-byte secret that is sensitive
unprefixed_secret_array_impl!(Secret, 32);

// A 32-byte secret that is no longer sensitive, because it is known or will
// soon be known to our counterparty
unprefixed_array_impl!(DisclosedSecret, 32);

// A 32-byte secret that is not sensitive, because it is used for testing / development
unprefixed_array_impl!(DevSecret, 32);

// A 32-byte secret that is not sensitive, because it is used for testing / development
unprefixed_array_impl!(DevPrivKey, 32);

unprefixed_array_impl!(PubKey32, 32);

array_impl!(PubKey, 33);

array_impl!(ExtKey, 78);

unprefixed_array_impl!(Sha256, 32);

unprefixed_array_impl!(BlockHash, 32);

#[derive(Debug, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Basepoints {
    pub revocation: PubKey,
    pub payment: PubKey,
    pub htlc: PubKey,
    pub delayed_payment: PubKey,
}

array_impl!(Signature, 64);
array_impl!(RecoverableSignature, 65);

array_impl!(TxId, 32);

array_impl!(OnionRoutingPacket, 1366);

#[derive(Debug, Serialize, Deserialize)]
pub struct FailedHtlc {
    pub id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BitcoinSignature {
    pub signature: Signature,
    pub sighash: u8,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CloseInfo {
    pub channel_id: u64,
    pub peer_id: PubKey,
    pub commitment_point: Option<PubKey>,
    // TODO this is unused
    pub is_anchors: bool,
    pub csv: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: TxId,
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
        assert_eq!(debug, "******");
    }
}
