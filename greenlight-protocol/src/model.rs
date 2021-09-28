use core::fmt;
use core::marker::PhantomData;

use serde::{de, ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde::ser::SerializeTuple;
use core::fmt::Debug;
use std::fmt::Formatter;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bip32KeyVersion {
    pub pubkey_version: u32,
    pub privkey_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockID([u8; 32]);

#[derive(Debug, Serialize, Deserialize)]
pub struct Secret(pub [u8; 32]);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivKey(pub [u8; 32]);

#[derive(Debug, Serialize, Deserialize)]
pub struct PubKey32(pub [u8; 32]);

macro_rules! array_impl {
    ($ty:ident, $len:tt) => {
        pub struct $ty(pub [u8; $len]);

        impl Debug for $ty {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                self.0.to_vec().fmt(f)
            }
        }

        impl<'de> de::Deserialize<'de> for $ty {
            fn deserialize<D>(d: D) -> core::result::Result<Self, D::Error> where D: de::Deserializer<'de> {
                struct Visitor {
                    marker: PhantomData<$ty>,
                }

                impl<'de> de::Visitor<'de> for Visitor
                {
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
                        Self {
                            marker: PhantomData,
                        }
                    }
                }
                d.deserialize_tuple($len, Visitor::new())
            }
        }

        impl ser::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
                let mut tuple = serializer.serialize_tuple(self.0.len())?;
                for i in 0..self.0.len() {
                    tuple.serialize_element(&self.0[i])?;
                }
                tuple.end()
            }
        }
    }
}

array_impl!(PubKey, 33);

array_impl!(ExtKey, 78);

#[derive(Debug, Serialize, Deserialize)]
pub struct Sha256([u8; 32]);

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
    pub id: u64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BitcoinSignature {
    pub signature: Signature,
    pub sighash: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Htlc {
    pub state: u8,
    pub id: u64,
    pub amount: u64,
    pub payment_hash: Sha256,
    pub ctlv_expiry: u32,
    pub routing_packet: OnionRoutingPacket,
    pub preimage: Option<Secret>,
    pub failed: Option<FailedHtlc>,
    pub blinding: Option<PubKey>,
}
