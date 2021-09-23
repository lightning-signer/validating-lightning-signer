use core::fmt;
use core::marker::PhantomData;

use serde::{de, ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde::ser::SerializeTuple;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bip32KeyVersion {
    pubkey_version: u32,
    privkey_version : u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockID([u8; 32]);

#[derive(Debug, Serialize, Deserialize)]
pub struct Secret([u8; 32]);

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivKey([u8; 32]);

#[derive(Debug)]
pub struct PubKey([u8; 33]);

struct PubKeyVisitor {
    marker: PhantomData<PubKey>,
}

impl<'de> de::Visitor<'de> for PubKeyVisitor
{
    type Value = PubKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(concat!("an array of length 33"))
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
    {
        let mut buf = [0u8; 33];
        for i in 0..buf.len() {
            let next = seq.next_element()?;
            buf[i] = match next {
                None => return Err(de::Error::invalid_length(33, &self)),
                Some(val) => val,
            };
        }
        Ok(PubKey(buf))
    }
}

impl PubKeyVisitor {
    fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<'de> de::Deserialize<'de> for PubKey {
    fn deserialize<D>(d: D) -> core::result::Result<Self, D::Error> where D: de::Deserializer<'de> {
        d.deserialize_tuple(33, PubKeyVisitor::new())
    }
}

impl ser::Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut tuple = serializer.serialize_tuple(self.0.len())?;
        for el in self.0 {
            tuple.serialize_element(&el)?;
        }
        tuple.end()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sha256([u8; 32]);
