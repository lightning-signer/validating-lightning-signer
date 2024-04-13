//! By convention, structs ending with `Def` are serde local types
//! describing how to serialize a remote type via `serde(remote)`.
//! Structs ending with `Entry` are local types that require a manual
//! transformation from the remote type - implemented via `From` / `Into`.

use crate::prelude::*;

use alloc::borrow::Cow;
use core::fmt;
use core::fmt::Formatter;
use core::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Script, Txid};
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::util::ser::Writer;
use serde::de::SeqAccess;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, IfIsHumanReadable};
use serde_with::{DeserializeAs, SerializeAs};

use crate::channel::ChannelId;
use crate::io;

#[derive(Copy, Clone, Debug, Default)]
pub struct PublicKeyHandler;

impl SerializeAs<PublicKey> for PublicKeyHandler {
    fn serialize_as<S>(source: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(hex::encode(source.serialize().to_vec()).as_str())
    }
}

impl<'de> DeserializeAs<'de, PublicKey> for PublicKeyHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let res = <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer).unwrap();
        let key = PublicKey::from_slice(hex::decode(&*res).unwrap().as_slice()).unwrap();
        Ok(key)
    }
}

pub struct ChannelIdHandler;

impl SerializeAs<ChannelId> for ChannelIdHandler {
    fn serialize_as<S>(source: &ChannelId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(hex::encode(source.as_slice()).as_str())
    }
}

impl<'de> DeserializeAs<'de, ChannelId> for ChannelIdHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<ChannelId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let res = <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer).unwrap();
        let key = ChannelId::new(&hex::decode(&*res).unwrap());
        Ok(key)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "ChannelPublicKeys")]
pub struct ChannelPublicKeysDef {
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub funding_pubkey: PublicKey,
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub revocation_basepoint: PublicKey,
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub payment_point: PublicKey,
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub delayed_payment_basepoint: PublicKey,
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub htlc_basepoint: PublicKey,
}

#[derive(Deserialize)]
struct ChannelPublicKeysHelper(#[serde(with = "ChannelPublicKeysDef")] ChannelPublicKeys);

impl SerializeAs<ChannelPublicKeys> for ChannelPublicKeysDef {
    fn serialize_as<S>(value: &ChannelPublicKeys, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ChannelPublicKeysDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, ChannelPublicKeys> for ChannelPublicKeysDef {
    fn deserialize_as<D>(
        deserializer: D,
    ) -> Result<ChannelPublicKeys, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        ChannelPublicKeysHelper::deserialize(deserializer).map(|h| h.0)
    }
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), io::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "OutPoint")]
pub struct OutPointDef {
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Deserialize)]
struct OutPointHelper(#[serde(with = "OutPointDef")] OutPoint);

impl SerializeAs<OutPoint> for OutPointDef {
    fn serialize_as<S>(value: &OutPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OutPointDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, OutPoint> for OutPointDef {
    fn deserialize_as<D>(deserializer: D) -> Result<OutPoint, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        OutPointHelper::deserialize(deserializer).map(|h| h.0)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Script")]
pub struct ScriptDef(#[serde(getter = "Script::to_bytes")] Vec<u8>);

impl From<ScriptDef> for Script {
    fn from(s: ScriptDef) -> Self {
        Script::from(s.0)
    }
}

#[derive(Deserialize)]
struct ScriptHelper(#[serde(with = "ScriptDef")] Script);

impl SerializeAs<Script> for ScriptDef {
    fn serialize_as<S>(value: &Script, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ScriptDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, Script> for ScriptDef {
    fn deserialize_as<D>(deserializer: D) -> Result<Script, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        ScriptHelper::deserialize(deserializer).map(|h| h.0)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct DurationHandler;

impl SerializeAs<Duration> for DurationHandler {
    fn serialize_as<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&value.as_secs())?;
        seq.serialize_element(&value.subsec_nanos())?;
        seq.end()
    }
}

struct DurationVisitor;

impl<'de> serde::de::Visitor<'de> for DurationVisitor {
    type Value = Duration;

    fn expecting(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.write_str("tuple")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Duration, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let secs = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let nanos =
            seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        Ok(Duration::new(secs, nanos))
    }
}

impl<'de> DeserializeAs<'de, Duration> for DurationHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<Duration, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(DurationVisitor)
    }
}


#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use bitcoin::{OutPoint, Script};
    use bitcoin::{Txid, hashes::Hash};
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;
    use serde_with::DeserializeAs;
    use serde_with::SerializeAs;
    use serde_with::serde_as;
    use serde::Serialize;

    struct TxidDef;

    impl SerializeAs<Txid> for TxidDef {
        fn serialize_as<S>(value: &Txid, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(hex::encode(value.to_vec()).as_str())
        }
    }

    impl<'de> DeserializeAs<'de, Txid> for TxidDef {
        fn deserialize_as<D>(deserializer: D) -> Result<Txid, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            let res = <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer).unwrap();
            let txid = Txid::from_slice(hex::decode(&*res).unwrap().as_slice()).unwrap();
            Ok(txid)
        }
    }

    #[test]
    fn compare_serialize_txidef() {

        #[serde_as]
        #[derive(Serialize, Deserialize)]
        struct TxidWrapperAsDef {
            #[serde_as(as = "TxidDef")]
            txid: Txid,
        }

        #[derive(Serialize, Deserialize)]
        struct TxidWrapper {
            txid: Txid,
        }
        let txid = Txid::from_slice(&[1; 32]).unwrap();

        let txid_wrapper = TxidWrapper { txid };
        let txid_wrapper_def = TxidWrapperAsDef { txid };

        let txid_json = serde_json::to_string(&txid_wrapper).unwrap();
        let txid_def_json = serde_json::to_string(&txid_wrapper_def).unwrap();

        assert_eq!(txid_json, txid_def_json);
    }

}
