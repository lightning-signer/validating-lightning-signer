//! By convention, structs ending with `Def` are serde local types
//! describing how to serialize a remote type via `serde(remote)`.
//! Structs ending with `Entry` are local types that require a manual
//! transformation from the remote type - implemented via `From` / `Into`.

use crate::prelude::*;

use alloc::borrow::Cow;
use bitcoin::hashes::Hash as _;
use core::fmt;
use core::fmt::Formatter;
use core::str::FromStr as _;
use core::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Script, Txid};
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::util::ser::Writer;
use serde::de::{SeqAccess, Visitor};
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

impl SerializeAs<OutPoint> for OutPointDef {
    fn serialize_as<S>(value: &OutPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OutPoint::serialize(value, serializer)
    }
}

struct OutPointVisitor;

impl<'de> Visitor<'de> for OutPointVisitor {
    type Value = OutPoint;

    fn expecting(&self, formatter: &mut alloc::fmt::Formatter) -> alloc::fmt::Result {
        formatter.write_str("A string with txid and vout separated by a colon or a json object with txid and vout fields")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        let parts: Vec<&str> = v.split(':').collect();
        if parts.len() == 2 {
            let txid = Txid::from_slice(&hex::decode(parts[0]).unwrap()).unwrap();
            let vout = parts[1].parse().unwrap();
            Ok(OutPoint { txid, vout })
        } else {
            Err(serde::de::Error::custom("Invalid outpoint format"))
        }
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>, {
        let mut txid: Option<Txid> = None;
        let mut vout: Option<u32> = None;

        while let Some(key) = map.next_key()? {
            match key {
                "txid" => {
                    let txid_str: &str = map.next_value()?;
                    match Txid::from_str(txid_str) {
                        Ok(txid_val) => txid = Some(txid_val),
                        Err(_) => return Err(serde::de::Error::custom("Invalid txid format")),
                    }
                }
                "vout" => {
                    vout = Some(map.next_value()?);
                }
                _ => {}
            }
        }

        Ok(OutPoint {
            txid: txid.expect("txid is None"),
            vout: vout.expect("vout is None")
        })
    }
}

impl<'de> DeserializeAs<'de, OutPoint> for OutPointDef {
    fn deserialize_as<D>(deserializer: D) -> Result<OutPoint, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OutPointVisitor)
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

impl SerializeAs<Script> for ScriptDef {
    fn serialize_as<S>(value: &Script, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Script::serialize(value, serializer)
    }
}

struct ScriptVisitor;

impl<'de> serde::de::Visitor<'de> for ScriptVisitor {
    type Value = Script;

    fn expecting(&self, formatter: &mut alloc::fmt::Formatter) -> alloc::fmt::Result {
        formatter.write_str("expecting a byte array or a hex string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        let decoded_bytes = hex::decode(v).expect("hex string");
        Ok(Script::from(decoded_bytes))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(Script::from(bytes))
    }
}

impl<'de> DeserializeAs<'de, Script> for ScriptDef {
    fn deserialize_as<D>(deserializer: D) -> Result<Script, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ScriptVisitor)
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

    use super::{OutPointVisitor, ScriptVisitor};

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

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "OutPoint")]
    pub struct OutPointDef {
        pub txid: Txid,
        pub vout: u32,
    }

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
            deserializer.deserialize_any(OutPointVisitor)
        }
    }

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    pub struct OutPointDefWrapper {
        #[serde_as(as = "OutPointDef")]
        outpoint: OutPoint
    }

    #[derive(Serialize, Deserialize)]
    pub struct OutPointWrapper {
        outpoint: OutPoint
    }

    #[test]
    fn compare_serialize_outpointdef() {
        let outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
        let outpoint_wrapper = OutPointWrapper {
            outpoint
        };

        let outpoint_def_wrapper = OutPointDefWrapper {
            outpoint: outpoint.clone()
        };

        let serialized_outpoint_wrapper = serde_json::to_string(&outpoint_wrapper).unwrap();
        let serialized_outpoint_def_wrapper = serde_json::to_string(&outpoint_def_wrapper).unwrap();

        let deserialized_outpoint_wrapper: OutPointDefWrapper = serde_json::from_str(&serialized_outpoint_wrapper).unwrap();
        let deserialized_outpoint_def_wrapper: OutPointDefWrapper = serde_json::from_str(&serialized_outpoint_def_wrapper).unwrap();
        assert_eq!(deserialized_outpoint_wrapper.outpoint, deserialized_outpoint_def_wrapper.outpoint);
    }

    #[derive(Serialize, Deserialize)]
    #[serde(remote = "Script")]
    pub struct ScriptDef(#[serde(getter = "Script::to_bytes")] Vec<u8>);

    impl From<ScriptDef> for Script {
        fn from(s: ScriptDef) -> Self {
            Script::from(s.0)
        }
    }

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
            deserializer.deserialize_any(ScriptVisitor)
        }
    }


    #[serde_as]
    #[derive(Serialize, Deserialize)]
    struct ScriptWrapperDef {
        #[serde_as(as = "ScriptDef")]
        script: Script
    }

    #[derive(Serialize, Deserialize)]
    struct ScriptWrapper {
        script: Script
    }


    #[test]
    fn compare_serialize_scriptdef() {

        let script = Script::from(vec![0x6a, 0x14, 0x00, 0x90, 0x51, 0x1a, 0x0c, 0x0f, 0x2b, 0x6e, 0x1f, 0x2b, 0x6e, 0x1f, 0x2b, 0x6e, 0x1f, 0x2b, 0x6e, 0x1f]);
        let script_def = script.clone();

        let script_wrapper = ScriptWrapper{script};
        let script_wrapper_def = ScriptWrapperDef{script: script_def};

        let script_json = serde_json::to_string(&script_wrapper).unwrap();
        let script_def_json = serde_json::to_string(&script_wrapper_def).unwrap();

        let deserialized_script_def: ScriptWrapperDef = serde_json::from_str(&script_def_json).unwrap();
        let deserialized_script: ScriptWrapperDef = serde_json::from_str(&script_json).unwrap();

        assert_eq!(deserialized_script.script, deserialized_script_def.script);
    }
}
