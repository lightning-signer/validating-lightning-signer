//! By convention, structs ending with `Def` are serde local types
//! describing how to serialize a remote type via `serde(remote)`.
//! Structs ending with `Entry` are local types that require a manual
//! transformation from the remote type - implemented via `From` / `Into`.

use crate::prelude::*;

use alloc::borrow::Cow;
use core::fmt;
use core::fmt::Formatter;
use core::time::Duration;
use hex::ToHex;
use lightning::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
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

#[derive(Copy, Clone, Debug, Default)]
pub struct RevocationBasepointHandler;

impl SerializeAs<RevocationBasepoint> for RevocationBasepointHandler {
    fn serialize_as<S>(source: &RevocationBasepoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::Serialize::serialize(&source.0, serializer)
    }
}

impl<'de> DeserializeAs<'de, RevocationBasepoint> for RevocationBasepointHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<RevocationBasepoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = PublicKey::deserialize(deserializer)?;
        Ok(key.into())
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct DelayedPaymentBasepointHandler;

impl SerializeAs<DelayedPaymentBasepoint> for DelayedPaymentBasepointHandler {
    fn serialize_as<S>(source: &DelayedPaymentBasepoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::Serialize::serialize(&source.0, serializer)
    }
}

impl<'de> DeserializeAs<'de, DelayedPaymentBasepoint> for DelayedPaymentBasepointHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<DelayedPaymentBasepoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = PublicKey::deserialize(deserializer)?;
        Ok(key.into())
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct HtlcBasepointHandler;

impl SerializeAs<HtlcBasepoint> for HtlcBasepointHandler {
    fn serialize_as<S>(source: &HtlcBasepoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde::Serialize::serialize(&source.0, serializer)
    }
}

impl<'de> DeserializeAs<'de, HtlcBasepoint> for HtlcBasepointHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<HtlcBasepoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = PublicKey::deserialize(deserializer)?;
        Ok(key.into())
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
    // FIXME here and below, the binary representation needs to be restored
    #[serde_as(as = "IfIsHumanReadable<RevocationBasepointHandler, RevocationBasepointHandler>")]
    pub revocation_basepoint: RevocationBasepoint,
    #[serde_as(as = "IfIsHumanReadable<PublicKeyHandler>")]
    pub payment_point: PublicKey,
    #[serde_as(
        as = "IfIsHumanReadable<DelayedPaymentBasepointHandler, DelayedPaymentBasepointHandler>"
    )]
    pub delayed_payment_basepoint: DelayedPaymentBasepoint,
    #[serde_as(as = "IfIsHumanReadable<HtlcBasepointHandler, HtlcBasepointHandler>")]
    pub htlc_basepoint: HtlcBasepoint,
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

/// TxIdReversedDef should be used with the assumption
/// that the transaction is built from a big-endian vector
/// stream. This will produce a different Txid if not
/// properly considered. For more details, see [issue#490].
///
/// [issue#490]: https://gitlab.com/lightning-signer/validating-lightning-signer/-/issues/490
pub struct TxIdReversedDef;

impl SerializeAs<Txid> for TxIdReversedDef {
    fn serialize_as<S>(value: &Txid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_byte_array().encode_hex::<String>().as_str())
    }
}

impl<'de> DeserializeAs<'de, Txid> for TxIdReversedDef {
    fn deserialize_as<D>(deserializer: D) -> Result<Txid, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let res = <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer).unwrap();
        let txid = Txid::from_slice(hex::decode(&*res).unwrap().as_slice()).unwrap();
        Ok(txid)
    }
}

/// OutPointReversedDef uses TxIdReversedDef for decoding the txid
/// and this type should be used with the assumption
/// that the transaction is built from a big-endian vector stream.
/// This will produce a different Txid if not properly considered.
/// For more details, see [issue#490].
///
/// [issue#490]: https://gitlab.com/lightning-signer/validating-lightning-signer/-/issues/490
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "OutPoint")]
pub struct OutPointReversedDef {
    #[serde_as(as = "TxIdReversedDef")]
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Deserialize)]
struct OutPointHelper(#[serde(with = "OutPointReversedDef")] OutPoint);

impl SerializeAs<OutPoint> for OutPointReversedDef {
    fn serialize_as<S>(value: &OutPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OutPointReversedDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, OutPoint> for OutPointReversedDef {
    fn deserialize_as<D>(deserializer: D) -> Result<OutPoint, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        OutPointHelper::deserialize(deserializer).map(|h| h.0)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ScriptBuf")]
pub struct ScriptDef(#[serde(getter = "Script::to_bytes")] Vec<u8>);

impl From<ScriptDef> for ScriptBuf {
    fn from(s: ScriptDef) -> Self {
        ScriptBuf::from(s.0)
    }
}

#[derive(Deserialize)]
struct ScriptHelper(#[serde(with = "ScriptDef")] ScriptBuf);

impl SerializeAs<ScriptBuf> for ScriptDef {
    fn serialize_as<S>(value: &ScriptBuf, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ScriptDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, ScriptBuf> for ScriptDef {
    fn deserialize_as<D>(deserializer: D) -> Result<ScriptBuf, <D as Deserializer<'de>>::Error>
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
