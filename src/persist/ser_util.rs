use std::borrow::Cow;

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Script, Txid};
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::util::ser::Writer;
use secp256k1::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use serde_with::{DeserializeAs, SerializeAs};

use crate::node::node::{ChannelId, ChannelSetup, CommitmentType};
use crate::util::enforcing_trait_impls::EnforcementState;
use std::convert::TryInto;

#[derive(Copy, Clone, Debug, Default)] // NOT TESTED
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
        serializer.serialize_str(hex::encode(source.0).as_str())
    }
}

impl<'de> DeserializeAs<'de, ChannelId> for ChannelIdHandler {
    fn deserialize_as<D>(deserializer: D) -> Result<ChannelId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let res = <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer).unwrap();
        let key = ChannelId(hex::decode(&*res).unwrap().as_slice().try_into().unwrap());
        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ChannelPublicKeys")]
pub struct ChannelPublicKeysDef {
    pub funding_pubkey: PublicKey,
    pub revocation_basepoint: PublicKey,
    pub payment_point: PublicKey,
    pub delayed_payment_basepoint: PublicKey,
    pub htlc_basepoint: PublicKey,
}

#[derive(Deserialize)] // NOT TESTED
struct ChannelPublicKeysHelper(#[serde(with = "ChannelPublicKeysDef")] ChannelPublicKeys);

impl SerializeAs<ChannelPublicKeys> for ChannelPublicKeysDef {
    fn serialize_as<S>(value: &ChannelPublicKeys, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
    fn size_hint(&mut self, size: usize) {
        self.0.reserve_exact(size);
    }
}

struct TxidDef;

impl SerializeAs<Txid> for TxidDef {
    fn serialize_as<S>(value: &Txid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "OutPoint")]
pub struct OutPointDef {
    #[serde_as(as = "TxidDef")]
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Deserialize)]
struct OutPointHelper(#[serde(with = "OutPointDef")] OutPoint);

impl SerializeAs<OutPoint> for OutPointDef {
    fn serialize_as<S>(value: &OutPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
#[serde(remote = "CommitmentType")]
pub enum CommitmentTypeDef {
    Legacy,
    StaticRemoteKey,
    Anchors,
}

#[derive(Deserialize)]
struct CommitmentTypeHelper(#[serde(with = "CommitmentTypeDef")] CommitmentType);

impl SerializeAs<CommitmentType> for CommitmentTypeDef {
    fn serialize_as<S>(value: &CommitmentType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        CommitmentTypeDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, CommitmentType> for CommitmentTypeDef {
    fn deserialize_as<D>(deserializer: D) -> Result<CommitmentType, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        CommitmentTypeHelper::deserialize(deserializer).map(|h| h.0)
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

// BEGIN NOT TESTED

#[derive(Deserialize)]
struct ScriptHelper(#[serde(with = "ScriptDef")] Script);

impl SerializeAs<Script> for ScriptDef {
    fn serialize_as<S>(value: &Script, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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

// END NOT TESTED

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "ChannelSetup")]
pub struct ChannelSetupDef {
    pub is_outbound: bool,
    pub channel_value_sat: u64,
    pub push_value_msat: u64,
    #[serde_as(as = "OutPointDef")]
    pub funding_outpoint: OutPoint,
    pub holder_to_self_delay: u16,
    #[serde_as(as = "Option<ScriptDef>")]
    pub holder_shutdown_script: Option<Script>,
    #[serde(with = "ChannelPublicKeysDef")]
    pub counterparty_points: ChannelPublicKeys,
    pub counterparty_to_self_delay: u16,
    #[serde(with = "ScriptDef")]
    pub counterparty_shutdown_script: Script,
    #[serde_as(as = "CommitmentTypeDef")]
    pub commitment_type: CommitmentType,
}

#[derive(Deserialize)]
struct ChannelSetupHelper(#[serde(with = "ChannelSetupDef")] ChannelSetup);

impl SerializeAs<ChannelSetup> for ChannelSetupDef {
    fn serialize_as<S>(value: &ChannelSetup, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ChannelSetupDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, ChannelSetup> for ChannelSetupDef {
    fn deserialize_as<D>(deserializer: D) -> Result<ChannelSetup, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        ChannelSetupHelper::deserialize(deserializer).map(|h| h.0)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "EnforcementState")]
pub struct EnforcementStateDef {
    pub last_commitment_number: Option<u64>,
}

#[derive(Deserialize)]
struct EnforcementStateHelper(#[serde(with = "EnforcementStateDef")] EnforcementState);

impl SerializeAs<EnforcementState> for EnforcementStateDef {
    fn serialize_as<S>(value: &EnforcementState, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        EnforcementStateDef::serialize(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, EnforcementState> for EnforcementStateDef {
    fn deserialize_as<D>(
        deserializer: D,
    ) -> Result<EnforcementState, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        EnforcementStateHelper::deserialize(deserializer).map(|h| h.0)
    }
}
