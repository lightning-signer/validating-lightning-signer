use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fmt;

use kv::{Key, Raw};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use crate::node::node::{ChannelId, ChannelSetup};

use super::ser_util::{ChannelSetupDef, ChannelIdHandler, EnforcementStateDef};
use crate::util::enforcing_trait_impls::EnforcementState;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct NodeEntry {
    #[serde_as(as = "Hex")]
    pub seed: Vec<u8>,
    pub key_derivation_style: u8,
    pub network: String,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ChannelEntry {
    #[serde_as(as = "Hex")]
    pub nonce: Vec<u8>,
    pub channel_value_satoshis: u64,
    #[serde_as(as = "Option<ChannelSetupDef>")]
    pub channel_setup: Option<ChannelSetup>,
    // Permanent channel ID if different from the initial channel ID
    #[serde_as(as = "Option<ChannelIdHandler>")]
    pub id: Option<ChannelId>,
    #[serde_as(as = "EnforcementStateDef")]
    pub enforcement_state: EnforcementState,
}

/// Fully qualified channel ID
#[derive(Clone)]
pub struct NodeChannelId(Vec<u8>);

impl NodeChannelId {
    pub fn new(node_id: &PublicKey, channel_id: &ChannelId) -> Self {
        let mut res = Vec::with_capacity(65);
        res.append(node_id.serialize().to_vec().as_mut());
        res.append(channel_id.0.to_vec().as_mut());
        Self(res)
    }

    pub fn new_prefix(node_id: &PublicKey) -> Self {
        let mut res = Vec::with_capacity(33);
        res.append(node_id.serialize().to_vec().as_mut());
        Self(res)
    }

    pub fn node_id(&self) -> PublicKey {
        PublicKey::from_slice(&self.0.as_slice()[0..33]).unwrap()
    }

    pub fn channel_id(&self) -> ChannelId {
        ChannelId(self.0.as_slice()[33..].try_into().unwrap())
    }
}

impl Display for NodeChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", hex::encode(&self.0.as_slice()[0..33]), hex::encode(&self.0.as_slice()[33..]))
    }
}

impl AsRef<[u8]> for NodeChannelId {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_slice()
    }
}

impl<'a> Key<'a> for NodeChannelId {
    fn from_raw_key(r: &'a Raw) -> Result<Self, kv::Error> {
        Ok(NodeChannelId(r.to_vec()))
    }
}
