use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};

use bitcoin::secp256k1::PublicKey;
use kv::{Key, Raw};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use super::ser_util::{ChannelIdHandler, ChannelSetupDef, EnforcementStateDef};
use lightning_signer::node::{ChannelId, ChannelSetup};
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::util::enforcing_trait_impls::EnforcementState;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct NodeEntry {
    #[serde_as(as = "Hex")]
    pub seed: Vec<u8>,
    pub key_derivation_style: u8,
    pub network: String,
}

impl From<NodeEntry> for CoreNodeEntry {
    fn from(e: NodeEntry) -> Self {
        CoreNodeEntry {
            seed: e.seed,
            key_derivation_style: e.key_derivation_style,
            network: e.network,
        }
    }
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

impl From<ChannelEntry> for CoreChannelEntry {
    fn from(e: ChannelEntry) -> Self {
        CoreChannelEntry {
            nonce: e.nonce,
            channel_value_satoshis: e.channel_value_satoshis,
            channel_setup: e.channel_setup,
            id: e.id,
            enforcement_state: e.enforcement_state,
        }
    }
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

    // BEGIN NOT TESTED

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

    // END NOT TESTED
}

// BEGIN NOT TESTED
impl Display for NodeChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            hex::encode(&self.0.as_slice()[0..33]),
            hex::encode(&self.0.as_slice()[33..])
        )
    }
}
// END NOT TESTED

impl AsRef<[u8]> for NodeChannelId {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_slice()
    }
}

// BEGIN NOT TESTED
impl<'a> Key<'a> for NodeChannelId {
    fn from_raw_key(r: &'a Raw) -> Result<Self, kv::Error> {
        Ok(NodeChannelId(r.to_vec()))
    }
}
// END NOT TESTED
