use std::collections::{BTreeMap as Map, BTreeMap};
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, OutPoint, Script};
use kv::{Key, Raw};
use lightning_signer::chain::tracker::{ChainTracker, ListenSlot};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use lightning_signer::channel::ChannelId;
use lightning_signer::channel::ChannelSetup;
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::monitor::State as ChainMonitorState;
use lightning_signer::persist::model::{
    ChannelEntry as CoreChannelEntry, NodeEntry as CoreNodeEntry,
};
use lightning_signer::policy::validator::EnforcementState;

use super::ser_util::{
    ChainMonitorStateDef, ChannelIdHandler, ChannelSetupDef, EnforcementStateDef, ListenSlotDef,
    OutPointDef, ScriptDef,
};

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

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct AllowlistItemEntry {
    #[serde_as(as = "Vec<ScriptDef>")]
    pub allowlist: Vec<Script>,
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
        write!(
            f,
            "{}/{}",
            hex::encode(&self.0.as_slice()[0..33]),
            hex::encode(&self.0.as_slice()[33..])
        )
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

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct ChainTrackerEntry {
    // Serialized headers beyond tip
    #[serde_as(as = "Vec<Hex>")]
    headers: Vec<Vec<u8>>,
    // Serialized header at tip
    #[serde_as(as = "Hex")]
    tip: Vec<u8>,
    height: u32,
    network: Network,
    #[serde_as(as = "Vec<(OutPointDef, (ChainMonitorStateDef, ListenSlotDef))>")]
    listeners: BTreeMap<OutPoint, (ChainMonitorState, ListenSlot)>,
}

impl From<&ChainTracker<ChainMonitor>> for ChainTrackerEntry {
    fn from(t: &ChainTracker<ChainMonitor>) -> Self {
        let tip = serialize(&t.tip);
        let headers = t.headers.iter().map(|h| serialize(h)).collect();
        let listeners = t
            .listeners
            .iter()
            .map(|(l, s)| (l.funding_outpoint, (l.get_state().clone(), s.clone())))
            .collect();
        ChainTrackerEntry { headers, tip, height: t.height(), network: t.network, listeners }
    }
}

impl Into<ChainTracker<ChainMonitor>> for ChainTrackerEntry {
    fn into(self) -> ChainTracker<ChainMonitor> {
        let tip = deserialize(&self.tip).expect("deserialize tip");
        let headers =
            self.headers.iter().map(|h| deserialize(h).expect("deserialize header")).collect();
        let listeners: Map<ChainMonitor, ListenSlot> =
            Map::from_iter(self.listeners.into_iter().map(|(outpoint, (state, slot))| {
                (ChainMonitor::new_from_persistence(outpoint, state), slot)
            }));
        ChainTracker { headers, tip, height: self.height, network: self.network, listeners }
    }
}
