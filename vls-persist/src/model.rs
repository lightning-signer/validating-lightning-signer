use lightning_signer::prelude::*;

use core::fmt;
use core::fmt::{Display, Formatter};
use core::iter::FromIterator;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, OutPoint};
use lightning_signer::chain::tracker::{ChainTracker, ListenSlot};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use lightning_signer::bitcoin;
use lightning_signer::channel::ChannelId;
use lightning_signer::channel::ChannelSetup;
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::monitor::State as ChainMonitorState;
use lightning_signer::node::{InvoiceState, NodeState};
use lightning_signer::persist::model::ChannelEntry as CoreChannelEntry;
use lightning_signer::policy::validator::EnforcementState;
use lightning_signer::util::velocity::VelocityControl as CoreVelocityControl;

use super::ser_util::{
    ChainMonitorStateDef, ChannelIdHandler, ChannelSetupDef, EnforcementStateDef, InvoiceStateDef,
    ListenSlotDef, OutPointDef,
};

#[derive(Serialize, Deserialize)]
pub struct VelocityControl {
    pub start_sec: u64,
    pub bucket_interval: u32,
    pub buckets: Vec<u64>,
    pub limit: u64,
}

impl From<VelocityControl> for CoreVelocityControl {
    fn from(v: VelocityControl) -> Self {
        CoreVelocityControl {
            start_sec: v.start_sec,
            bucket_interval: v.bucket_interval,
            buckets: v.buckets,
            limit: v.limit,
        }
    }
}

impl From<CoreVelocityControl> for VelocityControl {
    fn from(v: CoreVelocityControl) -> Self {
        VelocityControl {
            start_sec: v.start_sec,
            bucket_interval: v.bucket_interval,
            buckets: v.buckets,
            limit: v.limit,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct NodeStateEntry {
    #[serde_as(as = "Vec<(Hex, InvoiceStateDef)>")]
    pub invoices: Vec<(Vec<u8>, InvoiceState)>,
    #[serde_as(as = "Vec<(Hex, InvoiceStateDef)>")]
    pub issued_invoices: Vec<(Vec<u8>, InvoiceState)>,
    pub velocity_control: VelocityControl,
    // TODO(devrandom): add routing control fields, once they stabilize
}

impl From<&NodeState> for NodeStateEntry {
    fn from(state: &NodeState) -> Self {
        // TODO(devrandom) reduce cloning
        let invoices = state.invoices.iter().map(|(a, b)| (a.0.to_vec(), b.clone())).collect();
        let issued_invoices =
            state.issued_invoices.iter().map(|(a, b)| (a.0.to_vec(), b.clone())).collect();
        let velocity_control = state.velocity_control.clone().into();
        NodeStateEntry { invoices, issued_invoices, velocity_control }
    }
}

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
    pub allowlist: Vec<String>,
}

/// Fully qualified channel ID
#[derive(Clone)]
pub struct NodeChannelId(pub Vec<u8>);

impl NodeChannelId {
    pub fn new(node_id: &PublicKey, channel_id: &ChannelId) -> Self {
        let mut res = Vec::with_capacity(65);
        res.append(&mut node_id.serialize().to_vec());
        res.append(&mut channel_id.inner().clone());
        Self(res)
    }

    pub fn new_prefix(node_id: &PublicKey) -> Self {
        let mut res = Vec::with_capacity(33);
        res.append(&mut node_id.serialize().to_vec());
        Self(res)
    }

    pub fn node_id(&self) -> PublicKey {
        PublicKey::from_slice(&self.0.as_slice()[0..33]).unwrap()
    }

    pub fn channel_id(&self) -> ChannelId {
        ChannelId::new(&self.0.as_slice()[33..])
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
    listeners: OrderedMap<OutPoint, (ChainMonitorState, ListenSlot)>,
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
        let listeners =
            OrderedMap::from_iter(self.listeners.into_iter().map(|(outpoint, (state, slot))| {
                (ChainMonitor::new_from_persistence(outpoint, state), slot)
            }));
        ChainTracker { headers, tip, height: self.height, network: self.network, listeners }
    }
}
