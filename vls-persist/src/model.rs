use lightning_signer::prelude::*;

use alloc::sync::Arc;
use core::fmt;
use core::fmt::{Display, Formatter};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, OutPoint};
use lightning_signer::chain::tracker::{ChainTracker, Headers, ListenSlot};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::{hex::Hex, Bytes, IfIsHumanReadable};

use lightning_signer::bitcoin;
use lightning_signer::bitcoin::hashes::Hash;
use lightning_signer::bitcoin::{BlockHeader, FilterHeader};
use lightning_signer::channel::ChannelId;
use lightning_signer::channel::ChannelSetup;
use lightning_signer::monitor::ChainMonitor;
use lightning_signer::monitor::State as ChainMonitorState;
use lightning_signer::node::{NodeState, PaymentState};
use lightning_signer::persist::model::ChannelEntry as CoreChannelEntry;
use lightning_signer::persist::ChainTrackerListenerEntry;
use lightning_signer::policy::validator::{EnforcementState, ValidatorFactory};
use lightning_signer::policy::DEFAULT_FEE_VELOCITY_CONTROL;
use lightning_signer::util::ser_util::{ChannelIdHandler, OutPointDef};
use lightning_signer::util::velocity::VelocityControl as CoreVelocityControl;

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
    #[serde_as(as = "IfIsHumanReadable<Vec<(Hex, _)>, Vec<(Bytes, _)>>")]
    pub invoices: Vec<(Vec<u8>, PaymentState)>,
    #[serde_as(as = "IfIsHumanReadable<Vec<(Hex, _)>, Vec<(Bytes, _)>>")]
    pub issued_invoices: Vec<(Vec<u8>, PaymentState)>,
    pub velocity_control: VelocityControl,
    #[serde(default = "default_fee_velocity_control")]
    pub fee_velocity_control: VelocityControl,
    #[serde(default)]
    #[serde_as(as = "IfIsHumanReadable<_, Vec<Bytes>>")]
    pub preimages: Vec<[u8; 32]>,
    // TODO(devrandom): add routing control fields, once they stabilize
}

fn default_fee_velocity_control() -> VelocityControl {
    CoreVelocityControl::new(DEFAULT_FEE_VELOCITY_CONTROL).into()
}

impl From<&NodeState> for NodeStateEntry {
    fn from(state: &NodeState) -> Self {
        // TODO(devrandom) reduce cloning
        let invoices = state.invoices.iter().map(|(a, b)| (a.0.to_vec(), b.clone())).collect();
        let issued_invoices =
            state.issued_invoices.iter().map(|(a, b)| (a.0.to_vec(), b.clone())).collect();
        let velocity_control = state.velocity_control.clone().into();
        let fee_velocity_control = state.fee_velocity_control.clone().into();
        // extract preimages from payments
        let preimages = state.payments.values().filter_map(|p| p.preimage.map(|p| p.0)).collect();
        NodeStateEntry {
            invoices,
            issued_invoices,
            velocity_control,
            fee_velocity_control,
            preimages,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct NodeEntry {
    pub key_derivation_style: u8,
    pub network: String,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ChannelEntry {
    pub channel_value_satoshis: u64,
    pub channel_setup: Option<ChannelSetup>,
    // Permanent channel ID if different from the initial channel ID
    #[serde_as(as = "IfIsHumanReadable<Option<ChannelIdHandler>>")]
    pub id: Option<ChannelId>,
    pub enforcement_state: EnforcementState,
    // birth blockheight for stub, None for channel
    pub blockheight: Option<u32>,
}

impl From<ChannelEntry> for CoreChannelEntry {
    fn from(e: ChannelEntry) -> Self {
        CoreChannelEntry {
            channel_value_satoshis: e.channel_value_satoshis,
            channel_setup: e.channel_setup,
            id: e.id,
            enforcement_state: e.enforcement_state,
            blockheight: e.blockheight,
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
    #[serde_as(as = "IfIsHumanReadable<Vec<Hex>, Vec<Bytes>>")]
    headers: Vec<Vec<u8>>,
    // Serialized header at tip
    #[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")]
    tip: Vec<u8>,
    height: u32,
    network: Network,
    #[serde_as(as = "IfIsHumanReadable<Vec<(OutPointDef, (_, _))>>")]
    listeners: Vec<(OutPoint, (ChainMonitorState, ListenSlot))>,
}

impl From<&ChainTracker<ChainMonitor>> for ChainTrackerEntry {
    fn from(t: &ChainTracker<ChainMonitor>) -> Self {
        let tip = serialize(&t.tip);
        let headers = t.headers.iter().map(|h| serialize(h)).collect();
        let listeners = t
            .listeners
            .iter()
            .map(|(k, (l, s))| (k.clone(), (l.get_state().clone(), s.clone())))
            .collect();
        ChainTrackerEntry { headers, tip, height: t.height(), network: t.network, listeners }
    }
}

impl ChainTrackerEntry {
    /// Convert to a ChainTracker, consuming the entry
    pub fn into_tracker(
        self,
        node_id: PublicKey,
        validator_factory: Arc<dyn ValidatorFactory>,
    ) -> (ChainTracker<ChainMonitor>, Vec<ChainTrackerListenerEntry>) {
        let tip: Headers = match deserialize::<Headers>(&self.tip) {
            Err(_) => {
                log::warn!("Failed to deserialize tip, falling back on old format.  This is expected if you are upgrading from a version prior to 0.9.0");
                let tip = deserialize::<BlockHeader>(&self.tip).expect("fallback deserialize tip");
                // Signal to the [`ChainTracker`] that the filter header was not available.
                // This is used to upgrade old signers.  This should only happen once.
                Headers(tip, FilterHeader::all_zeros())
            }
            Ok(t) => t,
        };
        let headers =
            self.headers.iter().map(|h| deserialize(h).expect("deserialize header")).collect();
        let listeners: Vec<_> = self
            .listeners
            .into_iter()
            .map(|(outpoint, (state, slot))| ChainTrackerListenerEntry(outpoint, (state, slot)))
            .collect();
        (
            ChainTracker::restore(
                headers,
                tip,
                self.height,
                self.network,
                OrderedMap::new(),
                node_id,
                validator_factory,
            ),
            listeners,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ChainTrackerEntry;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::Network;
    use core::iter::FromIterator;
    use lightning_signer::bitcoin::hashes::Hash;
    use lightning_signer::bitcoin::FilterHeader;
    use lightning_signer::chain::tracker::{ChainTracker, Error, Headers};
    use lightning_signer::monitor::ChainMonitorBase;
    use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
    use lightning_signer::util::test_utils::*;
    use test_log::test;

    #[test]
    fn test_chain_tracker() -> Result<(), Error> {
        let tx = make_tx(vec![make_txin(1), make_txin(2)]);
        let outpoint = OutPoint::new(tx.txid(), 0);
        let commitment_point_provider = Box::new(DummyCommitmentPointProvider {});
        let chan_id = ChannelId::new(&[33u8; 32]);
        let monitor =
            ChainMonitorBase::new(outpoint, 0, &chan_id).as_monitor(commitment_point_provider);
        monitor.add_funding(&tx, 0);
        let genesis = genesis_block(Network::Regtest);
        let validator_factory = Arc::new(SimpleValidatorFactory::new());
        let (node_id, _, _) = make_node();
        let tip = Headers(genesis.header, FilterHeader::all_zeros());
        let mut tracker =
            ChainTracker::new(Network::Regtest, 0, tip, node_id, validator_factory.clone())?;
        tracker.add_listener(monitor.clone(), OrderedSet::new());
        tracker.add_listener_watches(
            &outpoint,
            OrderedSet::from_iter(vec![make_txin(1).previous_output]),
        );

        let entry = ChainTrackerEntry::from(&tracker);
        let json = serde_json::to_string(&entry).expect("json");
        let entry_de: ChainTrackerEntry = serde_json::from_str(&json).expect("de json");
        let _ = entry_de.into_tracker(node_id, validator_factory);
        Ok(())
    }
}
