use crate::channel::ChannelId;
use crate::channel::ChannelSetup;
use crate::node::NodeState;
use crate::policy::validator::EnforcementState;
use crate::prelude::*;

/// A persistence layer entry for a Node
#[allow(missing_docs)]
pub struct NodeEntry {
    pub seed: Vec<u8>,
    pub key_derivation_style: u8,
    pub network: String,
    pub state: NodeState,
}

/// A persistence layer entry for a channel
#[allow(missing_docs)]
#[derive(Debug)]
pub struct ChannelEntry {
    pub channel_value_satoshis: u64,
    pub channel_setup: Option<ChannelSetup>,
    // Permanent channel ID if different from the initial channel ID
    pub id: Option<ChannelId>,
    pub enforcement_state: EnforcementState,
}
