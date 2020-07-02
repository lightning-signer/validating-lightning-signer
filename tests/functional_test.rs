#![allow(unused_imports)]

extern crate lightning_signer;

use std::sync::{Arc, Mutex};

use bitcoin::{Network, Script};
use lightning::chain::chaininterface;
use lightning::chain::keysinterface::KeysInterface;
use lightning::ln::features::InitFeatures;
use lightning::util::logger::Logger;
use secp256k1::PublicKey;

use lightning_signer::server::my_signer::MySigner;
use lightning_signer::util::functional_test_utils::{
    create_announced_chan_between_nodes, create_chanmon_cfgs, create_network, create_node_chanmgrs,
    send_payment, NodeCfg, TestChanMonCfg, TestChannelMonitor,
};
use lightning_signer::util::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use lightning_signer::util::test_utils;

fn make_features() -> InitFeatures {
    InitFeatures::known()
}

// BEGIN NOT TESTED
pub fn create_node_cfgs_with_signer<'a>(
    node_count: usize,
    signer: &Arc<MySigner>,
    chanmon_cfgs: &'a Vec<TestChanMonCfg>,
) -> Vec<NodeCfg<'a>> {
    let mut nodes = Vec::new();

    for i in 0..node_count {
        let seed = [i as u8; 32];

        let node_id = signer.new_node();
        let keys_manager = LoopbackSignerKeysInterface {
            node_id,
            signer: Arc::clone(signer),
        };

        let chan_monitor = TestChannelMonitor::new(
            &chanmon_cfgs[i].chain_monitor,
            &chanmon_cfgs[i].tx_broadcaster,
            &chanmon_cfgs[i].logger,
            &chanmon_cfgs[i].fee_estimator,
        );

        nodes.push(NodeCfg {
            chain_monitor: &chanmon_cfgs[i].chain_monitor,
            logger: &chanmon_cfgs[i].logger,
            tx_broadcaster: &chanmon_cfgs[i].tx_broadcaster,
            fee_estimator: &chanmon_cfgs[i].fee_estimator,
            chan_monitor,
            keys_manager,
            node_seed: seed,
        });
    }

    nodes
}

#[test]
fn fake_network_with_signer_test() {
    // Simple test which builds a network of ChannelManagers, connects them to each other, and
    // tests that payments get routed and transactions broadcast in semi-reasonable ways.
    let signer = Arc::new(MySigner::new());

    let chanmon_cfgs = create_chanmon_cfgs(4);
    let node_cfgs = create_node_cfgs_with_signer(4, &signer, &chanmon_cfgs);
    let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
    let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

    // Create some initial channels
    let _chan_1 =
        create_announced_chan_between_nodes(&nodes, 0, 1, make_features(), make_features());
    let _chan_2 =
        create_announced_chan_between_nodes(&nodes, 1, 2, make_features(), make_features());
    let _chan_3 =
        create_announced_chan_between_nodes(&nodes, 2, 3, make_features(), make_features());

    // Rebalance the network a bit by relaying one payment through all the channels...
    send_payment(
        &nodes[0],
        &vec![&nodes[1], &nodes[2], &nodes[3]][..],
        8000000,
        8_000_000,
    );
    // close_channel(&nodes[0], &nodes[1], &chan_1.2, chan_1.3, true);
}
// END NOT TESTED
