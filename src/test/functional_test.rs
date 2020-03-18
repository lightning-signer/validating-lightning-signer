use std::sync::{Arc, Mutex};

use bitcoin::{Network, Script};
use lightning::chain::chaininterface;
use lightning::chain::keysinterface::KeysInterface;
use lightning::ln::features::InitFeatures;
use lightning::util::logger::Logger;
use secp256k1::PublicKey;

use crate::server::my_signer::MySigner;
use crate::test::functional_test_utils::{
    create_announced_chan_between_nodes, create_network, create_node_cfgs, create_node_chanmgrs,
    send_payment, NodeCfg,
};
use crate::test::loopback::{LoopbackChannelSigner, LoopbackSignerKeysInterface};
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;
use crate::util::test_utils;

fn make_features() -> InitFeatures {
    InitFeatures::supported()
}

#[test]
fn fake_network_test() {
    // Simple test which builds a network of ChannelManagers, connects them to each other, and
    // tests that payments get routed and transactions broadcast in semi-reasonable ways.
    let node_cfgs = create_node_cfgs(4);
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
}

pub fn create_node_cfgs_with_signer(
    node_count: usize,
    signer: &Arc<MySigner>,
) -> Vec<NodeCfg<LoopbackChannelSigner>> {
    let mut nodes = Vec::new();

    for i in 0..node_count {
        let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
        let fee_estimator = Arc::new(test_utils::TestFeeEstimator { sat_per_kw: 253 });
        let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(
            Network::Testnet,
            logger.clone() as Arc<Logger>,
        ));
        let tx_broadcaster = Arc::new(test_utils::TestBroadcaster {
            txn_broadcasted: Mutex::new(Vec::new()),
        });
        let node_id = signer.new_node();
        let keys_interface = LoopbackSignerKeysInterface {
            node_id,
            signer: Arc::clone(signer),
        };
        let keys_manager =
            Arc::new(keys_interface) as Arc<KeysInterface<ChanKeySigner = LoopbackChannelSigner>>;
        let chan_monitor = test_utils::TestChannelMonitor::new(
            chain_monitor.clone(),
            tx_broadcaster.clone(),
            logger.clone(),
            fee_estimator.clone(),
        );
        nodes.push(NodeCfg {
            chain_monitor,
            logger,
            tx_broadcaster,
            fee_estimator,
            chan_monitor,
            keys_manager,
        });
    }

    nodes
}

#[test]
fn fake_network_with_signer_test() {
    // Simple test which builds a network of ChannelManagers, connects them to each other, and
    // tests that payments get routed and transactions broadcast in semi-reasonable ways.
    let signer = Arc::new(MySigner::new());

    let node_cfgs = create_node_cfgs_with_signer(4, &signer);
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
}
