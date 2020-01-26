use lightning::ln::features::InitFeatures;

use crate::test::functional_test_utils::{create_announced_chan_between_nodes, create_network, create_node_cfgs, create_node_chanmgrs, send_payment};

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
    let chan_1 = create_announced_chan_between_nodes(&nodes, 0, 1, make_features(), make_features());
    let chan_2 = create_announced_chan_between_nodes(&nodes, 1, 2, make_features(), make_features());
    let chan_3 = create_announced_chan_between_nodes(&nodes, 2, 3, make_features(), make_features());

    // Rebalance the network a bit by relaying one payment through all the channels...
    send_payment(&nodes[0], &vec!(&nodes[1], &nodes[2], &nodes[3])[..], 8000000, 8_000_000);
}
