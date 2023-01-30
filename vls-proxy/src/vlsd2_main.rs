use bitcoind_client::BlockExplorerType;
use clap::Parser;
use grpc::signer::make_handler;
use grpc::signer::start_signer;
use lightning_signer::bitcoin::Network;
use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, NETWORK_NAMES};
use log::*;
use std::fs;
use url::Url;
use util::setup_logging;
use vls_protocol_signer::handler::Handler;
use vls_proxy::recovery::{direct::DirectRecoveryKeys, recover_close};
use vls_proxy::GIT_DESC;

pub mod client;
pub mod connection;
pub mod grpc;
pub mod tx_util;
pub mod util;

const DEFAULT_DIR: &str = ".lightning-signer";

// note that value_parser gives us clap 4 forward compatibility
#[derive(Parser, Debug)]
#[clap(author, about, long_about = None)]
struct Args {
    #[clap(long, value_parser, help = "print git desc version and exit")]
    git_desc: bool,
    #[clap(short, long, value_parser, help = "node RPC endpoint",
    required_unless_present_any(&["recover-close", "git-desc"]), value_name = "URL")]
    connect: Option<Url>,
    #[clap(short, long, value_parser, default_value = DEFAULT_DIR, help = "data directory", value_name = "DIR")]
    datadir: String,
    #[clap(short, long, value_parser, value_name = "NETWORK", possible_values = NETWORK_NAMES, default_value = NETWORK_NAMES[0])]
    network: Network,
    #[clap(
        long,
        value_parser,
        help = "use integration test mode, reading/writing hsm_secret from CWD"
    )]
    integration_test: bool,
    #[clap(
        long,
        value_parser,
        help = "block explorer/bitcoind RPC endpoint - used for broadcasting recovery transactions",
        default_value_ifs(CLAP_NETWORK_URL_MAPPING),
        value_name = "URL"
    )]
    recover_rpc: Option<Url>,
    #[clap(long, value_parser, help = "block explorer type - used for broadcasting recovery transactions", value_name = "TYPE", default_value = "bitcoind", possible_values = &["bitcoind", "esplora"]
    )]
    recover_type: String,
    #[clap(
        long,
        value_parser,
        help = "send a force-close transaction to the given address",
        value_name = "BITCOIN_ADDRESS"
    )]
    recover_close: Option<String>,
}

pub fn main() {
    let args = Args::parse();
    if args.git_desc {
        println!("vlsd2 git_desc={}", GIT_DESC);
        return;
    }
    let network = args.network;
    let datadir = args.datadir;
    let datapath = format!("{}/{}", datadir, network.to_string());
    fs::create_dir_all(&datapath).expect("mkdir datapath");
    setup_logging(&datapath, "vlsd2", "debug");
    info!("vlsd2 git_desc={} starting", GIT_DESC);

    if let Some(address) = args.recover_close {
        let recover_type = match args.recover_type.as_str() {
            "bitcoind" => BlockExplorerType::Bitcoind,
            "esplora" => BlockExplorerType::Esplora,
            _ => panic!("unknown recover type"),
        };
        let root_handler = make_handler(&datadir, network, false);
        let node = root_handler.node().clone();
        node.set_allowlist(&[address.to_string()]).expect("add destination to allowlist");
        let keys = DirectRecoveryKeys { node };
        recover_close(network, recover_type, args.recover_rpc, &address, keys);
        return;
    }

    let uri_s = args.connect.expect("connect URL").to_string();
    let uri = uri_s.parse().expect("uri parse");
    let integration_test = args.integration_test;
    if network == Network::Bitcoin && integration_test {
        panic!("integration-test mode not supported on mainnet");
    }
    start_signer(&datadir, uri, network, integration_test);
}
