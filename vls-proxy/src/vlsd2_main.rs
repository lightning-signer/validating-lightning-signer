use bitcoind_client::BlockExplorerType;
use clap::{App, AppSettings, Arg};
use grpc::signer::make_handler;
use grpc::signer::start_signer;
use lightning_signer::bitcoin::Network;
use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, NETWORK_NAMES};
use std::fs;
use url::Url;
use util::setup_logging;
use vls_protocol_signer::handler::Handler;
use vls_proxy::recovery::{direct::DirectRecoveryKeys, recover_close};

pub mod client;
pub mod connection;
pub mod grpc;
pub mod tx_util;
pub mod util;

const DEFAULT_DIR: &str = ".lightning-signer";

pub fn main() {
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Validating Lightning Signer")
        .arg(
            Arg::new("connect")
                .about("node RPC endpoint")
                .long("connect")
                .short('c')
                .value_name("URL")
                .required_unless_present("recover-close"),
        )
        .arg(
            Arg::new("datadir")
                .short('d')
                .long("datadir")
                .default_value(DEFAULT_DIR)
                .about("data directory")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("NETWORK")
                .possible_values(NETWORK_NAMES)
                .default_value(NETWORK_NAMES[0]),
        )
        .arg(
            Arg::new("integration-test")
                .long("integration-test")
                .about("use integration test mode, reading/writing hsm_secret from CWD"),
        )
        .arg(
            Arg::new("recover-rpc")
                .about("block explorer/bitcoind RPC endpoint - used for broadcasting recovery transactions")
                .long("recover-rpc")
                .default_value_ifs(CLAP_NETWORK_URL_MAPPING)
                .value_name("URL"),
        )
        .arg(
            Arg::new("recover-type")
                .about("block explorer type - used for broadcasting recovery transactions")
                .long("recover-type")
                .possible_values(&["bitcoind", "esplora"])
                .default_value("bitcoind")
                .value_name("TYPE"),
        )
        .arg(
            Arg::new("recover-close").long("recover-close").value_name("BITCOIN_ADDRESS").about(
                "send a force-close transaction to recover funds when the node is unavailable",
            ),
        );
    let matches = app.get_matches();
    let datadir = matches.value_of("datadir").unwrap();
    let network: Network = matches.value_of_t("network").expect("network");

    let recover_rpc =
        matches.value_of("recover-rpc").map(|s| Url::parse(s).expect("recover RPC URL"));
    let recover_address = matches.value_of("recover-close");

    let datapath = format!("{}/{}", datadir, network.to_string());
    fs::create_dir_all(&datapath).expect("mkdir datapath");
    setup_logging(&datapath, "vlsd2", "debug");

    if let Some(address) = recover_address {
        let recover_type = match matches.value_of("recover-type").unwrap() {
            "bitcoind" => BlockExplorerType::Bitcoind,
            "esplora" => BlockExplorerType::Esplora,
            _ => panic!("unknown recover type"),
        };
        let root_handler = make_handler(datadir, network, false);
        let node = root_handler.node().clone();
        node.set_allowlist(&[address.to_string()]).expect("add destination to allowlist");
        let keys = DirectRecoveryKeys { node };
        recover_close(network, recover_type, recover_rpc, address, keys);
        return;
    }

    let uri_s = matches.value_of("connect").unwrap();
    let uri = uri_s.parse().expect("uri parse");
    let integration_test = matches.is_present("integration-test");
    if network == Network::Bitcoin && integration_test {
        panic!("integration-test mode not supported on mainnet");
    }
    start_signer(datadir, uri, network, integration_test);
}
