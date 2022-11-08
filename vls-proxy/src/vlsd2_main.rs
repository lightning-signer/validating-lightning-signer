use crate::grpc::signer::recover_close;
use clap::{App, AppSettings, Arg};
use grpc::signer::start_signer;
use lightning_signer::bitcoin::Network;
use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, NETWORK_NAMES};
use url::Url;
use util::setup_logging;

pub mod client;
pub mod connection;
pub mod grpc;
pub mod tx_util;
pub mod util;

const DEFAULT_DIR: &str = ".lightning-signer";

pub fn main() {
    setup_logging("vlsd2", "debug");
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
            Arg::new("bitcoin")
                .about("bitcoind RPC endpoint - used for broadcasting recovery transactions")
                .short('b')
                .long("bitcoin")
                .default_value_ifs(CLAP_NETWORK_URL_MAPPING)
                .value_name("URL"),
        )
        .arg(
            Arg::new("recover-close").long("recover-close").value_name("BITCOIN_ADDRESS").about(
                "send a force-close transaction to recover funds when the node is unavailable",
            ),
        );
    let matches = app.get_matches();
    let datadir = matches.value_of("datadir").unwrap();
    let network: Network = matches.value_of_t("network").expect("network");

    let bitcoin_rpc = matches.value_of("bitcoin").map(|s| Url::parse(s).expect("bitcoin url"));
    let recover_address = matches.value_of("recover-close");

    if let Some(address) = recover_address {
        recover_close(datadir, network, bitcoin_rpc, address);
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
