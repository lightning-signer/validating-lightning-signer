use crate::grpc::signer::recover_close;
use clap::{App, AppSettings, Arg};
use grpc::signer::start_signer;
use lightning_signer::bitcoin::Network;
use lightning_signer_server::NETWORK_NAMES;
use url::Url;
use util::setup_logging;

pub mod client;
pub mod connection;
pub mod grpc;
pub mod tx_util;
pub mod util;

const DEFAULT_DIR: &str = ".lightning-signer";

pub fn main() {
    setup_logging("vlsd2", "info");
    let app =
        App::new("signer")
            .setting(AppSettings::NoAutoVersion)
            .about("Greenlight lightning-signer")
            .arg(
                Arg::new("connect")
                    .about("URI of node")
                    .long("connect")
                    .short('c')
                    .takes_value(true)
                    .required_unless_present("recover-close"),
            )
            .arg(
                Arg::new("datadir")
                    .short('d')
                    .long("datadir")
                    .default_value(DEFAULT_DIR)
                    .about("data directory")
                    .takes_value(true),
            )
            .arg(
                Arg::new("network")
                    .short('n')
                    .long("network")
                    .possible_values(&NETWORK_NAMES)
                    .default_value(NETWORK_NAMES[0]),
            )
            .arg(
                Arg::new("integration-test")
                    .long("integration-test")
                    .about("use integration test mode, reading/writing hsm_secret from CWD"),
            )
            .arg(
                Arg::new("bitcoin")
                    .about("Bitcoin RPC endpoint - used for broadcasting recovery transactions")
                    .short('b')
                    .long("bitcoin")
                    .default_value("http://user:pass@localhost:18443")
                    .takes_value(true),
            )
            .arg(Arg::new("recover-close").long("recover-close").about(
                "send a force-close transaction to recover funds when the node is unavailable",
            ));
    let matches = app.get_matches();
    let datadir = matches.value_of("datadir").unwrap();
    let network: Network = matches.value_of_t("network").expect("network");

    let is_recover_close = matches.is_present("recover-close");
    let bitcoin_rpc = matches.value_of("bitcoin").map(|s| Url::parse(s).expect("bitcoin url"));
    if is_recover_close {
        recover_close(datadir, network, bitcoin_rpc);
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
