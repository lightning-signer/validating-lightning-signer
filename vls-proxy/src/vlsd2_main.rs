use clap::{App, AppSettings, Arg};
use grpc::signer::start_signer;
use lightning_signer::bitcoin::Network;
use lightning_signer_server::NETWORK_NAMES;
use util::setup_logging;

pub mod client;
pub mod connection;
pub mod grpc;
pub mod util;

const DEFAULT_DIR: &str = ".lightning-signer";

pub fn main() {
    setup_logging("vlsd2", "info");
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(
            Arg::new("connect")
                .about("URI of node")
                .long("connect")
                .short('c')
                .takes_value(true)
                .required(true),
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
        );
    let matches = app.get_matches();
    let uri_s = matches.value_of("connect").unwrap();
    let uri = uri_s.parse().expect("uri parse");
    let datadir = matches.value_of("datadir").unwrap();
    let network: Network = matches.value_of_t("network").expect("network");
    start_signer(datadir, uri, network);
}
