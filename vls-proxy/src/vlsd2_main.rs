use clap::{App, AppSettings, Arg};
use grpc::signer::start_signer;

pub mod client;
pub mod connection;
pub mod grpc;
pub mod util;

pub fn main() {
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
        );
    let matches = app.get_matches();
    let uri_s = matches.value_of("connect").unwrap();
    let uri = uri_s.parse().expect("uri parse");
    start_signer(uri);
}
