//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::env;

use clap::{App, AppSettings, Arg};

#[allow(unused_imports)]
use log::{error, info};

use connection::{open_parent_fd, UnixConnection};

use vls_protocol_signer::vls_protocol::msgs::{self, Message};
use vls_protocol_signer::vls_protocol::serde_bolt::WireString;

use embedded::{connect, SignerLoop};
use vls_proxy::client::UnixClient;
use vls_proxy::util::setup_logging;
use vls_proxy::*;

mod embedded;

fn run_test(serial_port: String) -> anyhow::Result<()> {
    let mut serial = connect(serial_port)?;
    let mut id = 0u16;
    let mut sequence = 1;

    loop {
        msgs::write_serial_request_header(&mut serial, sequence, 0)?;
        let ping = msgs::Ping { id, message: WireString("ping".as_bytes().to_vec()) };
        msgs::write(&mut serial, ping)?;
        msgs::read_serial_response_header(&mut serial, sequence)?;
        sequence = sequence.wrapping_add(1);
        let reply = msgs::read(&mut serial)?;
        match reply {
            Message::Pong(p) => {
                info!("got reply {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                assert_eq!(p.id, id);
            }
            _ => {
                panic!("unknown response");
            }
        }
        id += 1;
    }
}

pub fn main() -> anyhow::Result<()> {
    let parent_fd = open_parent_fd();

    setup_logging("hsmd  ", "info");
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(
            Arg::new("--dev-disconnect")
                .about("ignored dev flag")
                .long("dev-disconnect")
                .takes_value(true),
        )
        .arg(Arg::from("--log-io ignored dev flag"))
        .arg(Arg::from("--version show a dummy version"))
        .arg(Arg::from("--test run a test against the embedded device"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        return Ok(());
    }

    let serial_port = env::var("VLS_SERIAL_PORT").unwrap_or("/dev/ttyACM1".to_string());

    if matches.is_present("test") {
        run_test(serial_port)?;
    } else {
        let conn = UnixConnection::new(parent_fd);
        let client = UnixClient::new(conn);
        let serial = connect(serial_port)?;
        let mut signer_loop = SignerLoop::new(client, serial);
        signer_loop.start();
    }

    Ok(())
}
