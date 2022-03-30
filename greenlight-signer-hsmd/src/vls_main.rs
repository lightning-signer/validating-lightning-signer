//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::{env, thread};

use clap::{App, AppSettings, Arg};
use log::{error, info};

use connection::UnixConnection;
use greenlight_protocol::{msgs, msgs::Message, Error, Result};
use greenlight_signer::greenlight_protocol;
use lightning_signer::persist::Persist;
use lightning_signer::Arc;

use client::{Client, UnixClient};
use greenlight_signer::handler::{Handler, RootHandler};
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use util::read_allowlist;

mod test;
use remote_hsmd::*;
use remote_hsmd::util::{read_integration_test_seed, setup_logging};

fn signer_loop<C: 'static + Client, H: Handler>(client: C, handler: H) {
    let id = handler.client_id();
    let pid = std::process::id();
    info!("loop {} {}: start", pid, id);
    match do_signer_loop(client, handler) {
        Ok(()) => info!("loop {} {}: done", pid, id),
        Err(Error::Eof) => info!("loop {} {}: ending", pid, id),
        Err(e) => error!("loop {} {}: error {:?}", pid, id, e),
    }
}

fn do_signer_loop<C: 'static + Client, H: Handler>(mut client: C, handler: H) -> Result<()> {
    loop {
        let msg = client.read()?;
        info!("loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
        match msg {
            Message::ClientHsmFd(m) => {
                client.write(msgs::ClientHsmFdReply {}).unwrap();
                let new_client = client.new_client();
                info!("new client {} {} -> {}", std::process::id(), handler.client_id(), new_client.id());
                let handler = handler.for_new_client(new_client.id(), m.peer_id, m.dbid);
                thread::spawn(move || signer_loop(new_client, handler));
            }
            msg => {
                let reply = handler.handle(msg).expect("handle");
                let v = reply.vec_serialize();
                client.write_vec(v).unwrap();
                info!("replied {} {}", std::process::id(), handler.client_id());
            }
        }
    }
}

pub fn main() {
    setup_logging("hsmd  ","info");
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
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        return;
    }
    if matches.is_present("test") {
        test::run_test();
    } else {
        let conn = UnixConnection::new(3);
        let client = UnixClient::new(conn);
        let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("signer.kv"));
        let allowlist = read_allowlist();
        let handler =
            RootHandler::new(client.id(), read_integration_test_seed(), persister, allowlist);
        signer_loop(client, handler);
    }
}
