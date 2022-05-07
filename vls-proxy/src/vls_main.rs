//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::thread;

use clap::{App, AppSettings, Arg};
use log::{error, info};

use connection::UnixConnection;
use lightning_signer::persist::Persist;
use lightning_signer::Arc;
use vls_protocol::{msgs, msgs::Message, Error, Result};
use vls_protocol_signer::vls_protocol;

use client::{Client, UnixClient};
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use util::read_allowlist;
use vls_protocol_signer::handler::{Handler, RootHandler};

mod test;
use vls_proxy::util::{add_hsmd_args, handle_hsmd_version, read_integration_test_seed, setup_logging};
use vls_proxy::*;

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
                info!(
                    "new client {} {} -> {}",
                    std::process::id(),
                    handler.client_id(),
                    new_client.id()
                );
                let handler = handler.for_new_client(new_client.id(), Some(m.peer_id), m.dbid);
                thread::spawn(move || signer_loop(new_client, handler));
            }
            msg => {
                let reply = handler.handle(msg).expect("handle");
                let v = reply.as_vec();
                client.write_vec(v).unwrap();
                info!("replied {} {}", std::process::id(), handler.client_id());
            }
        }
    }
}

pub fn main() {
    setup_logging("hsmd  ", "info");
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let app = add_hsmd_args(app);
    let matches = app.get_matches();
    if handle_hsmd_version(&matches) {
        return
    }
    if matches.is_present("test") {
        test::run_test();
    } else {
        let conn = UnixConnection::new(3);
        let client = UnixClient::new(conn);
        let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("remote_hsmd_vls.kv"));
        let allowlist = read_allowlist();
        let handler =
            RootHandler::new(client.id(), read_integration_test_seed(), persister, allowlist);
        signer_loop(client, handler);
    }
}
