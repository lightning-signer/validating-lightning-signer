//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::thread;

use clap::{App, AppSettings, Arg};
use log::{error, info};
use url::Url;

use connection::UnixConnection;
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::Persist;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::Arc;
use vls_frontend::Frontend;
use vls_protocol::{msgs, msgs::Message, Error, Result};
use vls_protocol_signer::vls_protocol;

use client::{Client, UnixClient};
use lightning_signer::node::NodeServices;
use lightning_signer::util::clock::StandardClock;
use lightning_signer_server::nodefront::SingleFront;
use lightning_signer_server::persist::kv_json::KVJsonPersister;
use util::{create_runtime, read_allowlist};
use vls_protocol_signer::handler::{ChannelHandler, Handler, RootHandler, RootHandlerBuilder};

mod test;
use vls_proxy::util::{
    add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version, make_validator_factory,
    read_integration_test_seed, setup_logging, vls_network,
};
use vls_proxy::*;

fn root_signer_loop<C: 'static + Client>(client: C, handler: RootHandler) {
    let id = handler.client_id();
    let pid = std::process::id();
    info!("root loop {} {}: start", pid, id);
    match do_root_signer_loop(client, handler) {
        Ok(()) => info!("root loop {} {}: done", pid, id),
        Err(Error::Eof) => info!("loop {} {}: ending", pid, id),
        Err(e) => error!("root loop {} {}: error {:?}", pid, id, e),
    }
}

fn do_root_signer_loop<C: 'static + Client>(mut client: C, handler: RootHandler) -> Result<()> {
    loop {
        let msg = client.read()?;
        info!("loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
        match msg {
            Message::ClientHsmFd(m) => {
                client.write(msgs::ClientHsmFdReply {}).unwrap();
                let new_client = client.new_client();
                info!(
                    "new client {} client_id={} dbid={} -> {}",
                    std::process::id(),
                    handler.client_id(),
                    m.dbid,
                    new_client.id()
                );
                if m.dbid > 0 {
                    let handler = handler.for_new_client(new_client.id(), m.peer_id, m.dbid);
                    thread::spawn(move || channel_signer_loop(new_client, handler));
                } else {
                    let handler = handler.clone();
                    thread::spawn(move || root_signer_loop(new_client, handler));
                }
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

fn channel_signer_loop<C: 'static + Client>(client: C, handler: ChannelHandler) {
    let id = handler.client_id();
    let pid = std::process::id();
    info!("chan loop {} {} {}: start", pid, id, handler.dbid);
    match do_channel_signer_loop(client, handler) {
        Ok(()) => info!("chan loop {} {}: done", pid, id),
        Err(Error::Eof) => info!("chan loop {} {}: ending", pid, id),
        Err(e) => error!("chan loop {} {}: error {:?}", pid, id, e),
    }
}

fn do_channel_signer_loop<C: 'static + Client>(
    mut client: C,
    handler: ChannelHandler,
) -> Result<()> {
    loop {
        let msg = client.read()?;
        info!("chan loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
        let reply = handler.handle(msg).expect("handle");
        let v = reply.as_vec();
        client.write_vec(v).unwrap();
        info!("replied {} {}", std::process::id(), handler.client_id());
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
        return;
    }
    if matches.is_present("test") {
        test::run_test();
    } else {
        let conn = UnixConnection::new(3);
        let client = UnixClient::new(conn);
        let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("remote_hsmd_vls.kv"));
        let allowlist = read_allowlist();
        let network = vls_network().parse::<Network>().expect("malformed vls network");
        let starting_time_factory = ClockStartingTimeFactory::new();
        let validator_factory = make_validator_factory(network);
        let clock = Arc::new(StandardClock());
        let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
        let handler = RootHandlerBuilder::new(network, client.id(), services)
            .seed_opt(read_integration_test_seed())
            .allowlist(allowlist)
            .build();

        let frontend = Frontend::new(
            Arc::new(SingleFront { node: Arc::clone(&handler.node) }),
            Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
        );

        let runtime = create_runtime("inplace-frontend");
        runtime.block_on(async {
            frontend.start();
        });

        root_signer_loop(client, handler);
    }
}
