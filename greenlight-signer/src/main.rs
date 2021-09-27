#![allow(unused_variables)]

use std::os::unix::io::RawFd;

use env_logger::Env;
use log::{error, info};
use nix::sys::socket::{AddressFamily, socketpair, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult};

use connection::UnixConnection;
use greenlight_protocol::{Error, msgs, Result, msgs::Message};
use clap::{App, Arg, AppSettings};
use std::{env, thread};
use crate::client::{Client, UnixClient};
use greenlight_protocol::model::PubKey;
use crate::handler::Handler;

mod connection;
mod client;
mod handler;

fn run_parent(fd: RawFd) {
    let mut client = UnixClient::new(UnixConnection::new(fd));
    info!("parent: start");
    client.write(msgs::Memleak {}).unwrap();
    info!("parent: {:?}", client.read());
    client.write(msgs::ClientHsmFd {
        id: PubKey([0; 33]),
        dbid: 0,
        capabilities: 0
    }).unwrap();
    info!("parent: {:?}", client.read());
    let fd = client.recv_fd().expect("fd");
    info!("parent: received fd {}", fd);
    let mut client1 = UnixClient::new(UnixConnection::new(fd));
    client1.write(msgs::Memleak {}).unwrap();
    info!("parent: client1 {:?}", client1.read());
}

fn signer_loop(handler: Handler<UnixClient>) {
    let id = handler.client.id();
    info!("loop {}: start", id);
    match do_signer_loop(handler) {
        Ok(()) => info!("loop {}: done", id),
        Err(Error::Eof) => info!("loop {}: ending", id),
        Err(e) => error!("loop {}: error {:?}", id, e),
    }
}

fn do_signer_loop(mut handler: Handler<UnixClient>) -> Result<()> {
    loop {
        let msg = handler.client.read()?;
        info!("loop {}: got {:?}", handler.client.id(), msg);
        match msg {
            Message::ClientHsmFd(_) => {
                handler.client.write(msgs::ClientHsmFdReply {}).unwrap();
                let new_client = handler.client.new_client();
                let handler = handler.with_new_client(new_client);
                thread::spawn(|| signer_loop(handler));
            }
            msg => handler.handle(msg)
        }
    }
}

pub fn main() {
    setup_logging("info");
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(Arg::from("--version show a dummy version"))
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version = env::var("GREENLIGHT_VERSION")
            .expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        return;
    }
    if matches.is_present("test") {
        run_test();

    } else {
        let conn = UnixConnection::new(3);
        let client = UnixClient::new(conn);
        let handler = Handler::new(client);
        signer_loop(handler);
    }
}

fn run_test() {
    info!("starting test");
    let (fd3, fd4) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
    assert_eq!(fd3, 3);
    assert_eq!(fd4, 4);
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            close(fd3).unwrap();
            run_parent(fd4)
        },
        Ok(ForkResult::Child) => {
            close(fd4).unwrap();
            let conn = UnixConnection::new(fd3);
            let client = UnixClient::new(conn);
            let handler = Handler::new(client);
            signer_loop(handler)
        },
        Err(_) => {}
    }
}

fn setup_logging(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}
