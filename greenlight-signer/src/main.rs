#![allow(dead_code, unused_variables, unused_imports)]

use std::os::unix::io::{FromRawFd, RawFd};

use env_logger::Env;
use log::{error, info};
use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, socketpair, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult};
use serde::Serialize;
use serde_bolt::{Error as SError, Read, Result as SResult, Write};

use connection::Connection;
use greenlight_protocol::{Error, msgs, Result, serde_bolt};
use greenlight_protocol::model::{Basepoints, ExtKey, PubKey, PubKey32, Secret};
use greenlight_protocol::msgs::{ClientHsmFdReply, GetChannelBasepointsReply, HsmdInitReply, Memleak, MemleakReply, Message};
use clap::{App, Arg};
use std::thread;

mod connection;

pub(crate) struct Client {
    conn: Connection,
}

impl Client {
    fn new(conn: Connection) -> Self {
        Self {
            conn
        }
    }
    fn write<M: msgs::TypedMessage + Serialize>(&mut self, msg: M) -> Result<()> {
        msgs::write(&mut self.conn, msg)?;
        Ok(())
    }

    fn read(&mut self) -> Result<msgs::Message> {
        msgs::read(&mut self.conn)
    }

    #[must_use = "don't leak the client fd"]
    fn new_client(&mut self) -> Client {
        let (fd_a, fd_b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
        self.conn.send_fd(fd_a);
        Client::new(Connection::new(fd_b))
    }

    fn recv_fd(&mut self) -> core::result::Result<RawFd, ()> {
        self.conn.recv_fd()
    }

    fn id(&self) -> u64 {
        self.conn.id()
    }
}

fn run_parent(fd: RawFd) {
    let mut client = Client::new(Connection::new(fd));
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
    let mut client1 = Client::new(Connection::new(fd));
    client1.write(msgs::Memleak {}).unwrap();
    info!("parent: client1 {:?}", client1.read());
}

fn signer_loop(client: Client) {
    let id = client.id();
    info!("loop {}: start", id);
    match do_client_loop(client) {
        Ok(()) => info!("loop {}: done", id),
        Err(Error::Eof) => info!("loop {}: EOF", id),
        Err(e) => error!("loop {}: error {:?}", id, e),
    }
}

fn do_client_loop(mut client: Client) -> Result<()> {
    loop {
        let msg = client.read()?;
        info!("loop {}: got {:?}", client.id(), msg);
        match msg {
            Message::Memleak(m) => {
                client.write(MemleakReply { result: false }).unwrap();
            }
            Message::HsmdInit(_) => {
                client.write(HsmdInitReply {
                    node_id: PubKey([0; 33]),
                    bip32: ExtKey([0; 78]),
                    bolt12: PubKey32([0; 32]),
                    onion_reply_secret: Secret([0; 32])
                }).unwrap();
            }
            Message::ClientHsmFd(_) => {
                client.write(ClientHsmFdReply {}).unwrap();
                let new_client = client.new_client();
                thread::spawn(|| signer_loop(new_client));
            }
            Message::GetChannelBasepoints(_) => {
                let basepoints = Basepoints {
                    revocation: PubKey([0; 33]),
                    payment: PubKey([0; 33]),
                    htlc: PubKey([0; 33]),
                    delayed_payment: PubKey([0; 33]),
                };
                client.write(GetChannelBasepointsReply { basepoints, node_id: PubKey([0; 33]) }).unwrap();
            }
            Message::Unknown(u) => unimplemented!("loop {}: unknown message type {}", client.id(), u.message_type),
            m => unimplemented!("loop {}: unimplemented message {:?}", client.id(), m),
        }
    }
}

pub fn main() {
    setup_logging("info");
    let app = App::new("signer")
        .about("Greenlight lightning-signer")
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let matches = app.get_matches();
    if matches.is_present("test") {
        run_test();
    } else {
        let conn = Connection::new(3);
        let client = Client::new(conn);
        signer_loop(client);
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
            let conn = Connection::new(fd3);
            let client = Client::new(conn);
            signer_loop(client)
        },
        Err(_) => {}
    }
}

fn setup_logging(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}
