#![allow(dead_code, unused_variables, unused_imports)]

use std::os::unix::io::{FromRawFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, socketpair, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult};
use serde::Serialize;
use serde_bolt::{Error as SError, Read, Result as SResult, Write};

use connection::Connection;
use greenlight_protocol::{msgs, serde_bolt, Error, Result};
use greenlight_protocol::msgs::{Memleak, MemleakReply, Message, HsmdInitReply, ClientHsmFdReply};
use env_logger::Env;
use log::{info, error};
use greenlight_protocol::model::{PubKey32, PubKey, ExtKey, Secret};

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

    fn new_client(&mut self) {
        let (fd_a, fd_b) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
        self.conn.send_fd(fd_a);
        // TODO client loop for fd_b
    }

    fn recv_fd(&mut self) -> core::result::Result<RawFd, ()> {
        self.conn.recv_fd()
    }
}

fn run_parent(fd: RawFd) {
    let conn = Connection::new(fd);
    let mut client = Client::new(conn);
    info!("start parent");
    client.write(msgs::Memleak {}).unwrap();
    info!("{:?}", client.read());
    client.write(msgs::ClientHsmFd {
        id: PubKey([0; 33]),
        dbid: 0,
        capabilities: 0
    }).unwrap();
    info!("{:?}", client.read());
    let fd = client.recv_fd().expect("fd");
    info!("received fd {}", fd);
}

fn run_child(fd: RawFd) {
    let conn = Connection::new(fd);
    let mut client = Client::new(conn);
    info!("start child");
    match do_child_loop(&mut client) {
        Ok(()) => {}
        Err(Error::Eof) => info!("done child"),
        Err(e) => error!("child got error {:?}", e),
    }
}

fn do_child_loop(client: &mut Client) -> Result<()> {
    loop {
        let msg = client.read()?;
        match msg {
            Message::Memleak(m) => {
                info!("got {:?}", m);
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
                client.new_client();
            }
            Message::Unknown(u) => unimplemented!("unknown message type {}", u.message_type),
            m => unimplemented!("unimplemented message {:?}", m),
        }
    }
}

fn main() {
    setup_logging("info");

    info!("starting");
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
            run_child(fd3)
        },
        Err(_) => {}
    }
}

fn setup_logging(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}
