use std::os::fd::IntoRawFd;
use std::os::unix::io::RawFd;

use bitcoin::consensus::Encodable;
use lightning_signer::bitcoin;
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

use serde_bolt::{io::Read, ReadBigEndian};
use vls_protocol::serde_bolt;
use vls_protocol::serde_bolt::io::FromStd;
use vls_protocol::{msgs, Error, Result};
use vls_protocol_signer::vls_protocol;

use crate::connection::UnixConnection;

pub trait Client: Send {
    fn write<M: msgs::DeBolt + Encodable>(&mut self, msg: M) -> Result<()>;
    fn write_vec(&mut self, v: Vec<u8>) -> Result<()>;
    fn read(&mut self) -> Result<msgs::Message>;
    fn read_raw(&mut self) -> Result<Vec<u8>>;
    fn id(&self) -> u64;
    #[must_use = "don't leak the client fd"]
    fn new_client(&mut self) -> Self;
}

pub struct UnixClient {
    conn: FromStd<UnixConnection>,
}

impl UnixClient {
    pub fn new(conn: UnixConnection) -> Self {
        Self { conn: FromStd::new(conn) }
    }

    pub fn recv_fd(&mut self) -> core::result::Result<RawFd, ()> {
        self.conn.inner().recv_fd()
    }
}

impl Client for UnixClient {
    fn write<M: msgs::DeBolt + Encodable>(&mut self, msg: M) -> Result<()> {
        msgs::write(&mut self.conn, msg)?;
        Ok(())
    }

    fn write_vec(&mut self, v: Vec<u8>) -> Result<()> {
        msgs::write_vec(&mut self.conn, v)?;
        Ok(())
    }

    fn read(&mut self) -> Result<msgs::Message> {
        msgs::read(&mut self.conn)
    }

    fn read_raw(&mut self) -> Result<Vec<u8>> {
        // map to IO error, otherwise we get a Bitcoin error because of where read_u32_be is defined
        let len = self.conn.read_u32_be().map_err(|e| Error::Io(e.to_string()))?;
        let mut data = Vec::new();
        data.resize(len as usize, 0);
        let len = self.conn.read(&mut data)?;
        if len < data.len() {
            return Err(Error::ShortRead);
        }
        Ok(data)
    }

    fn id(&self) -> u64 {
        self.conn.inner().id()
    }

    fn new_client(&mut self) -> UnixClient {
        let (fd_a, fd_b) =
            socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
        self.conn.inner().send_fd(fd_a.into_raw_fd());
        UnixClient::new(UnixConnection::new(fd_b.into_raw_fd()))
    }
}
