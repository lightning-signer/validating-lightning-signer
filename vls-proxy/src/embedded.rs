use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;

use async_trait::async_trait;
use tokio::task::spawn_blocking;

use bitcoin::Network;
use log::{debug, error, info};
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
use secp256k1::PublicKey;

use lightning_signer::bitcoin;
use lightning_signer::bitcoin::secp256k1;
use vls_protocol::model::Secret;
use vls_protocol::{msgs, msgs::Message, serde_bolt, serde_bolt::WireString, Error, Result};
use vls_protocol_client::SignerPort;
use vls_protocol_signer::vls_protocol;
use vls_proxy::client::Client;
use vls_proxy::util::{read_allowlist, read_integration_test_seed};

pub struct SerialWrap {
    inner: File,
    peek: Option<u8>,
    sequence: u16,
}

impl SerialWrap {
    fn new(inner: File) -> Self {
        let fd = inner.as_raw_fd();
        let mut termios = tcgetattr(fd).expect("tcgetattr");
        cfmakeraw(&mut termios);
        tcsetattr(fd, SetArg::TCSANOW, &termios).expect("tcsetattr");
        Self { inner, peek: None, sequence: 0 }
    }
}

impl serde_bolt::Read for SerialWrap {
    type Error = serde_bolt::Error;

    fn read(&mut self, mut buf: &mut [u8]) -> serde_bolt::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut nread = 0;

        if let Some(p) = self.peek.take() {
            buf[0] = p;
            nread += 1;
            let len = buf.len();
            buf = &mut buf[1..len];
        }

        // Not well documented in serde_bolt, but we are expected to block
        // until we can read the whole buf or until we get to EOF.
        while !buf.is_empty() {
            let n = self.inner.read(buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
            if n == 0 {
                // we are at EOF
                return if nread != 0 { Ok(nread) } else { Err(serde_bolt::Error::Eof) };
            }
            nread += n;
            let len = buf.len();
            buf = &mut buf[n..len];
        }
        Ok(nread)
    }

    fn peek(&mut self) -> serde_bolt::Result<Option<u8>> {
        if self.peek.is_some() {
            return Ok(self.peek);
        }
        let mut buf = [0; 1];
        let n = self.inner.read(&mut buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
        if n == 1 {
            self.peek = Some(buf[0]);
        }
        Ok(self.peek)
    }
}

impl serde_bolt::Write for SerialWrap {
    type Error = serde_bolt::Error;

    fn write_all(&mut self, buf: &[u8]) -> serde_bolt::Result<()> {
        self.inner.write_all(&buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
        Ok(())
    }
}

pub fn connect(serial_port: String) -> anyhow::Result<SerialWrap> {
    info!("connecting to {}", serial_port);
    let file = File::options().read(true).write(true).open(serial_port)?;
    let mut serial = SerialWrap::new(file);
    let allowlist =
        read_allowlist().into_iter().map(|s| WireString(s.as_bytes().to_vec())).collect::<Vec<_>>();
    let seed = read_integration_test_seed().map(|s| Secret(s)).or(Some(Secret([1; 32])));
    // FIXME remove this
    info!("allowlist {:?} seed {:?}", allowlist, seed);
    let init = msgs::HsmdInit2 {
        derivation_style: 0,
        network_name: WireString(Network::Testnet.to_string().as_bytes().to_vec()),
        dev_seed: seed,
        dev_allowlist: allowlist,
    };
    let sequence = 0;
    msgs::write_serial_request_header(&mut serial, sequence, 0)?;
    msgs::write(&mut serial, init)?;
    msgs::read_serial_response_header(&mut serial, sequence)?;
    let init_reply: msgs::HsmdInit2Reply = msgs::read_message(&mut serial)?;
    info!("init reply {:?}", init_reply);
    Ok(serial)
}

#[derive(Clone, Debug)]
pub struct ClientId {
    pub peer_id: PublicKey,
    pub dbid: u64,
}

pub struct SerialSignerPort {
    serial: Arc<Mutex<SerialWrap>>,
}

#[async_trait]
impl SignerPort for SerialSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let serial = Arc::clone(&self.serial);
        spawn_blocking(move || {
            let mut serial_guard = serial.lock().unwrap();
            let serial = &mut *serial_guard;
            let dbid = 0;
            msgs::write_serial_request_header(serial, serial.sequence, dbid)?;
            msgs::write_vec(serial, message)?;
            msgs::read_serial_response_header(serial, serial.sequence)?;
            serial.sequence = serial.sequence.wrapping_add(1);
            let reply = msgs::read_raw(serial)?;
            Ok(reply)
        })
        .await
        .map_err(|_| Error::Eof)?
    }

    fn clone(&self) -> Box<dyn SignerPort> {
        Box::new(Self { serial: self.serial.clone() })
    }
}

impl SerialSignerPort {
    pub fn new(serial: Arc<Mutex<SerialWrap>>) -> Self {
        SerialSignerPort { serial }
    }
}

/// Implement the hsmd UNIX fd protocol.
/// This doesn't actually perform the signing - the hsmd packets are transported via serial to the
/// real signer.
pub struct SignerLoop<C: 'static + Client> {
    client: C,
    log_prefix: String,
    serial: Arc<Mutex<SerialWrap>>,
    client_id: Option<ClientId>,
}

impl<C: 'static + Client> SignerLoop<C> {
    /// Create a loop for the root (lightningd) connection, but doesn't start it yet
    pub fn new(client: C, serial: Arc<Mutex<SerialWrap>>) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self { client, log_prefix, serial, client_id: None }
    }

    // Create a loop for a non-root connection
    fn new_for_client(client: C, serial: Arc<Mutex<SerialWrap>>, client_id: ClientId) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self { client, log_prefix, serial, client_id: Some(client_id) }
    }

    /// Start the read loop
    pub fn start(&mut self) {
        info!("loop {}: start", self.log_prefix);
        match self.do_loop() {
            Ok(()) => info!("loop {}: done", self.log_prefix),
            Err(Error::Eof) => info!("loop {}: ending", self.log_prefix),
            Err(e) => error!("loop {}: error {:?}", self.log_prefix, e),
        }
    }

    fn do_loop(&mut self) -> Result<()> {
        loop {
            let raw_msg = self.client.read_raw()?;
            debug!("loop {}: got raw", self.log_prefix);
            let msg = msgs::from_vec(raw_msg.clone())?;
            info!("loop {}: got {:x?}", self.log_prefix, msg);
            match msg {
                Message::ClientHsmFd(m) => {
                    self.client.write(msgs::ClientHsmFdReply {}).unwrap();
                    let new_client = self.client.new_client();
                    info!("new client {} -> {}", self.log_prefix, new_client.id());
                    let peer_id = PublicKey::from_slice(&m.peer_id.0).expect("client pubkey"); // we don't expect a bad key from lightningd parent
                    let client_id = ClientId { peer_id, dbid: m.dbid };
                    let mut new_loop =
                        SignerLoop::new_for_client(new_client, self.serial.clone(), client_id);
                    thread::spawn(move || new_loop.start());
                }
                Message::Memleak(_) => {
                    let reply = msgs::MemleakReply { result: false };
                    self.client.write(reply)?;
                }
                _ => {
                    let reply = self.handle_message(raw_msg)?;

                    // Write the reply to the node
                    self.client.write_vec(reply)?;
                    info!("replied {}", self.log_prefix);
                }
            }
        }
    }

    fn handle_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        let mut serial_guard = self.serial.lock().unwrap();
        let serial = &mut *serial_guard;
        let dbid = self.client_id.as_ref().map(|c| c.dbid).unwrap_or(0);
        msgs::write_serial_request_header(serial, serial.sequence, dbid)?;
        msgs::write_vec(serial, message)?;
        msgs::read_serial_response_header(serial, serial.sequence)?;
        serial.sequence = serial.sequence.wrapping_add(1);
        let reply = msgs::read_raw(serial)?;
        Ok(reply)
    }
}
