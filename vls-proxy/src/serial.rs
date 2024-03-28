#![macro_use]

use std::fs::File;
use std::io;
use std::num::NonZeroUsize;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use lru::LruCache;
use tokio::task::spawn_blocking;

use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::Network;
use log::*;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};
use secp256k1::PublicKey;

use lightning_signer::bitcoin;
use lightning_signer::bitcoin::secp256k1;
use vls_protocol::model::DevSecret;
use vls_protocol::msgs::HsmdDevPreinit2Options;
use vls_protocol::{msgs, msgs::Message, msgs::SerialRequestHeader, serde_bolt::WireString, Error};
use vls_protocol_client::Error as ClientError;
use vls_protocol_client::{ClientResult as Result, SignerPort};
use vls_protocol_signer::vls_protocol;

use crate::client::Client;
use crate::util::{read_allowlist, read_integration_test_seed};
use crate::*;

pub struct SerialWrap {
    inner: File,
    sequence: u16,
}

impl SerialWrap {
    fn new(inner: File) -> Self {
        let fd = inner.as_raw_fd();
        let mut termios = tcgetattr(fd).expect("tcgetattr");
        cfmakeraw(&mut termios);
        tcsetattr(fd, SetArg::TCSANOW, &termios).expect("tcsetattr");
        Self { inner, sequence: 0 }
    }
}

impl io::Read for SerialWrap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.inner.read(buf);
        if let Ok(n) = r {
            trace!("SERIAL read {} bytes {}", n, hex::encode(&buf[..n]));
        }
        r
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact(buf)?;
        trace!("SERIAL read_exact {} bytes {}", buf.len(), hex::encode(buf));
        Ok(())
    }
}

impl io::Write for SerialWrap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let r = self.inner.write(buf);
        if let Ok(n) = r {
            trace!("SERIAL write {} bytes {}", n, hex::encode(&buf[..n]));
        }
        r
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        trace!("SERIAL write_all {} bytes {}", buf.len(), hex::encode(buf));
        self.inner.write_all(&buf)
    }
}

pub fn connect(serial_port: String) -> anyhow::Result<SerialWrap> {
    info!("connecting to {}", serial_port);
    let file = File::options().read(true).write(true).open(serial_port)?;
    let mut serial = SerialWrap::new(file);
    let allowlist =
        read_allowlist().into_iter().map(|s| WireString(s.as_bytes().to_vec())).collect::<Vec<_>>();
    // Check if a testing seed is available, otherwise send None
    let seed = read_integration_test_seed(".").map(|s| DevSecret(s));
    let mut options = HsmdDevPreinit2Options::default();
    options.derivation_style = Some(0);
    options.network_name = Some(WireString(Network::Testnet.to_string().as_bytes().to_vec()));
    options.seed = seed;
    options.allowlist = Some(allowlist.into());
    let preinit2 = msgs::HsmdDevPreinit2 { options };
    let sequence = 0;
    let peer_id = [0; 33];
    let dbid = 0;
    msgs::write_serial_request_header(
        &mut serial,
        &SerialRequestHeader { sequence, peer_id, dbid },
    )?;
    msgs::write(&mut serial, preinit2)?;
    Ok(serial)
}

#[derive(Clone)]
pub struct ClientId {
    pub peer_id: PublicKey,
    pub dbid: u64,
}

impl core::fmt::Debug for ClientId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("ClientId")
            .field("peer_id", &hex::encode(&self.peer_id.serialize()))
            .field("dbid", &self.dbid)
            .finish()
    }
}

pub struct SerialSignerPort {
    serial: Arc<Mutex<SerialWrap>>,
}

#[async_trait]
impl SignerPort for SerialSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        if log::log_enabled!(log::Level::Debug) {
            let msg = msgs::from_vec(message.clone())?;
            log_request!(msg);
        }
        let serial = Arc::clone(&self.serial);
        spawn_blocking(move || {
            let mut serial_guard = serial.lock().unwrap();
            let serial = &mut *serial_guard;
            let peer_id = [0u8; 33];
            let dbid = 0;
            msgs::write_serial_request_header(
                serial,
                &SerialRequestHeader { sequence: serial.sequence, peer_id, dbid },
            )?;
            msgs::write_vec(serial, message)?;
            msgs::read_serial_response_header(serial, serial.sequence)?;
            serial.sequence = serial.sequence.wrapping_add(1);
            let result = msgs::read_raw(serial);
            if let Err(ref err) = result {
                log_error!(err);
            }
            let reply = result?;
            log_reply!(reply);
            Ok(reply)
        })
        .await
        .map_err(|_| Error::Eof)?
    }

    fn is_ready(&self) -> bool {
        true
    }
}

impl SerialSignerPort {
    pub fn new(serial: Arc<Mutex<SerialWrap>>) -> Self {
        SerialSignerPort { serial }
    }
}

const PREAPPROVE_CACHE_TTL: Duration = Duration::from_secs(60);

struct PreapprovalCacheEntry {
    tstamp: SystemTime,
    reply_bytes: Vec<u8>,
}

/// Implement the hsmd UNIX fd protocol.
/// This doesn't actually perform the signing - the hsmd packets are transported via serial to the
/// real signer.
pub struct SignerLoop<C: 'static + Client> {
    client: C,
    log_prefix: String,
    serial: Arc<Mutex<SerialWrap>>,
    client_id: Option<ClientId>,
    preapproval_cache: LruCache<Sha256Hash, PreapprovalCacheEntry>,
}

impl<C: 'static + Client> SignerLoop<C> {
    /// Create a loop for the root (lightningd) connection, but doesn't start it yet
    pub fn new(client: C, serial: Arc<Mutex<SerialWrap>>) -> Self {
        let log_prefix = format!("{}/{}/{}", std::process::id(), client.id(), 0);
        let preapproval_cache = LruCache::new(NonZeroUsize::new(6).unwrap());
        Self { client, log_prefix, serial, client_id: None, preapproval_cache }
    }

    // Create a loop for a non-root connection
    fn new_for_client(client: C, serial: Arc<Mutex<SerialWrap>>, client_id: ClientId) -> Self {
        let log_prefix = format!("{}/{}/{}", std::process::id(), client.id(), client_id.dbid);
        let preapproval_cache = LruCache::new(NonZeroUsize::new(6).unwrap());
        Self { client, log_prefix, serial, client_id: Some(client_id), preapproval_cache }
    }

    /// Start the read loop
    pub fn start(&mut self) {
        info!("loop {}: start", self.log_prefix);
        match self.do_loop() {
            Ok(()) => info!("loop {}: done", self.log_prefix),
            Err(ClientError::Protocol(Error::Eof)) => {
                info!("loop {}: ending", self.log_prefix)
            }
            Err(e) => error!("loop {}: error {:?}", self.log_prefix, e),
        }
    }

    fn do_loop(&mut self) -> Result<()> {
        loop {
            let raw_msg = self.client.read_raw()?;
            let msg = msgs::from_vec(raw_msg.clone())?;
            log_request!(msg, self);
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
                Message::PreapproveInvoice(_) | Message::PreapproveKeysend(_) => {
                    let now = SystemTime::now();
                    let req_hash = Sha256Hash::hash(&raw_msg);
                    if let Some(entry) = self.preapproval_cache.get(&req_hash) {
                        let age = now.duration_since(entry.tstamp).expect("age");
                        if age < PREAPPROVE_CACHE_TTL {
                            let reply = entry.reply_bytes.clone();
                            log_reply!(reply, self);
                            self.client.write_vec(reply)?;
                            continue;
                        }
                    }
                    let reply_bytes = self.do_proxy_msg(raw_msg)?;
                    let reply = msgs::from_vec(reply_bytes.clone()).expect("parse reply failed");
                    // Did we just witness an approval?
                    match reply {
                        Message::PreapproveKeysendReply(pkr) =>
                            if pkr.result == true {
                                self.preapproval_cache.put(
                                    req_hash,
                                    PreapprovalCacheEntry { tstamp: now, reply_bytes },
                                );
                            },
                        Message::PreapproveInvoiceReply(pir) =>
                            if pir.result == true {
                                self.preapproval_cache.put(
                                    req_hash,
                                    PreapprovalCacheEntry { tstamp: now, reply_bytes },
                                );
                            },
                        _ => {} // allow future out-of-band reply types
                    }
                }
                _ => {
                    self.do_proxy_msg(raw_msg)?;
                }
            }
        }
    }

    // Proxy the request to the signer, return the result to the node.
    // Returns the last response for caching
    fn do_proxy_msg(&mut self, raw_msg: Vec<u8>) -> Result<Vec<u8>> {
        let result = self.handle_message(raw_msg);
        if let Err(ref err) = result {
            log_error!(err, self);
        }
        let reply = result?;
        log_reply!(reply, self);
        self.client.write_vec(reply.clone())?;
        Ok(reply)
    }

    fn handle_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        let mut serial_guard = self.serial.lock().unwrap();
        let serial = &mut *serial_guard;
        let peer_id = self.client_id.as_ref().map(|c| c.peer_id.serialize()).unwrap_or([0u8; 33]);
        let dbid = self.client_id.as_ref().map(|c| c.dbid).unwrap_or(0);
        msgs::write_serial_request_header(
            serial,
            &SerialRequestHeader { sequence: serial.sequence, peer_id, dbid },
        )?;
        msgs::write_vec(serial, message)?;
        msgs::read_serial_response_header(serial, serial.sequence)?;
        serial.sequence = serial.sequence.wrapping_add(1);
        let reply = msgs::read_raw(serial)?;
        info!("handle_message {}: got reply {}", self.log_prefix, hex::encode(&reply));
        Ok(reply)
    }
}
