use async_trait::async_trait;
use backoff::Error as BackoffError;
use log::*;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use triggered::{Listener, Trigger};

use lightning_signer::bitcoin::hashes::sha256::Hash as Sha256Hash;
use lightning_signer::bitcoin::hashes::Hash;

use super::adapter::{ChannelReply, ChannelRequest, ClientId};
use crate::client::Client;
use crate::{log_error, log_pretty, log_reply, log_request};
use vls_protocol::{msgs, msgs::SerBolt as _, msgs::DeBolt as _, msgs::Message, Error as ProtocolError};
use vls_protocol_client::{ClientResult as Result, Error, SignerPort};
use vls_protocol_signer::vls_protocol;

const PREAPPROVE_CACHE_TTL: Duration = Duration::from_secs(60);
const PREAPPROVE_CACHE_SIZE: usize = 6;

struct PreapprovalCacheEntry {
    tstamp: SystemTime,
    reply_bytes: Vec<u8>,
}

pub struct GrpcSignerPort {
    sender: mpsc::Sender<ChannelRequest>,
    is_ready: Arc<AtomicBool>,
}

// create a Backoff
fn backoff() -> backoff::ExponentialBackoff {
    backoff::ExponentialBackoffBuilder::default()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_interval(Duration::from_secs(10))
        .with_max_elapsed_time(Some(Duration::from_secs(300)))
        .build()
}

#[async_trait]
impl SignerPort for GrpcSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let result = backoff::future::retry(backoff(), || async {
            let reply_rx =
                self.send_request(message.clone()).await.map_err(|e| BackoffError::permanent(e))?;
            // Wait for the signer reply
            // Can fail if the adapter shut down
            let reply = reply_rx.await.map_err(|_| BackoffError::permanent(Error::Transport))?;
            if reply.is_temporary_failure {
                // Retry with backoff
                info!("temporary error, retrying");
                return Err(BackoffError::transient(Error::Transport));
            }
            return Ok(reply.reply);
        })
        .await
        .map_err(|e| {
            error!("signer retry failed: {:?}", e);
            e
        })?;
        Ok(result)
    }

    fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::Relaxed)
    }
}

impl GrpcSignerPort {
    pub fn new(sender: mpsc::Sender<ChannelRequest>) -> Self {
        GrpcSignerPort { sender, is_ready: Arc::new(AtomicBool::new(false)) }
    }

    async fn send_request(&self, message: Vec<u8>) -> Result<oneshot::Receiver<ChannelReply>> {
        let (reply_rx, request) = Self::prepare_request(message, None);

        // Send a request to the gRPC handler to send to signer
        // This can fail if gRPC adapter shut down
        self.sender.send(request).await.map_err(|_| ProtocolError::Eof)?;

        // Once the initial packet is sent, the signer is ready
        self.is_ready.store(true, Ordering::Relaxed);

        Ok(reply_rx)
    }

    // Send a blocking request to the signer with an optional client_id
    // for use in [`SignerLoop`]
    fn send_request_blocking(
        &self,
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> Result<oneshot::Receiver<ChannelReply>> {
        let (reply_rx, request) = Self::prepare_request(message, client_id);

        // Send a request to the gRPC handler to send to signer
        // This can fail if gRPC adapter shut down
        self.sender.blocking_send(request).map_err(|_| ProtocolError::Eof)?;

        // Once the initial packet is sent, the signer is ready
        self.is_ready.store(true, Ordering::Relaxed);

        Ok(reply_rx)
    }

    fn prepare_request(
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> (oneshot::Receiver<ChannelReply>, ChannelRequest) {
        // Create a one-shot channel to receive the reply
        let (reply_tx, reply_rx) = oneshot::channel();

        let request = ChannelRequest { client_id, message, reply_tx };
        (reply_rx, request)
    }
}

/// A cache of the init message from the node, in case the signer reconnects
#[derive(Clone)]
pub struct InitMessageCache {
    /// The HsmdInit or HsmdInit2 message from node
    pub init_message: Option<Vec<u8>>,
}

impl InitMessageCache {
    /// Create a new cache
    pub fn new() -> Self {
        Self { init_message: None }
    }
}

/// Implement the hsmd UNIX fd protocol.
/// This doesn't actually perform the signing - the hsmd packets are transported via gRPC to the
/// real signer.
pub struct SignerLoop<C: 'static + Client> {
    client: C,
    log_prefix: String,
    signer_port: Arc<GrpcSignerPort>,
    client_id: Option<ClientId>,
    shutdown_trigger: Option<Trigger>,
    shutdown_signal: Option<Listener>,
    preapproval_cache: LruCache<Sha256Hash, PreapprovalCacheEntry>,
    init_message_cache: Arc<Mutex<InitMessageCache>>,
}

impl<C: 'static + Client> SignerLoop<C> {
    /// Create a loop for the root (lightningd) connection, but doesn't start it yet
    pub fn new(
        client: C,
        signer_port: Arc<GrpcSignerPort>,
        shutdown_trigger: Trigger,
        shutdown_signal: Listener,
        init_message_cache: Arc<Mutex<InitMessageCache>>,
    ) -> Self {
        let log_prefix = format!("{}/{}/{}", std::process::id(), client.id(), 0);
        let preapproval_cache = LruCache::new(NonZeroUsize::new(PREAPPROVE_CACHE_SIZE).unwrap());
        Self {
            client,
            log_prefix,
            signer_port,
            client_id: None,
            shutdown_trigger: Some(shutdown_trigger),
            shutdown_signal: Some(shutdown_signal),
            preapproval_cache,
            init_message_cache,
        }
    }

    // Create a loop for a non-root connection
    fn new_for_client(client: C, signer_port: Arc<GrpcSignerPort>, client_id: ClientId) -> Self {
        let log_prefix = format!("{}/{}/{}", std::process::id(), client.id(), client_id.dbid);
        let preapproval_cache = LruCache::new(NonZeroUsize::new(PREAPPROVE_CACHE_SIZE).unwrap());
        Self {
            client,
            log_prefix,
            signer_port,
            client_id: Some(client_id),
            shutdown_trigger: None,
            shutdown_signal: None,
            preapproval_cache,
            init_message_cache: Arc::new(Mutex::new(InitMessageCache::new())),
        }
    }

    fn is_root(&self) -> bool {
        self.client_id.is_none()
    }

    /// The init message cache
    pub fn init_message_cache(&self) -> Arc<Mutex<InitMessageCache>> {
        self.init_message_cache.clone()
    }

    /// Start the read loop
    pub fn start(&mut self) {
        info!("read loop {}: start", self.log_prefix);
        if let Some(shutdown_signal) = self.shutdown_signal.as_ref() {
            // TODO exit more cleanly
            // Right now there's no clean way to stop the UNIX fd reader loop so just be
            // aggressive here and exit when it's time to shutdown
            let shutdown_signal_clone = shutdown_signal.clone();
            let log_prefix_clone = self.log_prefix.clone();
            tokio::spawn(async move {
                info!("read loop {} waiting for shutdown", log_prefix_clone);
                tokio::select! {
                    _ = shutdown_signal_clone => {
                        info!("read loop {} saw shutdown, calling exit", log_prefix_clone);
                        process::exit(0);
                    }
                }
            });
        }
        match self.do_loop() {
            Ok(()) => info!("read loop {} done", self.log_prefix),
            Err(Error::Protocol(ProtocolError::Eof)) =>
                info!("read loop {} saw EOF; ending", self.log_prefix),
            Err(e) => error!("read loop {} saw error {:?}; ending", self.log_prefix, e),
        }
        if let Some(trigger) = self.shutdown_trigger.as_ref() {
            warn!("read loop {} terminated; triggering shutdown", self.log_prefix);
            trigger.trigger();
        }
    }

    fn do_loop(&mut self) -> Result<()> {
        loop {
            let raw_msg = self.client.read_raw()?;
            debug!("read loop {}: got raw", self.log_prefix);
            let msg = msgs::from_vec(raw_msg.clone())?;
            log_request!(msg);
            match msg {
                Message::ClientHsmFd(m) => {
                    self.client.write(msgs::ClientHsmFdReply {}).unwrap();
                    let new_client = self.client.new_client();
                    info!("new client {} -> {}", self.log_prefix, new_client.id());
                    let peer_id = m.peer_id.0;
                    let client_id = ClientId { peer_id, dbid: m.dbid };
                    let mut new_loop =
                        SignerLoop::new_for_client(new_client, self.signer_port.clone(), client_id);
                    spawn_blocking(move || new_loop.start());
                }
                Message::PreapproveInvoice(_) | Message::PreapproveKeysend(_) => {
                    let now = SystemTime::now();
                    let req_hash = Sha256Hash::hash(&raw_msg);
                    if let Some(entry) = self.preapproval_cache.get(&req_hash) {
                        let age = now.duration_since(entry.tstamp).expect("age");
                        if age < PREAPPROVE_CACHE_TTL {
                            debug!("{} found in preapproval cache", self.log_prefix);
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
                                debug!("{} adding keysend to preapproval cache", self.log_prefix);
                                self.preapproval_cache.put(
                                    req_hash,
                                    PreapprovalCacheEntry { tstamp: now, reply_bytes },
                                );
                            },
                        Message::PreapproveInvoiceReply(pir) =>
                            if pir.result == true {
                                debug!("{} adding invoice to preapproval cache", self.log_prefix);
                                self.preapproval_cache.put(
                                    req_hash,
                                    PreapprovalCacheEntry { tstamp: now, reply_bytes },
                                );
                            },
                        _ => {} // allow future out-of-band reply types
                    }
                }
                Message::HsmdInit(mut m) => {
                    if !self.is_root() {
                        error!(
                            "read loop {}: unexpected HsmdInit on non-root connection",
                            self.log_prefix
                        );
                        return Err(Error::Protocol(ProtocolError::UnexpectedType(
                            msgs::HsmdInit::TYPE,
                        )));
                    }
                    let raw_reply = self.do_proxy_msg(raw_msg)?;
                    // decode the reply and extract the protocol version
                    let reply = msgs::from_vec(raw_reply)?;
                    // we expect a HsmdInitReply
                    let init_reply = match reply {
                        Message::HsmdInitReplyV4(m) => m,
                        x => {
                            error!(
                                "read loop {}: unexpected reply to HsmdInit {:?}",
                                self.log_prefix, x
                            );
                            return Err(Error::Protocol(ProtocolError::UnexpectedType(0)));
                        }
                    };

                    // We will only accept the version that was negotiated
                    m.hsm_wire_max_version = init_reply.hsm_version;
                    m.hsm_wire_min_version = init_reply.hsm_version;

                    let mut init_message_cache = self.init_message_cache.lock().unwrap();
                    if init_message_cache.init_message.is_some() {
                        error!("read loop {}: unexpected duplicate HsmdInit", self.log_prefix);
                        return Err(Error::Protocol(ProtocolError::UnexpectedType(
                            msgs::HsmdInit::TYPE,
                        )));
                    }
                    init_message_cache.init_message = Some(m.as_vec());
                }
                Message::HsmdInit2(m) => {
                    if !self.is_root() {
                        error!(
                            "read loop {}: unexpected HsmdInit on non-root connection",
                            self.log_prefix
                        );
                        return Err(Error::Protocol(ProtocolError::UnexpectedType(
                            msgs::HsmdInit2::TYPE,
                        )));
                    }
                    self.do_proxy_msg(raw_msg)?;

                    // TODO HsmdInit2 does not have version negotiation
                    let mut init_message_cache = self.init_message_cache.lock().unwrap();
                    if init_message_cache.init_message.is_some() {
                        error!("read loop {}: unexpected duplicate HsmdInit", self.log_prefix);
                        return Err(Error::Protocol(ProtocolError::UnexpectedType(
                            msgs::HsmdInit2::TYPE,
                        )));
                    }
                    init_message_cache.init_message = Some(m.as_vec());
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
        info!("replied {}", self.log_prefix);
        Ok(reply)
    }

    fn handle_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        let result = backoff::retry(backoff(), || {
            let reply_rx =
                self.send_request(message.clone()).map_err(|e| BackoffError::permanent(e))?;
            // Wait for the signer reply
            // Can fail if the adapter shut down
            let reply =
                reply_rx.blocking_recv().map_err(|_| BackoffError::permanent(Error::Transport))?;
            if reply.is_temporary_failure {
                // Retry with backoff
                info!("read loop {}: temporary error, retrying", self.log_prefix);
                return Err(BackoffError::transient(Error::Transport));
            }
            return Ok(reply.reply);
        })
        .map_err(|e| error_from_backoff(e))
        .map_err(|e| {
            error!("read loop {}: signer retry failed: {:?}", self.log_prefix, e);
            e
        })?;
        Ok(result)
    }

    fn send_request(&mut self, message: Vec<u8>) -> Result<oneshot::Receiver<ChannelReply>> {
        self.signer_port.send_request_blocking(message, self.client_id.clone())
    }
}

fn error_from_backoff(e: BackoffError<Error>) -> Error {
    match e {
        BackoffError::Transient { err, .. } => err,
        BackoffError::Permanent(err) => err,
    }
}
