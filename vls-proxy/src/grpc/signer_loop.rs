use log::{debug, error, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use triggered::Trigger;

use async_trait::async_trait;

use super::adapter::{ChannelReply, ChannelRequest, ClientId};
use crate::client::Client;
use crate::{log_error, log_pretty, log_reply, log_request};
use vls_protocol::{msgs, msgs::Message, Error};
use vls_protocol_client::Error::ProtocolError;
use vls_protocol_client::{ClientResult as Result, SignerPort};
use vls_protocol_signer::vls_protocol;

pub struct GrpcSignerPort {
    sender: mpsc::Sender<ChannelRequest>,
    is_ready: Arc<AtomicBool>,
}

#[async_trait]
impl SignerPort for GrpcSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let reply_rx = self.send_request(message).await?;
        self.get_reply(reply_rx).await
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
        self.sender.send(request).await.map_err(|_| Error::Eof)?;

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
        self.sender.blocking_send(request).map_err(|_| Error::Eof)?;

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

    async fn get_reply(&self, reply_rx: oneshot::Receiver<ChannelReply>) -> Result<Vec<u8>> {
        // Wait for the signer reply
        // Can fail if the adapter shut down
        let reply = reply_rx.await.map_err(|_| Error::Eof)?;
        Ok(reply.reply)
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
}

impl<C: 'static + Client> SignerLoop<C> {
    /// Create a loop for the root (lightningd) connection, but doesn't start it yet
    pub fn new(client: C, signer_port: Arc<GrpcSignerPort>, shutdown_trigger: Trigger) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self {
            client,
            log_prefix,
            signer_port,
            client_id: None,
            shutdown_trigger: Some(shutdown_trigger),
        }
    }

    // Create a loop for a non-root connection
    fn new_for_client(client: C, signer_port: Arc<GrpcSignerPort>, client_id: ClientId) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self { client, log_prefix, signer_port, client_id: Some(client_id), shutdown_trigger: None }
    }

    /// Start the read loop
    pub fn start(&mut self) {
        info!("loop {}: start", self.log_prefix);
        match self.do_loop() {
            Ok(()) => info!("loop {}: done", self.log_prefix),
            Err(ProtocolError(Error::Eof)) => info!("loop {}: ending", self.log_prefix),
            Err(e) => error!("loop {}: error {:?}", self.log_prefix, e),
        }
        if let Some(trigger) = self.shutdown_trigger.as_ref() {
            trigger.trigger();
            info!("loop {}: triggered shutdown", self.log_prefix);
        }
    }

    fn do_loop(&mut self) -> Result<()> {
        loop {
            let raw_msg = self.client.read_raw()?;
            debug!("loop {}: got raw", self.log_prefix);
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
                _ => {
                    let result = self.handle_message(raw_msg);
                    if let Err(ref err) = result {
                        log_error!(err);
                    }
                    let reply = result?;
                    log_reply!(reply);

                    // Write the reply to the node
                    self.client.write_vec(reply)?;
                    info!("replied {}", self.log_prefix);
                }
            }
        }
    }

    fn handle_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        let reply_rx = self.send_request(message)?;
        self.get_reply(reply_rx)
    }

    fn send_request(&mut self, message: Vec<u8>) -> Result<oneshot::Receiver<ChannelReply>> {
        self.signer_port.send_request_blocking(message, self.client_id.clone())
    }

    fn get_reply(&mut self, reply_rx: oneshot::Receiver<ChannelReply>) -> Result<Vec<u8>> {
        // Wait for the signer reply
        // Can fail if the adapter shut down
        let reply = reply_rx.blocking_recv().map_err(|_| Error::Eof)?;
        Ok(reply.reply)
    }
}
