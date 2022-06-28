use log::{debug, error, info};
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use triggered::Trigger;

use async_trait::async_trait;

use super::adapter::{ChannelReply, ChannelRequest, ClientId};
use crate::client::Client;
use vls_protocol::{msgs, msgs::Message, Error, Result};
use vls_protocol_client::SignerPort;
use vls_protocol_signer::vls_protocol;

pub struct GrpcSignerPort {
    sender: mpsc::Sender<ChannelRequest>,
}

#[async_trait]
impl SignerPort for GrpcSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let reply_rx = self.send_request(message).await?;
        self.get_reply(reply_rx).await
    }

    fn clone(&self) -> Box<dyn SignerPort> {
        Box::new(Self { sender: self.sender.clone() })
    }
}

impl GrpcSignerPort {
    pub fn new(sender: mpsc::Sender<ChannelRequest>) -> Self {
        GrpcSignerPort { sender }
    }

    async fn send_request(&self, message: Vec<u8>) -> Result<oneshot::Receiver<ChannelReply>> {
        // Create a one-shot channel to receive the reply
        let (reply_tx, reply_rx) = oneshot::channel();

        // Send a request to the gRPC handler to send to signer
        let request = ChannelRequest { client_id: None, message, reply_tx };

        // This can fail if gRPC adapter shut down
        self.sender.send(request).await.map_err(|_| Error::Eof)?;
        Ok(reply_rx)
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
    sender: mpsc::Sender<ChannelRequest>,
    client_id: Option<ClientId>,
    shutdown_trigger: Option<Trigger>,
}

impl<C: 'static + Client> SignerLoop<C> {
    /// Create a loop for the root (lightningd) connection, but doesn't start it yet
    pub fn new(client: C, sender: mpsc::Sender<ChannelRequest>, shutdown_trigger: Trigger) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self {
            client,
            log_prefix,
            sender,
            client_id: None,
            shutdown_trigger: Some(shutdown_trigger),
        }
    }

    // Create a loop for a non-root connection
    fn new_for_client(
        client: C,
        sender: mpsc::Sender<ChannelRequest>,
        client_id: ClientId,
    ) -> Self {
        let log_prefix = format!("{}/{}", std::process::id(), client.id());
        Self { client, log_prefix, sender, client_id: Some(client_id), shutdown_trigger: None }
    }

    /// Start the read loop
    pub fn start(&mut self) {
        info!("loop {}: start", self.log_prefix);
        match self.do_loop() {
            Ok(()) => info!("loop {}: done", self.log_prefix),
            Err(Error::Eof) => info!("loop {}: ending", self.log_prefix),
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
            info!("loop {}: got {:x?}", self.log_prefix, msg);
            match msg {
                Message::ClientHsmFd(m) => {
                    self.client.write(msgs::ClientHsmFdReply {}).unwrap();
                    let new_client = self.client.new_client();
                    info!("new client {} -> {}", self.log_prefix, new_client.id());
                    let peer_id = m.peer_id.0;
                    let client_id = ClientId { peer_id, dbid: m.dbid };
                    let mut new_loop =
                        SignerLoop::new_for_client(new_client, self.sender.clone(), client_id);
                    spawn_blocking(move || new_loop.start());
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
        let reply_rx = self.send_request(message)?;
        self.get_reply(reply_rx)
    }

    fn send_request(&mut self, message: Vec<u8>) -> Result<oneshot::Receiver<ChannelReply>> {
        // Create a one-shot channel to receive the reply
        let (reply_tx, reply_rx) = oneshot::channel();

        // Send a request to the gRPC handler to send to signer
        let request = ChannelRequest { client_id: self.client_id.clone(), message, reply_tx };

        // This can fail if gRPC adapter shut down
        self.sender.blocking_send(request).map_err(|_| Error::Eof)?;
        Ok(reply_rx)
    }

    fn get_reply(&mut self, reply_rx: oneshot::Receiver<ChannelReply>) -> Result<Vec<u8>> {
        // Wait for the signer reply
        // Can fail if the adapter shut down
        let reply = reply_rx.blocking_recv().map_err(|_| Error::Eof)?;
        Ok(reply.reply)
    }
}
