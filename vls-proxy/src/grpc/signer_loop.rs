use backoff::Error as BackoffError;
use log::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use triggered::Trigger;

use async_trait::async_trait;

use super::adapter::{ChannelReply, ChannelRequest, ClientId};
use crate::client::Client;
use crate::{log_error, log_pretty, log_reply, log_request};
use vls_protocol::{msgs, msgs::Message, Error as ProtocolError};
use vls_protocol_client::{ClientResult as Result, Error, SignerPort};
use vls_protocol_signer::vls_protocol;

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
            Err(Error::Protocol(ProtocolError::Eof)) => info!("loop {}: ending", self.log_prefix),
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
        let result = backoff::retry(backoff(), || {
            let reply_rx =
                self.send_request(message.clone()).map_err(|e| BackoffError::permanent(e))?;
            // Wait for the signer reply
            // Can fail if the adapter shut down
            let reply =
                reply_rx.blocking_recv().map_err(|_| BackoffError::permanent(Error::Transport))?;
            if reply.is_temporary_failure {
                // Retry with backoff
                info!("loop {}: temporary error, retrying", self.log_prefix);
                return Err(BackoffError::transient(Error::Transport));
            }
            return Ok(reply.reply);
        })
        .map_err(|e| error_from_backoff(e))
        .map_err(|e| {
            error!("loop {}: signer retry failed: {:?}", self.log_prefix, e);
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
