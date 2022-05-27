use std::collections::HashMap;
use std::pin::Pin;
use std::process::exit;
use std::result::Result as StdResult;
use std::sync::Arc;

use futures::{Stream, StreamExt};
use log::{error, info};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tonic::{transport::Server, Request, Response, Status, Streaming};

use super::hsmd::{
    hsmd_server, HsmRequestContext, PingReply, PingRequest, SignerRequest, SignerResponse,
};
use super::incoming::TcpIncoming;
use std::sync::atomic::{AtomicU64, Ordering};
use tonic::transport::Error;
use triggered::{Listener, Trigger};

struct Requests {
    requests: HashMap<u64, ChannelRequest>,
    request_id: AtomicU64,
}

/// Adapt the hsmd UNIX socket protocol to gRPC streaming
#[derive(Clone)]
pub struct ProtocolAdapter {
    receiver: Arc<Mutex<Receiver<ChannelRequest>>>,
    requests: Arc<Mutex<Requests>>,
    #[allow(unused)]
    shutdown_trigger: Trigger,
    shutdown_signal: Listener,
}

pub type SignerStream =
    Pin<Box<dyn Stream<Item = StdResult<SignerRequest, Status>> + Send + 'static>>;

impl ProtocolAdapter {
    pub fn new(
        receiver: Receiver<ChannelRequest>,
        shutdown_trigger: Trigger,
        shutdown_signal: Listener,
    ) -> Self {
        ProtocolAdapter {
            receiver: Arc::new(Mutex::new(receiver)),
            requests: Arc::new(Mutex::new(Requests {
                requests: HashMap::new(),
                request_id: AtomicU64::new(0),
            })),
            shutdown_trigger,
            shutdown_signal,
        }
    }
    // Get requests from the parent process and feed them to gRPC.
    // Will abort the stream reader task of the parent process goes away.
    pub async fn writer_stream(&self, stream_reader_task: JoinHandle<()>) -> SignerStream {
        let receiver = self.receiver.clone();
        let requests = self.requests.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        let output = async_stream::try_stream! {
            let mut receiver = receiver.lock().await;
            // TODO resend outstanding requests
            // Parent request
            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => {
                        info!("writer got shutdown_signal");
                        break;
                    }
                    resp_opt = receiver.recv() => {
                        if let Some(req) = resp_opt {
                            let message = req.message.clone();
                            let mut reqs = requests.lock().await;
                            let request_id = reqs.request_id.fetch_add(1, Ordering::AcqRel);
                            let context = req.client_id.as_ref().map(|c| HsmRequestContext {
                                peer_id: c.peer_id.to_vec(),
                                dbid: c.dbid,
                                capabilities: 0,
                            });
                            reqs.requests.insert(request_id, req);
                            info!("sending request {} to signer", request_id);
                            yield SignerRequest {
                                request_id,
                                message: message,
                                context,
                            };
                        } else {
                            // parent closed UNIX fd - we are shutting down
                            info!("parent closed - shutting down signer stream");
                            break;
                        }
                    }
                }
            }
            info!("stream writer loop finished");
            stream_reader_task.abort();
            // ignore join result
            let _ = stream_reader_task.await;
        };
        Box::pin(output)
    }

    // Get signer responses from gRPC and feed them back to the parent process
    pub fn start_stream_reader(&self, mut stream: Streaming<SignerResponse>) -> JoinHandle<()> {
        let requests = self.requests.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => {
                        info!("reader got shutdown_signal");
                        break;
                    }
                    resp_opt = stream.next() => {
                        match resp_opt {
                            Some(Ok(resp)) => {
                                info!("got signer response {}", resp.request_id);
                                if !resp.error.is_empty() {
                                    error!("signer error: {}", resp.error);
                                    // all signer errors are fatal
                                    // TODO exit more cleanly
                                    // Right now there's no clean way to stop the UNIX fd reader
                                    // loop (aka "Signer Loop") if the adapter determines there's a
                                    // fatal error in the signer sub-process, so just be aggressive
                                    // here and exit.
                                    exit(1);
                                }
                                let mut reqs = requests.lock().await;
                                let channel_req_opt = reqs.requests.remove(&resp.request_id);
                                if let Some(channel_req) = channel_req_opt {
                                    let reply = ChannelReply { reply: resp.message };
                                    let send_res = channel_req.reply_tx.send(reply);
                                    if send_res.is_err() {
                                        error!("failed to send response back to internal channel");
                                        // TODO exit more cleanly
                                        // see above
                                        exit(1);
                                    }
                                } else {
                                    error!("got response for unknown request ID {}", resp.request_id);
                                    // TODO exit more cleanly
                                    // see above
                                    exit(1);
                                }
                            }
                            Some(Err(err)) => {
                                // signer connection error
                                error!("got signer gRPC error {}", err);
                                break;
                            }
                            None => {
                                // signer closed connection
                                info!("response task closing - EOF");
                                break;
                            }
                        }
                    }
                }
            }
            info!("stream reader loop finished");
        })
    }
}

/// A request
/// Responses are received on the oneshot sender inside this struct
pub struct ChannelRequest {
    pub message: Vec<u8>,
    pub reply_tx: oneshot::Sender<ChannelReply>,
    pub client_id: Option<ClientId>,
}

// mpsc reply
pub struct ChannelReply {
    pub reply: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ClientId {
    pub peer_id: [u8; 33],
    pub dbid: u64,
}

/// Listens for a connection from the signer, and then sends requests to it
#[derive(Clone)]
pub struct HsmdService {
    #[allow(unused)]
    shutdown_trigger: Trigger,
    adapter: ProtocolAdapter,
    sender: Sender<ChannelRequest>,
}

impl HsmdService {
    /// Create the service
    pub fn new(shutdown_trigger: Trigger, shutdown_signal: Listener) -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        let adapter =
            ProtocolAdapter::new(receiver, shutdown_trigger.clone(), shutdown_signal.clone());

        HsmdService { shutdown_trigger, adapter, sender }
    }

    pub async fn start(
        self,
        incoming: TcpIncoming,
        shutdown_signal: Listener,
    ) -> Result<(), Error> {
        let service = Server::builder()
            .add_service(hsmd_server::HsmdServer::new(self))
            .serve_with_incoming_shutdown(incoming, shutdown_signal);
        service.await
    }

    /// Get the sender for the request channel
    pub fn sender(&self) -> Sender<ChannelRequest> {
        self.sender.clone()
    }
}

#[tonic::async_trait]
impl hsmd_server::Hsmd for HsmdService {
    async fn ping(&self, request: Request<PingRequest>) -> StdResult<Response<PingReply>, Status> {
        info!("got ping request");
        let r = request.into_inner();
        Ok(Response::new(PingReply { message: r.message }))
    }

    type SignerStreamStream = SignerStream;

    async fn signer_stream(
        &self,
        request: Request<Streaming<SignerResponse>>,
    ) -> StdResult<Response<Self::SignerStreamStream>, Status> {
        let stream = request.into_inner();

        let stream_reader_task = self.adapter.start_stream_reader(stream);

        let stream = self.adapter.writer_stream(stream_reader_task).await;

        Ok(Response::new(stream as Self::SignerStreamStream))
    }
}
