use std::collections::HashMap;
use std::pin::Pin;
use std::process::exit;
use std::result::Result as StdResult;
use std::sync::Arc;

use futures::{Stream, StreamExt};
use log::{error, info};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tonic::{Status, Streaming};

use super::hsmd::{HsmRequestContext, SignerRequest, SignerResponse};
use super::signer_loop::{ChannelReply, ChannelRequest};
use std::sync::atomic::{AtomicU64, Ordering};
use triggered::Trigger;

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
}

pub type SignerStream =
    Pin<Box<dyn Stream<Item = StdResult<SignerRequest, Status>> + Send + 'static>>;

impl ProtocolAdapter {
    pub fn new(receiver: Receiver<ChannelRequest>, shutdown_trigger: Trigger) -> Self {
        ProtocolAdapter {
            receiver: Arc::new(Mutex::new(receiver)),
            requests: Arc::new(Mutex::new(Requests {
                requests: HashMap::new(),
                request_id: AtomicU64::new(0),
            })),
            shutdown_trigger,
        }
    }
    // Get requests from the parent process and feed them to gRPC.
    // Will abort the stream reader task of the parent process goes away.
    pub async fn writer_stream(&self, stream_reader_task: JoinHandle<()>) -> SignerStream {
        let receiver = self.receiver.clone();
        let requests = self.requests.clone();

        let output = async_stream::try_stream! {
            let mut receiver = receiver.lock().await;
            // TODO resend outstanding requests
            // Parent request
            loop {
                if let Some(req) = receiver.recv().await {
                    let message = req.message.clone();
                    let mut reqs = requests.lock().await;
                    let request_id = reqs.request_id.fetch_add(1, Ordering::AcqRel);
                    let context = req.client_id.as_ref().map(|c| HsmRequestContext {
                        peer_id: c.peer_id.serialize().to_vec(),
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
            stream_reader_task.abort();
            // ignore join result
            let _ = stream_reader_task.await;
        };
        Box::pin(output)
    }

    // Get signer responses from gRPC and feed them back to the parent process
    pub fn start_stream_reader(&self, mut stream: Streaming<SignerResponse>) -> JoinHandle<()> {
        let requests = self.requests.clone();
        tokio::spawn(async move {
            loop {
                let resp_opt = stream.next().await;
                match resp_opt {
                    Some(Ok(resp)) => {
                        info!("got signer response {}", resp.request_id);
                        if !resp.error.is_empty() {
                            error!("signer error: {}", resp.error);
                            // all signer errors are fatal
                            // TODO exit more cleanly
                            // Right now there's no clean way to stop the UNIX fd reader loop (aka "Signer Loop")
                            // if the adapter determines there's a fatal error in the signer
                            // sub-process, so just be aggressive here and exit.
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
        })
    }
}
