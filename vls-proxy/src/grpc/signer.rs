use super::hsmd::{self, PingRequest, SignerRequest, SignerResponse};
use crate::util::{read_allowlist, read_integration_test_seed};
use http::Uri;
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::Persist;
use lightning_signer::util::status::Status;
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use log::{error, info};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use vls_protocol_signer::handler::{Error, Handler, RootHandler};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

/// Signer binary entry point
#[tokio::main(worker_threads = 2)]
pub async fn start_signer_localhost(port: u16) {
    let loopback = Ipv4Addr::LOCALHOST;
    let addr = SocketAddrV4::new(loopback, port);
    let uri = Uri::builder()
        .scheme("http")
        .authority(addr.to_string().as_str())
        .path_and_query("/")
        .build()
        .expect("uri"); // infallible by construction

    let network = Network::Testnet; // FIXME
    connect("remote_hsmd_vls_grpc2.kv", uri, network).await;
    info!("signer stopping");
}

/// Signer binary entry point
#[tokio::main(worker_threads = 2)]
pub async fn start_signer(datadir: &str, uri: Uri, network: Network) {
    connect(datadir, uri, network).await;
    info!("signer stopping");
}

async fn connect(datadir: &str, uri: Uri, network: Network) {
    let data_path = format!("{}/{}", datadir, network.to_string());
    let mut client = hsmd::hsmd_client::HsmdClient::connect(uri).await.expect("client connect");
    let result = client.ping(PingRequest { message: "hello".to_string() }).await.expect("ping");
    let reply = result.into_inner();
    info!("ping result {}", reply.message);
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new(&data_path));
    let allowlist = read_allowlist();
    let root_handler = RootHandler::new(0, read_integration_test_seed(), persister, allowlist);

    let mut request_stream = client.signer_stream(response_stream).await.unwrap().into_inner();

    while let Some(item) = request_stream.next().await {
        match item {
            Ok(request) => {
                let request_id = request.request_id;
                let response = handle(request, &root_handler);
                match response {
                    Ok(response) => {
                        let res = sender.send(response).await;
                        if res.is_err() {
                            error!("stream closed");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("received error from handler: {:?}", e);
                        let response = SignerResponse {
                            request_id,
                            message: vec![],
                            error: format!("{:?}", e),
                        };
                        let res = sender.send(response).await;
                        if res.is_err() {
                            error!("stream closed");
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                error!("error on stream: {}", e);
                break;
            }
        }
    }
}

fn handle(request: SignerRequest, root_handler: &RootHandler) -> StdResult<SignerResponse, Error> {
    let msg = msgs::from_vec(request.message)?;
    info!(
        "signer got request {} dbid {} - {:?}",
        request.request_id,
        request.context.as_ref().map(|c| c.dbid).unwrap_or(0),
        msg
    );
    let reply = if let Some(context) = request.context {
        let peer = PubKey(
            context
                .peer_id
                .try_into()
                .map_err(|_| Error::SigningError(Status::invalid_argument("peer id")))?,
        );
        let handler = root_handler.for_new_client(context.dbid, Some(peer), context.dbid);
        handler.handle(msg)?
    } else {
        root_handler.handle(msg)?
    };
    info!("signer sending reply {} - {:?}", request.request_id, reply);
    let ser_res = reply.as_vec();
    Ok(SignerResponse { request_id: request.request_id, message: ser_res, error: String::new() })
}
