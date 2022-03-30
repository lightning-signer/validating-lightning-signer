use super::hsmd::{self, PingRequest, SignerRequest, SignerResponse};
use greenlight_signer::greenlight_protocol::model::PubKey;
use greenlight_signer::greenlight_protocol::msgs;
use greenlight_signer::handler::{Handler, RootHandler};
use http::Uri;
use lightning_signer::persist::Persist;
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use log::{error, info};
use remote_hsmd::util::{read_allowlist, read_integration_test_seed};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

/// Signer binary entry point
#[tokio::main(worker_threads = 2)]
pub async fn start_signer(port: u16) {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let addr = SocketAddrV4::new(loopback, port);
    let uri = Uri::builder()
        .scheme("http")
        .authority(addr.to_string().as_str())
        .path_and_query("/")
        .build()
        .expect("uri");

    let mut client = hsmd::hsmd_client::HsmdClient::connect(uri).await.expect("client connect");
    let result = client.ping(PingRequest { message: "hello".to_string() }).await.expect("ping");
    let reply = result.into_inner();
    info!("child got {}", reply.message);
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let mut request_stream = client.signer_stream(response_stream).await.unwrap().into_inner();
    let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("signer.kv"));
    let allowlist = read_allowlist();
    let root_handler = RootHandler::new(0, read_integration_test_seed(), persister, allowlist);
    while let Some(item) = request_stream.next().await {
        match item {
            Ok(request) => {
                let response = handle(request, &root_handler);
                match response {
                    Ok(response) => {
                        sender.send(response).await.expect("send to internal channel");
                    }
                    Err(()) => {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("signer error - {}", e);
                break;
            }
        }
    }
    info!("child stopping");
}

fn handle(mut request: SignerRequest, root_handler: &RootHandler) -> StdResult<SignerResponse, ()> {
    let len = request.message.len();
    let msg = msgs::read_unframed(&mut request.message, len as u32).map_err(|e| {
        error!("could not decode message for request {} {:?}", request.request_id, e)
    })?;
    info!(
        "signer got request {} dbid {} - {:?}",
        request.request_id,
        request.context.as_ref().map(|c| c.dbid).unwrap_or(0),
        msg
    );
    let reply = if let Some(context) = request.context {
        let peer = PubKey(context.peer_id.try_into().map_err(|_| ())?);
        let handler = root_handler.for_new_client(context.dbid, peer, context.dbid);
        handler.handle(msg).map_err(|e| {
            error!("error while handling message: {:?}", e);
        })?
    } else {
        root_handler.handle(msg).map_err(|e| {
            error!("error while handling message: {:?}", e);
        })?
    };
    let ser_res = reply.vec_serialize();
    Ok(SignerResponse { request_id: request.request_id, message: ser_res })
}
