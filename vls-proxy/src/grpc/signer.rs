use super::hsmd::{self, PingRequest, SignerRequest, SignerResponse};
use crate::util::integration_test_seed_or_generate;
use crate::util::{make_validator_factory, read_allowlist};
use http::Uri;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::persist::SeedPersist;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::util::status::Status;
use lightning_signer_server::persist::kv_json::KVJsonPersister;
use log::*;
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use vls_protocol_signer::handler::{Error, Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

/// Signer binary entry point for local integration test
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

    let network = Network::Regtest; // FIXME
    let integration_test = true;
    connect("remote_hsmd.kv", uri, network, integration_test).await;
    info!("signer stopping");
}

/// Signer binary entry point
#[tokio::main(worker_threads = 2)]
pub async fn start_signer(datadir: &str, uri: Uri, network: Network, integration_test: bool) {
    info!("signer starting on {} connecting to {}", network, uri);
    connect(datadir, uri, network, integration_test).await;
    info!("signer stopping");
}

pub fn make_handler(datadir: &str, network: Network, integration_test: bool) -> RootHandler {
    let data_path = format!("{}/{}", datadir, network.to_string());
    let persister = Arc::new(KVJsonPersister::new(&data_path));
    let seed_persister = Arc::new(FileSeedPersister::new(&data_path));
    let seed = get_or_generate_seed(network, seed_persister, integration_test);
    let allowlist = read_allowlist();
    let starting_time_factory = ClockStartingTimeFactory::new();
    let validator_factory = make_validator_factory(network);
    let clock = Arc::new(StandardClock());
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let handler_builder =
        RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist.clone());
    let (root_handler, _muts) = handler_builder.build();

    root_handler
}

// NOTE - For this signer mode it is easier to use the ALLOWLIST file to maintain the
// allowlist. Replace existing entries w/ the current ALLOWLIST file contents.
fn reset_allowlist(root_handler: &RootHandler, allowlist: &Vec<String>) {
    let node = root_handler.node();
    node.set_allowlist(&allowlist).expect("allowlist");
    info!("allowlist={:?}", node.allowlist().expect("allowlist"));
}

async fn connect(datadir: &str, uri: Uri, network: Network, integration_test: bool) {
    let mut client = hsmd::hsmd_client::HsmdClient::connect(uri).await.expect("client connect");
    let result = client.ping(PingRequest { message: "hello".to_string() }).await.expect("ping");
    let reply = result.into_inner();
    info!("ping result {}", reply.message);
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let root_handler = make_handler(datadir, network, integration_test);
    reset_allowlist(&root_handler, &read_allowlist());

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

fn get_or_generate_seed(
    network: Network,
    seed_persister: Arc<dyn SeedPersist>,
    integration_test: bool,
) -> [u8; 32] {
    if let Some(seed) = seed_persister.get("node") {
        info!("loaded seed");
        seed.as_slice().try_into().expect("seed length in storage")
    } else {
        if network == Network::Bitcoin || !integration_test {
            info!("generating new seed");
            // for mainnet, we generate our own seed
            let seed = generate_seed();
            seed_persister.put("node", &seed);
            seed
        } else {
            // for testnet, we allow the test framework to optionally supply the seed
            let seed = integration_test_seed_or_generate();
            seed_persister.put("node", &seed);
            seed
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
        if context.dbid > 0 {
            let peer = PubKey(
                context
                    .peer_id
                    .try_into()
                    .map_err(|_| Error::SigningError(Status::invalid_argument("peer id")))?,
            );
            let handler = root_handler.for_new_client(context.dbid, peer, context.dbid);
            handler.handle(msg)?
        } else {
            root_handler.handle(msg)?
        }
    } else {
        root_handler.handle(msg)?
    };
    info!("signer sending reply {} - {:?}", request.request_id, reply);
    // TODO handle memorized mutations
    let (res, _muts) = reply;
    Ok(SignerResponse {
        request_id: request.request_id,
        message: res.as_vec(),
        error: String::new(),
    })
}
