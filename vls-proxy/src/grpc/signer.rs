use super::hsmd::hsmd_client::HsmdClient;
use super::hsmd::{PingRequest, SignerRequest, SignerResponse};
use crate::config::SignerArgs;
use crate::rpc_server::start_rpc_server;
use crate::util::{
    integration_test_seed_or_generate, make_validator_factory_with_filter_and_velocity,
    read_allowlist, should_auto_approve,
};

use clap::Parser;
use http::Uri;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::{Node, NodeServices};
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::persist::SeedPersist;
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::DEFAULT_FEE_VELOCITY_CONTROL;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::util::status::Status;
use lightning_signer::util::velocity::VelocityControlSpec;
use log::*;
use std::convert::TryInto;
use std::env;
use std::error::Error as _;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use vls_persist::kvv::{redb::RedbKVVStore, JsonFormat, KVVPersister};
use vls_protocol_signer::approver::WarningPositiveApprover;
use vls_protocol_signer::handler::{Error, Handler, HandlerBuilder, InitHandler, RootHandler};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

#[cfg(feature = "heapmon_requests")]
use heapmon::{self, HeapMon, SummaryOrder};
#[cfg(feature = "heapmon_requests")]
use std::alloc::System;
use tokio::sync::mpsc::Sender;
use tonic::Streaming;

#[cfg(feature = "heapmon_requests")]
#[global_allocator]
pub static HEAPMON: HeapMon<System> = HeapMon::system();

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

    let args = SignerArgs::parse_from(&["signer", "--integration-test", "--network", "regtest"]);
    assert!(args.integration_test);
    connect("remote_hsmd.kv", uri, &args).await;
    info!("signer stopping");
}

/// Signer binary entry point
pub async fn start_signer(datadir: &str, uri: Uri, args: &SignerArgs) {
    info!("signer starting on {} connecting to {}", args.network, uri);
    connect(datadir, uri, args).await;
    info!("signer stopping");
}

/// Create a signer protocol handler
pub fn make_handler(datadir: &str, args: &SignerArgs) -> InitHandler {
    let network = args.network;
    let data_path = format!("{}/{}", datadir, network.to_string());
    let persister = Arc::new(KVVPersister(RedbKVVStore::new(&data_path), JsonFormat));
    let seed_persister = Arc::new(FileSeedPersister::new(&data_path));
    let seeddir = PathBuf::from_str(datadir).unwrap().join("..").join(network.to_string());
    let seed = get_or_generate_seed(network, seed_persister, args.integration_test, Some(seeddir));
    let allowlist = read_allowlist();
    let starting_time_factory = ClockStartingTimeFactory::new();
    let mut filter_opt = if args.integration_test {
        // TODO(236)
        Some(PolicyFilter { rules: vec![FilterRule::new_warn("policy-channel-safe-type-anchors")] })
    } else {
        None
    };

    if !args.policy_filter.is_empty() {
        let mut filter = filter_opt.unwrap_or(PolicyFilter::default());
        filter.merge(PolicyFilter { rules: args.policy_filter.clone() });
        filter_opt = Some(filter);
    }

    let velocity_control_spec = args.velocity_control.unwrap_or(VelocityControlSpec::UNLIMITED);
    let fee_velocity_control_spec =
        args.fee_velocity_control.unwrap_or(DEFAULT_FEE_VELOCITY_CONTROL);
    let validator_factory = make_validator_factory_with_filter_and_velocity(
        network,
        filter_opt,
        velocity_control_spec,
        fee_velocity_control_spec,
    );
    let clock = Arc::new(StandardClock());
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let mut handler_builder =
        HandlerBuilder::new(network, 0, services, seed).allowlist(allowlist.clone());
    if should_auto_approve() {
        handler_builder = handler_builder.approver(Arc::new(WarningPositiveApprover()));
    }
    if let Ok(protocol_version_str) = env::var("VLS_MAX_PROTOCOL_VERSION") {
        match protocol_version_str.parse::<u32>() {
            Ok(protocol_version) => {
                warn!("setting max_protocol_version to {}", protocol_version);
                handler_builder = handler_builder.max_protocol_version(protocol_version);
            }
            Err(e) => {
                panic!("invalid VLS_MAX_PROTOCOL_VERSION {}: {}", protocol_version_str, e);
            }
        }
    }

    let (init_handler, _muts) = handler_builder.build().expect("handler build");

    init_handler
}

// NOTE - For this signer mode it is easier to use the ALLOWLIST file to maintain the
// allowlist. Replace existing entries w/ the current ALLOWLIST file contents.
fn reset_allowlist(node: &Node, allowlist: &Vec<String>) {
    node.set_allowlist(&allowlist).expect("allowlist");
    info!("allowlist={:?}", node.allowlist().expect("allowlist"));
}

async fn connect(datadir: &str, uri: Uri, args: &SignerArgs) {
    let mut client = do_connect(uri).await;
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let mut init_handler = make_handler(datadir, args);
    let node = Arc::clone(init_handler.node());

    reset_allowlist(&*node, &read_allowlist());

    let (addr, join_rpc_server) =
        start_rpc_server(node, args.rpc_server_address, args.rpc_server_port)
            .await
            .expect("start_rpc_server");
    info!("rpc server running on {}", addr);

    let mut request_stream = client.signer_stream(response_stream).await.unwrap().into_inner();

    let is_success = handle_init_requests(&sender, &mut request_stream, &mut init_handler).await;

    if is_success {
        let root_handler = init_handler.into_root_handler();
        handle_requests(&sender, &mut request_stream, &root_handler).await;
    }

    let join_result = join_rpc_server.await;
    if let Err(e) = join_result {
        error!("rpc server error: {:?}", e);
    }
}

// return true if the negotiation succeeded
async fn handle_init_requests(
    sender: &Sender<SignerResponse>,
    request_stream: &mut Streaming<SignerRequest>,
    init_handler: &mut InitHandler,
) -> bool {
    while let Some(item) = request_stream.next().await {
        match item {
            Ok(request) => {
                let request_id = request.request_id;

                let response = handle_init_request(init_handler, request, request_id);
                let is_done = response.as_ref().map(|(is_done, _)| *is_done).unwrap_or(false);
                let response = response.map(|(_, r)| r);

                if send_response(sender, request_id, response).await {
                    // stream closed
                    return false;
                }
                if is_done {
                    return true;
                }
            }
            Err(e) => {
                error!("error on stream: {}", e);
                return false;
            }
        }
    }
    false
}

fn handle_init_request(
    init_handler: &mut InitHandler,
    request: SignerRequest,
    request_id: u64,
) -> StdResult<(bool, SignerResponse), Error> {
    let msg = msgs::from_vec(request.message)?;
    let reply = init_handler.handle(msg);

    let (is_done, response) = match reply {
        Ok((is_done, res)) => (
            is_done,
            Ok(SignerResponse {
                request_id,
                message: res.as_vec(),
                error: String::new(),
                is_temporary_failure: false,
            }),
        ),
        Err(e) => (false, Err(e)),
    };
    response.map(|r| (is_done, r))
}

async fn handle_requests(
    sender: &Sender<SignerResponse>,
    request_stream: &mut Streaming<SignerRequest>,
    root_handler: &RootHandler,
) {
    #[cfg(feature = "heapmon_requests")]
    let peak_thresh = {
        let peak_thresh = env::var("VLS_HEAPMON_PEAK_THRESH")
            .map(|s| s.parse().expect("VLS_HEAPMON_PEAK_THRESH parse"))
            .unwrap_or(50 * 1024);
        info!("using VLS_HEAPMON_PEAK_THRESH={}", peak_thresh);
        HEAPMON.filter("KVJsonPersister");
        HEAPMON.filter("sled::pagecache");
        HEAPMON.filter("backtrace::symbolize");
        HEAPMON.filter("redb::");
        HEAPMON.filter("tokio_util::codec::length_delimited");
        peak_thresh
    };

    while let Some(item) = request_stream.next().await {
        match item {
            Ok(request) => {
                let request_id = request.request_id;

                #[cfg(feature = "heapmon_requests")]
                let heapmon_label = {
                    // Enable peakhold for every message
                    let heapmon_label =
                        msgs::from_vec(request.clone().message).expect("msg").inner().name();
                    HEAPMON.reset();
                    HEAPMON.peakhold();
                    heapmon_label
                };

                let response = handle_request(request, &root_handler);

                #[cfg(feature = "heapmon_requests")]
                {
                    // But only dump big heap excursions
                    let (_heapsz, peaksz) = HEAPMON.disable();
                    if peaksz > peak_thresh {
                        // The filters are applied here and the threshold check re-applied
                        HEAPMON.dump(SummaryOrder::MemoryUsed, peak_thresh, heapmon_label);
                    }
                }

                if send_response(sender, request_id, response).await {
                    // stream closed
                    break;
                }
            }
            Err(e) => {
                error!("error on stream: {}", e);
                break;
            }
        }
    }
}

// returns true if there stream was closed
async fn send_response(
    sender: &Sender<SignerResponse>,
    request_id: u64,
    response: Result<SignerResponse, Error>,
) -> bool {
    match response {
        Ok(response) => {
            let res = sender.send(response).await;
            if res.is_err() {
                error!("stream closed");
                return true;
            }
        }
        Err(Error::Temporary(error)) => {
            error!("received temporary error from handler: {}", error);
            let response = SignerResponse {
                request_id,
                message: vec![],
                error: error.message().to_string(),
                is_temporary_failure: true,
            };
            let res = sender.send(response).await;
            if res.is_err() {
                error!("stream closed");
                return true;
            }
        }
        Err(e) => {
            error!("received error from handler: {:?}", e);
            let response = SignerResponse {
                request_id,
                message: vec![],
                error: format!("{:?}", e),
                is_temporary_failure: false,
            };
            let res = sender.send(response).await;
            if res.is_err() {
                error!("stream closed");
            }
            return true;
        }
    }
    false
}

async fn do_connect(uri: Uri) -> HsmdClient<Channel> {
    loop {
        let client = HsmdClient::connect(uri.clone()).await;
        match client {
            Ok(mut client) => {
                let result =
                    client.ping(PingRequest { message: "hello".to_string() }).await.expect("ping");
                let reply = result.into_inner();
                info!("ping result {}", reply.message);
                return client;
            }
            Err(e) => {
                // unfortunately the error kind is not otherwise exposed
                if e.to_string() == "transport error" {
                    let source = e.source().map_or("-".to_string(), |e| e.to_string());
                    warn!("error connecting to node, will retry: {} - {}", e, source);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    panic!("fatal error connecting to node: {}", e);
                }
            }
        }
    }
}

fn get_or_generate_seed(
    network: Network,
    seed_persister: Arc<dyn SeedPersist>,
    integration_test: bool,
    seeddir: Option<PathBuf>,
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
            let seed = integration_test_seed_or_generate(seeddir);
            seed_persister.put("node", &seed);
            seed
        }
    }
}

fn handle_request(
    request: SignerRequest,
    root_handler: &RootHandler,
) -> StdResult<SignerResponse, Error> {
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
                    .map_err(|_| Error::Signing(Status::invalid_argument("peer id")))?,
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
        is_temporary_failure: false,
    })
}
