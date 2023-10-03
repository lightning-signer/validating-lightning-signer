use super::hsmd::hsmd_client::HsmdClient;
use super::hsmd::{PingRequest, SignerRequest, SignerResponse};
use crate::config::SignerArgs;
use crate::util::{
    integration_test_seed_or_generate, make_validator_factory_with_filter_and_velocity,
    read_allowlist, should_auto_approve,
};
use clap::Parser;
use http::Uri;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
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
use vls_persist::kvv::redb::RedbKVVStore;
use vls_protocol_signer::approver::WarningPositiveApprover;
use vls_protocol_signer::handler::{Error, Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

#[cfg(feature = "heapmon_requests")]
use heapmon::{self, HeapMon, SummaryOrder};
#[cfg(feature = "heapmon_requests")]
use std::alloc::System;
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
#[allow(unused)]
#[tokio::main(worker_threads = 2)]
pub async fn start_signer(datadir: &str, uri: Uri, args: &SignerArgs) {
    info!("signer starting on {} connecting to {}", args.network, uri);
    connect(datadir, uri, args).await;
    info!("signer stopping");
}

/// Create a signer protocol handler
pub fn make_handler(datadir: &str, args: &SignerArgs) -> RootHandler {
    let network = args.network;
    let data_path = format!("{}/{}", datadir, network.to_string());
    let persister = Arc::new(RedbKVVStore::new(&data_path));
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
        RootHandlerBuilder::new(network, 0, services, seed).allowlist(allowlist.clone());
    if should_auto_approve() {
        handler_builder = handler_builder.approver(Arc::new(WarningPositiveApprover()));
    }
    let (root_handler, _muts) = handler_builder.build().expect("handler build");

    root_handler
}

// NOTE - For this signer mode it is easier to use the ALLOWLIST file to maintain the
// allowlist. Replace existing entries w/ the current ALLOWLIST file contents.
fn reset_allowlist(root_handler: &RootHandler, allowlist: &Vec<String>) {
    let node = root_handler.node();
    node.set_allowlist(&allowlist).expect("allowlist");
    info!("allowlist={:?}", node.allowlist().expect("allowlist"));
}

async fn connect(datadir: &str, uri: Uri, args: &SignerArgs) {
    let mut client = do_connect(uri).await;
    let (sender, receiver) = mpsc::channel(1);
    let response_stream = ReceiverStream::new(receiver);
    let root_handler = make_handler(datadir, args);
    reset_allowlist(&root_handler, &read_allowlist());

    let mut request_stream = client.signer_stream(response_stream).await.unwrap().into_inner();

    #[cfg(feature = "heapmon_requests")]
    let peak_thresh = {
        use std::env;
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

                let response = handle(request, &root_handler);

                #[cfg(feature = "heapmon_requests")]
                {
                    // But only dump big heap excursions
                    let (_heapsz, peaksz) = HEAPMON.disable();
                    if peaksz > peak_thresh {
                        // The filters are applied here and the threshold check re-applied
                        HEAPMON.dump(SummaryOrder::MemoryUsed, peak_thresh, heapmon_label);
                    }
                }

                match response {
                    Ok(response) => {
                        let res = sender.send(response).await;
                        if res.is_err() {
                            error!("stream closed");
                            break;
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
                            break;
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
                    warn!("{} connecting to signer, will retry", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    panic!("{} connecting to signer", e);
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
