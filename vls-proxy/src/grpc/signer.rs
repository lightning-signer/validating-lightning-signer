use super::hsmd::hsmd_client::HsmdClient;
use super::hsmd::{PingRequest, SignerRequest, SignerResponse};
use crate::config::SignerArgs;
use crate::rpc_server::start_rpc_server;
use crate::util::{
    get_rpc_credentials, integration_test_seed_or_generate,
    make_validator_factory_with_filter_and_velocity, read_allowlist, should_auto_approve,
};

use clap::Parser;
use http::Uri;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::{Node, NodeServices};
use lightning_signer::persist::fs::FileSeedPersister;
use lightning_signer::persist::Error as PersistError;
use lightning_signer::persist::{ExternalPersistHelper, Mutations, Persist, SeedPersist};
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::DEFAULT_FEE_VELOCITY_CONTROL;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::util::status::Status;
use lightning_signer::util::velocity::VelocityControlSpec;
use std::convert::TryInto;
use std::env;
use std::error::Error as _;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::{from_utf8, FromStr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::*;
use vls_persist::kvv::{redb::RedbKVVStore, JsonFormat, KVVPersister, KVVStore};
use vls_protocol::Error as ProtocolError;
use vls_protocol_signer::approver::WarningPositiveApprover;
use vls_protocol_signer::handler::{
    Error as HandlerError, Handler, HandlerBuilder, InitHandler, RootHandler,
};
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;

use crate::persist::ExternalPersistWithHelper;
#[cfg(feature = "heapmon_requests")]
use heapmon::{self, HeapMon, SummaryOrder};
use lightning_storage_server::client::Auth;
#[cfg(feature = "heapmon_requests")]
use std::alloc::System;
use std::fmt::Debug;
use tokio::sync::mpsc::Sender;
use tonic::Streaming;
use url::Url;
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::{self, ExternalPersist};
use vls_persist::kvv::cloud::CloudKVVStore;
use vls_protocol::msgs::{Message, SerBolt};

#[cfg(feature = "heapmon_requests")]
#[global_allocator]
pub static HEAPMON: HeapMon<System> = HeapMon::system();

#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
    #[error("handler error")]
    Handler(#[from] HandlerError),
    #[error("LSS error")]
    LssClient(#[from] external_persist::Error),
    #[error("persist error")]
    Persist(#[from] PersistError),
}

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
    let (_shutdown_trigger, shutdown_signal) = triggered::trigger();
    let args = SignerArgs::parse_from(&["signer", "--integration-test", "--network", "regtest"]);
    assert!(args.integration_test);
    connect("remote_hsmd.kv", uri, &args, shutdown_signal).await;
    info!("signer stopping");
}

/// Signer binary entry point
pub async fn start_signer(
    datadir: &str,
    uri: Uri,
    args: &SignerArgs,
    shutdown_signal: triggered::Listener,
) {
    info!("signer starting on {} connecting to {}", args.network, uri);
    connect(datadir, uri, args, shutdown_signal).await;
    info!("signer stopping");
}

/// Create a signer protocol handler.
/// Must commit the transaction if persisting to cloud.
pub fn make_handler(datadir: &str, args: &SignerArgs) -> (InitHandler, Mutations) {
    let persister = make_persister(datadir, args);
    // TODO error handling
    persister.enter().expect("start transaction during handler build");
    let handler =
        make_handler_builder(datadir, args, persister.clone()).build().expect("handler build");
    let muts = persister.prepare();
    (handler, muts)
}

pub fn make_handler_builder(
    datadir: &str,
    args: &SignerArgs,
    persister: Arc<dyn Persist>,
) -> HandlerBuilder {
    let network = args.network;
    let data_path = format!("{}/{}", datadir, network.to_string());
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
    let services = NodeServices {
        validator_factory,
        starting_time_factory,
        persister,
        clock,
        trusted_oracle_pubkeys: args.trusted_oracle_pubkey.clone(),
    };
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
    handler_builder
}

fn make_persister(datadir: &str, args: &SignerArgs) -> Arc<dyn Persist> {
    let local_store = make_local_store(datadir, args);
    if args.lss.is_some() {
        Arc::new(KVVPersister(CloudKVVStore::new(local_store), JsonFormat))
    } else {
        Arc::new(KVVPersister(local_store, JsonFormat))
    }
}

fn make_local_store(datadir: &str, args: &SignerArgs) -> RedbKVVStore {
    let network = args.network;
    let data_path = format!("{}/{}", datadir, network.to_string());
    RedbKVVStore::new(&data_path)
}

// NOTE - For this signer mode it is easier to use the ALLOWLIST file to maintain the
// allowlist. Replace existing entries w/ the current ALLOWLIST file contents.
fn reset_allowlist(node: &Node, allowlist: &[String]) {
    node.set_allowlist(&allowlist).expect("allowlist");
    info!("allowlist={:?}", node.allowlist().expect("allowlist"));
}

#[instrument(skip(args, shutdown_signal))]
async fn connect(datadir: &str, uri: Uri, args: &SignerArgs, shutdown_signal: triggered::Listener) {
    if args.dump_storage {
        let local_store = make_local_store(datadir, args);
        let mut iter = local_store.get_prefix("").expect("get_prefix");
        while let Some(kvv) = iter.next() {
            let value = kvv.1 .1;
            // this assumes that the value is utf8, which is currently true since we use JSON
            let value_str = from_utf8(&value).expect("utf8");
            println!("{} = {} @ {}", kvv.0, value_str, kvv.1 .0);
        }
        return;
    }

    let (mut init_handler, external_persist) = if let Some(mut lss_url) = args.lss.clone() {
        if lss_url.port().is_none() {
            lss_url.set_port(Some(55551)).expect("set port");
        }
        info!("connecting to LSS at {}", lss_url);
        let persister = make_persister(datadir, args);
        let builder = make_handler_builder(datadir, args, persister.clone());
        let external_persist = make_external_persist(&lss_url, &builder).await;

        // get the initial state from the LSS
        external_persist.init_state().await;
        let state = external_persist.state.lock().unwrap();
        let muts: Vec<_> = state.iter().map(|(k, (v, vv))| (k.clone(), (*v, vv.clone()))).collect();
        drop(state);

        if args.dump_lss {
            for (k, (v, value)) in muts.iter() {
                let value_str = from_utf8(&value).expect("utf8");
                println!("{} = {} @ {}", k, value_str, v);
            }
            return;
        }

        if args.init_lss {
            if !muts.is_empty() {
                error!("LSS state is not empty, but --init-lss was specified");
                return;
            }
            let muts = persister.begin_replication().expect("get_all during LSS init");
            let client = external_persist.persist_client.lock().await;
            store_with_client(muts, &*client, &external_persist.helper)
                .await
                .expect("store during LSS init");

            info!("LSS state initialized, exiting");
            return;
        }

        // update local persister with the initial cloud state
        persister.put_batch_unlogged(Mutations::from_vec(muts)).expect("put_batch_unlogged");

        // TODO error handling
        persister.enter().expect("start transaction during handler build");
        // build the init handler, potentially changing the state (e.g. new node or modified allowlist)
        let handler = builder.build().expect("handler build");
        reset_allowlist(&handler.node(), &read_allowlist());

        let muts = persister.prepare();

        // store any changes made during build to LSS
        let client = external_persist.persist_client.lock().await;
        store_with_client(muts, &*client, &external_persist.helper)
            .await
            .expect("store during build");

        persister.commit().expect("commit during build");
        drop(client);

        (handler, Some(external_persist))
    } else {
        let (handler, muts) = make_handler(datadir, args);
        assert!(muts.is_empty(), "got memorized mutations, but not persisting to cloud");
        (handler, None)
    };

    let node = Arc::clone(init_handler.node());

    let join_handle =
        start_rpc_server_with_auth(Arc::clone(&node), &args, shutdown_signal.clone()).await;

    loop {
        let handle_connection = async {
            init_handler.reset();

            let (sender, receiver) = mpsc::channel(1);
            let response_stream = ReceiverStream::new(receiver);
            init_handler.log_chaninfo();

            let mut client = do_connect(&uri).await;
            let mut request_stream =
                client.signer_stream(response_stream).await.unwrap().into_inner();

            let handle_loop = InitHandleLoop::new(init_handler.clone(), external_persist.clone());

            let root_handler = handle_loop.handle_requests(&sender, &mut request_stream).await;

            if let Some(mut handle_loop) = root_handler {
                handle_loop.handle_requests(&sender, &mut request_stream).await;
            }
        };

        tokio::select! {
            _ = shutdown_signal.clone() => {
                info!("signer shutting down");
                break;
            }
            _ = handle_connection => {}
        }

        if args.integration_test {
            // no reconnects needed for integration tests, just exit
            break;
        }
    }

    if let Some(join_rpc_server) = join_handle {
        let join_result = join_rpc_server.await;
        if let Err(e) = join_result {
            error!("rpc server error: {:?}", e);
        }
    }
}

impl InitHandleLoop {
    // return true if the negotiation succeeded
    async fn handle_requests(
        mut self,
        sender: &Sender<SignerResponse>,
        request_stream: &mut Streaming<SignerRequest>,
    ) -> Option<HandleLoop> {
        while let Some(item) = request_stream.next().await {
            match item {
                Ok(request) => {
                    let request_id = request.request_id;

                    let rspframe = self.handle_request(request, request_id).await;
                    let is_done = rspframe.as_ref().map(|(is_done, _)| *is_done).unwrap_or(false);
                    let maybe_response = rspframe.map(|(_, r)| r);

                    match maybe_response {
                        Ok(Some(response)) => {
                            if send_response(sender, request_id, Ok(response)).await {
                                // stream closed
                                return None;
                            }
                        }
                        Ok(None) => {} // success w/o return message
                        Err(err) => {
                            if send_response(sender, request_id, Err(err)).await {
                                // stream closed
                                return None;
                            }
                        }
                    }
                    if is_done {
                        let root_handler = self.handler.into();
                        return Some(HandleLoop::new(root_handler, self.external_persist));
                    }
                }
                Err(e) => {
                    error!("error on init stream: {}", e);
                    return None;
                }
            }
        }
        return None;
    }

    #[instrument(
        name = "InitHandleLoop::handle_request",
        skip(request),
        fields(message_name),
        err(Debug)
    )]
    async fn handle_request(
        &mut self,
        request: SignerRequest,
        request_id: u64,
    ) -> StdResult<(bool, Option<SignerResponse>), Error> {
        let msg = msgs::from_vec(request.message)?;
        Span::current().record("message_name", msg.inner().name());

        let (is_done, reply) = if let Some(external_persist) = &self.external_persist {
            let node = self.handler.node();
            let persister = node.get_persister();
            persister.enter()?;

            // see comments in HandleLoop::handle_request
            let persist_client = external_persist.persist_client.lock().await;
            let result = self.handler.handle(msg);
            let muts = persister.prepare();

            // if this fails, our in-memory state is out of sync with both the local store and the cloud, which is fatal
            // TODO we could potentially recover by reloading from local storage
            store_with_client(muts, &*persist_client, &external_persist.helper)
                .await
                .expect("store during init handle");
            persister.commit()?;
            result?
        } else {
            let (is_done, reply) = self.handler.handle(msg)?;
            (is_done, reply)
        };

        let response = reply.map(|reply| SignerResponse {
            request_id,
            message: reply.as_vec(),
            error: String::new(),
            is_temporary_failure: false,
        });
        Ok((is_done, response))
    }
}

// Handle a request stream while initializing
struct InitHandleLoop {
    handler: InitHandler,
    pub external_persist: Option<ExternalPersistWithHelper>,
}

impl InitHandleLoop {
    fn new(handler: InitHandler, external_persist: Option<ExternalPersistWithHelper>) -> Self {
        Self { handler, external_persist }
    }
}

impl Debug for InitHandleLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitHandleLoop").finish()
    }
}

// Handle a request stream
struct HandleLoop {
    handler: RootHandler,
    pub external_persist: Option<ExternalPersistWithHelper>,
}

impl HandleLoop {
    fn new(handler: RootHandler, external_persist: Option<ExternalPersistWithHelper>) -> Self {
        Self { handler, external_persist }
    }
}

impl Debug for HandleLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandleLoop").finish()
    }
}

impl HandleLoop {
    async fn handle_requests(
        &mut self,
        sender: &Sender<SignerResponse>,
        request_stream: &mut Streaming<SignerRequest>,
    ) {
        #[cfg(feature = "heapmon_requests")]
        let peak_thresh = {
            let peak_thresh = env::var("VLS_HEAPMON_PEAK_THRESH")
                .map(|s| s.parse().expect("VLS_HEAPMON_PEAK_THRESH parse"))
                .unwrap_or(50 * 1024);
            info!("using VLS_HEAPMON_PEAK_THRESH={}", peak_thresh);
            HEAPMON.filter("KVJsonPersister");
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

                    let response = self.handle_request(request).await;

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

        // log channel information on shutdown
        self.handler.log_chaninfo();
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
        Err(Error::Handler(HandlerError::Temporary(error))) => {
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

async fn do_connect(uri: &Uri) -> HsmdClient<Channel> {
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

impl HandleLoop {
    #[instrument(
        skip(request),
        fields(
        request_id = % request.request_id,
        message_name
        ),
        parent = None,
        err(Debug)
    )]
    async fn handle_request(&mut self, request: SignerRequest) -> StdResult<SignerResponse, Error> {
        let msg = msgs::from_vec(request.message)?;
        Span::current().record("message_name", msg.inner().name());

        let context = request.context.as_ref().map(|c| (c.dbid, c.peer_id.clone()));
        let dbid = context.as_ref().map(|c| c.0).unwrap_or(0);
        info!("signer got request {} dbid {} - {:?}", request.request_id, dbid, msg);
        let res = if let Some(external_persist) = &self.external_persist {
            // Note: we lock early because we actually need a global lock right now,
            // since our copy of the cloud state is not atomic.  In particular, if one request
            // advances a version of a key, another request might advance the same
            // version again, but may write to the cloud before the first.
            // TODO(devrandom) evaluate atomicity
            let persist_client = external_persist.persist_client.lock().await;
            let (res, muts) = self.do_handle(context.as_ref(), msg);

            // if this fails, our in-memory state is out of sync with both the local store and the cloud, which is fatal
            // TODO we could potentially recover by reloading from local storage
            store_with_client(muts, &*persist_client, &external_persist.helper)
                .await
                .expect("store during handle");

            self.handler.commit();
            res?
        } else {
            let (res, muts) = self.do_handle(context.as_ref(), msg);
            assert!(muts.is_empty(), "got memorized mutations, but not persisting to cloud");
            res?
        };
        info!("signer sending reply {} - {:?}", request.request_id, res);

        Ok(SignerResponse {
            request_id: request.request_id,
            message: res.as_vec(),
            error: String::new(),
            is_temporary_failure: false,
        })
    }

    fn do_handle(
        &self,
        context: Option<&(u64, Vec<u8>)>,
        msg: Message,
    ) -> (Result<Box<dyn SerBolt>, Error>, Mutations) {
        let node = self.handler.node();
        let persister = node.get_persister();
        if let Err(e) = persister.enter() {
            error!("failed to start transaction: {:?}", e);
            return (
                Err(Error::Handler(Status::internal("failed to start transaction").into())),
                Mutations::new(),
            );
        }

        let result = if let Some((dbid, peer_id)) = context {
            if *dbid > 0 {
                let peer = match peer_id.clone().try_into() {
                    Ok(pubkey) => PubKey(pubkey),
                    Err(_) => {
                        // this should trivially succeed, because we didn't do any work yet
                        persister.commit().expect("commit");
                        return (
                            Err(Error::Handler(HandlerError::Signing(Status::invalid_argument(
                                "peer id",
                            )))
                            .into()),
                            Mutations::new(),
                        );
                    }
                };
                let handler = self.handler.for_new_client(*dbid, peer, *dbid);
                handler.handle(msg)
            } else {
                self.handler.handle(msg)
            }
        } else {
            self.handler.handle(msg)
        };

        let muts = persister.prepare();

        if let Err(HandlerError::Temporary(_)) = result {
            // There must be no mutated state when a temporary error is returned
            if !muts.is_empty() {
                #[cfg(not(feature = "log_pretty_print"))]
                debug!("stranded mutations: {:?}", &muts);
                #[cfg(feature = "log_pretty_print")]
                debug!("stranded mutations: {:#?}", &muts);
                panic!("temporary error with stranded mutations");
            }
        }

        let result = result.map_err(|e| Error::Handler(e));
        (result, muts)
    }
}

async fn start_rpc_server_with_auth(
    node: Arc<Node>,
    args: &SignerArgs,
    shutdown_signal: triggered::Listener,
) -> Option<JoinHandle<()>> {
    let (username, password) = match get_rpc_credentials(
        args.rpc_user.clone(),
        args.rpc_pass.clone(),
        args.rpc_cookie.clone(),
    ) {
        Ok((username, password)) => (username, password),
        Err(e) => {
            warn!("rpc server not started as no password provided: {}", e);
            return None;
        }
    };

    let (addr, join_rpc_server) = start_rpc_server(
        node,
        args.rpc_server_address,
        args.rpc_server_port,
        username.as_str(),
        password.as_str(),
        shutdown_signal,
    )
    .await
    .expect("start_rpc_server");
    info!("rpc server running on {}", addr);
    Some(join_rpc_server)
}

async fn store_with_client(
    muts: Mutations,
    client: &Box<dyn ExternalPersist>,
    helper: &ExternalPersistHelper,
) -> Result<(), Error> {
    if !muts.is_empty() {
        let client_hmac = helper.client_hmac(&muts);
        client.put(muts, &client_hmac).await?;
    }
    Ok(())
}

async fn make_external_persist(uri: &Url, builder: &HandlerBuilder) -> ExternalPersistWithHelper {
    let (keys_manager, node_id) = builder.build_keys_manager();
    let client_id = keys_manager.get_persistence_pubkey();
    let server_pubkey =
        LssClient::get_server_pubkey(uri.as_str()).await.expect("failed to get pubkey");
    let shared_secret = keys_manager.get_persistence_shared_secret(&server_pubkey.inner);
    let auth_token = keys_manager.get_persistence_auth_token(&server_pubkey.inner);
    let helper = ExternalPersistHelper::new(shared_secret);
    let auth = Auth { client_id, token: auth_token.to_vec() };

    let client =
        LssClient::new(uri.as_str(), &server_pubkey, auth).await.expect("failed to connect to LSS");
    info!("connected to LSS provider {} for node {}", server_pubkey, node_id);

    let persist_client = Arc::new(AsyncMutex::new(Box::new(client) as Box<dyn ExternalPersist>));
    let state = Arc::new(Mutex::new(Default::default()));
    ExternalPersistWithHelper { persist_client, state, helper }
}
