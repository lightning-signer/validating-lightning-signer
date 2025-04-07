use std::collections::HashMap;
use std::fs;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{cmp, env};

use lightning_signer::lightning::blinded_path::EmptyNodeIdLookUp;
use lightning_signer::lightning::events::ReplayEvent;
use lightning_signer::lightning::ln::channelmanager::Bolt11InvoiceParameters;
use lightning_signer::lightning::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
use lightning_signer::lightning::routing::gossip::NetworkGraph;
use lightning_signer::lightning::sign::KeysManager;
use lightning_signer::lightning_invoice::{Bolt11InvoiceDescription, Description};
use log::{self, *};

use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Network};
use lightning::chain;
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::BestBlock;
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::chain::Watch;
use lightning::events::{Event, EventHandler};
use lightning::ln::bolt11_payment;
use lightning::ln::channelmanager::{ChainParameters, ChannelManagerReadArgs};
use lightning::ln::channelmanager::{PaymentId, RecipientOnionFields, Retry};
use lightning::ln::peer_handler::MessageHandler;
use lightning::routing::gossip::P2PGossipSync;
use lightning::routing::router::DefaultRouter;
use lightning::routing::router::{PaymentParameters, RouteParameters};
use lightning::routing::scoring::ProbabilisticScoringFeeParameters;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::ser::ReadableArgs;
use lightning_background_processor::{BackgroundProcessor, GossipSync as LdkGossipSync};
use lightning_block_sync::{init, poll, SpvClient, UnboundedCache};
use lightning_invoice::Bolt11Invoice;
use lightning_persister::fs_store::FilesystemStore;
use lightning_rapid_gossip_sync::RapidGossipSync;
use lightning_signer::{bitcoin, lightning, lightning_invoice};
use rand::{thread_rng, RngCore};
use tokio::runtime::Handle;

use crate::bitcoind_client::BitcoindClient;
use crate::config::Config;
use crate::convert::BlockchainInfo;
use crate::disk::HostAndPort;
use crate::fslogger::FilesystemLogger;
use crate::logadapter::LoggerAdapter;
use crate::net::Connector;
use crate::signer::get_keys_manager;
use crate::util::Shutter;
use crate::PaymentInfo;
use crate::{
    disk, handle_ldk_events, ArcChainMonitor, ChannelManager, HTLCStatus, IgnoringMessageHandler,
    MilliSatoshiAmount, PaymentInfoStorage, PeerManager, Sha256,
};
use crate::{DynKeysInterface, MyEntropySource};

#[derive(Clone)]
pub struct NodeBuildArgs {
    pub bitcoind_rpc_username: String,
    pub bitcoind_rpc_password: String,
    pub bitcoind_rpc_host: String,
    pub bitcoind_rpc_port: u16,
    pub bitcoind_rpc_path: String,
    pub storage_dir_path: String,
    pub peer_listening_port: u16,
    pub network: Network,
    pub disk_log_level: LevelFilter,
    pub console_log_level: LevelFilter,
    pub signer_name: String,
    /// Whether to turn on Tor support
    pub tor: bool,
    /// p2p announcement name for this node
    pub name: Option<String>,
    pub config: Config,
    pub vls_port: u16,
}

type GossipSync<P, G, A, L> = LdkGossipSync<P, Arc<RapidGossipSync<G, L>>, G, A, L>;

pub struct MyEventHandler {
    handle: Handle,
    channel_manager: Arc<ChannelManager>,
    chain_monitor: Arc<ArcChainMonitor>,
    bitcoind_client: Arc<BitcoindClient>,
    keys_manager: Arc<DynKeysInterface>,
    inbound_payments: PaymentInfoStorage,
    outbound_payments: PaymentInfoStorage,
    network: Network,
}

impl EventHandler for MyEventHandler {
    fn handle_event(&self, event: Event) -> Result<(), ReplayEvent> {
        self.handle.block_on(handle_ldk_events(
            self.channel_manager.clone(),
            self.chain_monitor.clone(),
            self.bitcoind_client.clone(),
            self.keys_manager.clone(),
            self.inbound_payments.clone(),
            self.outbound_payments.clone(),
            self.network,
            event.clone(),
        ))
    }
}

#[allow(dead_code)]
pub(crate) struct Node {
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) channel_manager: Arc<ChannelManager>,
    pub(crate) inbound_payments: PaymentInfoStorage,
    pub(crate) outbound_payments: PaymentInfoStorage,
    pub(crate) keys_manager: Arc<DynKeysInterface>,
    pub(crate) ldk_data_dir: String,
    pub(crate) bitcoind_client: Arc<BitcoindClient>,
    pub(crate) network: Network,
    pub(crate) background_processor: BackgroundProcessor,
    pub(crate) chain_monitor: Arc<ArcChainMonitor>,
    pub(crate) connector: Arc<Connector>,
    pub(crate) logger: Arc<LoggerAdapter>,
}

pub(crate) struct NetworkController {}

pub(crate) async fn build_node(
    args: NodeBuildArgs,
    shutter: Shutter,
    p2p_handle: Handle,
    signer_handle: Handle,
) -> (Node, NetworkController) {
    // Initialize the LDK data directory if necessary.
    let ldk_data_dir = args.storage_dir_path.clone();
    fs::create_dir_all(ldk_data_dir.clone()).unwrap();

    // Initialize the Logger
    // TODO(ksedgwic) - Resolve data_dir setup and move this to main_server because earlier.
    let is_daemon = false;
    let console_log_level = if is_daemon { LevelFilter::Off } else { args.console_log_level };
    set_boxed_logger(Box::new(FilesystemLogger::new(
        ldk_data_dir.clone(),
        args.disk_log_level,
        console_log_level,
    )))
    .unwrap_or_else(|e| panic!("Failed to create FilesystemLogger: {}", e));
    log::set_max_level(cmp::max(args.disk_log_level, console_log_level));

    // Initialize our bitcoind client.
    let (user, pass) = if args.bitcoind_rpc_username.is_empty() {
        // try to get from cookie file
        bitcoin_rpc_cookie(args.network)
    } else {
        (args.bitcoind_rpc_username.clone(), args.bitcoind_rpc_password.clone())
    };
    let bitcoind_client = BitcoindClient::new(
        args.bitcoind_rpc_host.clone(),
        args.bitcoind_rpc_port,
        user,
        pass,
        args.bitcoind_rpc_path.clone(),
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to connect to bitcoind client: {}", e));

    let bitcoind_client_arc = Arc::new(bitcoind_client.clone());

    // Initialize the KeysManager

    let manager = get_keys_manager(
        shutter,
        signer_handle,
        args.signer_name.as_str(),
        args.vls_port,
        args.network,
        ldk_data_dir.clone(),
        bitcoind_client.clone(),
    )
    .await
    .unwrap();
    let keys_manager = Arc::new(DynKeysInterface::new(manager));

    build_with_signer(keys_manager, args, ldk_data_dir, bitcoind_client_arc, p2p_handle).await
}

fn bitcoin_network_path(base_path: PathBuf, network: Network) -> PathBuf {
    match network {
        Network::Bitcoin => base_path,
        Network::Testnet => base_path.join("testnet3"),
        Network::Signet => base_path.join("signet"),
        Network::Regtest => base_path.join("regtest"),
        _ => panic!("Unsupported network: {:?}", network),
    }
}

fn bitcoin_rpc_cookie(network: Network) -> (String, String) {
    let home = env::var("HOME").expect("cannot get cookie file if HOME is not set");
    let bitcoin_path = Path::new(&home).join(".bitcoin");
    let bitcoin_net_path = bitcoin_network_path(bitcoin_path, network);
    let cookie_path = bitcoin_net_path.join("cookie");
    info!("auth to bitcoind via cookie {}", cookie_path.to_string_lossy());
    let cookie_contents = read_to_string(cookie_path).expect("cookie file read");
    let mut iter = cookie_contents.splitn(2, ":");
    (iter.next().expect("cookie user").to_string(), iter.next().expect("cookie pass").to_string())
}

async fn build_with_signer(
    keys_manager: Arc<DynKeysInterface>,
    args: NodeBuildArgs,
    ldk_data_dir: String,
    bitcoind_client_arc: Arc<BitcoindClient>,
    p2p_handle: Handle,
) -> (Node, NetworkController) {
    let mut bitcoind_client = (*bitcoind_client_arc).clone();

    // ## Setup
    // Step 1: Initialize the FeeEstimator

    // BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
    let fee_estimator = Arc::clone(&bitcoind_client_arc);

    let logadapter = Arc::new(LoggerAdapter::new());

    // Step 3: Initialize the BroadcasterInterface

    // BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
    // broadcaster.
    let broadcaster = Arc::clone(&bitcoind_client_arc);

    // Step 4: Initialize Persist
    let persister = Arc::new(FilesystemStore::new(ldk_data_dir.clone().into()));

    // Step 5: Initialize the ChainMonitor
    let chain_monitor: Arc<ArcChainMonitor> = Arc::new(ChainMonitor::new(
        None,
        broadcaster.clone(),
        logadapter.clone(),
        fee_estimator.clone(),
        persister.clone(),
    ));

    let entropy_source = Arc::new(MyEntropySource::new());

    // Step 7: Read ChannelMonitor state from disk
    let monitors_path = format!("{}/monitors", ldk_data_dir.clone());
    let mut outpoint_to_channelmonitor = disk::read_channelmonitors(
        monitors_path.to_string(),
        entropy_source.clone(),
        keys_manager.clone(),
    )
    .unwrap();

    // Step 8: ... profit

    // Step 9: Initialize the ChannelManager
    let user_config = args.config.bitcoin_channel().into();
    println!("CONFIG {:?}", user_config);

    // Step 13: Optional: Initialize the P2PGossipSync
    // XXX persist routing data
    let network_graph_path = format!("{}/network_graph", ldk_data_dir.clone());
    let network_graph = Arc::new(disk::read_network(
        Path::new(&network_graph_path),
        args.network,
        logadapter.clone(),
    ));

    let params = ProbabilisticScoringDecayParameters::default();
    let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
        params,
        network_graph.clone(),
        logadapter.clone(),
    )));

    let entropy_source = Arc::new(MyEntropySource::new());

    let scoring_fee_params = ProbabilisticScoringFeeParameters::default();

    let router = Arc::new(DefaultRouter::new(
        network_graph.clone(),
        logadapter.clone(),
        entropy_source.clone(),
        scorer.clone(),
        scoring_fee_params,
    ));

    let message_router =
        Arc::new(DefaultMessageRouter::new(network_graph.clone(), entropy_source.clone()));

    let mut restarting_node = true;
    let (channel_manager_blockhash, channel_manager) = {
        if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
            let mut channel_monitor_mut_references = Vec::new();
            for (_, channel_monitor) in outpoint_to_channelmonitor.iter_mut() {
                channel_monitor_mut_references.push(&channel_monitor.1);
            }
            let read_args = ChannelManagerReadArgs::new(
                entropy_source.clone(),
                keys_manager.clone(),
                keys_manager.clone(),
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                router,
                message_router,
                logadapter.clone(),
                user_config,
                channel_monitor_mut_references,
            );
            <(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
        } else {
            // We're starting a fresh node.
            restarting_node = false;
            let getinfo_resp = bitcoind_client.get_blockchain_info().await;
            let best_block =
                BestBlock::new(getinfo_resp.latest_blockhash, getinfo_resp.latest_height as u32);
            let chain_params = ChainParameters { network: args.network, best_block };
            let cur = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();

            let fresh_channel_manager = ChannelManager::new(
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                router,
                message_router,
                logadapter.clone(),
                entropy_source,
                keys_manager.clone(),
                keys_manager.clone(),
                user_config,
                chain_params,
                cur.as_secs() as u32,
            );
            (getinfo_resp.latest_blockhash, fresh_channel_manager)
        }
    };

    // Step 10: Sync ChannelMonitors and ChannelManager to chain tip
    let mut chain_listener_channel_monitors = Vec::new();
    let mut cache = UnboundedCache::new();
    let mut chain_tip: Option<poll::ValidatedBlockHeader> = None;
    if restarting_node {
        let mut chain_listeners =
            vec![(channel_manager_blockhash, &channel_manager as &dyn chain::Listen)];

        for (outpoint, blockhash_and_monitor) in outpoint_to_channelmonitor.drain() {
            let blockhash = blockhash_and_monitor.0;
            let channel_monitor = blockhash_and_monitor.1;
            chain_listener_channel_monitors.push((
                blockhash,
                (channel_monitor, broadcaster.clone(), fee_estimator.clone(), logadapter.clone()),
                outpoint,
            ));
        }

        for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
            chain_listeners
                .push((monitor_listener_info.0, &monitor_listener_info.1 as &dyn chain::Listen));
        }
        chain_tip = Some(
            init::synchronize_listeners(
                &mut bitcoind_client,
                args.network,
                &mut cache,
                chain_listeners,
            )
            .await
            .unwrap(),
        );
    }

    // Step 11: Give ChannelMonitors to ChainMonitor
    for item in chain_listener_channel_monitors.drain(..) {
        let channel_monitor = item.1 .0;
        let funding_outpoint = item.2;
        let status = chain_monitor.watch_channel(funding_outpoint, channel_monitor);
        match status {
            Ok(status) => assert_ne!(status, ChannelMonitorUpdateStatus::UnrecoverableError),
            Err(e) => error!("Error watching channel: {:?}", e),
        }
    }

    let network_gossip =
        Arc::new(P2PGossipSync::new(Arc::clone(&network_graph), None, logadapter.clone()));

    disk::start_network_graph_persister(network_graph_path, &network_graph);

    // Step 14: Initialize the PeerManager
    let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
    let mut ephemeral_bytes = [0; 32];
    thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: network_gossip.clone(),
        onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        custom_message_handler: IgnoringMessageHandler {},
    };
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        lightning_msg_handler,
        current_time,
        &ephemeral_bytes,
        logadapter.clone(),
        keys_manager.clone(),
    ));

    // ## Running LDK
    // Step 16: Initialize Peer Connection Handling

    let peer_manager_connection_handler = peer_manager.clone();
    let listening_port = args.peer_listening_port;

    p2p_handle.spawn(start_p2p_listener(peer_manager_connection_handler, listening_port));

    // Step 17: Connect and Disconnect Blocks
    if chain_tip.is_none() {
        chain_tip = Some(init::validate_best_block_header(&mut bitcoind_client).await.unwrap());
    }
    let channel_manager_listener = channel_manager.clone();
    let chain_monitor_listener = chain_monitor.clone();
    let network = args.network;
    tokio::spawn(async move {
        let chain_poller = poll::ChainPoller::new(&mut bitcoind_client, network);
        let chain_listener = (chain_monitor_listener, channel_manager_listener);
        let mut spv_client =
            SpvClient::new(chain_tip.unwrap(), chain_poller, &mut cache, &chain_listener);
        loop {
            spv_client.poll_best_tip().await.unwrap();
            tokio::time::sleep(Duration::new(1, 0)).await;
        }
    });

    // Step 17 & 18: Initialize ChannelManager persistence & Once Per Minute: ChannelManager's
    // timer_chan_freshness_every_min() and PeerManager's timer_tick_occurred
    let persister = Arc::new(FilesystemStore::new(ldk_data_dir.clone().into()));

    let inbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));
    let outbound_payments: PaymentInfoStorage = Arc::new(Mutex::new(HashMap::new()));

    let handle = Handle::current();

    let channel_manager_event_listener = channel_manager.clone();
    let chain_monitor_event_listener = chain_monitor.clone();
    let keys_manager_listener = keys_manager.clone();
    let inbound_payments_for_events = inbound_payments.clone();
    let outbound_payments_for_events = outbound_payments.clone();

    let event_handler = MyEventHandler {
        handle,
        channel_manager: channel_manager_event_listener,
        chain_monitor: chain_monitor_event_listener,
        bitcoind_client: bitcoind_client_arc.clone(),
        keys_manager: keys_manager_listener,
        inbound_payments: inbound_payments_for_events,
        outbound_payments: outbound_payments_for_events,
        network,
    };

    let no_om = None::<
        Arc<
            OnionMessenger<
                Arc<KeysManager>,
                Arc<KeysManager>,
                Arc<LoggerAdapter>,
                EmptyNodeIdLookUp,
                Arc<
                    DefaultMessageRouter<
                        Arc<NetworkGraph<Arc<LoggerAdapter>>>,
                        Arc<LoggerAdapter>,
                        Arc<MyEntropySource>,
                    >,
                >,
                IgnoringMessageHandler,
                IgnoringMessageHandler,
                IgnoringMessageHandler,
                IgnoringMessageHandler,
            >,
        >,
    >;

    let background_processor = BackgroundProcessor::start(
        persister,
        event_handler,
        chain_monitor.clone(),
        channel_manager.clone(),
        no_om,
        GossipSync::P2P(network_gossip.clone()),
        peer_manager.clone(),
        logadapter.clone(),
        Some(scorer),
    );

    let peer_manager_processor = peer_manager.clone();
    tokio::spawn(async move {
        loop {
            peer_manager_processor.timer_tick_occurred();
            tokio::time::sleep(Duration::new(60, 0)).await;
        }
    });

    let (connector, network_controller) = (Arc::new(Connector {}), NetworkController {});

    // These are clones for the reconnect thread below
    let connect_cm = Arc::clone(&channel_manager);
    let connect_pm = Arc::clone(&peer_manager);
    let connect_connector = Arc::clone(&connector);

    let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());

    let node = Node {
        peer_manager,
        channel_manager,
        inbound_payments,
        outbound_payments,
        keys_manager,
        ldk_data_dir,
        bitcoind_client: bitcoind_client_arc,
        network: args.network,
        background_processor,
        chain_monitor,
        connector,
        logger: logadapter,
    };

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            match disk::read_channel_peer_data(Path::new(&peer_data_path)) {
                Ok(info) => {
                    let peers = connect_pm
                        .list_peers()
                        .into_iter()
                        .map(|peer| peer.counterparty_node_id)
                        .collect::<Vec<_>>();
                    for node_id in connect_cm
                        .list_channels()
                        .iter()
                        .map(|chan| chan.counterparty.node_id)
                        .filter(|id| !peers.contains(id))
                    {
                        for (pubkey, peer_addr) in info.iter() {
                            if *pubkey == node_id {
                                // ignore errors, we'll retry later and there's logging in do_connect_peer
                                let _ = connect_connector
                                    .do_connect_peer(
                                        *pubkey,
                                        peer_addr.clone(),
                                        Arc::clone(&connect_pm),
                                    )
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => println!("ERROR: errored reading channel peer info from disk: {:?}", e),
            }
        }
    });

    (node, network_controller)
}

async fn start_p2p_listener(
    peer_manager_connection_handler: Arc<PeerManager>,
    listening_port: u16,
) {
    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listening_port)).await.unwrap();
    loop {
        let tcp_stream = listener.accept().await.unwrap().0;
        let peer_mgr = peer_manager_connection_handler.clone();
        info!("accepted");
        tokio::spawn(async move {
            lightning_net_tokio::setup_inbound(peer_mgr, tcp_stream.into_std().unwrap()).await;
        });
        info!("setup");
    }
}

impl Node {
    pub fn new_invoice(&self, amount_msat: u64) -> Result<Bolt11Invoice, String> {
        let invoice_params = Bolt11InvoiceParameters {
            amount_msats: Some(amount_msat),
            description: Bolt11InvoiceDescription::Direct(
                Description::new("lnrod invoice".into()).unwrap(),
            ),
            invoice_expiry_delta_secs: Some(7200),
            min_final_cltv_expiry_delta: None,
            payment_hash: None,
        };
        let invoice = self.channel_manager.create_bolt11_invoice(invoice_params).unwrap();
        let mut payments = self.inbound_payments.lock().unwrap();
        let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
        let payment_secret = invoice.payment_secret().clone();

        info!(
            "generated invoice with hash {} secret {}",
            hex::encode(payment_hash.0),
            hex::encode(payment_secret.0)
        );
        let payment_info = PaymentInfo {
            preimage: None,
            secret: Some(payment_secret),
            status: HTLCStatus::Pending,
            amt_msat: MilliSatoshiAmount(Some(amount_msat)),
        };
        payments.insert(PaymentHash(payment_hash.0), payment_info);
        Ok(invoice)
    }

    pub fn send_payment(&self, invoice: Bolt11Invoice) -> Result<(), String> {
        let (payment_hash, recipient_onion, route_params) =
            bolt11_payment::payment_parameters_from_invoice(&invoice)
                .expect("invoice should be valid");
        let status = match self.channel_manager.send_payment(
            payment_hash,
            recipient_onion,
            PaymentId(payment_hash.clone().0),
            route_params,
            Retry::Timeout(Duration::from_secs(1)),
        ) {
            Ok(_payment_id) => {
                let payee_pubkey = invoice.recover_payee_pub_key();
                let amt_msat = invoice.amount_milli_satoshis().unwrap();
                info!("EVENT: initiated sending {} msats to {}", amt_msat, payee_pubkey);
                HTLCStatus::Pending
            }
            Err(e) => {
                error!("ERROR: failed to send payment: {:?}", e);
                HTLCStatus::Failed
            }
        };
        let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
        let mut payments = self.outbound_payments.lock().unwrap();
        let payment = PaymentInfo {
            preimage: None,
            secret: Some(invoice.payment_secret().clone()),
            status,
            amt_msat: MilliSatoshiAmount(Some(invoice.amount_milli_satoshis().unwrap())),
        };
        payments.insert(payment_hash, payment);
        Ok(())
    }

    pub fn keysend_payment(&self, payee_pubkey: PublicKey, value_msat: u64) -> Result<(), String> {
        let mut payment_preimage = PaymentPreimage([0; 32]);
        thread_rng().fill_bytes(&mut payment_preimage.0);
        let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0).to_byte_array());
        let route_params = RouteParameters {
            payment_params: PaymentParameters::for_keysend(payee_pubkey, 40, false),
            final_value_msat: value_msat,
            max_total_routing_fee_msat: None,
        };
        let status = match self.channel_manager.send_spontaneous_payment(
            Some(payment_preimage),
            RecipientOnionFields::spontaneous_empty(),
            PaymentId(payment_hash.0),
            route_params,
            Retry::Timeout(Duration::from_secs(10)),
        ) {
            Ok(_payment_id) => {
                info!("initiated keysend of {} msat to {}", value_msat, payee_pubkey);
                HTLCStatus::Pending
            }
            Err(e) => {
                error!("ERROR: failed to send payment: {:?}", e);
                HTLCStatus::Failed
            }
        };
        let mut payments = self.outbound_payments.lock().unwrap();
        let payment_info = PaymentInfo {
            preimage: None,
            secret: None,
            status,
            amt_msat: MilliSatoshiAmount(Some(value_msat)),
        };
        payments.insert(payment_hash, payment_info);
        Ok(())
    }

    pub async fn blockchain_info(&self) -> BlockchainInfo {
        self.bitcoind_client.get_blockchain_info().await
    }

    pub(crate) async fn connect_peer_if_necessary(
        &self,
        pubkey: PublicKey,
        peer_addr: HostAndPort,
        peer_manager: Arc<PeerManager>,
    ) -> Result<(), ()> {
        for peer in peer_manager.list_peers() {
            if peer.counterparty_node_id == pubkey {
                return Ok(());
            }
        }

        self.connector.do_connect_peer(pubkey, peer_addr.clone(), peer_manager).await?;

        let peer_data_path = format!("{}/channel_peer_data", self.ldk_data_dir);
        disk::persist_channel_peer(Path::new(&peer_data_path), pubkey, peer_addr)
            .expect("disk write error");

        Ok(())
    }
}
