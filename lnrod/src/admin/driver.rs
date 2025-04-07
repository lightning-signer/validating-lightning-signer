use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use lightning_signer::bitcoin::hashes::Hash;
use log::{debug, info};

use anyhow::Result;
use serde_json::json;
use tonic::{transport::Server, Request, Response, Status};

use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;
use lightning::chain::channelmonitor::Balance;
use lightning::ln::types::ChannelId;
use lightning::sign::{NodeSigner, Recipient, SignerProvider};
use lightning::util::config::UserConfig;
use lightning_invoice::Bolt11Invoice;
use lightning_signer::{bitcoin, lightning, lightning_invoice};
use tokio::runtime::{Builder, Handle};

use crate::admin::admin_api::{
    Channel, ChannelCloseRequest, ChannelNewReply, ChannelNewRequest, InvoiceNewReply,
    InvoiceNewRequest, Payment, PaymentKeysendRequest, PaymentListReply, PaymentSendReply,
    PaymentSendRequest, Peer, PeerConnectReply, PeerConnectRequest, PeerListReply, PeerListRequest,
};
use crate::node::{build_node, Node, NodeBuildArgs};
use crate::util::Shutter;

use super::admin_api::admin_server::{Admin, AdminServer};
use super::admin_api::{ChannelListReply, NodeInfoReply, PingReply, PingRequest, Void};

struct AdminHandler {
    node: Node,
}

impl AdminHandler {
    pub fn new(node: Node) -> Self {
        AdminHandler { node }
    }

    // TODO use (cp_id, channel_id) pairs for looking up channels, since channel ID set by counterparties
    // is not guaranteed to be unique
    fn get_channel_counterparty(&self, channel_id: &[u8; 32]) -> PublicKey {
        let chans = self.node.channel_manager.list_channels();
        let channel_id = ChannelId::from_bytes(*channel_id);
        let chan = chans.iter().find(|c| channel_id == c.channel_id).unwrap();
        chan.counterparty.node_id
    }
}

#[tonic::async_trait]
impl Admin for AdminHandler {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let req = request.into_inner();
        info!("ENTER ping");
        debug!("{}", type_and_value!(&req));
        let reply = PingReply {
            // We must use .into_inner() as the fields of gRPC requests and responses are private
            message: format!("Hello {}!", req.message),
        };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY ping");
        Ok(Response::new(reply))
    }

    async fn node_info(&self, _request: Request<Void>) -> Result<Response<NodeInfoReply>, Status> {
        info!("ENTER node_info");
        let node_pubkey = self.node.keys_manager.get_node_id(Recipient::Node).unwrap();
        let shutdown_scriptpubkey = self.node.keys_manager.get_shutdown_scriptpubkey();
        let shutdown_address = Address::from_script(
            &shutdown_scriptpubkey.unwrap().into_inner().as_script(),
            self.node.network,
        )
        .unwrap()
        .to_string();
        let chain_info = self.node.blockchain_info().await;
        let reply = NodeInfoReply {
            node_id: node_pubkey.serialize().to_vec(),
            shutdown_address,
            best_block_hash: chain_info.latest_blockhash.as_byte_array().to_vec(),
            num_blocks: chain_info.latest_height as u32,
        };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY node_info");
        Ok(Response::new(reply))
    }

    async fn channel_list(
        &self,
        _request: Request<Void>,
    ) -> Result<Response<ChannelListReply>, Status> {
        info!("ENTER channel_list");
        let mut channels = Vec::new();
        for details in self.node.channel_manager.list_channels() {
            let monitor_balance: Option<u64> = if let Some(funding_txo) = details.funding_txo {
                let monitor_opt = self.node.chain_monitor.get_monitor(funding_txo);
                if let Ok(monitor) = monitor_opt {
                    let balances = monitor.get_claimable_balances();
                    Some(
                        balances
                            .into_iter()
                            .map(|b| match b {
                                Balance::ClaimableOnChannelClose { amount_satoshis, .. } =>
                                    amount_satoshis,
                                Balance::ClaimableAwaitingConfirmations {
                                    amount_satoshis, ..
                                } => amount_satoshis,
                                Balance::CounterpartyRevokedOutputClaimable {
                                    amount_satoshis,
                                    ..
                                } => amount_satoshis,
                                Balance::ContentiousClaimable { .. } => 0,
                                Balance::MaybeTimeoutClaimableHTLC { .. } => 0,
                                Balance::MaybePreimageClaimableHTLC { .. } => 0,
                            })
                            .sum(),
                    )
                } else {
                    None
                }
            } else {
                None
            };
            let balance = monitor_balance.unwrap_or(0) * 1000;
            let channel = Channel {
                peer_node_id: details.counterparty.node_id.serialize().to_vec(),
                channel_id: details.channel_id.0.to_vec(),
                is_pending: details.short_channel_id.is_none(),
                value_sat: details.channel_value_satoshis,
                is_active: details.is_usable,
                outbound_msat: balance,
            };
            channels.push(channel);
        }
        let reply = ChannelListReply { channels };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY channel_list");
        Ok(Response::new(reply))
    }

    async fn channel_new(
        &self,
        request: Request<ChannelNewRequest>,
    ) -> Result<Response<ChannelNewReply>, Status> {
        let req = request.into_inner();
        info!("ENTER channel_new");
        debug!("{}", type_and_value!(&req));
        let node_id = PublicKey::from_slice(req.node_id.as_slice())
            .map_err(|_| Status::invalid_argument("failed to parse node_id"))?;

        let mut config = UserConfig::default();
        if req.is_public {
            config.channel_handshake_config.announce_for_forwarding = true;
        }
        // lnd's max to_self_delay is 2016, so we want to be compatible.
        config.channel_handshake_limits.their_to_self_delay = 2016;
        self.node
            .channel_manager
            .create_channel(node_id, req.value_sat, req.push_msat, 0, None, Some(config))
            .map_err(|e| {
                let msg = format!("failed to create channel {:?}", e);
                Status::aborted(msg)
            })?;
        info!("created");

        let reply = ChannelNewReply {};
        debug!("{}", type_and_value!(&reply));
        info!("REPLY channel_new");
        Ok(Response::new(reply))
    }

    async fn peer_connect(
        &self,
        request: Request<PeerConnectRequest>,
    ) -> Result<Response<PeerConnectReply>, Status> {
        let req = request.into_inner();
        info!("ENTER peer_connect");
        debug!("{}", type_and_value!(&req));
        let peer_addr =
            req.address.parse().map_err(|_| Status::invalid_argument("address parse"))?;
        let node_id = PublicKey::from_slice(req.node_id.as_slice())
            .map_err(|_| Status::invalid_argument("failed to parse node_id"))?;
        self.node
            .connect_peer_if_necessary(node_id, peer_addr, self.node.peer_manager.clone())
            .await
            .map_err(|_| Status::aborted("could not connect to peer"))?;

        info!("connected");
        let reply = PeerConnectReply {};
        debug!("{}", type_and_value!(&reply));
        info!("REPLY peer_connect");
        Ok(Response::new(reply))
    }

    async fn peer_list(
        &self,
        request: Request<PeerListRequest>,
    ) -> Result<Response<PeerListReply>, Status> {
        let _req = request.into_inner();
        info!("ENTER peer_list");
        let peers = self
            .node
            .peer_manager
            .list_peers()
            .iter()
            .map(|peer| Peer { node_id: peer.counterparty_node_id.serialize().to_vec() })
            .collect();
        let reply = PeerListReply { peers };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY peer_list");
        Ok(Response::new(reply))
    }

    async fn invoice_new(
        &self,
        request: Request<InvoiceNewRequest>,
    ) -> Result<Response<InvoiceNewReply>, Status> {
        let req = request.into_inner();
        info!("ENTER invoice_new");
        debug!("{}", type_and_value!(&req));
        let invoice =
            self.node.new_invoice(req.value_msat).map_err(|e| Status::invalid_argument(e))?;
        let reply = InvoiceNewReply { invoice: invoice.to_string() };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY invoice_new");
        Ok(Response::new(reply))
    }

    async fn payment_send(
        &self,
        request: Request<PaymentSendRequest>,
    ) -> Result<Response<PaymentSendReply>, Status> {
        let req = request.into_inner();
        info!("ENTER payment_send");
        debug!("{}", type_and_value!(&req));
        let invoice = Bolt11Invoice::from_str(req.invoice.as_str())
            .map_err(|_| Status::invalid_argument("invalid invoice"))?;
        self.node.send_payment(invoice).map_err(|e| Status::invalid_argument(e))?;
        let reply = PaymentSendReply {};
        debug!("{}", type_and_value!(&reply));
        info!("REPLY payment_send");
        Ok(Response::new(reply))
    }

    async fn payment_keysend(
        &self,
        request: Request<PaymentKeysendRequest>,
    ) -> Result<Response<PaymentSendReply>, Status> {
        let req = request.into_inner();
        info!("ENTER payment_keysend");
        debug!("{}", type_and_value!(&req));
        let node_id = PublicKey::from_slice(req.node_id.as_slice())
            .map_err(|_| Status::invalid_argument("failed to parse node_id"))?;
        let value = req.value_msat;
        self.node.keysend_payment(node_id, value).map_err(|e| Status::invalid_argument(e))?;
        let reply = PaymentSendReply {};
        debug!("{}", type_and_value!(&reply));
        info!("REPLY payment_keysend");
        Ok(Response::new(reply))
    }

    async fn payment_list(
        &self,
        request: Request<Void>,
    ) -> Result<Response<PaymentListReply>, Status> {
        let _req = request.into_inner();
        info!("ENTER payment_list");
        let outbound_payments = self
            .node
            .outbound_payments
            .lock()
            .map_err(|_| Status::unavailable("Failed to acquire lock on payment info"))?
            .iter()
            .map(|(payment_hash, info)| Payment {
                value_msat: info.amt_msat.0.unwrap(),
                payment_hash: payment_hash.0.to_vec(),
                is_outbound: true,
                status: info.status.clone() as i32,
            })
            .collect::<Vec<_>>();
        let inbound_payments = self
            .node
            .inbound_payments
            .lock()
            .map_err(|_| Status::unavailable("Failed to acquire lock on payment info"))?
            .iter()
            .map(|(payment_hash, info)| Payment {
                value_msat: info.amt_msat.0.unwrap(),
                payment_hash: payment_hash.0.to_vec(),
                is_outbound: false,
                status: info.status.clone() as i32,
            })
            .collect::<Vec<_>>();
        let mut payments = inbound_payments;
        payments.extend(outbound_payments);
        let reply = PaymentListReply { payments };
        debug!("{}", type_and_value!(&reply));
        info!("REPLY payment_list");
        Ok(Response::new(reply))
    }

    async fn channel_close(
        &self,
        request: Request<ChannelCloseRequest>,
    ) -> Result<Response<Void>, Status> {
        let req = request.into_inner();
        info!("ENTER channel_close");
        debug!("{}", type_and_value!(&req));
        let channel_id_vec = req
            .channel_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("channel ID must be 32 bytes"))?;
        let channel_id = ChannelId::from_bytes(channel_id_vec);
        let cp_id = self.get_channel_counterparty(&channel_id_vec);
        if req.is_force {
            self.node.channel_manager.force_close_broadcasting_latest_txn(
                &channel_id,
                &cp_id,
                String::from("ERROR"),
            )
        } else {
            self.node.channel_manager.close_channel(&channel_id, &cp_id)
        }
        .map_err(|e| Status::aborted(format!("{:?}", e)))?;
        info!("REPLY channel_close");
        Ok(Response::new(Void {}))
    }
}

// A small number of threads for debugging
pub fn start(rpc_port: u16, args: NodeBuildArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Various housekeeping things run on this
    let runtime = std::thread::spawn(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("main")
            .worker_threads(2) // for debugging
            .build()
    })
    .join()
    .expect("runtime join")
    .expect("runtime");
    // The Lightning p2p protocol runs on this
    let p2p_runtime = std::thread::spawn(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("p2p")
            .worker_threads(2) // for debugging
            .build()
    })
    .join()
    .expect("runtime join")
    .expect("runtime");
    let p2p_handle = p2p_runtime.handle().clone();

    let signer_runtime = std::thread::spawn(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("signer")
            .worker_threads(2) // for debugging
            .build()
    })
    .join()
    .expect("runtime join")
    .expect("runtime");
    let signer_handle = signer_runtime.handle().clone();

    runtime.block_on(do_start(rpc_port, args, p2p_handle, signer_handle))
}

pub async fn do_start(
    rpc_port: u16,
    args: NodeBuildArgs,
    p2p_handle: Handle,
    signer_handle: Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    let shutter = Shutter::new();

    let (node, _network_controller) =
        build_node(args.clone(), shutter.clone(), p2p_handle, signer_handle).await;
    let node_id = node.keys_manager.get_node_id(Recipient::Node).unwrap();

    info!("p2p {} 127.0.0.1:{}", node_id, args.peer_listening_port);
    info!(
        "admin port {}, datadir {}, signer {}, vls port {}",
        rpc_port, args.storage_dir_path, args.signer_name, args.vls_port,
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let handler = AdminHandler::new(node);
    info!("starting server");
    Server::builder()
        .add_service(AdminServer::new(handler))
        .serve_with_shutdown(addr, shutter.signal)
        .await?;
    info!("stopping server");
    Ok(())
}
