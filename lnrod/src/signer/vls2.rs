use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa::RecoverableSignature, All, PublicKey, Scalar, Secp256k1,
};
use bitcoin::{Address, Network, Transaction, TxOut};
use lightning::ln::msgs::DecodeError;
use lightning::ln::msgs::UnsignedGossipMessage;
use lightning::ln::script::ShutdownScript;
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::sign::{Recipient, SpendableOutputDescriptor};
use lightning_signer::lightning::ln::inbound_payment::ExpandedKey;
use lightning_signer::lightning_invoice::RawBolt11Invoice;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::DummyPersister;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, OptionizedSimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::{bitcoin, lightning};
use log::{debug, error, info};
use tokio::runtime::Handle;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::task;
use url::Url;
use vls_frontend::Frontend;
use vls_protocol::model::PubKey;
use vls_protocol::msgs::{self};
use vls_protocol::serde_bolt::{Array, WireString};
use vls_protocol_client::SignerPort;
use vls_protocol_client::{ClientResult, Error, KeysManagerClient, Transport};
use vls_protocol_signer::handler::{Handler, HandlerBuilder, RootHandler};
use vls_protocol_signer::vls_protocol;
use vls_proxy::grpc::adapter::{ChannelRequest, ClientId, HsmdService};
use vls_proxy::grpc::incoming::TcpIncoming;
use vls_proxy::grpc::signer_loop::InitMessageCache;
use vls_proxy::portfront::SignerPortFront;
use vls_proxy::vls_frontend;
use vls_proxy::vls_frontend::frontend::DummySourceFactory;
use vls_proxy::vls_protocol_client;
use vls_proxy::vls_protocol_signer;

use crate::bitcoin::Witness;
use crate::signer::util::create_spending_transaction;
use crate::util::Shutter;
use crate::{DynSigner, SpendableKeysInterface};

// A VLS client with a null transport.
// Actually runs VLS in-process, but still performs the protocol.
// No persistence.
struct NullTransport {
    handler: RootHandler,
}

impl NullTransport {
    pub fn new(address: Address) -> Self {
        let persister = Arc::new(DummyPersister);
        let allowlist = vec![address.to_string()];
        info!("allowlist {:?}", allowlist);
        let network = Network::Regtest; // TODO - get from config, env or args
        let policy = make_simple_policy(network, OptionizedSimplePolicy::new());
        let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
        let starting_time_factory = ClockStartingTimeFactory::new();
        let clock = Arc::new(StandardClock());
        let trusted_oracle_pubkeys = vec![];
        let services = NodeServices {
            validator_factory,
            starting_time_factory,
            persister,
            clock,
            trusted_oracle_pubkeys,
        };
        let seed = generate_seed();
        let builder = HandlerBuilder::new(network, 0, services, seed).allowlist(allowlist);
        let mut init_handler = builder.build().unwrap();

        let preinit = msgs::HsmdDevPreinit {
            derivation_style: 0,
            network_name: WireString(network.to_string().into_bytes()),
            seed: None,
            allowlist: Array(vec![WireString(address.to_string().into_bytes())]),
        };
        let init = msgs::HsmdInit2 {
            derivation_style: 0,
            network_name: WireString(network.to_string().into_bytes()),
            dev_seed: None,
            dev_allowlist: Array(vec![WireString(address.to_string().into_bytes())]),
        };

        init_handler.handle(msgs::Message::HsmdDevPreinit(preinit)).expect("HSMD preinit failed");
        init_handler.handle(msgs::Message::HsmdInit2(init)).expect("HSMD init failed");
        let root_handler = init_handler.into();
        NullTransport { handler: root_handler }
    }
}

impl Transport for NullTransport {
    fn node_call(&self, message_ser: Vec<u8>) -> ClientResult<Vec<u8>> {
        let message = msgs::from_vec(message_ser)?;
        debug!("ENTER node_call {:?}", message);
        let result = self.handler.handle(message).map_err(|e| {
            error!("error in handle: {:?}", e);
            Error::Transport
        })?;
        debug!("REPLY node_call {:?}", result);
        Ok(result.as_vec())
    }

    fn call(&self, dbid: u64, peer_id: PubKey, message_ser: Vec<u8>) -> ClientResult<Vec<u8>> {
        let message = msgs::from_vec(message_ser)?;
        debug!("ENTER call({}) {:?}", dbid, message);
        let handler = self.handler.for_new_client(0, peer_id, dbid);
        let result = handler.handle(message).map_err(|e| {
            error!("error in handle: {:?}", e);
            Error::Transport
        })?;
        debug!("REPLY call({}) {:?}", dbid, result);
        Ok(result.as_vec())
    }
}

struct TransportSignerPort {
    transport: Arc<dyn Transport>,
}

#[async_trait]
impl SignerPort for TransportSignerPort {
    async fn handle_message(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        self.transport.node_call(message)
    }

    fn is_ready(&self) -> bool {
        true
    }
}

struct KeysManager {
    client: KeysManagerClient,
    sweep_address: Address,
}

impl SignerProvider for KeysManager {
    type EcdsaSigner = DynSigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        self.client.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        let client = self.client.derive_channel_signer(channel_value_satoshis, channel_keys_id);
        DynSigner::new(client)
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        let signer = self.client.read_chan_signer(reader)?;
        Ok(DynSigner::new(signer))
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<bitcoin::ScriptBuf, ()> {
        self.client.get_destination_script(channel_keys_id)
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        self.client.get_shutdown_scriptpubkey()
    }
}

impl EntropySource for KeysManager {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.client.get_secure_random_bytes()
    }
}

impl NodeSigner for KeysManager {
    fn get_inbound_payment_key(&self) -> ExpandedKey {
        self.client.get_inbound_payment_key()
    }

    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        self.client.get_node_id(recipient)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        self.client.ecdh(recipient, other_key, tweak)
    }

    fn sign_invoice(
        &self,
        raw_invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.client.sign_invoice(raw_invoice, recipient)
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        self.client.sign_gossip_message(msg)
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &lightning::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.client.sign_bolt12_invoice(invoice)
    }
}

impl SpendableKeysInterface for KeysManager {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: bitcoin::ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        _secp_ctx: &Secp256k1<All>,
    ) -> anyhow::Result<Transaction> {
        info!("ENTER spend_spendable_outputs");
        let mut tx = create_spending_transaction(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
        )?;
        let witnesses = self.client.sign_onchain_tx(&tx, descriptors);
        assert_eq!(witnesses.len(), tx.input.len());
        for (idx, w) in witnesses.into_iter().enumerate() {
            tx.input[idx].witness = Witness::from_slice(&w);
        }
        Ok(tx)
    }

    fn get_sweep_address(&self) -> Address {
        self.sweep_address.clone()
    }
}

pub(crate) async fn make_null_signer(
    shutter: Shutter,
    network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
    bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);

    if let Ok(_node_id_hex) = fs::read_to_string(node_id_path.clone()) {
        unimplemented!("read from disk {}", node_id_path);
    } else {
        let transport = Arc::new(NullTransport::new(sweep_address.clone()));

        let signer_port = Arc::new(TransportSignerPort { transport: transport.clone() });
        let source_factory = Arc::new(DummySourceFactory::new(ldk_data_dir, network));
        let frontend = Frontend::new(
            Arc::new(SignerPortFront::new(signer_port, network)),
            source_factory,
            bitcoin_rpc_url,
            shutter.signal,
        );
        frontend.start();

        let node_id = transport.handler.node().get_id();
        let client = KeysManagerClient::new(transport, network.to_string(), None, None);
        let keys_manager = KeysManager { client, sweep_address };
        fs::write(node_id_path, node_id.to_string()).expect("write node_id");
        Box::new(keys_manager)
    }
}

struct GrpcTransport {
    sender: Sender<ChannelRequest>,
    handle: Handle,
}

impl GrpcTransport {
    async fn new(sender: Sender<ChannelRequest>) -> ClientResult<Self> {
        info!("waiting for signer");
        let handle = Handle::current();
        Ok(Self { sender, handle })
    }

    fn do_call(
        handle: &Handle,
        sender: Sender<ChannelRequest>,
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> ClientResult<Vec<u8>> {
        let join = handle.spawn_blocking(move || {
            Handle::current().block_on(Self::do_call_async(sender, message, client_id)).unwrap()
        });
        let result = task::block_in_place(|| handle.block_on(join)).expect("join");
        Ok(result)
    }

    async fn do_call_async(
        sender: Sender<ChannelRequest>,
        message: Vec<u8>,
        client_id: Option<ClientId>,
    ) -> ClientResult<Vec<u8>> {
        // Create a one-shot channel to receive the reply
        let (reply_tx, reply_rx) = oneshot::channel();

        // Send a request to the gRPC handler to send to signer
        let request = ChannelRequest { client_id, message, reply_tx };

        // This can fail if gRPC adapter shut down
        sender.send(request).await.map_err(|_| Error::Transport)?;
        let reply = reply_rx.await.map_err(|_| Error::Transport)?;
        Ok(reply.reply)
    }
}

impl Transport for GrpcTransport {
    fn node_call(&self, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        Self::do_call(&self.handle, self.sender.clone(), message, None)
    }

    fn call(&self, dbid: u64, peer_id: PubKey, message: Vec<u8>) -> ClientResult<Vec<u8>> {
        let client_id = Some(ClientId { peer_id: peer_id.0, dbid });

        Self::do_call(&self.handle, self.sender.clone(), message, client_id)
    }
}

pub(crate) async fn make_grpc_signer(
    shutter: Shutter,
    signer_handle: Handle,
    vls_port: u16,
    network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
    bitcoin_rpc_url: Url,
) -> Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>> {
    let node_id_path = format!("{}/node_id", ldk_data_dir);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, vls_port));
    let incoming = TcpIncoming::new(addr, false).await.expect("listen incoming");
    let init_message_cache = Arc::new(Mutex::new(InitMessageCache::new()));

    let server =
        HsmdService::new(shutter.trigger.clone(), shutter.signal.clone(), init_message_cache);

    let sender = server.sender();

    signer_handle.spawn(server.start(incoming, shutter.signal.clone()));

    let transport = Arc::new(
        signer_handle
            .spawn(GrpcTransport::new(sender))
            .await
            .expect("join")
            .expect("gRPC transport init"),
    );

    let source_factory = Arc::new(DummySourceFactory::new(ldk_data_dir, network));
    let signer_port = Arc::new(TransportSignerPort { transport: transport.clone() });
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port, network)),
        source_factory,
        bitcoin_rpc_url,
        shutter.signal,
    );

    let dev_allowlist = Array(vec![WireString(sweep_address.clone().to_string().into_bytes())]);
    let client = KeysManagerClient::new(
        transport,
        network.to_string(),
        Some(KeyDerivationStyle::Ldk),
        Some(dev_allowlist),
    );
    // NOTE: for now the frontend must be started after the client is created
    // as the TranportSignerPort is always set to ready
    frontend.start();

    let node_id = client.get_node_id(Recipient::Node).expect("get node id");
    let keys_manager = KeysManager { client, sweep_address };
    fs::write(node_id_path, node_id.to_string()).expect("write node_id");

    Box::new(keys_manager)
}
