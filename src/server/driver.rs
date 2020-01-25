use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use lightning::chain::keysinterface::{InMemoryChannelKeys, KeysInterface, KeysManager};
use lightning::util::logger::Logger;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tonic::{Request, Response, Status, transport::Server};

use signer::*;
use signer::signer_server::{Signer, SignerServer};

use crate::util::test_utils::TestLogger;

pub mod signer {
    // The string specified here must match the proto package name
    tonic::include_proto!("signer");
}

pub struct Channel {
    keys: InMemoryChannelKeys,
}

pub struct Node {
    keys_manager: KeysManager,
    channels: Mutex<HashMap<[u8; 32], Channel>>,
}

pub struct MySigner {
    logger: Arc<Logger>,
    nodes: Mutex<HashMap<PublicKey, Node>>,
}

impl MySigner {
    pub fn new() -> MySigner {
        let test_logger = Arc::new(TestLogger::with_id("server".to_owned()));
        let logger = Arc::clone(&test_logger) as Arc<Logger>;
        let signer = MySigner {
            logger: test_logger,
            nodes: Mutex::new(HashMap::new()),
        };
        log_info!(signer, "new MySigner");
        signer
    }

    fn new_node(&mut self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;
        let seed = [0; 32]; // FIXME
        let logger = Arc::clone(&self.logger);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
        let node = Node {
            keys_manager: KeysManager::new(&seed, network, logger, now.as_secs(), now.subsec_nanos()),
            channels: Mutex::new(HashMap::new()),
        };
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, node);
        node_id
    }

    fn new_channel(&self, node_id: &PublicKey, channel_value_satoshi: u64) -> Result<(), ()> {
        let nodes = self.nodes.lock().unwrap();
        let node = match nodes.get(node_id) {
            Some(n) => n,
            None => {
                log_error!(self, "no such node {}", node_id);
                return Err(())
            }
        };
        let mut channels = node.channels.lock().unwrap();
        let keys_manager = &node.keys_manager;
        let channel_id = keys_manager.get_channel_id();
        if channels.contains_key(&channel_id) {
            log_error!(self, "already have channel ID {}", hex::encode(channel_id));
            return Err(())
        }
        let unused_inbound_flag = false;
        let chan_keys = keys_manager.get_channel_keys(unused_inbound_flag, channel_value_satoshi);
        let channel = Channel {
            keys: chan_keys
        };
        channels.insert(channel_id, channel);
        Ok(())
    }
}

fn invert(res: Result<(), ()>) -> Result<(), ()> {
    match res {
        Ok(()) => Err(()),
        Err(()) => Ok(())
    }
}

const TEST_NODE_ID: PublicKey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap());

#[test]
fn new_channel_test() -> Result<(), ()> {
    let mut signer = MySigner::new();
    let node_id = signer.new_node();
    signer.new_channel(&node_id, 1000)
}

#[test]
fn new_channel_bad_node_test() -> Result<(), ()> {
    let secp_ctx = Secp256k1::signing_only();
    let mut signer = MySigner::new();
    invert(signer.new_channel(&TEST_NODE_ID, 1000))
}

#[tonic::async_trait]
impl Signer for MySigner {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        log_info!(self, "Got a request: {:?}", request);

        let reply = signer::PingReply {
            message: format!("Hello {}!", request.into_inner().message).into(), // We must use .into_inner() as the fields of gRPC requests and responses are private
        };

        Ok(Response::new(reply))
    }

    async fn init(&self, _request: Request<InitRequest>) -> Result<Response<InitReply>, Status> {
        panic!("not implemented")
    }

    async fn ecdh(&self, _request: Request<EcdhRequest>) -> Result<Response<EcdhReply>, Status> {
        panic!("not implemented")
    }

    async fn new_channel(&self, _request: Request<NewChannelRequest>) -> Result<Response<NewChannelReply>, Status> {
        panic!("not implemented")
    }

    async fn get_per_commitment_point(&self, _request: Request<GetPerCommitmentPointRequest>) -> Result<Response<GetPerCommitmentPointReply>, Status> {
        panic!("not implemented")
    }

    async fn sign_funding_tx(&self, _request: Request<SignFundingTxRequest>) -> Result<Response<SignFundingTxReply>, Status> {
        panic!("not implemented")
    }

    async fn sign_remote_commitment_tx(&self, _request: Request<SignRemoteCommitmentTxRequest>) -> Result<Response<SignRemoteCommitmentTxReply>, Status> {
        panic!("not implemented")
    }

    async fn sign_remote_htlc_tx(&self, _request: Request<SignRemoteHtlcTxRequest>) -> Result<Response<SignRemoteHtlcTxReply>, Status> {
        panic!("not implemented")
    }

    async fn sign_mutual_close_tx(&self, _request: Request<SignMutualCloseTxRequest>) -> Result<Response<SignMutualCloseTxReply>, Status> {
        panic!("not implemented")
    }
}

#[tokio::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let signer = MySigner::new();

    Server::builder()
        .add_service(SignerServer::new(signer))
        .serve(addr)
        .await?;

    Ok(())
}
