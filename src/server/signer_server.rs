use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use lightning::chain::keysinterface::KeysManager;
use tonic::{Request, Response, Status, transport::Server};

use crate::util;
use util::test_utils::TestLogger;

use signer::*;
use signer::signer_server::{Signer, SignerServer};
use lightning::util::logger::Logger;


pub mod signer {
    // The string specified here must match the proto package name
    tonic::include_proto!("signer");
}

pub struct MySigner {
    keys_manager: KeysManager,
    logger: Arc<Logger>,
}

impl MySigner {
    fn new() -> MySigner {
        let network = Network::Testnet;
        let seed = [0; 32];
        let test_logger = Arc::new(TestLogger::with_id("server".to_owned()));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
        let logger = Arc::clone(&test_logger) as Arc<Logger>;
        let signer = MySigner {
            keys_manager: KeysManager::new(&seed, network, logger, now.as_secs(), now.subsec_nanos()),
            logger: test_logger,
        };
        log_info!(signer, "new MySigner");
        signer
    }
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let signer = MySigner::new();

    Server::builder()
        .add_service(SignerServer::new(signer))
        .serve(addr)
        .await?;

    Ok(())
}
