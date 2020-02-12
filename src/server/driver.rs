use std::convert::TryInto;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::{deserialize, encode};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use secp256k1::{PublicKey, Secp256k1};
use tonic::{Request, Response, Status, transport::Server};

use remotesigner::*;
use remotesigner::signer_server::{Signer, SignerServer};

use crate::server::my_signer::{ChannelId, MySigner};
use crate::server::remotesigner::version_server::Version;
use crate::util::crypto_utils::public_key_from_raw;

use super::remotesigner;

impl MySigner {
    fn invalid_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "invalid argument {}", &s);
        Status::invalid_argument(s)
    }

    #[allow(dead_code)]
    fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "internal error {}", &s);
        Status::internal(s)
    }

    fn node_id(&self, arg: Option<NodeId>) -> Result<PublicKey, Status> {
        let der_vec = &arg.ok_or_else(|| self.invalid_argument("missing node ID"))?.data;
        let slice: &[u8] = der_vec.as_slice().try_into().map_err(|_| self.invalid_argument("node ID wrong length"))?;
        PublicKey::from_slice(slice)
            .map_err(|e| self.invalid_argument(format!("could not deserialize remote_funding_pubkey - {}", e)))
    }

    fn public_key(&self, arg: Option<PubKey>) -> Result<PublicKey, Status> {
        let pubkey = arg.ok_or_else(|| self.invalid_argument("missing pubkey"))?;
        public_key_from_raw(pubkey.data.as_slice())
            .map_err(|e| self.invalid_argument(format!("could not deserialize pubkey - {}", e)))
    }

    // NOTE - this "channel_id" does *not* correspond to the
    // channel_id defined in BOLT #2.
    fn channel_id(&self, channel_nonce: &Option<ChannelNonce>) -> Result<ChannelId, Status> {
        let nonce = channel_nonce.as_ref()
            .ok_or_else(|| self.invalid_argument("missing channel nonce"))?
            .data.clone();
        // Impedance mismatch - we want a 32 byte channel ID for internal use
        // Hash the client supplied channel nonce
        let mut digest = Sha256::new();
        digest.input(nonce.as_slice());
        let mut result = [0u8; 32];
        digest.result(&mut result);
        Ok(ChannelId(result))
    }
}

#[tonic::async_trait]
impl Version for MySigner {
    async fn version(&self, _request: Request<VersionRequest>) -> Result<Response<VersionReply>, Status> {
        // TODO git commit
        Ok(Response::new(VersionReply {
            version_string: "0.1.0".to_string(),
            major: 0,
            minor: 1,
            patch: 0,
            prerelease: "pre".to_string(),
            build_metadata: "".to_string()
        }))
    }
}

#[tonic::async_trait]
impl Signer for MySigner {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        log_info!(self, "Got a ping request: {:?}", request);
        let msg = request.into_inner();

        let reply = PingReply {
            message: format!("Hello {}!", msg.message).into(), // We must use .into_inner() as the fields of gRPC requests and responses are private
        };

        Ok(Response::new(reply))
    }

    async fn init(&self, request: Request<InitRequest>) -> Result<Response<InitReply>, Status> {
        let msg = request.into_inner();
        log_info!(self, "ENTER init");
        let hsm_secret = msg.hsm_secret.ok_or_else(|| self.invalid_argument("missing hsm_secret"))?.data;
        let hsm_secret = hsm_secret.as_slice().try_into()
            .map_err(|_| self.invalid_argument("secret length != 32"))?;
        let node_id = self.new_node_from_seed(hsm_secret).serialize().to_vec();
        log_info!(self, "REPLY init {}", hex::encode(&node_id));

        let reply = InitReply {
            node_id: Some(NodeId { data: node_id })
        };
        Ok(Response::new(reply))
    }

    async fn new_channel(&self, request: Request<NewChannelRequest>) -> Result<Response<NewChannelReply>, Status> {
        let msg: NewChannelRequest = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce).ok();
        let opt_channel_nonce =
            if msg.channel_nonce.is_none() {
                None
            } else {
                Some(msg.channel_nonce.unwrap().data)
            };
        log_info!(self, "ENTER new_channel request({}/{:?})", node_id, channel_id);

        let channel_id_result = self.new_channel(&node_id, msg.channel_value, opt_channel_nonce, channel_id).unwrap();
        let reply = NewChannelReply {
            channel_nonce: Some(ChannelNonce { data: channel_id_result.0.to_vec() })
        };
        log_info!(self, "REPLY new_channel request({}/{:?})", node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn sign_mutual_close_tx(&self, request: Request<SignMutualCloseTxRequest>) -> Result<Response<SignMutualCloseTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignMutualCloseTxReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn check_future_secret(&self, request: Request<CheckFutureSecretRequest>) -> Result<Response<CheckFutureSecretReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = CheckFutureSecretReply {
            correct: false
        };
        Ok(Response::new(reply))
    }

    async fn get_channel_basepoints(&self, request: Request<GetChannelBasepointsRequest>) -> Result<Response<GetChannelBasepointsReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_error!(self, "NOT IMPLEMENTED get_channel_basepoints({}/{})", node_id, channel_id);
        Ok(Response::new(GetChannelBasepointsReply {
            basepoints: None,
        }))
    }
    
    async fn get_per_commitment_point(&self, request: Request<GetPerCommitmentPointRequest>) -> Result<Response<GetPerCommitmentPointReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER get_per_commitment_point({}/{})", node_id, channel_id);
        let secp_ctx = Secp256k1::signing_only();
        let commitment_number = msg.n;

        let point = self.get_per_commitment_point(&node_id, &channel_id, &secp_ctx, commitment_number);
        let reply = GetPerCommitmentPointReply {
            per_commitment_point: Some(PubKey{
                data: (point?).serialize().to_vec()
            }),
            old_secret: Some(Secret{ data: vec![] }), // TODO
        };
        log_info!(self, "REPLY get_per_commitment_point({}/{})", node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn sign_funding_tx(&self, request: Request<SignFundingTxRequest>) -> Result<Response<SignFundingTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER sign_funding_tx({}/{})", node_id, channel_id);
        let reqtx = msg.tx.ok_or_else(|| self.invalid_argument("missing tx"))?;
        let tx_res: Result<Transaction, encode::Error> = deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res.map_err(|e| self.invalid_argument(format!("could not deserialize tx - {}", e)))?;
        let mut indices = Vec::new();
        let mut values = Vec::new();
        let mut iswits = Vec::new();

        for idx in 0..tx.input.len() {
            let child_index = reqtx.input_descs[idx].key_loc.as_ref().ok_or_else(|| self.invalid_argument("missing key_loc desc"))?.key_index as u32;
            indices.push(child_index);
            let value = reqtx.input_descs[idx].output.as_ref().ok_or_else(|| self.invalid_argument("missing output desc"))?.value as u64;
            values.push(value);
            iswits.push(true);
        }

        let sigs = self.sign_funding_tx(&node_id, &channel_id, &tx, &indices, &values, &iswits)?;
        let witnesses = sigs.into_iter().map(|s| WitnessStack { item: s }).collect();

        let reply = SignFundingTxReply { witnesses };
        log_info!(self, "REPLY sign_funding_tx({}/{})", node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn sign_remote_commitment_tx(&self, request: Request<SignRemoteCommitmentTxRequest>) -> Result<Response<SignRemoteCommitmentTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER sign_remote_commitment_tx({}/{})", node_id, channel_id);
        let reqtx = msg.tx.ok_or_else(|| self.invalid_argument("missing tx"))?;
        let tx_res: Result<Transaction, encode::Error> = deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res.map_err(|e| self.invalid_argument(format!("could not deserialize tx - {}", e)))?;
        let remote_funding_pubkey = self.public_key(msg.remote_funding_pubkey)?;
        let per_commitment_point = self.public_key(msg.remote_per_commit_point)?;
        let channel_value_satoshis = reqtx.input_descs[0].output.as_ref().unwrap().value as u64;
        let sig_data =
            self.sign_remote_commitment_tx(&node_id, &channel_id, &tx, msg.output_witscripts, &per_commitment_point, &remote_funding_pubkey, channel_value_satoshis)?;
        let reply = SignRemoteCommitmentTxReply { signature: Some(BitcoinSignature { data: sig_data }) };
        log_info!(self, "REPLY sign_remote_commitment_tx({}/{})", node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn sign_commitment_tx(&self, request: Request<SignCommitmentTxRequest>) -> Result<Response<SignCommitmentTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignCommitmentTxReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_local_htlc_tx(&self, request: Request<SignLocalHtlcTxRequest>) -> Result<Response<SignLocalHtlcTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignLocalHtlcTxReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_delayed_payment_to_us(&self, request: Request<SignDelayedPaymentToUsRequest>) -> Result<Response<SignDelayedPaymentToUsReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignDelayedPaymentToUsReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_remote_htlc_tx(&self, request: Request<SignRemoteHtlcTxRequest>) -> Result<Response<SignRemoteHtlcTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignRemoteHtlcTxReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_remote_htlc_to_us(&self, request: Request<SignRemoteHtlcToUsRequest>) -> Result<Response<SignRemoteHtlcToUsReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignRemoteHtlcToUsReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_penalty_to_us(&self, request: Request<SignPenaltyToUsRequest>) -> Result<Response<SignPenaltyToUsReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignPenaltyToUsReply {
            signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_channel_announcement(&self, request: Request<SignChannelAnnouncementRequest>) -> Result<Response<SignChannelAnnouncementReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignChannelAnnouncementReply {
            node_signature: None,
            bitcoin_signature: None
        };
        Ok(Response::new(reply))
    }
    
    async fn sign_node_announcement(
        &self, request: Request<SignNodeAnnouncementRequest>)
        -> Result<Response<SignNodeAnnouncementReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let na = msg.node_announcement;
        log_info!(self, "ENTER sign_node_announcement({}) node_announcement={}", node_id, hex::encode(&na).as_str());
        let sig_data = self.sign_node_announcement(&node_id, &na)?;
        let reply = SignNodeAnnouncementReply {
            signature: Some(EcdsaSignature{data: sig_data}),
        };
        log_info!(self, "REPLY sign_node_announcement({}) {:x?}", node_id, reply);
        Ok(Response::new(reply))
    }
    
    async fn sign_channel_update(&self, request: Request<SignChannelUpdateRequest>) -> Result<Response<SignChannelUpdateReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let cu = msg.channel_update;
        log_info!(self, "ENTER sign_channel_update({}) cu={}", node_id, hex::encode(&cu).as_str());
        let sig_data = self.sign_channel_update(&node_id, &cu)?;
        let reply = SignChannelUpdateReply {
            signature: Some(EcdsaSignature{data: sig_data}),
        };
        log_info!(self, "REPLY sign_channel_update({}) {:x?}", node_id, reply);
        Ok(Response::new(reply))
    }

    async fn ecdh(&self, request: Request<EcdhRequest>) -> Result<Response<EcdhReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let other_key = self.public_key(msg.point)?;
        log_info!(self, "ENTER ecdh({} + {})", node_id, other_key);
        let reply = EcdhReply {
            shared_secret: Some(Secret{data: self.ecdh(&node_id, &other_key)?}),
        };
        log_info!(self, "REPLY ecdh({} + {})", node_id, other_key);
        Ok(Response::new(reply))
    }

    async fn sign_invoice(&self, request: Request<SignInvoiceRequest>) -> Result<Response<SignInvoiceReply>, Status> {
        let _msg = request.into_inner();
//        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED sign_invoice");
        let reply = SignInvoiceReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_message(&self, request: Request<SignMessageRequest>) -> Result<Response<SignMessageReply>, Status> {
        let _msg = request.into_inner();
//        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED sign_message");
        let reply = SignMessageReply {
            signature: None
        };
        Ok(Response::new(reply))
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
