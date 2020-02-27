use std::convert::TryInto;

use bitcoin;
use bitcoin::consensus::{deserialize, encode};
use bitcoin::OutPoint;
use bitcoin_hashes::{Hash, sha256d};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::ln::channelmanager::PaymentHash;
use secp256k1::{PublicKey, Secp256k1};
use tonic::{Request, Response, Status, transport::Server};

use remotesigner::*;
use remotesigner::signer_server::{Signer, SignerServer};

use crate::server::my_signer::{ChannelId, MySigner};
use crate::server::remotesigner::version_server::Version;
use crate::tx::tx::HTLCInfo;
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
        let pubkey = arg.ok_or_else(
            || self.invalid_argument("missing pubkey"))?;
        public_key_from_raw(pubkey.data.as_slice())
            .map_err(|e| self.invalid_argument(
                format!("could not deserialize pubkey - {}", e)))
    }

    // Converts secp256k1::PublicKey into remotesigner::PubKey
    fn to_pubkey(&self, arg: PublicKey) -> PubKey {
        PubKey { data: arg.serialize().to_vec() }
    }

    // NOTE - this "channel_id" does *not* correspond to the
    // channel_id defined in BOLT #2.
    fn channel_id(&self, channel_nonce: &Option<ChannelNonce>) -> Result<ChannelId, Status> {
        let nonce = channel_nonce.as_ref()
            .ok_or_else(|| self.invalid_argument("missing channel nonce"))?
            .data.clone();
        let res = channel_nonce_to_id(&nonce);
        Ok(res)
    }

    fn convert_htlcs(&self, msg_htlcs: &Vec<HtlcInfo>) -> Result<Vec<HTLCInfo>, Status> {
        let mut htlcs = Vec::new();
        for h in msg_htlcs.iter() {
            let hash = h.payment_hash.as_slice().try_into()
                .map_err(|_| self.invalid_argument(
                    "could not decode payment hash"))?;
            htlcs.push(HTLCInfo { value: h.value, payment_hash: PaymentHash(hash), cltv_expiry: h.cltv_expiry });
        }
        Ok(htlcs)
    }
}

pub fn channel_nonce_to_id(nonce: &Vec<u8>) -> ChannelId {
    // Impedance mismatch - we want a 32 byte channel ID for internal use
    // Hash the client supplied channel nonce
    let mut digest = Sha256::new();
    digest.input(nonce.as_slice());
    let mut result = [0u8; 32];
    digest.result(&mut result);
    ChannelId(result)
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

        let channel_id_result =
            self.new_channel(&node_id, msg.channel_value,
                             opt_channel_nonce, channel_id,
                             msg.is_outbound).unwrap();
        let reply = NewChannelReply {
            channel_nonce: Some(ChannelNonce { data: channel_id_result.0.to_vec() })
        };
        log_info!(self, "REPLY new_channel request({}/{:?})", node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn get_channel_basepoints(
        &self, request: Request<GetChannelBasepointsRequest>)
        -> Result<Response<GetChannelBasepointsReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER get_channel_basepoints({}/{})",
                  node_id, channel_id);

        // WORKAROUND - We need to derive and pass the channel_nonce
        // in case this call needs to create the channel.
        let channel_nonce = msg.channel_nonce
            .ok_or_else(|| self.invalid_argument("missing channel_nonce"))?
            .data;

        let bps =
            self.get_channel_basepoints(&node_id,
                                        &channel_id,
                                        &channel_nonce)?;

        let basepoints = Basepoints {
            revocation: Some(self.to_pubkey(bps.revocation_basepoint)),
            payment: Some(self.to_pubkey(bps.payment_basepoint)),
            htlc: Some(self.to_pubkey(bps.htlc_basepoint)),
            delayed_payment: Some(
                self.to_pubkey(bps.delayed_payment_basepoint)),
            funding_pubkey: Some(self.to_pubkey(bps.funding_pubkey)),
        };

        log_info!(self, "REPLY get_channel_basepoints({}/{}) basepoints={:?}",
                  node_id, channel_id, &basepoints);
        Ok(Response::new(GetChannelBasepointsReply {
            basepoints: Some(basepoints),
        }))
    }

    async fn ready_channel(&self, request: Request<ReadyChannelRequest>)
                           -> Result<Response<ReadyChannelReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        let basepoints =
            msg.basepoints.ok_or_else(|| self.invalid_argument("missing basepoints"))?;
        let keys = ChannelPublicKeys {
            funding_pubkey: self.public_key(basepoints.funding_pubkey)?,
            revocation_basepoint: self.public_key(basepoints.revocation)?,
            payment_basepoint: self.public_key(basepoints.payment)?,
            delayed_payment_basepoint: self.public_key(basepoints.delayed_payment)?,
            htlc_basepoint: self.public_key(basepoints.htlc)?,
        };
        let msg_outpoint =
            msg.funding_outpoint.ok_or_else(|| self.invalid_argument("missing funding outpoint"))?;
        let txid = sha256d::Hash::from_slice(&msg_outpoint.txid)
            .map_err(|_| self.invalid_argument("cannot decode funding outpoint txid"))?;
        let funding_outpoint = OutPoint {
            txid,
            vout: msg_outpoint.index,
        };
        self.ready_channel(&node_id, &channel_id, &keys, msg.to_self_delay as u16, &msg.shutdown_script, funding_outpoint)?;
        Ok(Response::new(ReadyChannelReply {}))
    }

    async fn sign_mutual_close_tx(&self, request: Request<SignMutualCloseTxRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
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

    async fn get_per_commitment_point(
        &self,
        request: Request<GetPerCommitmentPointRequest>)
        -> Result<Response<GetPerCommitmentPointReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER get_per_commitment_point({}/{})",
                  node_id, channel_id);
        let secp_ctx = Secp256k1::signing_only();
        let commitment_number = msg.n;

        let pointdata =
            self.get_per_commitment_point(
                &node_id, &channel_id, &secp_ctx, commitment_number)
            .map_err(|_| self.invalid_argument(
                "get_per_commitment_point failed"))?
            .serialize().to_vec();

        let mut secretdata: Vec<u8> = vec![];
        if commitment_number >= 2 {
            secretdata =
                self.get_per_commitment_secret(
                    &node_id, &channel_id, &secp_ctx, commitment_number - 2)
            .map_err(|_| self.invalid_argument(
                "get_per_commitment_secret failed"))?
                [..].to_vec();
        }

        let reply = GetPerCommitmentPointReply {
            per_commitment_point: Some(PubKey { data: pointdata.clone(), }),
            old_secret: Some(Secret{ data: secretdata.clone() }), // TODO
        };
        log_info!(self,
                  "REPLY get_per_commitment_point({}/{}) point={} oldsecret={}",
                  node_id, channel_id,
                  hex::encode(&pointdata),
                  hex::encode(&secretdata));
        Ok(Response::new(reply))
    }

    async fn sign_funding_tx(&self, request: Request<SignFundingTxRequest>) -> Result<Response<SignFundingTxReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER sign_funding_tx({}/{})", node_id, channel_id);
        let reqtx = msg.tx.ok_or_else(|| self.invalid_argument("missing tx"))?;
        let tx_res: Result<bitcoin::Transaction, encode::Error> = deserialize(reqtx.raw_tx_bytes.as_slice());
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

    async fn sign_remote_commitment_tx(
        &self, request: Request<SignRemoteCommitmentTxRequest>)
        -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER sign_remote_commitment_tx({}/{})",
                  node_id, channel_id);

        let reqtx = msg.tx.ok_or_else(|| self.invalid_argument("missing tx"))?;
        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res.map_err(
            |e| self.invalid_argument(format!("deserialize tx fail: {}", e)))?;

        let remote_funding_pubkey =
            self.public_key(msg.remote_funding_pubkey)?;
        let remote_per_commitment_point =
            self.public_key(msg.remote_per_commit_point)?;
        let channel_value_satoshis =
            reqtx.input_descs[0].output.as_ref().unwrap().value as u64;

        let sig_data =
            self.sign_remote_commitment_tx(
                &node_id, &channel_id, &tx, reqtx.output_witscripts,
                &remote_per_commitment_point, &remote_funding_pubkey,
                channel_value_satoshis)?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature { data: sig_data })
        };
        log_info!(self, "REPLY sign_remote_commitment_tx({}/{})",
                  node_id, channel_id);
        Ok(Response::new(reply))
    }

    async fn sign_commitment_tx(&self, request: Request<SignCommitmentTxRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_local_htlc_tx(&self, request: Request<SignLocalHtlcTxRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_delayed_payment_to_us(&self, request: Request<SignDelayedPaymentToUsRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_remote_htlc_tx(
        &self, request: Request<SignRemoteHtlcTxRequest>)
        -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        log_info!(self, "ENTER sign_remote_htlc_tx({}/{})",
                  node_id, channel_id);
        let reqtx = msg.tx.ok_or_else(|| self.invalid_argument("missing tx"))?;

        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res.map_err(
            |e| self.invalid_argument(format!("deserialize tx fail: {}", e)))?;

        let remote_per_commitment_point =
            self.public_key(msg.remote_per_commit_point)?;

        let htlc_amount =
            match reqtx.input_descs[0].output.as_ref() {
                Some(out) => out.value as u64,
                None => return Err(Status::internal("missing input_desc[0]")),
            };

        let sig_data =
            self.sign_remote_htlc_tx(
                &node_id,
                &channel_id,
                &tx,
                reqtx.output_witscripts,
                &remote_per_commitment_point,
                htlc_amount,
            )?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature { data: sig_data }),
        };
        // TODO - need REPLY log here.
        Ok(Response::new(reply))
    }

    async fn sign_remote_htlc_to_us(&self, request: Request<SignRemoteHtlcToUsRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_penalty_to_us(&self, request: Request<SignPenaltyToUsRequest>) -> Result<Response<SignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED {}", node_id);
        let reply = SignatureReply {
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

    async fn sign_node_announcement(&self, request: Request<SignNodeAnnouncementRequest>) -> Result<Response<NodeSignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let na = msg.node_announcement;
        log_info!(self, "ENTER sign_node_announcement({}) node_announcement={}", node_id, hex::encode(&na).as_str());
        let sig_data = self.sign_node_announcement(&node_id, &na)?;
        let reply = NodeSignatureReply {
            signature: Some(EcdsaSignature{data: sig_data}),
        };
        log_info!(self, "REPLY sign_node_announcement({}) {:x?}", node_id, reply);
        Ok(Response::new(reply))
    }

    async fn sign_channel_update(&self, request: Request<SignChannelUpdateRequest>) -> Result<Response<NodeSignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let cu = msg.channel_update;
        log_info!(self, "ENTER sign_channel_update({}) cu={}", node_id, hex::encode(&cu).as_str());
        let sig_data = self.sign_channel_update(&node_id, &cu)?;
        let reply = NodeSignatureReply {
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

    async fn sign_invoice(&self, request: Request<SignInvoiceRequest>) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let data_part = msg.data_part;
        let human_readable_part = msg.human_readable_part;
        log_info!(self,
                  "ENTER sign_invoice({}) data_part={} human_readable_part={}",
                  node_id,
                  hex::encode(&data_part).as_str(),
                  human_readable_part);
        let sig_data = self.sign_invoice(&node_id, &data_part,
                                         &human_readable_part)?;
        let reply = RecoverableNodeSignatureReply {
            signature: Some(EcdsaRecoverableSignature{data: sig_data}),
        };
        log_info!(self, "REPLY sign_invoice({}) rsig={}", node_id,
                  hex::encode(&reply.signature.as_ref().unwrap().data));
        Ok(Response::new(reply))
    }

    async fn sign_message(&self, request: Request<SignMessageRequest>) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        let _msg = request.into_inner();
//        let node_id = self.node_id(msg.node_id)?;
        log_error!(self, "NOT IMPLEMENTED sign_message");
        let reply = RecoverableNodeSignatureReply {
            signature: None
        };
        Ok(Response::new(reply))
    }

    async fn sign_remote_commitment_tx_phase2(&self, request: Request<SignRemoteCommitmentTxPhase2Request>)
                                              -> Result<Response<CommitmentTxSignatureReply>, Status> {
        let msg = request.into_inner();
        let node_id = self.node_id(msg.node_id)?;
        let channel_id = self.channel_id(&msg.channel_nonce)?;
        let msg_info = msg.commitment_info
            .ok_or_else(|| self.invalid_argument("missing commitment info"))?;
        let remote_per_commitment_point = self.public_key(msg_info.per_commitment_point)?;

        let offered_htlcs = self.convert_htlcs(&msg_info.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&msg_info.received_htlcs)?;

        let (sig, htlc_sigs) = self.sign_remote_commitment_tx_phase2(
            &node_id, &channel_id, &remote_per_commitment_point, msg_info.n,
            msg_info.feerate_per_kw as u64,
            msg_info.to_local_value, msg_info.to_remote_value,
            offered_htlcs, received_htlcs
        )?;

        let htlc_bitcoin_sigs = htlc_sigs.iter()
            .map(|s| BitcoinSignature { data: s.clone() }).collect();
        let reply = CommitmentTxSignatureReply {
            signature: Some(BitcoinSignature { data: sig }),
            htlc_signatures: htlc_bitcoin_sigs,
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
