use std::convert::{TryFrom, TryInto};
use std::process;

use backtrace::Backtrace;
use bitcoin;
use bitcoin::consensus::{deserialize, encode};
use bitcoin::hashes::ripemd160::Hash as Ripemd160Hash;
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{OutPoint, Script, SigHashType};
use clap::{App, Arg};
use serde_json::json;
use tonic::{transport::Server, Request, Response, Status};

use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::ln::PaymentHash;
use lightning_signer::node::{self, ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::signer::multi_signer::{SpendType, SyncLogger};
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::{log_debug, log_error, log_info, log_internal, Map};
use remotesigner::signer_server::{Signer, SignerServer};
use remotesigner::*;

use crate::persist::persist_json::KVJsonPersister;
use crate::server::remotesigner::version_server::Version;

use super::remotesigner;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::signer::multi_signer::{channel_nonce_to_id, MultiSigner};
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::util::crypto_utils::signature_to_bitcoin_vec;
use lightning_signer::util::status;
use std::sync::Arc;

struct SignServer {
    pub logger: Arc<dyn SyncLogger>,
    pub signer: MultiSigner,
}

impl SignServer {
    pub(super) fn invalid_grpc_argument(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INVALID ARGUMENT: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::invalid_argument(s)
    }

    pub(super) fn internal_error(&self, msg: impl Into<String>) -> Status {
        let s = msg.into();
        log_error!(self, "INTERNAL ERROR: {}", &s);
        log_error!(self, "BACKTRACE:\n{:?}", Backtrace::new());
        Status::internal(s)
    }

    fn node_id(&self, arg: Option<NodeId>) -> Result<PublicKey, Status> {
        let der_vec = &arg
            .ok_or_else(|| self.invalid_grpc_argument("missing node ID"))?
            .data;
        let slice: &[u8] = der_vec.as_slice();
        if slice.len() != 33 {
            return Err(self.invalid_grpc_argument(format!("nodeid must be 33 bytes")));
        }
        PublicKey::from_slice(slice).map_err(|err| {
            self.invalid_grpc_argument(format!("could not deserialize nodeid: {}", err))
        })
    }

    fn public_key(&self, arg: Option<PubKey>) -> Result<PublicKey, Status> {
        let der_vec = &arg
            .ok_or_else(|| self.invalid_grpc_argument("missing pubkey"))?
            .data;
        let slice: &[u8] = der_vec.as_slice();
        if slice.len() != 33 {
            return Err(self.invalid_grpc_argument(format!("pubkey must be 33 bytes")));
        }
        PublicKey::from_slice(slice).map_err(|err| {
            self.invalid_grpc_argument(format!("could not deserialize pubkey: {}", err))
        })
    }

    fn secret_key(&self, arg: Option<Secret>) -> Result<SecretKey, Status> {
        return SecretKey::from_slice(
            arg.ok_or_else(|| self.invalid_grpc_argument("missing secret"))?
                .data
                .as_slice(),
        )
        .map_err(|err| {
            self.invalid_grpc_argument(format!("could not deserialize secret: {}", err))
        });
    }

    // Converts secp256k1::PublicKey into remotesigner::PubKey
    fn to_pubkey(&self, arg: PublicKey) -> PubKey {
        PubKey {
            data: arg.serialize().to_vec(),
        }
    }

    // NOTE - this "channel_id" does *not* correspond to the
    // channel_id defined in BOLT #2.
    fn channel_id(&self, channel_nonce: &Option<ChannelNonce>) -> Result<ChannelId, Status> {
        let nonce = channel_nonce
            .as_ref()
            .ok_or_else(|| self.invalid_grpc_argument("missing channel nonce"))?
            .data
            .clone();
        let res = channel_nonce_to_id(&nonce);
        Ok(res)
    }

    fn convert_htlcs(&self, msg_htlcs: &Vec<HtlcInfo>) -> Result<Vec<HTLCInfo2>, Status> {
        let mut htlcs = Vec::new();
        for h in msg_htlcs.iter() {
            let hash = h.payment_hash.as_slice().try_into().map_err(|err| {
                self.invalid_grpc_argument(format!("could not decode payment hash: {}", err))
            })?;
            htlcs.push(HTLCInfo2 {
                value_sat: h.value_sat,
                payment_hash: PaymentHash(hash),
                cltv_expiry: h.cltv_expiry,
            });
        }
        Ok(htlcs)
    }

    fn get_unilateral_close_key(
        &self,
        node_id: &PublicKey,
        closeinfo: Option<&UnilateralCloseInfo>,
    ) -> Result<Option<SecretKey>, Status> {
        match closeinfo {
            // Normal case, no unilateral_close_info present.
            None => Ok(None),
            // Handling a peer unilateral close from old channel.
            Some(ci) => {
                let old_chan_id = self.channel_id(&ci.channel_nonce)?;
                // Is there a commitment_point provided?
                let commitment_point = match &ci.commitment_point {
                    // No, option_static_remotekey in effect.
                    None => None,
                    // Yes, commitment_point provided.
                    Some(cpoint) => Some(self.public_key(Some(cpoint.clone()))?),
                };
                let key = self
                    .signer
                    .with_ready_channel(node_id, &old_chan_id, |chan| {
                        chan.get_unilateral_close_key(&commitment_point)
                    })?;
                Ok(Some(key))
            }
        }
    }
}

pub fn collect_output_witscripts(output_descs: &Vec<OutputDescriptor>) -> Vec<Vec<u8>> {
    output_descs
        .iter()
        .map(|odsc| odsc.witscript.clone())
        .collect()
}

#[tonic::async_trait]
impl Version for SignServer {
    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<VersionReply>, Status> {
        // TODO git commit
        Ok(Response::new(VersionReply {
            version_string: "0.1.0".to_string(),
            major: 0,
            minor: 1,
            patch: 0,
            prerelease: "pre".to_string(),
            build_metadata: "".to_string(),
        }))
    }
}

fn convert_commitment_type(proto_commitment_type: i32) -> node::CommitmentType {
    if proto_commitment_type == ready_channel_request::CommitmentType::Legacy as i32 {
        CommitmentType::Legacy
    } else if proto_commitment_type == ready_channel_request::CommitmentType::StaticRemotekey as i32
    {
        CommitmentType::StaticRemoteKey
    } else if proto_commitment_type == ready_channel_request::CommitmentType::Anchors as i32 {
        CommitmentType::Anchors
    } else {
        panic!("invalid commitment type")
    }
}

fn convert_node_config(proto_node_config: NodeConfig) -> node::NodeConfig {
    let proto_style = proto_node_config.key_derivation_style;
    let key_derivation_style = if proto_style == node_config::KeyDerivationStyle::Lnd as i32 {
        KeyDerivationStyle::Lnd
    } else if proto_style == node_config::KeyDerivationStyle::Native as i32 {
        KeyDerivationStyle::Native
    } else {
        panic!("invalid key derivation style")
    };
    node::NodeConfig {
        key_derivation_style,
    }
}

#[tonic::async_trait]
impl Signer for SignServer {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let req = request.into_inner();
        log_info!(self, "ENTER ping");
        log_debug!(self, "req={}", json!(&req));
        let reply = PingReply {
            // We must use .into_inner() as the fields of gRPC requests and responses are private
            message: format!("Hello {}!", req.message),
        };
        log_info!(self, "REPLY ping");
        log_debug!(self, "reply={}", json!(&reply));
        Ok(Response::new(reply))
    }

    async fn init(&self, request: Request<InitRequest>) -> Result<Response<InitReply>, Status> {
        let req = request.into_inner();
        log_info!(self, "ENTER init");
        // We don't want to log the secret, so comment this out by default
        //log_debug!(self, "req={}", json!(&req));
        let proto_node_config = req
            .node_config
            .ok_or_else(|| self.invalid_grpc_argument("missing node_config"))?;
        if proto_node_config.key_derivation_style != node_config::KeyDerivationStyle::Native as i32
            && proto_node_config.key_derivation_style != node_config::KeyDerivationStyle::Lnd as i32
        {
            return Err(self.invalid_grpc_argument("unknown node_config.key_derivation_style"));
        }
        let hsm_secret = req.hsm_secret.map(|o| o.data).unwrap_or_else(|| Vec::new());

        let hsm_secret = hsm_secret.as_slice();
        if hsm_secret.len() > 0 {
            if hsm_secret.len() < 16 {
                return Err(self.invalid_grpc_argument("hsm_secret must be at least 16 bytes"));
            }
            if hsm_secret.len() > 64 {
                return Err(
                    self.invalid_grpc_argument("hsm_secret must be no larger than 64 bytes")
                );
            }
        }
        let node_config = convert_node_config(proto_node_config);

        let node_id = if hsm_secret.len() == 0 {
            Ok(self.signer.new_node(node_config))
        } else {
            if req.coldstart {
                self.signer.new_node_from_seed(node_config, hsm_secret)
            } else {
                self.signer.warmstart_with_seed(node_config, hsm_secret)
            }
        }
        .map_err(|e| e)?
        .serialize()
        .to_vec();
        let reply = InitReply {
            node_id: Some(NodeId { data: node_id }),
        };
        log_info!(self, "REPLY init");
        log_debug!(self, "reply={}", json!(&reply));
        Ok(Response::new(reply))
    }

    async fn get_ext_pub_key(
        &self,
        request: Request<GetExtPubKeyRequest>,
    ) -> Result<Response<GetExtPubKeyReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        log_info!(self, "ENTER get_ext_pub_key({})", node_id);
        let node = self.signer.get_node(&node_id)?;
        let extpubkey = node.get_account_extended_pubkey();
        let reply = GetExtPubKeyReply {
            xpub: Some(ExtPubKey {
                encoded: format!("{}", extpubkey),
            }),
        };
        log_info!(self, "REPLY get_ext_pub_key({})", node_id);
        log_debug!(self, "reply={}", json!(&reply));
        Ok(Response::new(reply))
    }

    async fn new_channel(
        &self,
        request: Request<NewChannelRequest>,
    ) -> Result<Response<NewChannelReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        // If the nonce is specified, the channel ID is the sha256 of the nonce
        // If the nonce is not specified, the channel ID is the nonce, per Node::new_channel
        // TODO this is inconsistent
        let opt_channel_id = req
            .channel_nonce0
            .as_ref()
            .map(|n| channel_nonce_to_id(&n.data));
        let opt_channel_nonce0 = req.channel_nonce0.as_ref().map(|cn| cn.data.clone());
        log_info!(
            self,
            "ENTER new_channel({}/{:?}/{:?})",
            node_id,
            opt_channel_id,
            opt_channel_nonce0
        );

        let node = self.signer.get_node(&node_id)?;
        let (channel_id, stub) = node.new_channel(opt_channel_id, opt_channel_nonce0, &node)?;
        let stub = stub.ok_or_else(|| self.invalid_grpc_argument("channel already exists"))?;

        let reply = NewChannelReply {
            channel_nonce0: Some(ChannelNonce { data: stub.nonce }),
        };
        log_info!(self, "REPLY new_channel({}/{})", node_id, channel_id);
        log_debug!(self, "reply={}", json!(&reply));
        Ok(Response::new(reply))
    }

    async fn get_channel_basepoints(
        &self,
        request: Request<GetChannelBasepointsRequest>,
    ) -> Result<Response<GetChannelBasepointsReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER get_channel_basepoints({}/{})",
            node_id,
            channel_id
        );

        let bps = self
            .signer
            .with_channel_base(&node_id, &channel_id, |base| {
                Ok(base.get_channel_basepoints())
            })?;

        let basepoints = Basepoints {
            revocation: Some(self.to_pubkey(bps.revocation_basepoint)),
            payment: Some(self.to_pubkey(bps.payment_point)),
            htlc: Some(self.to_pubkey(bps.htlc_basepoint)),
            delayed_payment: Some(self.to_pubkey(bps.delayed_payment_basepoint)),
            funding_pubkey: Some(self.to_pubkey(bps.funding_pubkey)),
        };

        let reply = GetChannelBasepointsReply {
            basepoints: Some(basepoints),
        };
        log_info!(
            self,
            "REPLY get_channel_basepoints({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn ready_channel(
        &self,
        request: Request<ReadyChannelRequest>,
    ) -> Result<Response<ReadyChannelReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id0 = self.channel_id(&req.channel_nonce0)?;
        let opt_channel_id = req
            .option_channel_nonce
            .map_or(None, |nonce| Some(channel_nonce_to_id(&nonce.data)));
        log_info!(
            self,
            "ENTER ready_channel({}/{})->({}/{:?})",
            node_id,
            channel_id0,
            node_id,
            opt_channel_id
        );

        let req_outpoint = req
            .funding_outpoint
            .ok_or_else(|| self.invalid_grpc_argument("missing funding outpoint"))?;
        let txid = bitcoin::Txid::from_slice(&req_outpoint.txid).map_err(|err| {
            self.invalid_grpc_argument(format!("cannot decode funding outpoint txid: {}", err))
        })?;
        let funding_outpoint = OutPoint {
            txid,
            vout: req_outpoint.index,
        };

        let holder_shutdown_script = if req.holder_shutdown_script.is_empty() {
            None
        } else {
            Some(
                Script::deserialize(&req.holder_shutdown_script.as_slice()).map_err(|err| {
                    self.invalid_grpc_argument(format!(
                        "could not parse holder_shutdown_script: {}",
                        err
                    ))
                })?,
            )
        };

        let points = req
            .counterparty_basepoints
            .ok_or_else(|| self.invalid_grpc_argument("missing counterparty_basepoints"))?;
        let counterparty_points = ChannelPublicKeys {
            funding_pubkey: self.public_key(points.funding_pubkey)?,
            revocation_basepoint: self.public_key(points.revocation)?,
            payment_point: self.public_key(points.payment)?,
            delayed_payment_basepoint: self.public_key(points.delayed_payment)?,
            htlc_basepoint: self.public_key(points.htlc)?,
        };

        let counterparty_shutdown_script =
            Script::deserialize(&req.counterparty_shutdown_script.as_slice()).map_err(|err| {
                self.invalid_grpc_argument(format!(
                    "could not parse counterparty_shutdown_script: {}",
                    err
                ))
            })?;

        let setup = ChannelSetup {
            is_outbound: req.is_outbound,
            channel_value_sat: req.channel_value_sat,
            push_value_msat: req.push_value_msat,
            funding_outpoint,
            holder_to_self_delay: req.holder_to_self_delay as u16,
            counterparty_points,
            holder_shutdown_script,
            counterparty_to_self_delay: req.counterparty_to_self_delay as u16,
            counterparty_shutdown_script,
            commitment_type: convert_commitment_type(req.commitment_type),
        };
        let node = self.signer.get_node(&node_id)?;
        node.ready_channel(channel_id0, opt_channel_id, setup)?;
        let reply = ReadyChannelReply {};
        log_info!(
            self,
            "REPLY ready_channel({}/{})->({}/{:?})",
            node_id,
            channel_id0,
            node_id,
            opt_channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_mutual_close_tx(
        &self,
        request: Request<SignMutualCloseTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_mutual_close_tx({}/{})",
            node_id,
            channel_id
        );
        let reqtx = req
            .tx
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(self.invalid_grpc_argument("tx.input.len() != 1")); // NOT TESTED
        }
        if tx.output.len() == 0 {
            return Err(self.invalid_grpc_argument("tx.output.len() == 0")); // NOT TESTED
        }

        let funding_amount_sat = reqtx.input_descs[0].value_sat as u64;

        let sigvec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_mutual_close_tx(&tx, funding_amount_sat)?;

                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| self.internal_error("signing mutual close failed"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: sigvec.clone(),
            }),
        };
        log_info!(
            self,
            "REPLY sign_mutual_close_tx({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_mutual_close_tx_phase2(
        &self,
        request: Request<SignMutualCloseTxPhase2Request>,
    ) -> Result<Response<CloseTxSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_mutual_tx_phase2({}/{})",
            node_id,
            channel_id
        );

        let opt_counterparty_shutdown_script = if req.counterparty_shutdown_script.is_empty() {
            None
        } else {
            Some(
                Script::deserialize(&req.counterparty_shutdown_script.as_slice()).map_err(
                    |_| {
                        self.invalid_grpc_argument(
                            "could not deserialize counterparty_shutdown_script",
                        )
                    },
                )?,
            )
        };

        let sig_data = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_mutual_close_tx_phase2(
                    req.to_holder_value_sat,
                    req.to_counterparty_value_sat,
                    opt_counterparty_shutdown_script.clone(),
                )?;
                let mut bitcoin_sig = sig.serialize_der().to_vec();
                bitcoin_sig.push(SigHashType::All as u8);
                Ok(bitcoin_sig)
            })?;

        let reply = CloseTxSignatureReply {
            signature: Some(BitcoinSignature { data: sig_data }),
        };
        log_info!(
            self,
            "REPLY sign_mutual_close_tx_phase2({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn check_future_secret(
        &self,
        request: Request<CheckFutureSecretRequest>,
    ) -> Result<Response<CheckFutureSecretReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER check_future_secret({}/{})",
            node_id,
            channel_id
        );
        let commitment_number = req.n;
        let suggested = self.secret_key(req.suggested)?;

        let correct = self
            .signer
            .with_channel_base(&node_id, &channel_id, |base| {
                let secret = base.get_per_commitment_secret(commitment_number);
                Ok(suggested[..] == secret[..])
            })?;

        let reply = CheckFutureSecretReply { correct };
        log_info!(
            self,
            "REPLY check_future_secret({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn get_per_commitment_point(
        &self,
        request: Request<GetPerCommitmentPointRequest>,
    ) -> Result<Response<GetPerCommitmentPointReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER get_per_commitment_point({}/{})",
            node_id,
            channel_id
        );
        let commitment_number = req.n;

        // This API call can be made on a channel stub as well as a ready channel.
        let res: Result<(PublicKey, Option<SecretKey>), status::Status> = self
            .signer
            .with_channel_base(&node_id, &channel_id, |base| {
                let point = base.get_per_commitment_point(commitment_number);
                let secret = if commitment_number >= 2 {
                    Some(base.get_per_commitment_secret(commitment_number - 2))
                } else {
                    None
                };
                Ok((point, secret))
            });

        let (point, old_secret) = res?;

        let pointdata = point.serialize().to_vec();

        let old_secret_data: Option<Vec<u8>> = old_secret.map(|s| s[..].to_vec());

        let old_secret_reply = old_secret_data.clone().map(|s| Secret { data: s.clone() });

        let reply = GetPerCommitmentPointReply {
            per_commitment_point: Some(PubKey {
                data: pointdata.clone(),
            }),
            old_secret: old_secret_reply,
        };
        log_info!(
            self,
            "REPLY get_per_commitment_point({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_funding_tx(
        &self,
        request: Request<SignFundingTxRequest>,
    ) -> Result<Response<SignFundingTxReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(self, "ENTER sign_funding_tx({}/{})", node_id, channel_id);
        let reqtx = req
            .tx
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;
        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res
            .map_err(|e| self.invalid_grpc_argument(format!("could not deserialize tx - {}", e)))?;
        let mut paths: Vec<Vec<u32>> = Vec::new();
        let mut values_sat = Vec::new();
        let mut spendtypes: Vec<SpendType> = Vec::new();
        let mut uniclosekeys: Vec<Option<SecretKey>> = Vec::new();

        for idx in 0..tx.input.len() {
            // Use SpendType::Invalid to flag/designate inputs we are not
            // signing (PSBT case).
            let spendtype = SpendType::try_from(reqtx.input_descs[idx].spend_type)
                .map_err(|_| self.invalid_grpc_argument("bad spend_type"))?;
            if spendtype == SpendType::Invalid {
                paths.push(vec![]);
                values_sat.push(0);
                spendtypes.push(spendtype);
                uniclosekeys.push(None);
            } else {
                let child_path = &reqtx.input_descs[idx]
                    .key_loc
                    .as_ref()
                    .ok_or_else(|| self.invalid_grpc_argument("missing key_loc desc"))?
                    .key_path;
                paths.push(child_path.to_vec());
                let value_sat = reqtx.input_descs[idx].value_sat as u64;
                values_sat.push(value_sat);
                spendtypes.push(spendtype);
                let closeinfo = reqtx.input_descs[idx]
                    .key_loc
                    .as_ref()
                    .ok_or_else(|| self.invalid_grpc_argument("missing key_loc desc"))?
                    .close_info
                    .as_ref();
                let uck = self.get_unilateral_close_key(&node_id, closeinfo)?;
                uniclosekeys.push(uck);
            }
        }

        let witvec = self.signer.sign_funding_tx(
            &node_id,
            &channel_id,
            &tx,
            &paths,
            &values_sat,
            &spendtypes,
            &uniclosekeys,
        )?;

        let wits = witvec
            .into_iter()
            .map(|(sigdata, pubkeydata)| Witness {
                signature: Some(BitcoinSignature { data: sigdata }),
                pubkey: Some(PubKey { data: pubkeydata }),
            })
            .collect();

        let reply = SignFundingTxReply { witnesses: wits };
        log_info!(self, "REPLY sign_funding_tx({}/{})", node_id, channel_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_commitment_tx(
        &self,
        request: Request<SignCounterpartyCommitmentTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce.clone())?;
        log_info!(
            self,
            "ENTER sign_counterparty_commitment_tx({}/{})",
            node_id,
            channel_id
        );

        let reqtx = req
            .tx
            .clone()
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;
        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point.clone())?;
        let channel_value_sat = reqtx.input_descs[0].value_sat as u64;
        let witscripts = reqtx
            .output_descs
            .iter()
            .map(|odsc| odsc.witscript.clone())
            .collect();

        let mut payment_hashmap = Map::new();
        for hash in req.payment_hashes.iter() {
            let phash = hash.as_slice().try_into().map_err(|err| {
                self.invalid_grpc_argument(format!("could not decode payment hash: {}", err))
            })?;
            payment_hashmap.insert(Ripemd160Hash::hash(hash).into_inner(), PaymentHash(phash));
        }

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_counterparty_commitment_tx(
                    &tx,
                    &witscripts,
                    &remote_per_commitment_point,
                    channel_value_sat,
                    &payment_hashmap,
                    req.commit_num,
                )
            })?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: signature_to_bitcoin_vec(sig),
            }),
        };
        log_info!(
            self,
            "REPLY sign_counterparty_commitment_tx({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_holder_commitment_tx(
        &self,
        request: Request<SignHolderCommitmentTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_holder_commitment_tx({}/{})",
            node_id,
            channel_id
        );

        let reqtx = req
            .tx
            .clone()
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(self.invalid_grpc_argument("tx.input.len() != 1")); // NOT TESTED
        }
        if tx.output.len() == 0 {
            return Err(self.invalid_grpc_argument("tx.output.len() == 0")); // NOT TESTED
        }

        let funding_amount_sat = reqtx.input_descs[0].value_sat as u64;

        let witscripts = reqtx
            .output_descs
            .iter()
            .map(|odsc| odsc.witscript.clone())
            .collect();

        let mut payment_hashmap = Map::new();
        for hash in req.payment_hashes.iter() {
            let phash = hash.as_slice().try_into().map_err(|err| {
                self.invalid_grpc_argument(format!("could not decode payment hash: {}", err))
            })?;
            payment_hashmap.insert(Ripemd160Hash::hash(hash).into_inner(), PaymentHash(phash));
        }

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_holder_commitment_tx(
                    &tx,
                    &witscripts,
                    funding_amount_sat,
                    &payment_hashmap,
                    req.commit_num,
                )
            })?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: signature_to_bitcoin_vec(sig),
            }),
        };
        log_info!(
            self,
            "REPLY sign_holder_commitment_tx({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_holder_htlc_tx(
        &self,
        request: Request<SignHolderHtlcTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce.clone())?;
        log_info!(
            self,
            "ENTER sign_holder_htlc_tx({}/{})",
            node_id,
            channel_id
        );
        let reqtx = req
            .tx
            .clone()
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(self.invalid_grpc_argument("tx.input.len() != 1")); // NOT TESTED
        }
        if tx.output.len() == 0 {
            return Err(self.invalid_grpc_argument("tx.output.len() == 0")); // NOT TESTED
        }

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let opt_per_commitment_point = match req.per_commit_point.clone() {
            Some(p) => Some(self.public_key(Some(p))?),
            _ => None,
        };

        let output_witscript = Script::from(reqtx.output_descs[0].witscript.clone());

        let sigvec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_holder_htlc_tx(
                    &tx,
                    req.n,
                    opt_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: sigvec.clone(),
            }),
        };
        log_info!(
            self,
            "REPLY sign_holder_htlc_tx({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_delayed_sweep(
        &self,
        request: Request<SignDelayedSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(self, "ENTER sign_delayed_sweep({}/{})", node_id, channel_id);

        let reqtx = req
            .tx
            .clone()
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = input_desc.redeem_script;

        let input: usize = req
            .input
            .try_into()
            .map_err(|_| self.invalid_grpc_argument("bad input index"))?;

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("tx.output.len() != 1")); // NOT TESTED
        }

        let htlc_redeemscript = Script::from(redeemscript.clone());

        let sigvec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_delayed_sweep(
                    &tx,
                    input,
                    req.commitment_number,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                )?;
                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: sigvec.clone(),
            }),
        };
        log_info!(self, "REPLY sign_delayed_sweep({}/{})", node_id, channel_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_htlc_tx(
        &self,
        request: Request<SignCounterpartyHtlcTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_counterparty_htlc_tx({}/{})",
            node_id,
            channel_id
        );
        let reqtx = req
            .tx
            .clone()
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res
            .map_err(|e| self.invalid_grpc_argument(format!("deserialize tx fail: {}", e)))?;

        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point)?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("len(tx.output) != 1")); // NOT TESTED
        }

        let output_witscript = Script::from(reqtx.output_descs[0].witscript.clone());

        let sig_vec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_counterparty_htlc_tx(
                    &tx,
                    &remote_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )?;
                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature { data: sig_vec }),
        };
        log_info!(
            self,
            "REPLY sign_counterparty_htlc_tx({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_htlc_sweep(
        &self,
        request: Request<SignCounterpartyHtlcSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_counterparty_htlc_sweep({}/{})",
            node_id,
            channel_id
        );
        let reqtx = req
            .tx
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point)?;

        let input: usize = req
            .input
            .try_into()
            .map_err(|_| self.invalid_grpc_argument("bad input index"))?;

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("tx.output.len() != 1")); // NOT TESTED
        }

        let sigvec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_counterparty_htlc_sweep(
                    &tx,
                    input,
                    &remote_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                )?;
                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: sigvec.clone(),
            }),
        };
        log_info!(
            self,
            "REPLY sign_counterparty_htlc_sweep({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_justice_sweep(
        &self,
        request: Request<SignJusticeSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(self, "ENTER sign_justice_sweep({}/{})", node_id, channel_id);
        let reqtx = req
            .tx
            .ok_or_else(|| self.invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| self.invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let revocation_secret = self.secret_key(req.revocation_secret)?;

        let input: usize = req
            .input
            .try_into()
            .map_err(|_| self.invalid_grpc_argument("bad input index"))?;

        let sigvec = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let sig = chan.sign_justice_sweep(
                    &tx,
                    input,
                    &revocation_secret,
                    &redeemscript,
                    htlc_amount_sat,
                )?;
                Ok(signature_to_bitcoin_vec(sig))
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply {
            signature: Some(BitcoinSignature {
                data: sigvec.clone(),
            }),
        };
        log_info!(self, "REPLY sign_justice_sweep({}/{})", node_id, channel_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_channel_announcement(
        &self,
        request: Request<SignChannelAnnouncementRequest>,
    ) -> Result<Response<SignChannelAnnouncementReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_channel_announcement({}/{})",
            node_id,
            channel_id
        );

        let ca = req.channel_announcement;
        let (nsig, bsig) = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(chan.sign_channel_announcement(&ca))
            })
            .map_err(|e| Status::internal(e.to_string()))?;
        let reply = SignChannelAnnouncementReply {
            node_signature: Some(EcdsaSignature {
                data: nsig.serialize_der().to_vec(),
            }),
            bitcoin_signature: Some(EcdsaSignature {
                data: bsig.serialize_der().to_vec(),
            }),
        };
        log_info!(
            self,
            "REPLY sign_channel_announcement({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_node_announcement(
        &self,
        request: Request<SignNodeAnnouncementRequest>,
    ) -> Result<Response<NodeSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let na = req.node_announcement;
        log_info!(self, "ENTER sign_node_announcement({})", node_id);

        let node = self.signer.get_node(&node_id)?;
        let sig_data = node.sign_node_announcement(&na)?;
        let reply = NodeSignatureReply {
            signature: Some(EcdsaSignature { data: sig_data }),
        };
        log_info!(self, "REPLY sign_node_announcement({})", node_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_channel_update(
        &self,
        request: Request<SignChannelUpdateRequest>,
    ) -> Result<Response<NodeSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let cu = req.channel_update;
        log_info!(self, "ENTER sign_channel_update({})", node_id);
        let node = self.signer.get_node(&node_id)?;
        let sig_data = node.sign_channel_update(&cu)?;
        let reply = NodeSignatureReply {
            signature: Some(EcdsaSignature { data: sig_data }),
        };
        log_info!(self, "REPLY sign_channel_update({})", node_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn ecdh(&self, request: Request<EcdhRequest>) -> Result<Response<EcdhReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let other_key = self.public_key(req.point.clone())?;
        log_info!(self, "ENTER ecdh({} + {})", node_id, other_key);

        let node = self.signer.get_node(&node_id)?;
        let data = node.ecdh(&other_key);
        let reply = EcdhReply {
            shared_secret: Some(Secret { data }),
        };
        log_info!(self, "REPLY ecdh({} + {})", node_id, other_key);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_invoice(
        &self,
        request: Request<SignInvoiceRequest>,
    ) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let data_part = req.data_part;
        let human_readable_part = req.human_readable_part;
        log_info!(self, "ENTER sign_invoice({})", node_id);

        let node = self.signer.get_node(&node_id)?;
        let sig_data = node.sign_invoice_in_parts(&data_part, &human_readable_part)?;
        let reply = RecoverableNodeSignatureReply {
            signature: Some(EcdsaRecoverableSignature {
                data: sig_data.clone(),
            }),
        };
        log_info!(self, "REPLY sign_invoice({})", node_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let message = req.message;
        log_info!(self, "ENTER sign_message({})", node_id);

        let node = self.signer.get_node(&node_id)?;
        let rsigvec = node.sign_message(&message)?;
        let reply = RecoverableNodeSignatureReply {
            signature: Some(EcdsaRecoverableSignature {
                data: rsigvec.clone(),
            }),
        };
        log_info!(self, "REPLY sign_message({})", node_id);
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_commitment_tx_phase2(
        &self,
        request: Request<SignCounterpartyCommitmentTxPhase2Request>,
    ) -> Result<Response<CommitmentTxSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_counterparty_commitment_tx_phase2({}/{})",
            node_id,
            channel_id
        );

        let req_info = req
            .commitment_info
            .ok_or_else(|| self.invalid_grpc_argument("missing commitment info"))?;
        let remote_per_commitment_point = self.public_key(req_info.per_commitment_point.clone())?;

        let offered_htlcs = self.convert_htlcs(&req_info.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&req_info.received_htlcs)?;

        let (sig, htlc_sigs) = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_counterparty_commitment_tx_phase2(
                    &remote_per_commitment_point,
                    req_info.n,
                    req_info.feerate_sat_per_kw,
                    req_info.to_holder_value_sat,
                    req_info.to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )
            })?;

        let htlc_bitcoin_sigs = htlc_sigs
            .iter()
            .map(|s| BitcoinSignature { data: s.clone() })
            .collect();
        let reply = CommitmentTxSignatureReply {
            signature: Some(BitcoinSignature { data: sig }),
            htlc_signatures: htlc_bitcoin_sigs,
        };
        log_info!(
            self,
            "REPLY sign_counterparty_commitment_tx_phase2({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn sign_holder_commitment_tx_phase2(
        &self,
        request: Request<SignHolderCommitmentTxPhase2Request>,
    ) -> Result<Response<CommitmentTxSignatureReply>, Status> {
        let req = request.into_inner();
        log_debug!(self, "req={}", json!(&req));
        let node_id = self.node_id(req.node_id)?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_info!(
            self,
            "ENTER sign_holder_commitment_tx_phase2({}/{})",
            node_id,
            channel_id
        );

        let req_info = req
            .commitment_info
            .ok_or_else(|| self.invalid_grpc_argument("missing commitment info"))?;
        if req_info.per_commitment_point.is_some() {
            return Err(self.invalid_grpc_argument(
                "per-commitment point must not be provided for holder txs",
            ));
        }

        let offered_htlcs = self.convert_htlcs(&req_info.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&req_info.received_htlcs)?;

        let (sig, htlc_sigs) = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                let result = chan.sign_holder_commitment_tx_phase2(
                    req_info.n,
                    req_info.feerate_sat_per_kw,
                    req_info.to_holder_value_sat,
                    req_info.to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?;
                Ok(result)
            })?;

        let htlc_bitcoin_sigs = htlc_sigs
            .iter()
            .map(|s| BitcoinSignature { data: s.clone() })
            .collect();
        let reply = CommitmentTxSignatureReply {
            signature: Some(BitcoinSignature { data: sig }),
            htlc_signatures: htlc_bitcoin_sigs,
        };
        log_info!(
            self,
            "REPLY sign_holder_commitment_tx_phase2({}/{})",
            node_id,
            channel_id
        );
        log_debug!(self, "reply={}", json!(reply));
        Ok(Response::new(reply))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesReply>, Status> {
        let node_ids = self
            .signer
            .get_node_ids()
            .iter()
            .map(|k| k.serialize().to_vec())
            .map(|id| NodeId { data: id })
            .collect();
        let reply = ListNodesReply { node_ids };
        Ok(Response::new(reply))
    }

    async fn list_channels(
        &self,
        request: Request<ListChannelsRequest>,
    ) -> Result<Response<ListChannelsReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id)?;

        let node = self.signer.get_node(&node_id)?;
        let channel_nonces = node
            .channels()
            .iter()
            .map(|(id, chan_mutex)| {
                let chan = chan_mutex.lock().unwrap();
                log_info!(
                    self,
                    "chan id={} nonce={} id_in_obj={}",
                    id,
                    hex::encode(chan.nonce()),
                    chan.id()
                );
                chan.nonce()
            })
            .map(|nonce| ChannelNonce { data: nonce })
            .collect();
        Ok(Response::new(ListChannelsReply { channel_nonces }))
    }
}

const DEFAULT_DIR: &str = ".lightning-signer";

#[tokio::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("rsignerd {} starting", process::id());
    let app = App::new("server")
        .about("Lightning Signer with a gRPC interface.  Persists to .lightning-signer .")
        .arg(
            Arg::new("test-mode")
                .about("allow nodes to be recreated, deleting all channels")
                .short('t')
                .long("test-mode")
                .takes_value(false),
        )
        .arg(
            Arg::new("no-persist")
                .about("disable all persistence")
                .long("no-persist")
                .takes_value(false),
        )
        .arg(
            Arg::new("interface")
                .about("the interface to listen on (ip v4 or v6)")
                .short('i')
                .long("interface")
                .takes_value(true)
                .value_name("0.0.0.0")
                .default_value("[::1]"),
        )
        .arg(
            Arg::new("datadir")
                .short('d')
                .long("datadir")
                .default_value(DEFAULT_DIR)
                .about("data directory")
                .takes_value(true),
        )
        .arg(
            Arg::new("port")
                .about("the port to listen")
                .short('p')
                .long("port")
                .takes_value(true)
                .default_value("50051"),
        );
    let matches = app.get_matches();
    let addr = format!(
        "{}:{}",
        matches.value_of("interface").unwrap(),
        matches.value_of("port").unwrap()
    )
    .parse()?;

    let path = format!("{}/{}", matches.value_of("datadir").unwrap(), "data");
    let test_mode = matches.is_present("test-mode");
    let persister: Arc<dyn Persist> = if matches.is_present("no-persist") {
        Arc::new(DummyPersister)
    } else {
        Arc::new(KVJsonPersister::new(path.as_str()))
    };
    let signer = MultiSigner::new_with_persister(persister, test_mode);
    let server = SignServer {
        logger: Arc::clone(&signer.logger),
        signer,
    };

    let (shutdown_trigger, shutdown_signal) = triggered::trigger();
    ctrlc::set_handler(move || {
        shutdown_trigger.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let service = Server::builder()
        .add_service(SignerServer::new(server))
        .serve_with_shutdown(addr, shutdown_signal);

    println!("rsignerd {} ready on {}", process::id(), addr);
    service.await?;
    println!("rsignerd {} finished", process::id());

    Ok(())
}
