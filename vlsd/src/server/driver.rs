use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;
use std::{cmp, process};

use anyhow::{anyhow, bail};
use backtrace::Backtrace;
use bitcoin::consensus::{deserialize, encode};
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::secp256k1::{ecdsa::Signature, PublicKey, SecretKey};
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{EcdsaSighashType, Network, OutPoint, Script};
use clap::{App, Arg, ArgMatches};
use lightning::ln::chan_utils::ChannelPublicKeys;
use lightning::ln::PaymentHash;
use log::{debug, error, info};
use serde_json::json;
use tonic::{transport::Server, Request, Response, Status};
use url::Url;

use lightning_signer::bitcoin;
use lightning_signer::channel::{ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::lightning;
use lightning_signer::lightning_invoice::SignedRawInvoice;
use lightning_signer::node::{self};
use lightning_signer::node::{NodeServices, SpendType};
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{
    make_simple_policy, SimplePolicy, SimpleValidatorFactory,
};

use vls_protocol_signer::approver::{Approver, PositiveApprover};

use lightning_signer::signer::{
    derive::KeyDerivationStyle, multi_signer::MultiSigner, ClockStartingTimeFactory,
};
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::bitcoin_vec_to_signature;
use lightning_signer::util::log_utils::{parse_log_level_filter, LOG_LEVEL_FILTER_NAMES};
use lightning_signer::util::status;
use lightning_signer::util::status::invalid_argument;
use lightning_signer::{channel, containing_function, debug_vals, short_function, vals_str};
use lightning_signer_server::fslogger::FilesystemLogger;
use lightning_signer_server::grpc::remotesigner;
use lightning_signer_server::nodefront::SignerFront;
use lightning_signer_server::persist::kv_json::KVJsonPersister;
use lightning_signer_server::NETWORK_NAMES;
use lightning_signer_server::SERVER_APP_NAME;
use remotesigner::signer_server::{Signer, SignerServer};
use remotesigner::version_server::Version;
use remotesigner::*;
use vls_frontend::Frontend;

macro_rules! log_req_enter_with_id {
    ($id: expr, $req: expr) => {
        info!("ENTER {}({})", containing_function!(), $id);
        if log::log_enabled!(log::Level::Debug) {
            #[cfg(not(feature = "log_pretty_print"))]
            let reqstr = json!($req);
            #[cfg(feature = "log_pretty_print")]
            let reqstr = serde_json::to_string_pretty(&json!($req)).unwrap();
            debug!("ENTER {}({}): {}", containing_function!(), $id, &reqstr);
        }
    };
}

macro_rules! log_req_enter {
    () => {
        log_req_enter_with_id!("", ());
    };
    ($req: expr) => {
        log_req_enter_with_id!("", $req);
    };
    ($node_id: expr, $req: expr) => {
        log_req_enter_with_id!(format!("{}", $node_id), $req);
    };
    ($node_id: expr, $chan_id: expr, $req: expr) => {
        log_req_enter_with_id!(format!("{}/{}", $node_id, $chan_id), $req);
    };
    ($node_id: expr, $chan_id: expr, $nonce: expr, $req: expr) => {
        log_req_enter_with_id!(format!("{}/{:?}/{:?}", $node_id, $chan_id, $nonce), $req);
    };
}

macro_rules! log_req_reply_with_id {
    ($id: expr, $reply: expr) => {
        if log::log_enabled!(log::Level::Debug) {
            #[cfg(not(feature = "log_pretty_print"))]
            let replystr = json!($reply);
            #[cfg(feature = "log_pretty_print")]
            let replystr = serde_json::to_string_pretty(&json!($reply)).unwrap();
            debug!("REPLY {}({}): {}", containing_function!(), $id, &replystr);
        }
        info!("REPLY {}({})", containing_function!(), $id);
    };
}

macro_rules! log_req_reply {
    () => {
        log_req_reply_with_id!("", ());
    };
    ($reply: expr) => {
        log_req_reply_with_id!("", $reply);
    };
    ($node_id: expr, $reply: expr) => {
        log_req_reply_with_id!(format!("{}", $node_id), $reply);
    };
    ($node_id: expr, $chan_id: expr, $reply: expr) => {
        log_req_reply_with_id!(format!("{}/{}", $node_id, $chan_id), $reply);
    };
    ($node_id: expr, $chan_id: expr, $nonce: expr, $reply: expr) => {
        log_req_reply_with_id!(format!("{}/{:?}/{:?}", $node_id, $chan_id, $nonce), $reply);
    };
}

struct SignServer {
    pub signer: Arc<MultiSigner>,
    pub network: Network,
    pub frontend: Frontend,
    approver: Arc<dyn Approver>,
}

pub(super) fn invalid_grpc_argument(msg: impl Into<String>) -> Status {
    let s = msg.into();
    error!("INVALID ARGUMENT: {}", &s);
    error!("BACKTRACE:\n{:?}", Backtrace::new());
    Status::invalid_argument(s)
}

#[allow(unused)]
pub(super) fn internal_error(msg: impl Into<String>) -> Status {
    let s = msg.into();
    error!("INTERNAL ERROR: {}", &s);
    #[cfg(feature = "backtrace")]
    error!("BACKTRACE:\n{:?}", Backtrace::new());
    Status::internal(s)
}

impl SignServer {
    fn node_id(&self, arg: Option<NodeId>) -> Result<PublicKey, Status> {
        let der_vec = &arg.ok_or_else(|| invalid_grpc_argument("missing node ID"))?.data;
        let slice: &[u8] = der_vec.as_slice();
        if slice.len() != 33 {
            return Err(invalid_grpc_argument(format!("nodeid must be 33 bytes")));
        }
        PublicKey::from_slice(slice)
            .map_err(|err| invalid_grpc_argument(format!("could not deserialize nodeid: {}", err)))
    }

    fn public_key(&self, arg: Option<PubKey>) -> Result<PublicKey, Status> {
        let der_vec = &arg.ok_or_else(|| invalid_grpc_argument("missing pubkey"))?.data;
        let slice: &[u8] = der_vec.as_slice();
        if slice.len() != 33 {
            return Err(invalid_grpc_argument(format!("pubkey must be 33 bytes")));
        }
        PublicKey::from_slice(slice)
            .map_err(|err| invalid_grpc_argument(format!("could not deserialize pubkey: {}", err)))
    }

    fn secret_key(&self, arg: Option<Secret>) -> Result<SecretKey, Status> {
        return SecretKey::from_slice(
            arg.ok_or_else(|| invalid_grpc_argument("missing secret"))?.data.as_slice(),
        )
        .map_err(|err| invalid_grpc_argument(format!("could not deserialize secret: {}", err)));
    }

    // NOTE - this "channel_id" does *not* correspond to the
    // channel_id defined in BOLT #2.
    fn channel_id(&self, channel_nonce: &Option<ChannelNonce>) -> Result<ChannelId, Status> {
        if let Some(nonce) = channel_nonce {
            Ok(ChannelId::new(&nonce.data))
        } else {
            return Err(invalid_grpc_argument("missing channel nonce"));
        }
    }

    fn convert_htlcs(&self, msg_htlcs: &Vec<HtlcInfo>) -> Result<Vec<HTLCInfo2>, Status> {
        let mut htlcs = Vec::new();
        for h in msg_htlcs.iter() {
            let hash = h.payment_hash.as_slice().try_into().map_err(|err| {
                invalid_grpc_argument(format!("could not decode payment hash: {}", err))
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
        spendtype: SpendType,
    ) -> Result<Option<(SecretKey, Vec<Vec<u8>>)>, Status> {
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
                let (key, redeemscript) =
                    self.signer.with_ready_channel(node_id, &old_chan_id, |chan| {
                        let pubkey_opt = match ci.revocation_pubkey.as_ref() {
                            None => None,
                            Some(p) => Some(p.clone().try_into().map_err(|_| {
                                invalid_argument("could not parse revocation_pubkey")
                            })?),
                        };
                        if pubkey_opt.is_some() && spendtype != SpendType::P2wsh {
                            return Err(invalid_argument("revocation spend must be p2wsh"));
                        }
                        if pubkey_opt.is_none() && spendtype == SpendType::P2wsh {
                            return Err(invalid_argument(
                                "can only handle p2wsh for revocation spend",
                            ));
                        }
                        chan.get_unilateral_close_key(&commitment_point, &pubkey_opt)
                    })?;
                Ok(Some((key, redeemscript)))
            }
        }
    }

    fn htlc_sighash_type(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> Result<EcdsaSighashType, Status> {
        self.signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(if chan.setup.option_anchors() {
                    EcdsaSighashType::SinglePlusAnyoneCanPay
                } else {
                    EcdsaSighashType::All
                })
            })
            .map_err(|e| e.into())
    }
}

fn signature_from_proto(
    proto_sig: &BitcoinSignature,
    sighash_type: EcdsaSighashType,
) -> Result<Signature, Status> {
    bitcoin_vec_to_signature(&proto_sig.data, sighash_type).map_err(|err| {
        invalid_grpc_argument(format!("trouble in bitcoin_vec_to_signature: {}", err))
    })
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

fn convert_commitment_type(proto_commitment_type: i32) -> channel::CommitmentType {
    if proto_commitment_type == ready_channel_request::CommitmentType::Legacy as i32 {
        CommitmentType::Legacy
    } else if proto_commitment_type == ready_channel_request::CommitmentType::StaticRemotekey as i32
    {
        CommitmentType::StaticRemoteKey
    } else if proto_commitment_type == ready_channel_request::CommitmentType::Anchors as i32 {
        CommitmentType::Anchors
    } else if proto_commitment_type
        == ready_channel_request::CommitmentType::AnchorsZeroFeeHtlc as i32
    {
        CommitmentType::AnchorsZeroFeeHtlc
    } else {
        panic!("invalid commitment type")
    }
}

fn convert_node_config(
    network: Network,
    chainparams: ChainParams,
    proto_node_config: NodeConfig,
) -> anyhow::Result<node::NodeConfig> {
    let proto_style = proto_node_config.key_derivation_style;
    use node_config::KeyDerivationStyle::{Ldk, Lnd, Native};
    let key_derivation_style = match proto_style {
        x if x == Native as i32 => Ok(KeyDerivationStyle::Native),
        x if x == Ldk as i32 => Ok(KeyDerivationStyle::Ldk),
        x if x == Lnd as i32 => Ok(KeyDerivationStyle::Lnd),
        _ => Err(anyhow!("invalid key derivation style")),
    }?;
    let supplied_network = Network::from_str(&chainparams.network_name).expect("bad network");
    if supplied_network != network {
        bail!("network mismatch {} vs configured {}", supplied_network, network);
    }
    Ok(node::NodeConfig { network, key_derivation_style })
}

#[tonic::async_trait]
impl Signer for SignServer {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let req = request.into_inner();
        log_req_enter!(&req);
        let reply = PingReply {
            // We must use .into_inner() as the fields of gRPC requests and responses are private
            message: format!("Hello {}!", req.message),
        };
        log_req_reply!(&reply);
        Ok(Response::new(reply))
    }

    async fn init(&self, request: Request<InitRequest>) -> Result<Response<InitReply>, Status> {
        let req = request.into_inner();
        info!("ENTER init");
        // We don't want to log the secret, so comment this out by default
        //debug!("req={}", json!(&req));

        let proto_node_config =
            req.node_config.ok_or_else(|| invalid_grpc_argument("missing node_config"))?;

        let proto_chainparams =
            req.chainparams.ok_or_else(|| invalid_grpc_argument("missing chainparams"))?;

        let hsm_secret = req.hsm_secret.map(|o| o.data).unwrap_or_else(|| Vec::new());

        let hsm_secret = hsm_secret.as_slice();
        if hsm_secret.len() > 0 {
            if hsm_secret.len() < 16 {
                return Err(invalid_grpc_argument("hsm_secret must be at least 16 bytes"));
            }
            if hsm_secret.len() > 64 {
                return Err(invalid_grpc_argument("hsm_secret must be no larger than 64 bytes"));
            }
        }
        let node_config = convert_node_config(self.network, proto_chainparams, proto_node_config)
            .map_err(|e| invalid_grpc_argument(e.to_string()))?;

        let node_id = if hsm_secret.len() == 0 {
            self.signer.new_node(node_config)?
        } else {
            if req.coldstart {
                self.signer.new_node_with_seed(node_config, hsm_secret)?
            } else {
                self.signer.warmstart_with_seed(node_config, hsm_secret)?
            }
        };

        self.frontend.start_follower(self.frontend.signer.tracker(&node_id)).await;

        let reply = InitReply { node_id: Some(NodeId { data: node_id.serialize().to_vec() }) };

        // We don't want to log the secret, so comment this out by default
        // log_req_reply!(&reply);
        Ok(Response::new(reply))
    }

    async fn get_node_param(
        &self,
        request: Request<GetNodeParamRequest>,
    ) -> Result<Response<GetNodeParamReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        let extpubkey = node.get_account_extended_pubkey();
        let bolt12_pubkey = node.get_bolt12_pubkey();
        let onion_reply_secret = node.get_onion_reply_secret();
        let node_secret = node.get_node_secret();
        let reply = GetNodeParamReply {
            xpub: Some(ExtPubKey { encoded: format!("{}", extpubkey) }),
            bolt12_pubkey: Some(XOnlyPubKey { data: bolt12_pubkey.serialize().to_vec() }),
            onion_reply_secret: Some(SecKey { data: onion_reply_secret[..].to_vec() }),
            node_secret: Some(SecKey { data: node_secret[..].to_vec() }),
        };

        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn new_channel(
        &self,
        request: Request<NewChannelRequest>,
    ) -> Result<Response<NewChannelReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce0)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let node = self.signer.get_node(&node_id)?;
        let (channel_id, stub) = node.new_channel(Some(channel_id), &node)?;
        stub.ok_or_else(|| invalid_grpc_argument("channel already exists"))?;

        let reply = NewChannelReply { channel_nonce0: req.channel_nonce0 };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn get_channel_basepoints(
        &self,
        request: Request<GetChannelBasepointsRequest>,
    ) -> Result<Response<GetChannelBasepointsReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let bps = self
            .signer
            .with_channel_base(&node_id, &channel_id, |base| Ok(base.get_channel_basepoints()))?;

        let basepoints = Basepoints {
            revocation: Some(bps.revocation_basepoint.into()),
            payment: Some(bps.payment_point.into()),
            htlc: Some(bps.htlc_basepoint.into()),
            delayed_payment: Some(bps.delayed_payment_basepoint.into()),
            funding_pubkey: Some(bps.funding_pubkey.into()),
        };

        let reply = GetChannelBasepointsReply { basepoints: Some(basepoints) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn ready_channel(
        &self,
        request: Request<ReadyChannelRequest>,
    ) -> Result<Response<ReadyChannelReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id0 = self.channel_id(&req.channel_nonce0)?;
        let new_channel_id = if let Some(ref new_nonce) = req.option_channel_nonce {
            Some(self.channel_id(&Some(new_nonce.clone()))?)
        } else {
            None
        };
        log_req_enter!(&node_id, &channel_id0, new_channel_id, &req);

        let req_outpoint = req
            .funding_outpoint
            .ok_or_else(|| invalid_grpc_argument("missing funding outpoint"))?;
        let txid = bitcoin::Txid::from_slice(&req_outpoint.txid).map_err(|err| {
            invalid_grpc_argument(format!("cannot decode funding outpoint txid: {}", err))
        })?;
        let funding_outpoint = OutPoint { txid, vout: req_outpoint.index };
        debug_vals!(&funding_outpoint); // because req_outpoint.txid is reversed

        let holder_shutdown_script = if req.holder_shutdown_script.is_empty() {
            None
        } else {
            Some(Script::deserialize(&req.holder_shutdown_script.as_slice()).map_err(|err| {
                invalid_grpc_argument(format!("could not parse holder_shutdown_script: {}", err))
            })?)
        };

        let points = req
            .counterparty_basepoints
            .ok_or_else(|| invalid_grpc_argument("missing counterparty_basepoints"))?;
        let counterparty_points = ChannelPublicKeys {
            funding_pubkey: self.public_key(points.funding_pubkey)?,
            revocation_basepoint: self.public_key(points.revocation)?,
            payment_point: self.public_key(points.payment)?,
            delayed_payment_basepoint: self.public_key(points.delayed_payment)?,
            htlc_basepoint: self.public_key(points.htlc)?,
        };

        let counterparty_shutdown_script = if req.counterparty_shutdown_script.is_empty() {
            None
        } else {
            Some(Script::deserialize(&req.counterparty_shutdown_script.as_slice()).map_err(
                |err| {
                    invalid_grpc_argument(format!(
                        "could not parse counterparty_shutdown_script: {}",
                        err
                    ))
                },
            )?)
        };

        let holder_shutdown_key_path = req.holder_shutdown_key_path.to_vec();
        let setup = ChannelSetup {
            is_outbound: req.is_outbound,
            channel_value_sat: req.channel_value_sat,
            push_value_msat: req.push_value_msat,
            funding_outpoint,
            holder_selected_contest_delay: req.holder_selected_contest_delay as u16,
            counterparty_points,
            holder_shutdown_script,
            counterparty_selected_contest_delay: req.counterparty_selected_contest_delay as u16,
            counterparty_shutdown_script,
            commitment_type: convert_commitment_type(req.commitment_type),
        };
        let node = self.signer.get_node(&node_id)?;
        node.ready_channel(
            channel_id0.clone(),
            new_channel_id.clone(),
            setup,
            &holder_shutdown_key_path,
        )?;
        let reply = ReadyChannelReply {};
        log_req_reply!(&node_id, &channel_id0, new_channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_mutual_close_tx(
        &self,
        request: Request<SignMutualCloseTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(node_id, channel_id, &req);

        let reqtx = req.tx.ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(invalid_grpc_argument("tx.input.len() != 1"));
        }
        if tx.output.len() == 0 {
            return Err(invalid_grpc_argument("tx.output.len() == 0"));
        }

        let opaths = reqtx
            .output_descs
            .into_iter()
            .map(|od| od.key_loc.unwrap_or_default().key_path.to_vec())
            .collect();

        let sig = self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_mutual_close_tx(&tx, &opaths)
        })?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_mutual_close_tx_phase2(
        &self,
        request: Request<SignMutualCloseTxPhase2Request>,
    ) -> Result<Response<CloseTxSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let holder_shutdown_script = if req.holder_shutdown_script.is_empty() {
            None
        } else {
            Some(Script::deserialize(&req.holder_shutdown_script.as_slice()).map_err(|_| {
                invalid_grpc_argument("could not deserialize holder_shutdown_script")
            })?)
        };

        let counterparty_shutdown_script = if req.counterparty_shutdown_script.is_empty() {
            None
        } else {
            Some(Script::deserialize(&req.counterparty_shutdown_script.as_slice()).map_err(
                |_| invalid_grpc_argument("could not deserialize counterparty_shutdown_script"),
            )?)
        };

        let sig = self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_mutual_close_tx_phase2(
                req.to_holder_value_sat,
                req.to_counterparty_value_sat,
                &holder_shutdown_script,
                &counterparty_shutdown_script,
                &req.holder_wallet_path_hint,
            )
        })?;

        let reply = CloseTxSignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn check_future_secret(
        &self,
        request: Request<CheckFutureSecretRequest>,
    ) -> Result<Response<CheckFutureSecretReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let commitment_number = req.n;
        let suggested = self.secret_key(req.suggested)?;

        let correct = self.signer.with_channel_base(&node_id, &channel_id, |base| {
            Ok(base.check_future_secret(commitment_number, &suggested)?)
        })?;

        let reply = CheckFutureSecretReply { correct };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn get_per_commitment_point(
        &self,
        request: Request<GetPerCommitmentPointRequest>,
    ) -> Result<Response<GetPerCommitmentPointReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let commitment_number = req.n;

        // This API call can be made on a channel stub as well as a ready channel.
        let res: Result<(PublicKey, Option<SecretKey>), status::Status> =
            self.signer.with_channel_base(&node_id, &channel_id, |base| {
                let point = base.get_per_commitment_point(commitment_number)?;
                let secret = if commitment_number >= 2 && !req.point_only {
                    Some(base.get_per_commitment_secret(commitment_number - 2)?)
                } else {
                    None
                };
                Ok((point, secret))
            });

        let (point, old_secret) = res?;

        let reply = GetPerCommitmentPointReply {
            per_commitment_point: Some(point.into()),
            old_secret: old_secret.map(|s| s.into()),
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_onchain_tx(
        &self,
        request: Request<SignOnchainTxRequest>,
    ) -> Result<Response<SignOnchainTxReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let reqtx = req.tx.ok_or_else(|| invalid_grpc_argument("missing tx"))?;
        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx = tx_res
            .map_err(|e| invalid_grpc_argument(format!("could not deserialize tx - {}", e)))?;
        let mut ipaths: Vec<Vec<u32>> = Vec::new();
        let mut values_sat = Vec::new();
        let mut spendtypes: Vec<SpendType> = Vec::new();
        // Key and redeemscript
        let mut uniclosekeys = Vec::new();

        for idx in 0..tx.input.len() {
            // Use SpendType::Invalid to flag/designate inputs we are not
            // signing (PSBT case).
            let spendtype = SpendType::try_from(reqtx.input_descs[idx].spend_type)
                .map_err(|_| invalid_grpc_argument("bad spend_type"))?;
            if spendtype == SpendType::Invalid {
                ipaths.push(vec![]);
                values_sat.push(0);
                spendtypes.push(spendtype);
                uniclosekeys.push(None);
            } else {
                let child_path = &reqtx.input_descs[idx]
                    .key_loc
                    .as_ref()
                    .ok_or_else(|| invalid_grpc_argument("missing input key_loc desc"))?
                    .key_path;
                ipaths.push(child_path.to_vec());
                let value_sat = reqtx.input_descs[idx].value_sat as u64;
                values_sat.push(value_sat);
                spendtypes.push(spendtype);
                let closeinfo = reqtx.input_descs[idx]
                    .key_loc
                    .as_ref()
                    .ok_or_else(|| invalid_grpc_argument("missing input closeinfo key_loc desc"))?
                    .close_info
                    .as_ref();
                let uck = self.get_unilateral_close_key(&node_id, closeinfo, spendtype)?;
                uniclosekeys.push(uck);
            }
        }

        let opaths = reqtx
            .output_descs
            .into_iter()
            .map(|od| od.key_loc.unwrap_or_default().key_path.to_vec())
            .collect();

        let node = self.signer.get_node(&node_id)?;

        let witvec =
            node.sign_onchain_tx(&tx, &ipaths, &values_sat, &spendtypes, uniclosekeys, &opaths)?;

        let wits = witvec.into_iter().map(|stack| Witness { stack }).collect();

        let reply = SignOnchainTxReply { witnesses: wits };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_commitment_tx(
        &self,
        request: Request<SignCounterpartyCommitmentTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce.clone())?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.clone().ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;
        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point.clone())?;
        let witscripts = reqtx.output_descs.iter().map(|odsc| odsc.witscript.clone()).collect();

        let commit_num = req.commit_num;
        let offered_htlcs = self.convert_htlcs(&req.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&req.received_htlcs)?;
        let feerate_sat_per_kw = req.feerate_sat_per_kw;

        let sig = self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_counterparty_commitment_tx(
                &tx,
                &witscripts,
                &remote_per_commitment_point,
                commit_num,
                feerate_sat_per_kw,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )
        })?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn validate_holder_commitment_tx(
        &self,
        request: Request<ValidateHolderCommitmentTxRequest>,
    ) -> Result<Response<ValidateHolderCommitmentTxReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.clone().ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(invalid_grpc_argument("tx.input.len() != 1"));
        }
        if tx.output.len() == 0 {
            return Err(invalid_grpc_argument("tx.output.len() == 0"));
        }

        let witscripts = reqtx.output_descs.iter().map(|odsc| odsc.witscript.clone()).collect();

        let offered_htlcs = self.convert_htlcs(&req.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&req.received_htlcs)?;

        let proto_sig = req
            .commit_signature
            .ok_or_else(|| invalid_grpc_argument("missing commit_signature"))?;
        let commit_sig = signature_from_proto(&proto_sig, EcdsaSighashType::All)?;

        let htlc_sighash_type = self.htlc_sighash_type(&node_id, &channel_id)?;

        let htlc_sigs = req
            .htlc_signatures
            .iter()
            .map(|sig| signature_from_proto(sig, htlc_sighash_type))
            .collect::<Result<Vec<_>, Status>>()?;
        let commit_num = req.commit_num;
        let feerate_sat_per_kw = req.feerate_sat_per_kw;

        let (next_per_commitment_point, old_secret) =
            self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
                chan.validate_holder_commitment_tx(
                    &tx,
                    &witscripts,
                    commit_num,
                    feerate_sat_per_kw,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                    &commit_sig,
                    &htlc_sigs,
                )
            })?;

        let reply = ValidateHolderCommitmentTxReply {
            next_per_commitment_point: Some(next_per_commitment_point.into()),
            old_secret: old_secret.map(|s| s.into()),
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn validate_counterparty_revocation(
        &self,
        request: Request<ValidateCounterpartyRevocationRequest>,
    ) -> Result<Response<ValidateCounterpartyRevocationReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let revoke_num = req.revoke_num;
        let old_secret = self.secret_key(req.old_secret)?;
        self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.validate_counterparty_revocation(revoke_num, &old_secret)
        })?;
        let reply = ValidateCounterpartyRevocationReply {};
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_holder_htlc_tx(
        &self,
        request: Request<SignHolderHtlcTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce.clone())?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.clone().ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        if tx.input.len() != 1 {
            return Err(invalid_grpc_argument("tx.input.len() != 1"));
        }
        if tx.output.len() == 0 {
            return Err(invalid_grpc_argument("tx.output.len() == 0"));
        }

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let opt_per_commitment_point = match req.per_commit_point.clone() {
            Some(p) => Some(self.public_key(Some(p))?),
            _ => None,
        };

        let output_witscript = Script::from(reqtx.output_descs[0].witscript.clone());

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_holder_htlc_tx(
                    &tx,
                    req.n,
                    opt_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_delayed_sweep(
        &self,
        request: Request<SignDelayedSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.clone().ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = input_desc.redeem_script;

        let input: usize =
            req.input.try_into().map_err(|_| invalid_grpc_argument("bad input index"))?;

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("tx.output.len() != 1"));
        }

        let htlc_redeemscript = Script::from(redeemscript.clone());

        let wallet_path = &reqtx
            .output_descs
            .into_iter()
            .map(|od| od.key_loc.unwrap_or_default().key_path.to_vec())
            .collect::<Vec<Vec<u32>>>()[0];

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_delayed_sweep(
                    &tx,
                    input,
                    req.commitment_number,
                    &htlc_redeemscript,
                    htlc_amount_sat,
                    &wallet_path,
                )
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_htlc_tx(
        &self,
        request: Request<SignCounterpartyHtlcTxRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.clone().ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx_res: Result<bitcoin::Transaction, encode::Error> =
            deserialize(reqtx.raw_tx_bytes.as_slice());
        let tx =
            tx_res.map_err(|e| invalid_grpc_argument(format!("deserialize tx fail: {}", e)))?;

        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point)?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("len(tx.output) != 1"));
        }

        let output_witscript = Script::from(reqtx.output_descs[0].witscript.clone());

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_counterparty_htlc_tx(
                    &tx,
                    &remote_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                    &output_witscript,
                )
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_htlc_sweep(
        &self,
        request: Request<SignCounterpartyHtlcSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let remote_per_commitment_point = self.public_key(req.remote_per_commit_point)?;

        let input: usize =
            req.input.try_into().map_err(|_| invalid_grpc_argument("bad input index"))?;

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("tx.output.len() != 1"));
        }

        let wallet_path = &reqtx
            .output_descs
            .into_iter()
            .map(|od| od.key_loc.unwrap_or_default().key_path.to_vec())
            .collect::<Vec<Vec<u32>>>()[0];

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_counterparty_htlc_sweep(
                    &tx,
                    input,
                    &remote_per_commitment_point,
                    &redeemscript,
                    htlc_amount_sat,
                    &wallet_path,
                )
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_justice_sweep(
        &self,
        request: Request<SignJusticeSweepRequest>,
    ) -> Result<Response<SignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let reqtx = req.tx.ok_or_else(|| invalid_grpc_argument("missing tx"))?;

        let tx: bitcoin::Transaction = deserialize(reqtx.raw_tx_bytes.as_slice())
            .map_err(|e| invalid_grpc_argument(format!("bad tx: {}", e)))?;

        let input_desc = reqtx.input_descs[0].clone();
        let htlc_amount_sat = input_desc.value_sat as u64;
        let redeemscript = Script::from(input_desc.redeem_script);

        let revocation_secret = self.secret_key(req.revocation_secret)?;

        if tx.output.len() != 1 {
            return Err(Status::invalid_argument("tx.output.len() != 1"));
        }

        let input: usize =
            req.input.try_into().map_err(|_| invalid_grpc_argument("bad input index"))?;

        let wallet_path = &reqtx
            .output_descs
            .into_iter()
            .map(|od| od.key_loc.unwrap_or_default().key_path.to_vec())
            .collect::<Vec<Vec<u32>>>()[0];

        let sig = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                chan.sign_justice_sweep(
                    &tx,
                    input,
                    &revocation_secret,
                    &redeemscript,
                    htlc_amount_sat,
                    &wallet_path,
                )
            })
            .map_err(|_| Status::internal("failed to sign"))?;

        let reply = SignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_channel_announcement(
        &self,
        request: Request<SignChannelAnnouncementRequest>,
    ) -> Result<Response<SignChannelAnnouncementReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let ca = req.channel_announcement;
        let (nsig, bsig) = self
            .signer
            .with_ready_channel(&node_id, &channel_id, |chan| {
                Ok(chan.sign_channel_announcement(&ca))
            })
            .map_err(|e| Status::internal(e.to_string()))?;
        let reply = SignChannelAnnouncementReply {
            node_signature: Some(nsig.into()),
            bitcoin_signature: Some(bsig.into()),
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_node_announcement(
        &self,
        request: Request<SignNodeAnnouncementRequest>,
    ) -> Result<Response<NodeSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let na = req.node_announcement;
        let node = self.signer.get_node(&node_id)?;
        let sig = node.sign_node_announcement(&na)?;
        let reply = NodeSignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_channel_update(
        &self,
        request: Request<SignChannelUpdateRequest>,
    ) -> Result<Response<NodeSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let cu = req.channel_update;
        let node = self.signer.get_node(&node_id)?;
        let sig = node.sign_channel_update(&cu)?;
        let reply = NodeSignatureReply { signature: Some(sig.into()) };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn ecdh(&self, request: Request<EcdhRequest>) -> Result<Response<EcdhReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let other_key = self.public_key(req.point.clone())?;
        log_req_enter!(&node_id, &other_key, &req);

        let node = self.signer.get_node(&node_id)?;
        let data = node.ecdh(&other_key);
        let reply = EcdhReply { shared_secret: Some(Secret { data }) };
        log_req_reply!(&node_id, &other_key, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_invoice(
        &self,
        request: Request<SignInvoiceRequest>,
    ) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        use bitcoin::bech32::CheckBase32;

        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let data_part = req.data_part;
        let human_readable_part = req.human_readable_part.as_bytes();
        let node = self.signer.get_node(&node_id)?;
        let data =
            data_part.check_base32().map_err(|_| invalid_grpc_argument("invalid base32 data"))?;
        let (rid, sig) = node.sign_invoice(human_readable_part, &data)?.serialize_compact();
        let mut sig_data = sig.to_vec();
        // the range 0..3 is enforced in the RecoveryId constructor
        sig_data.push(rid.to_i32() as u8);
        let reply = RecoverableNodeSignatureReply {
            signature: Some(EcdsaRecoverableSignature { data: sig_data }),
        };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_bolt12(
        &self,
        request: Request<SignBolt12Request>,
    ) -> Result<Response<SchnorrSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let messagename = req.messagename.as_bytes();
        let fieldname = req.fieldname.as_bytes();
        let merkleroot = req.merkleroot.as_slice().try_into().map_err(|err| {
            invalid_grpc_argument(format!("could not decode merkleroot: {}", err))
        })?;
        let publictweak_opt =
            if req.publictweak.is_empty() { None } else { Some(req.publictweak.as_slice()) };

        let node = self.signer.get_node(&node_id)?;
        let sig = node.sign_bolt12(messagename, fieldname, merkleroot, publictweak_opt)?;
        let reply =
            SchnorrSignatureReply { signature: Some(SchnorrSignature { data: sig[..].to_vec() }) };

        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<RecoverableNodeSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let message = req.message;
        let node = self.signer.get_node(&node_id)?;
        let rsigvec = node.sign_message(&message)?;
        let reply = RecoverableNodeSignatureReply {
            signature: Some(EcdsaRecoverableSignature { data: rsigvec.clone() }),
        };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn derive_secret(
        &self,
        request: Request<DeriveSecretRequest>,
    ) -> Result<Response<DeriveSecretReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        let secret = node.derive_secret(&req.info);
        let reply = DeriveSecretReply { secret: Some(secret.into()) };

        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_counterparty_commitment_tx_phase2(
        &self,
        request: Request<SignCounterpartyCommitmentTxPhase2Request>,
    ) -> Result<Response<CommitmentTxSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let req_info =
            req.commitment_info.ok_or_else(|| invalid_grpc_argument("missing commitment info"))?;
        let remote_per_commitment_point = self.public_key(req_info.per_commitment_point.clone())?;

        let offered_htlcs = self.convert_htlcs(&req_info.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&req_info.received_htlcs)?;

        let (sig, htlc_sigs) = self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
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

        let htlc_bitcoin_sigs = htlc_sigs.into_iter().map(|s| s.into()).collect();
        let reply = CommitmentTxSignatureReply {
            signature: Some(sig.into()),
            htlc_signatures: htlc_bitcoin_sigs,
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn validate_holder_commitment_tx_phase2(
        &self,
        request: Request<ValidateHolderCommitmentTxPhase2Request>,
    ) -> Result<Response<ValidateHolderCommitmentTxReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(&node_id, &channel_id, &req);

        let info =
            req.commitment_info.ok_or_else(|| invalid_grpc_argument("missing commitment info"))?;

        let offered_htlcs = self.convert_htlcs(&info.offered_htlcs)?;
        let received_htlcs = self.convert_htlcs(&info.received_htlcs)?;

        let proto_sig = req
            .commit_signature
            .ok_or_else(|| invalid_grpc_argument("missing commit_signature"))?;
        let commit_sig = signature_from_proto(&proto_sig, EcdsaSighashType::All)?;

        let htlc_sighash_type = self.htlc_sighash_type(&node_id, &channel_id)?;

        let htlc_sigs = req
            .htlc_signatures
            .iter()
            .map(|sig| signature_from_proto(sig, htlc_sighash_type))
            .collect::<Result<Vec<_>, Status>>()?;

        let (point, old_secret) =
            self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
                chan.validate_holder_commitment_tx_phase2(
                    info.n,
                    info.feerate_sat_per_kw,
                    info.to_holder_value_sat,
                    info.to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                    &commit_sig,
                    &htlc_sigs,
                )
            })?;
        let reply = ValidateHolderCommitmentTxReply {
            next_per_commitment_point: Some(point.into()),
            old_secret: old_secret.map(|s| s.into()),
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn sign_holder_commitment_tx_phase2(
        &self,
        request: Request<SignHolderCommitmentTxPhase2Request>,
    ) -> Result<Response<CommitmentTxSignatureReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        let channel_id = self.channel_id(&req.channel_nonce)?;
        log_req_enter!(node_id, channel_id, &req);

        let commit_num = req.commit_num;

        let (sig, htlc_sigs) = self.signer.with_ready_channel(&node_id, &channel_id, |chan| {
            chan.sign_holder_commitment_tx_phase2(commit_num)
        })?;

        let htlc_bitcoin_sigs = htlc_sigs.into_iter().map(|s| s.into()).collect();
        let reply = CommitmentTxSignatureReply {
            signature: Some(sig.into()),
            htlc_signatures: htlc_bitcoin_sigs,
        };
        log_req_reply!(&node_id, &channel_id, &reply);
        Ok(Response::new(reply))
    }

    async fn preapprove_invoice(
        &self,
        request: Request<PreapproveInvoiceRequest>,
    ) -> Result<Response<PreapproveInvoiceReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let signed = req
            .invstring
            .parse::<SignedRawInvoice>()
            .map_err(|e| invalid_grpc_argument(e.to_string()))?;
        let node = self.signer.get_node(&node_id)?;
        self.approver.handle_proposed_invoice(&node, signed)?;

        let reply = PreapproveInvoiceReply {};
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesReply>, Status> {
        log_req_enter!();
        let node_ids = self
            .signer
            .get_node_ids()
            .iter()
            .map(|k| k.serialize().to_vec())
            .map(|id| NodeId { data: id })
            .collect();
        let reply = ListNodesReply { node_ids };
        log_req_reply!(&reply);
        Ok(Response::new(reply))
    }

    async fn list_channels(
        &self,
        request: Request<ListChannelsRequest>,
    ) -> Result<Response<ListChannelsReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        let channel_nonces = node
            .channels()
            .iter()
            .map(|(id, chan_mutex)| {
                let chan = chan_mutex.lock().unwrap();
                info!("chan id={} id_in_obj={}", id, chan.id());
                chan.id().inner().clone()
            })
            .map(|nonce| ChannelNonce { data: nonce })
            .collect();
        let reply = ListChannelsReply { channel_nonces };

        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn list_allowlist(
        &self,
        request: Request<ListAllowlistRequest>,
    ) -> Result<Response<ListAllowlistReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        let addresses = node.allowlist()?;
        let reply = ListAllowlistReply { addresses };
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn add_allowlist(
        &self,
        request: Request<AddAllowlistRequest>,
    ) -> Result<Response<AddAllowlistReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        node.add_allowlist(&req.addresses)?;
        let reply = AddAllowlistReply {};
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }

    async fn remove_allowlist(
        &self,
        request: Request<RemoveAllowlistRequest>,
    ) -> Result<Response<RemoveAllowlistReply>, Status> {
        let req = request.into_inner();
        let node_id = self.node_id(req.node_id.clone())?;
        log_req_enter!(&node_id, &req);

        let node = self.signer.get_node(&node_id)?;
        node.remove_allowlist(&req.addresses)?;
        let reply = RemoveAllowlistReply {};
        log_req_reply!(&node_id, &reply);
        Ok(Response::new(reply))
    }
}

const DEFAULT_DIR: &str = ".lightning-signer";

#[tokio::main(worker_threads = 2)]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} {} starting", SERVER_APP_NAME, process::id());
    let app = App::new(SERVER_APP_NAME)
        .about(
            "Validating Lightning Signer with a gRPC interface.  Persists to .lightning-signer .",
        )
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .possible_values(&NETWORK_NAMES)
                .default_value(NETWORK_NAMES[0]),
        )
        .arg(
            Arg::new("rpc")
                .about("bitcoind RPC URL, must have http(s) schema")
                .short('r')
                .long("rpc")
                .takes_value(true)
                .value_name("URL")
                .default_value("http://user:pass@localhost:18332"),
        )
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
                .default_value("127.0.0.1"),
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
        )
        .arg(
            Arg::new("logleveldisk")
                .about("logging level to disk")
                .short('v')
                .long("log-level-disk")
                .possible_values(&LOG_LEVEL_FILTER_NAMES)
                .default_value("TRACE")
                .takes_value(true),
        )
        .arg(
            Arg::new("loglevelconsole")
                .about("logging level to console")
                .short('V')
                .long("log-level-console")
                .possible_values(&LOG_LEVEL_FILTER_NAMES)
                .default_value("INFO")
                .takes_value(true),
        )
        .arg(
            Arg::new("initial-allowlist-file")
                .about("specify file containing initial allowlist")
                .short('A')
                .long("initial-allowlist-file")
                .takes_value(true),
        );
    let app = policy_args(app);
    let matches = app.get_matches();

    let addr =
        format!("{}:{}", matches.value_of("interface").unwrap(), matches.value_of("port").unwrap())
            .parse()?;

    // Network can be specified on the command line or in the config file
    let network: Network = matches.value_of_t("network").expect("network");

    let data_path = format!("{}/{}", matches.value_of("datadir").unwrap(), network.to_string());

    let console_log_level = parse_log_level_filter(matches.value_of_t("loglevelconsole").unwrap())
        .expect("loglevelconsole");
    let disk_log_level =
        parse_log_level_filter(matches.value_of_t("logleveldisk").unwrap()).expect("logleveldisk");
    log::set_boxed_logger(Box::new(FilesystemLogger::new(
        data_path.clone(),
        disk_log_level,
        console_log_level,
    )))
    .unwrap_or_else(|e| panic!("Failed to create FilesystemLogger: {}", e));
    log::set_max_level(cmp::max(disk_log_level, console_log_level));

    info!("data directory {}", data_path);

    let test_mode = matches.is_present("test-mode");
    let persister: Arc<dyn Persist> = if matches.is_present("no-persist") {
        Arc::new(DummyPersister)
    } else {
        Arc::new(KVJsonPersister::new(data_path.as_str()))
    };
    let mut initial_allowlist = vec![];
    if matches.is_present("initial-allowlist-file") {
        let alfp: String =
            matches.value_of_t("initial-allowlist-file").expect("allowlist file path");
        let file = File::open(&alfp).expect(format!("open {} failed", &alfp).as_str());
        initial_allowlist = BufReader::new(file).lines().map(|l| l.expect("line")).collect()
    }
    let policy = policy(&matches, network);
    let validator_factory = Arc::new(SimpleValidatorFactory::new_with_policy(policy));
    let starting_time_factory = ClockStartingTimeFactory::new();
    let clock = Arc::new(StandardClock());
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let signer = Arc::new(MultiSigner::new_with_test_mode(test_mode, initial_allowlist, services));

    let rpc_s: String = matches.value_of_t("rpc").expect("rpc url string");
    let rpc_url = Url::parse(&rpc_s).expect("malformed rpc url");

    let frontend = Frontend::new(Arc::new(SignerFront { signer: Arc::clone(&signer) }), rpc_url);
    frontend.start();
    let approver = Arc::new(PositiveApprover());
    let server = SignServer { signer, network, frontend, approver };

    let (shutdown_trigger, shutdown_signal) = triggered::trigger();
    ctrlc::set_handler(move || {
        shutdown_trigger.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let service = Server::builder()
        .add_service(SignerServer::new(server))
        .serve_with_shutdown(addr, shutdown_signal);

    setup_tokio_log();

    info!("{} {} ready on {}", SERVER_APP_NAME, process::id(), addr);
    service.await?;
    info!("{} {} finished", SERVER_APP_NAME, process::id());

    Ok(())
}

fn setup_tokio_log() {
    let subscriber =
        tracing_subscriber::FmtSubscriber::builder().with_max_level(tracing::Level::INFO).finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

fn policy_args(app: App) -> App {
    app.arg(Arg::new("require_invoices").long("require_invoices").takes_value(false))
        .arg(Arg::new("enforce_balance").long("enforce_balance").takes_value(false))
}

fn policy(matches: &ArgMatches, network: Network) -> SimplePolicy {
    let mut policy = make_simple_policy(network);
    policy.require_invoices = matches.is_present("require_invoices");
    policy.enforce_balance = matches.is_present("enforce_balance");
    use std::env;
    let warn_only =
        env::var("VLS_PERMISSIVE").map(|s| s.parse().expect("VLS_PERMISSIVE parse")).unwrap_or(0);
    if warn_only == 1 {
        info!("VLS_PERMISSIVE: ALL POLICY ERRORS ARE REPORTED AS WARNINGS");
        policy.filter = PolicyFilter::new_permissive();
    } else {
        info!("VLS_ENFORCING: ALL POLICY ERRORS ARE ENFORCED");
    }
    policy
}
