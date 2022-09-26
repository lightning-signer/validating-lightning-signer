use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use bit_vec::BitVec;
use core::convert::TryInto;

use bitcoin::blockdata::script;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{EcdsaSighashType, Network, Script};
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::bech32::u5;
use lightning_signer::bitcoin::consensus::{Decodable, Encodable};
use lightning_signer::bitcoin::secp256k1;
use lightning_signer::bitcoin::util::bip32::{ChildNumber, KeySource};
use lightning_signer::bitcoin::util::psbt::PartiallySignedTransaction;
use lightning_signer::bitcoin::{OutPoint, Transaction, Witness};
use lightning_signer::channel::{
    ChannelBalance, ChannelBase, ChannelId, ChannelSetup, CommitmentType, TypedSignature,
};
use lightning_signer::lightning::ln::chan_utils::{
    derive_public_revocation_key, ChannelPublicKeys,
};
use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::lightning_invoice::SignedRawInvoice;
use lightning_signer::node::{Node, NodeConfig, NodeMonitor, NodeServices, SpendType};
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::util::status;
use lightning_signer::Arc;
#[allow(unused_imports)]
use log::info;
#[cfg(feature = "std")]
use secp256k1::rand::{rngs::OsRng, RngCore};
use secp256k1::{ecdsa, PublicKey, Secp256k1};

use lightning_signer::util::status::Status;
use vls_protocol::features::*;
use vls_protocol::model::{
    Basepoints, BitcoinSignature, BlockHash, ExtKey, Htlc, OutPoint as ModelOutPoint, PubKey,
    PubKey32, RecoverableSignature, Secret, Signature, TxId,
};
use vls_protocol::msgs::{DeriveSecretReply, PreapproveInvoiceReply, SerBolt, SignBolt12Reply};
use vls_protocol::serde_bolt::{LargeBytes, WireString};
use vls_protocol::{msgs, msgs::Message, Error as ProtocolError};

use crate::approver::{Approver, PositiveApprover};

/// Error
#[derive(Debug)]
pub enum Error {
    ProtocolError(ProtocolError),
    SigningError(Status),
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::ProtocolError(e)
    }
}

impl From<Status> for Error {
    fn from(e: Status) -> Self {
        Error::SigningError(e)
    }
}

fn to_bitcoin_sig(sig: ecdsa::Signature) -> BitcoinSignature {
    BitcoinSignature {
        signature: Signature(sig.serialize_compact()),
        sighash: EcdsaSighashType::All as u8,
    }
}

fn typed_to_bitcoin_sig(sig: TypedSignature) -> BitcoinSignature {
    BitcoinSignature { signature: Signature(sig.sig.serialize_compact()), sighash: sig.typ as u8 }
}

fn to_script(bytes: &Vec<u8>) -> Option<Script> {
    if bytes.is_empty() {
        None
    } else {
        Some(Script::from(bytes.clone()))
    }
}

/// Result
pub type Result<T> = core::result::Result<T, Error>;

pub trait Handler {
    fn handle(&self, msg: Message) -> Result<Box<dyn SerBolt>>;
    fn client_id(&self) -> u64;
    fn for_new_client(&self, client_id: u64, peer_id: PubKey, dbid: u64) -> ChannelHandler;
}

/// Protocol handler
#[derive(Clone)]
pub struct RootHandler {
    pub(crate) id: u64,
    pub node: Arc<Node>,
    approver: Arc<dyn Approver>,
}

/// Builder for RootHandler
pub struct RootHandlerBuilder {
    network: Network,
    id: u64,
    seed_opt: Option<[u8; 32]>,
    allowlist: Vec<String>,
    services: NodeServices,
    approver: Arc<dyn Approver>,
}

impl RootHandlerBuilder {
    /// Create a RootHandlerBuilder
    pub fn new(network: Network, id: u64, services: NodeServices) -> RootHandlerBuilder {
        RootHandlerBuilder {
            network,
            id,
            seed_opt: None,
            allowlist: vec![],
            services,
            approver: Arc::new(PositiveApprover()),
        }
    }

    /// Set the seed option
    pub fn seed_opt(mut self, seed_opt: Option<[u8; 32]>) -> Self {
        self.seed_opt = seed_opt;
        self
    }

    /// Set the initial allowlist (only used if node is new)
    pub fn allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Set the approver
    pub fn approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = approver;
        self
    }

    /// Build the root handler
    pub fn build(self) -> RootHandler {
        let config =
            NodeConfig { network: self.network, key_derivation_style: KeyDerivationStyle::Native };

        let seed = self.seed_opt.unwrap_or_else(|| {
            #[cfg(feature = "std")]
            {
                let mut seed = [0; 32];
                let mut rng = OsRng;
                rng.fill_bytes(&mut seed);
                seed
            }
            #[cfg(not(feature = "std"))]
            todo!("no RNG available in no_std environments yet");
        });

        let persister = self.services.persister.clone();
        let nodes = persister.get_nodes();
        let node = if nodes.is_empty() {
            let node = Arc::new(Node::new(config, &seed, vec![], self.services));
            info!("New node {}", node.get_id());
            node.add_allowlist(&self.allowlist).expect("allowlist");
            persister.new_node(&node.get_id(), &config, &*node.get_state(), &seed);
            persister.new_chain_tracker(&node.get_id(), &node.get_tracker());
            node
        } else {
            assert_eq!(nodes.len(), 1);
            let (node_id, entry) = nodes.into_iter().next().unwrap();
            info!("Restore node {}", node_id);
            Node::restore_node(&node_id, entry, persister, self.services)
        };

        RootHandler { id: self.id, node, approver: self.approver }
    }
}

impl RootHandler {
    fn channel_id(node_id: &PubKey, dbid: u64) -> ChannelId {
        let mut nonce = [0u8; 33 + 8];
        nonce[0..33].copy_from_slice(&node_id.0);
        nonce[33..].copy_from_slice(&dbid.to_le_bytes());
        let channel_id = ChannelId::new(&nonce);
        channel_id
    }

    pub fn channel_balance(&self) -> ChannelBalance {
        self.node.channel_balance()
    }

    pub fn get_chain_height(&self) -> u32 {
        self.node.get_chain_height()
    }
}

impl Handler for RootHandler {
    fn handle(&self, msg: Message) -> Result<Box<dyn SerBolt>> {
        match msg {
            Message::Ping(p) => {
                info!("got ping with {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                let reply =
                    msgs::Pong { id: p.id, message: WireString("pong".as_bytes().to_vec()) };
                Ok(Box::new(reply))
            }
            Message::Memleak(_m) => Ok(Box::new(msgs::MemleakReply { result: false })),
            Message::SignBolt12(m) => {
                let tweak =
                    if m.public_tweak.is_empty() { None } else { Some(m.public_tweak.as_slice()) };
                let sig = self.node.sign_bolt12(
                    &m.message_name.0,
                    &m.field_name.0,
                    &m.merkle_root.0,
                    tweak,
                )?;
                Ok(Box::new(SignBolt12Reply { signature: Signature(sig.as_ref().clone()) }))
            }
            Message::PreapproveInvoice(m) => {
                let invstr = String::from_utf8(m.invstring.0)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;
                let signed = invstr
                    .parse::<SignedRawInvoice>()
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;
                self.approver.handle_proposed_invoice(&self.node, signed)?;
                Ok(Box::new(PreapproveInvoiceReply {}))
            }
            Message::DeriveSecret(m) => {
                let secret = self.node.derive_secret(&m.info);
                Ok(Box::new(DeriveSecretReply {
                    secret: Secret(secret[..].try_into().expect("secret")),
                }))
            }
            Message::SignMessage(m) => {
                let sig = self.node.sign_message(&m.message)?;
                let sig_slice = sig.try_into().expect("recoverable signature size");
                Ok(Box::new(msgs::SignMessageReply { signature: RecoverableSignature(sig_slice) }))
            }
            Message::HsmdInit(_) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_id = self.node.get_id().serialize();
                let bolt12_xonly = self.node.get_bolt12_pubkey().serialize();
                let onion_reply_secret = self.node.get_onion_reply_secret();
                Ok(Box::new(msgs::HsmdInitReply {
                    node_id: PubKey(node_id),
                    bip32: ExtKey(bip32),
                    bolt12: PubKey32(bolt12_xonly),
                    onion_reply_secret: Secret(onion_reply_secret),
                }))
            }
            Message::HsmdInit2(m) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_secret = self.node.get_node_secret()[..].try_into().unwrap();
                let bolt12_xonly = self.node.get_bolt12_pubkey().serialize();
                let allowlist = m
                    .dev_allowlist
                    .into_iter()
                    .map(|ws| String::from_utf8(ws.0).expect("utf8"))
                    .collect();
                // FIXME disable in production
                self.node.add_allowlist(&allowlist)?;
                Ok(Box::new(msgs::HsmdInit2Reply {
                    node_secret: Secret(node_secret),
                    bip32: ExtKey(bip32),
                    bolt12: PubKey32(bolt12_xonly),
                }))
            }
            Message::Ecdh(m) => {
                let pubkey = PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                Ok(Box::new(msgs::EcdhReply { secret: Secret(secret) }))
            }
            Message::NewChannel(m) => {
                let channel_id = Self::channel_id(&m.node_id, m.dbid);
                self.node.new_channel(Some(channel_id), &self.node)?;
                Ok(Box::new(msgs::NewChannelReply {}))
            }
            Message::GetChannelBasepoints(m) => {
                let channel_id = Self::channel_id(&m.node_id, m.dbid);
                let bps = self
                    .node
                    .with_channel_base(&channel_id, |base| Ok(base.get_channel_basepoints()))?;

                let basepoints = Basepoints {
                    revocation: PubKey(bps.revocation_basepoint.serialize()),
                    payment: PubKey(bps.payment_point.serialize()),
                    htlc: PubKey(bps.htlc_basepoint.serialize()),
                    delayed_payment: PubKey(bps.delayed_payment_basepoint.serialize()),
                };
                let funding = PubKey(bps.funding_pubkey.serialize());

                Ok(Box::new(msgs::GetChannelBasepointsReply { basepoints, funding }))
            }
            Message::SignWithdrawal(m) => {
                let mut psbt =
                    PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                        .expect("psbt");
                let mut tx = psbt.clone().extract_tx();
                let ipaths = m.utxos.iter().map(|u| vec![u.keyindex]).collect();
                let values_sat = m.utxos.iter().map(|u| u.amount).collect();
                let spendtypes = m
                    .utxos
                    .iter()
                    .map(|u|
                        // TODO this is kinda overloading the SignWithdrawal message
                        // (CLN uses a separate message to sign delayed output to us)
                        if u.is_p2sh {
                            SpendType::P2shP2wpkh
                        } else if let Some(ci) = u.close_info.as_ref() {
                            if ci.commitment_point.is_some() {
                                SpendType::P2wsh
                            } else {
                                SpendType::P2wpkh
                            }
                        } else {
                            SpendType::P2wpkh
                        })
                    .collect();
                let mut uniclosekeys = Vec::new();
                let secp_ctx = Secp256k1::new();
                for utxo in m.utxos.iter() {
                    if let Some(ci) = utxo.close_info.as_ref() {
                        let channel_id = Self::channel_id(&ci.peer_id, ci.channel_id);
                        let per_commitment_point = ci
                            .commitment_point
                            .as_ref()
                            .map(|p| PublicKey::from_slice(&p.0).expect("TODO"));

                        let ck = self.node.with_ready_channel(&channel_id, |chan| {
                            let revocation_pubkey = per_commitment_point.as_ref().map(|p| {
                                let revocation_basepoint =
                                    chan.keys.counterparty_pubkeys().revocation_basepoint;
                                derive_public_revocation_key(&secp_ctx, p, &revocation_basepoint)
                                    .expect("TODO")
                            });
                            chan.get_unilateral_close_key(&per_commitment_point, &revocation_pubkey)
                        })?;
                        uniclosekeys.push(Some(ck));
                    } else {
                        uniclosekeys.push(None)
                    }
                }

                let opaths = extract_psbt_output_paths(&psbt);

                // Populate script_sig for p2sh-p2wpkh signing
                for (psbt_in, tx_in) in psbt.inputs.iter_mut().zip(tx.input.iter_mut()) {
                    if let Some(script) = psbt_in.redeem_script.as_ref() {
                        assert!(psbt_in.final_script_sig.is_none());
                        assert!(tx_in.script_sig.is_empty());
                        let script_sig =
                            script::Builder::new().push_slice(script.as_bytes()).into_script();
                        tx_in.script_sig = script_sig.clone();
                        psbt_in.final_script_sig = Some(script_sig);
                    }
                }
                info!("opaths {:?}", opaths);
                info!("txid {}", tx.txid());
                info!("tx {:?}", tx);
                info!("psbt {:?}", psbt);
                let witvec = self.node.sign_onchain_tx(
                    &tx,
                    &ipaths,
                    &values_sat,
                    &spendtypes,
                    uniclosekeys,
                    &opaths,
                )?;

                for (i, stack) in witvec.into_iter().enumerate() {
                    if !stack.is_empty() {
                        psbt.inputs[i].final_script_witness = Some(Witness::from_vec(stack));
                    }
                }

                let mut ser_psbt = Vec::new();
                psbt.consensus_encode(&mut ser_psbt).expect("serialize psbt");
                Ok(Box::new(msgs::SignWithdrawalReply { psbt: LargeBytes(ser_psbt) }))
            }
            Message::SignInvoice(m) => {
                let hrp = String::from_utf8(m.hrp).expect("hrp");
                let hrp_bytes = hrp.as_bytes();
                let data: Vec<_> = m
                    .u5bytes
                    .into_iter()
                    .map(|b| u5::try_from_u8(b).expect("invoice not base32"))
                    .collect();
                let sig = self.node.sign_invoice(hrp_bytes, &data)?;
                let (rid, ser) = sig.serialize_compact();
                let mut sig_slice = [0u8; 65];
                sig_slice[0..64].copy_from_slice(&ser);
                sig_slice[64] = rid.to_i32() as u8;
                Ok(Box::new(msgs::SignInvoiceReply { signature: RecoverableSignature(sig_slice) }))
            }
            Message::SignCommitmentTx(m) => {
                // TODO why not channel handler??
                let channel_id = Self::channel_id(&m.peer_id, m.dbid);
                let mut tx_bytes = m.tx.0.clone();
                let tx: Transaction = deserialize(&mut tx_bytes).expect("tx");

                // WORKAROUND - sometimes c-lightning calls handle_sign_commitment_tx
                // with mutual close transactions.  We can tell the difference because
                // the locktime field will be set to 0 for a mutual close.
                let sig = if tx.lock_time.0 == 0 {
                    let psbt =
                        PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                            .unwrap();
                    let opaths = extract_psbt_output_paths(&psbt);
                    self.node.with_ready_channel(&channel_id, |chan| {
                        chan.sign_mutual_close_tx(&tx, &opaths)
                    })?
                } else {
                    // We ignore everything in the message other than the commitment number,
                    // since the signer already has this info.
                    self.node
                        .with_ready_channel(&channel_id, |chan| {
                            chan.sign_holder_commitment_tx_phase2(m.commitment_number)
                        })?
                        .0
                };
                Ok(Box::new(msgs::SignCommitmentTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::TipInfo(_) => {
                let tracker = self.node.get_tracker();
                Ok(Box::new(msgs::TipInfoReply {
                    height: tracker.height(),
                    block_hash: BlockHash(tracker.tip().block_hash()[..].try_into().unwrap()),
                }))
            }
            Message::ForwardWatches(_) => {
                let (txids, outpoints) = self.node.get_tracker().get_all_forward_watches();
                Ok(Box::new(msgs::ForwardWatchesReply {
                    txids: txids.iter().map(|txid| TxId(txid[..].try_into().unwrap())).collect(),
                    outpoints: outpoints
                        .iter()
                        .map(|op| ModelOutPoint {
                            txid: TxId(op.txid[..].try_into().unwrap()),
                            vout: op.vout,
                        })
                        .collect(),
                }))
            }
            Message::ReverseWatches(_) => {
                let (txids, outpoints) = self.node.get_tracker().get_all_reverse_watches();
                Ok(Box::new(msgs::ReverseWatchesReply {
                    txids: txids.iter().map(|txid| TxId(txid[..].try_into().unwrap())).collect(),
                    outpoints: outpoints
                        .iter()
                        .map(|op| ModelOutPoint {
                            txid: TxId(op.txid[..].try_into().unwrap()),
                            vout: op.vout,
                        })
                        .collect(),
                }))
            }
            Message::AddBlock(m) => {
                let mut tracker = self.node.get_tracker();
                tracker
                    .add_block(
                        deserialize(m.header.0.as_slice()).expect("header"),
                        m.txs.iter().map(|tx| deserialize(tx.0.as_slice()).expect("tx")).collect(),
                        m.txs_proof.map(|prf| deserialize(prf.0.as_slice()).expect("txs_proof")),
                    )
                    .expect("add_block");
                self.node
                    .get_persister()
                    .update_tracker(&self.node.get_id(), &tracker)
                    .unwrap_or_else(|e| {
                        panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
                    });
                Ok(Box::new(msgs::AddBlockReply {}))
            }
            Message::RemoveBlock(m) => {
                let mut tracker = self.node.get_tracker();
                tracker
                    .remove_block(
                        m.txs.iter().map(|tx| deserialize(tx.0.as_slice()).expect("tx")).collect(),
                        m.txs_proof.map(|prf| deserialize(prf.0.as_slice()).expect("txs_proof")),
                    )
                    .expect("remove_block");
                self.node
                    .get_persister()
                    .update_tracker(&self.node.get_id(), &tracker)
                    .unwrap_or_else(|e| {
                        panic!("{}: persist tracker failed: {:?}", self.node.log_prefix(), e)
                    });
                Ok(Box::new(msgs::RemoveBlockReply {}))
            }
            Message::Unknown(u) => {
                unimplemented!("loop {}: unknown message type {}", self.id, u.message_type)
            }
            Message::SignNodeAnnouncement(m) => {
                let message = m.announcement[64 + 2..].to_vec();
                let sig = self.node.sign_node_announcement(&message)?;

                Ok(Box::new(msgs::SignNodeAnnouncementReply {
                    node_signature: Signature(sig.serialize_compact()),
                }))
            }
            Message::SignChannelUpdate(m) => {
                // NOTE this is called without a dbid by gossipd, so it gets dispatched to the root handler
                let message = m.update[2 + 64..].to_vec();
                let sig = self.node.sign_channel_update(&message)?;
                let mut update = m.update;
                update[2..2 + 64].copy_from_slice(&sig.serialize_compact());
                Ok(Box::new(msgs::SignChannelUpdateReply { update }))
            }
            m => unimplemented!("loop {}: unimplemented message {:?}", self.id, m),
        }
    }

    fn client_id(&self) -> u64 {
        self.id
    }

    fn for_new_client(&self, client_id: u64, peer_id: PubKey, dbid: u64) -> ChannelHandler {
        let channel_id = Self::channel_id(&peer_id, dbid);
        ChannelHandler {
            id: client_id,
            node: Arc::clone(&self.node),
            peer_id: peer_id.0,
            dbid,
            channel_id,
        }
    }
}

fn extract_output_path(x: &BTreeMap<PublicKey, KeySource>) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    if x.len() > 1 {
        panic!("len > 1");
    }
    let (_fingerprint, path) = x.iter().next().unwrap().1;
    let segments: Vec<ChildNumber> = path.clone().into();
    segments.into_iter().map(|c| u32::from(c)).collect()
}

fn extract_psbt_output_paths(psbt: &PartiallySignedTransaction) -> Vec<Vec<u32>> {
    psbt.outputs.iter().map(|o| extract_output_path(&o.bip32_derivation)).collect::<Vec<Vec<u32>>>()
}

/// Protocol handler
pub struct ChannelHandler {
    pub(crate) id: u64,
    pub node: Arc<Node>,
    pub peer_id: [u8; 33],
    pub dbid: u64,
    pub channel_id: ChannelId,
}

impl ChannelHandler {}

impl Handler for ChannelHandler {
    fn handle(&self, msg: Message) -> Result<Box<dyn SerBolt>> {
        match msg {
            Message::Memleak(_m) => Ok(Box::new(msgs::MemleakReply { result: false })),
            Message::CheckFutureSecret(m) => {
                let secret_key = SecretKey::from_slice(&m.secret.0)
                    .map_err(|_| Status::invalid_argument("bad secret key"))?;
                let result = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.check_future_secret(m.commitment_number, &secret_key)
                })?;
                Ok(Box::new(msgs::CheckFutureSecretReply { result }))
            }
            Message::Ecdh(m) => {
                // TODO DRY with root handler
                let pubkey = PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                Ok(Box::new(msgs::EcdhReply { secret: Secret(secret) }))
            }
            Message::GetPerCommitmentPoint(m) => {
                let commitment_number = m.commitment_number;
                let res: core::result::Result<(PublicKey, Option<SecretKey>), status::Status> =
                    self.node.with_channel_base(&self.channel_id, |base| {
                        let point = base.get_per_commitment_point(commitment_number)?;
                        let secret = if commitment_number >= 2 {
                            Some(base.get_per_commitment_secret(commitment_number - 2)?)
                        } else {
                            None
                        };
                        Ok((point, secret))
                    });

                let (point, old_secret) = res?;

                let old_secret_reply =
                    old_secret.clone().map(|s| Secret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::GetPerCommitmentPointReply {
                    point: PubKey(point.serialize()),
                    secret: old_secret_reply,
                }))
            }
            Message::GetPerCommitmentPoint2(m) => {
                let commitment_number = m.commitment_number;
                let point = self.node.with_channel_base(&self.channel_id, |base| {
                    base.get_per_commitment_point(commitment_number)
                })?;

                Ok(Box::new(msgs::GetPerCommitmentPoint2Reply { point: PubKey(point.serialize()) }))
            }
            Message::ReadyChannel(m) => {
                let txid = bitcoin::Txid::from_slice(&m.funding_txid.0).expect("txid");
                let funding_outpoint = OutPoint { txid, vout: m.funding_txout as u32 };

                let holder_shutdown_script = if m.local_shutdown_script.is_empty() {
                    None
                } else {
                    Some(Script::deserialize(&m.local_shutdown_script.as_slice()).expect("script"))
                };

                let points = m.remote_basepoints;
                let counterparty_points = ChannelPublicKeys {
                    funding_pubkey: extract_pubkey(&m.remote_funding_pubkey),
                    revocation_basepoint: extract_pubkey(&points.revocation),
                    payment_point: extract_pubkey(&points.payment),
                    delayed_payment_basepoint: extract_pubkey(&points.delayed_payment),
                    htlc_basepoint: extract_pubkey(&points.htlc),
                };

                let counterparty_shutdown_script = if m.remote_shutdown_script.is_empty() {
                    None
                } else {
                    Some(Script::deserialize(&m.remote_shutdown_script.as_slice()).expect("script"))
                };

                // FIXME
                let holder_shutdown_key_path = vec![];
                let setup = ChannelSetup {
                    is_outbound: m.is_outbound,
                    channel_value_sat: m.channel_value,
                    push_value_msat: m.push_value,
                    funding_outpoint,
                    holder_selected_contest_delay: m.to_self_delay as u16,
                    counterparty_points,
                    holder_shutdown_script,
                    counterparty_selected_contest_delay: m.remote_to_self_delay as u16,
                    counterparty_shutdown_script,
                    commitment_type: extract_commitment_type(&m.channel_type),
                };
                self.node.ready_channel(
                    self.channel_id.clone(),
                    None,
                    setup,
                    &holder_shutdown_key_path,
                )?;

                Ok(Box::new(msgs::ReadyChannelReply {}))
            }
            Message::SignRemoteHtlcTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let tx: Transaction = deserialize(&mut tx_bytes).expect("tx");
                assert_eq!(psbt.outputs.len(), 1);
                assert_eq!(psbt.inputs.len(), 1);
                assert_eq!(tx.output.len(), 1);
                assert_eq!(tx.input.len(), 1);
                let redeemscript = Script::from(m.wscript);
                let htlc_amount_sat = psbt.inputs[0]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let output_witscript =
                    psbt.outputs[0].witness_script.as_ref().expect("output witscript");
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_htlc_tx(
                        &tx,
                        &remote_per_commitment_point,
                        &redeemscript,
                        htlc_amount_sat,
                        &output_witscript,
                    )
                })?;

                Ok(Box::new(msgs::SignTxReply { signature: typed_to_bitcoin_sig(sig) }))
            }
            Message::SignRemoteCommitmentTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let witscripts = extract_psbt_witscripts(&psbt);
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                // Flip offered and received
                let (offered_htlcs, received_htlcs) = extract_htlcs(&m.htlcs);
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
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
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::SignRemoteCommitmentTx2(m) => {
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                // Flip offered and received
                let (offered_htlcs, received_htlcs) = extract_htlcs(&m.htlcs);
                let (sig, htlc_sigs) = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_commitment_tx_phase2(
                        &remote_per_commitment_point,
                        commit_num,
                        feerate_sat_per_kw,
                        m.to_local_value_sat,
                        m.to_remote_value_sat,
                        offered_htlcs.clone(),
                        received_htlcs.clone(),
                    )
                })?;
                Ok(Box::new(msgs::SignCommitmentTxWithHtlcsReply {
                    signature: to_bitcoin_sig(sig),
                    htlc_signatures: htlc_sigs.into_iter().map(|s| to_bitcoin_sig(s)).collect(),
                }))
            }
            Message::SignDelayedPaymentToUs(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let commitment_number = m.commitment_number;
                let redeemscript = Script::from(m.wscript);
                let input = 0;
                let htlc_amount_sat = psbt.inputs[input]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let wallet_paths = extract_psbt_output_paths(&psbt);
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_delayed_sweep(
                        &tx,
                        input,
                        commitment_number,
                        &redeemscript,
                        htlc_amount_sat,
                        &wallet_paths[0],
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply {
                    signature: BitcoinSignature {
                        signature: Signature(sig.serialize_compact()),
                        sighash: EcdsaSighashType::All as u8,
                    },
                }))
            }
            Message::SignRemoteHtlcToUs(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let redeemscript = Script::from(m.wscript);
                let input = 0;
                let htlc_amount_sat = psbt.inputs[input]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let wallet_paths = extract_psbt_output_paths(&psbt);
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_counterparty_htlc_sweep(
                        &tx,
                        input,
                        &remote_per_commitment_point,
                        &redeemscript,
                        htlc_amount_sat,
                        &wallet_paths[0],
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply {
                    signature: BitcoinSignature {
                        signature: Signature(sig.serialize_compact()),
                        sighash: EcdsaSighashType::All as u8,
                    },
                }))
            }
            Message::SignLocalHtlcTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let commitment_number = m.commitment_number;
                let redeemscript = Script::from(m.wscript);
                let input = 0;
                let htlc_amount_sat = psbt.inputs[input]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let output_witscript =
                    psbt.outputs[0].witness_script.as_ref().expect("output witscript");
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_holder_htlc_tx(
                        &tx,
                        commitment_number,
                        None,
                        &redeemscript,
                        htlc_amount_sat,
                        output_witscript,
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply {
                    signature: BitcoinSignature {
                        signature: Signature(sig.sig.serialize_compact()),
                        sighash: sig.typ as u8,
                    },
                }))
            }
            Message::SignMutualCloseTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let opaths = extract_psbt_output_paths(&psbt);
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_mutual_close_tx(&tx, &opaths)
                })?;
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::SignMutualCloseTx2(m) => {
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_mutual_close_tx_phase2(
                        m.to_local_value_sat,
                        m.to_remote_value_sat,
                        &to_script(&m.local_script),
                        &to_script(&m.remote_script),
                        &m.local_wallet_path_hint,
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply { signature: to_bitcoin_sig(sig) }))
            }
            Message::ValidateCommitmentTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let witscripts = extract_psbt_witscripts(&psbt);
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                let (received_htlcs, offered_htlcs) = extract_htlcs(&m.htlcs);
                let commit_sig =
                    ecdsa::Signature::from_compact(&m.signature.signature.0).expect("signature");
                assert_eq!(m.signature.sighash, EcdsaSighashType::All as u8);
                let htlc_sigs = m
                    .htlc_signatures
                    .iter()
                    .map(|s| {
                        assert!(
                            s.sighash == EcdsaSighashType::All as u8
                                || s.sighash == EcdsaSighashType::SinglePlusAnyoneCanPay as u8
                        );
                        ecdsa::Signature::from_compact(&s.signature.0).expect("signature")
                    })
                    .collect();
                let (next_per_commitment_point, old_secret) =
                    self.node.with_ready_channel(&self.channel_id, |chan| {
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
                let old_secret_reply = old_secret.map(|s| Secret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::ValidateCommitmentTxReply {
                    next_per_commitment_point: PubKey(next_per_commitment_point.serialize()),
                    old_commitment_secret: old_secret_reply,
                }))
            }
            Message::ValidateCommitmentTx2(m) => {
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                let (received_htlcs, offered_htlcs) = extract_htlcs(&m.htlcs);
                let commit_sig =
                    ecdsa::Signature::from_compact(&m.signature.signature.0).expect("signature");
                assert_eq!(m.signature.sighash, EcdsaSighashType::All as u8);
                let htlc_sigs = m
                    .htlc_signatures
                    .iter()
                    .map(|s| {
                        assert!(
                            s.sighash == EcdsaSighashType::All as u8
                                || s.sighash == EcdsaSighashType::SinglePlusAnyoneCanPay as u8
                        );
                        ecdsa::Signature::from_compact(&s.signature.0).expect("signature")
                    })
                    .collect();
                let (next_per_commitment_point, old_secret) =
                    self.node.with_ready_channel(&self.channel_id, |chan| {
                        chan.validate_holder_commitment_tx_phase2(
                            commit_num,
                            feerate_sat_per_kw,
                            m.to_local_value_sat,
                            m.to_remote_value_sat,
                            offered_htlcs.clone(),
                            received_htlcs.clone(),
                            &commit_sig,
                            &htlc_sigs,
                        )
                    })?;
                let old_secret_reply = old_secret.map(|s| Secret(s[..].try_into().unwrap()));
                Ok(Box::new(msgs::ValidateCommitmentTxReply {
                    next_per_commitment_point: PubKey(next_per_commitment_point.serialize()),
                    old_commitment_secret: old_secret_reply,
                }))
            }
            Message::SignLocalCommitmentTx2(m) => {
                let (sig, htlc_sigs) = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_holder_commitment_tx_phase2(m.commitment_number)
                })?;
                Ok(Box::new(msgs::SignCommitmentTxWithHtlcsReply {
                    signature: to_bitcoin_sig(sig),
                    htlc_signatures: htlc_sigs.into_iter().map(|s| to_bitcoin_sig(s)).collect(),
                }))
            }
            Message::ValidateRevocation(m) => {
                let revoke_num = m.commitment_number;
                let old_secret = SecretKey::from_slice(&m.commitment_secret.0).expect("secret");
                self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.validate_counterparty_revocation(revoke_num, &old_secret)
                })?;
                Ok(Box::new(msgs::ValidateRevocationReply {}))
            }
            Message::SignPenaltyToUs(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(&mut m.psbt.0.as_slice())
                    .expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let revocation_secret =
                    SecretKey::from_slice(&m.revocation_secret.0).expect("secret");
                let redeemscript = Script::from(m.wscript);
                let input = 0;
                let htlc_amount_sat = psbt.inputs[input]
                    .witness_utxo
                    .as_ref()
                    .expect("will only spend witness UTXOs")
                    .value;
                let wallet_paths = extract_psbt_output_paths(&psbt);
                let sig = self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.sign_justice_sweep(
                        &tx,
                        input,
                        &revocation_secret,
                        &redeemscript,
                        htlc_amount_sat,
                        &wallet_paths[0],
                    )
                })?;
                Ok(Box::new(msgs::SignTxReply {
                    signature: BitcoinSignature {
                        signature: Signature(sig.serialize_compact()),
                        sighash: EcdsaSighashType::All as u8,
                    },
                }))
            }
            Message::SignChannelAnnouncement(m) => {
                let message = m.announcement[256 + 2..].to_vec();
                let (node_sig, bitcoin_sig) =
                    self.node.with_ready_channel(&self.channel_id, |chan| {
                        Ok(chan.sign_channel_announcement(&message))
                    })?;
                Ok(Box::new(msgs::SignChannelAnnouncementReply {
                    node_signature: Signature(node_sig.serialize_compact()),
                    bitcoin_signature: Signature(bitcoin_sig.serialize_compact()),
                }))
            }
            Message::Unknown(u) => {
                unimplemented!("cloop {}: unknown message type {}", self.id, u.message_type)
            }
            m => unimplemented!("cloop {}: unimplemented message {:?}", self.id, m),
        }
    }

    fn client_id(&self) -> u64 {
        self.id
    }

    fn for_new_client(&self, _client_id: u64, _peer_id: PubKey, _dbid: u64) -> ChannelHandler {
        unimplemented!("cannot create a sub-handler from a channel handler");
    }
}

fn extract_pubkey(key: &PubKey) -> PublicKey {
    PublicKey::from_slice(&key.0).expect("pubkey")
}

fn extract_commitment_type(channel_type: &Vec<u8>) -> CommitmentType {
    // The byte/bit order from the wire is wrong in every way ...
    let features = BitVec::from_bytes(
        &channel_type.iter().rev().map(|bb| bb.reverse_bits()).collect::<Vec<u8>>(),
    );
    if features.get(OPT_ANCHORS_ZERO_FEE_HTLC_TX).unwrap_or_default() {
        assert_eq!(features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default(), true);
        CommitmentType::AnchorsZeroFeeHtlc
    } else if features.get(OPT_ANCHOR_OUTPUTS).unwrap_or_default() {
        assert_eq!(features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default(), true);
        CommitmentType::Anchors
    } else if features.get(OPT_STATIC_REMOTEKEY).unwrap_or_default() {
        CommitmentType::StaticRemoteKey
    } else {
        CommitmentType::Legacy
    }
}

fn extract_psbt_witscripts(psbt: &PartiallySignedTransaction) -> Vec<Vec<u8>> {
    psbt.outputs
        .iter()
        .map(|o| o.witness_script.clone().unwrap_or(Script::new()))
        .map(|s| s[..].to_vec())
        .collect()
}

fn extract_htlcs(htlcs: &Vec<Htlc>) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
    let offered_htlcs: Vec<HTLCInfo2> = htlcs
        .iter()
        .filter(|h| h.side == Htlc::LOCAL)
        .map(|h| HTLCInfo2 {
            value_sat: h.amount / 1000,
            payment_hash: PaymentHash(h.payment_hash.0),
            cltv_expiry: h.ctlv_expiry,
        })
        .collect();
    let received_htlcs: Vec<HTLCInfo2> = htlcs
        .iter()
        .filter(|h| h.side == Htlc::REMOTE)
        .map(|h| HTLCInfo2 {
            value_sat: h.amount / 1000,
            payment_hash: PaymentHash(h.payment_hash.0),
            cltv_expiry: h.ctlv_expiry,
        })
        .collect();
    (received_htlcs, offered_htlcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der() {
        let sig = [
            83, 1, 22, 118, 14, 225, 143, 45, 119, 59, 51, 81, 117, 109, 12, 76, 141, 142, 137,
            167, 117, 28, 98, 150, 245, 134, 254, 105, 172, 236, 170, 4, 24, 195, 101, 175, 186,
            97, 224, 127, 128, 202, 94, 58, 56, 171, 51, 106, 153, 217, 229, 22, 217, 94, 169, 47,
            55, 71, 237, 36, 128, 102, 148, 61,
        ];
        ecdsa::Signature::from_compact(&sig).expect("signature");
    }

    #[test]
    fn test_extract_commitment_type() {
        assert_eq!(
            extract_commitment_type(&vec![0x10_u8, 0x10_u8, 0x00_u8]),
            CommitmentType::Anchors
        );
        assert_eq!(
            extract_commitment_type(&vec![0x10_u8, 0x00_u8]),
            CommitmentType::StaticRemoteKey
        );
        assert_eq!(extract_commitment_type(&vec![0x00_u8, 0x00_u8]), CommitmentType::Legacy);
    }

    #[test]
    #[should_panic]
    fn test_extract_commitment_type_panic() {
        extract_commitment_type(&vec![0x10_u8, 0x00_u8, 0x00_u8]);
    }
}
