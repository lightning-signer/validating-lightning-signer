use std::collections::BTreeMap;
use std::convert::TryInto;

use bitcoin::{Network, Script, SigHashType};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::psbt::serialize::Deserialize;
#[allow(unused_imports)]
use log::info;
use secp256k1::{PublicKey, Secp256k1};
use secp256k1::rand::rngs::OsRng;
use serde::Serialize;

use greenlight_protocol::{msgs, msgs::Message, Result};
use greenlight_protocol::model::{Basepoints, BitcoinSignature, ExtKey, PubKey, PubKey32, RecoverableSignature, Secret, Signature, Htlc};
use greenlight_protocol::msgs::TypedMessage;
use greenlight_protocol::serde_bolt::LargeBytes;
use lightning_signer::Arc;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::{OutPoint, Transaction};
use lightning_signer::bitcoin::consensus::{Decodable, Encodable};
use lightning_signer::bitcoin::util::bip32::{ChildNumber, KeySource};
use lightning_signer::bitcoin::util::psbt::PartiallySignedTransaction;
use lightning_signer::channel::{ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::node::{Node, NodeConfig, SpendType};
use lightning_signer::persist::Persist;
use lightning_signer::signer::my_keys_manager::KeyDerivationStyle;
use lightning_signer::tx::tx::HTLCInfo2;
use lightning_signer::util::status;

use crate::client::Client;

pub(crate) trait Handler<C: Client> {
    fn handle(&mut self, msg: Message);
    fn client_id(&self) -> u64;
    fn read(&mut self) -> Result<Message>;
    fn write<M: TypedMessage + Serialize>(&mut self, msg: M) -> Result<()>;
    fn with_new_client(&mut self, peer_id: PubKey, dbid: u64) -> ChannelHandler<C>;
}

/// Protocol handler
pub(crate) struct RootHandler<C: Client> {
    pub(crate) client: C,
    pub(crate) node: Arc<Node>
}

impl<C: Client> RootHandler<C> {
    pub(crate) fn new(client: C, seed_opt: Option<[u8; 32]>, persister: Arc<dyn Persist>) -> Self {
        let config = NodeConfig {
            network: Network::Testnet,
            key_derivation_style: KeyDerivationStyle::Native
        };

        let seed = seed_opt.expect("expected a seed");

        let nodes = persister.get_nodes();
        let node = if nodes.is_empty() {
            let node = Arc::new(Node::new(config, &seed, &persister, vec![]));
            persister.new_node(&node.get_id(), &config, &seed);
            node
        } else {
            assert_eq!(nodes.len(), 1);
            let (node_id, entry) = nodes.into_iter().next().unwrap();
            Node::restore_node(&node_id, entry, persister)
        };

        Self {
            client,
            node
        }
    }
}

impl<C: Client> Handler<C> for RootHandler<C> {
    fn handle(&mut self, msg: Message) {
        match msg {
            Message::Memleak(m) => {
                self.client.write(msgs::MemleakReply { result: false }).unwrap();
            }
            Message::HsmdInit(_) => {
                let bip32 = self.node.get_account_extended_pubkey().encode();
                let node_id = self.node.get_id().serialize();
                let secp = Secp256k1::new();
                let mut rng = OsRng::new().unwrap();
                let (_, bolt12_pubkey) = secp.generate_schnorrsig_keypair(&mut rng);
                let bolt12_xonly = bolt12_pubkey.serialize();
                self.client.write(msgs::HsmdInitReply {
                    node_id: PubKey(node_id),
                    bip32: ExtKey(bip32),
                    bolt12: PubKey32(bolt12_xonly),
                }).unwrap();
            }
            Message::Ecdh(m) => {
                let pubkey =
                    PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                self.client.write(msgs::EcdhReply { secret: Secret(secret) }).expect("write");
            }
            Message::NewChannel(m) => {
                let _peer_id = extract_pubkey(&m.node_id);
                let channel_id = extract_channel_id(m.dbid);
                // TODO mix in the peer_id
                let nonce = m.dbid.to_le_bytes();
                self.node.new_channel(Some(channel_id), Some(nonce.to_vec()), &self.node).expect("new_channel");
                self.client.write(msgs::NewChannelReply {}).expect("write");
            }
            Message::GetChannelBasepoints(m) => {
                let peer_id = extract_pubkey(&m.node_id);
                let channel_id = extract_channel_id(m.dbid);
                let bps = self.node
                    .with_channel_base(&channel_id, |base| {
                        Ok(base.get_channel_basepoints())
                    }).expect("basepoints");


                let basepoints = Basepoints {
                    revocation: PubKey(bps.revocation_basepoint.serialize()),
                    payment: PubKey(bps.payment_point.serialize()),
                    htlc: PubKey(bps.htlc_basepoint.serialize()),
                    delayed_payment: PubKey(bps.delayed_payment_basepoint.serialize()),
                };
                let funding = PubKey(bps.funding_pubkey.serialize());

                self.client.write(msgs::GetChannelBasepointsReply { basepoints, funding }).expect("write");
            }
            Message::SignWithdrawal(m) => {
                let mut psbt = PartiallySignedTransaction::consensus_decode(m.psbt.0.as_slice()).expect("psbt");
                let tx = psbt.clone().extract_tx();
                let ipaths = m.utxos.iter()
                    .map(|u| vec![u.keyindex]).collect();
                let values_sat = m.utxos.iter()
                    .map(|u| u.amount).collect();
                let spendtypes = m.utxos.iter()
                    .map(|u| if u.is_p2sh { SpendType::P2shP2wpkh } else { SpendType::P2wpkh }).collect();
                let uniclosekeys = m.utxos.iter()
                    .map(|u| None).collect(); // TODO
                let opaths = psbt.outputs.iter()
                    .map(|o| extract_output_path(&o.bip32_derivation)).collect();
                let witvec = self.node.sign_funding_tx(
                    &tx,
                    &ipaths,
                    &values_sat,
                    &spendtypes,
                    &uniclosekeys,
                    &opaths,
                ).expect("sign funding");

                for (i, (sig, pubkey)) in witvec.into_iter().enumerate() {
                    if !sig.is_empty() {
                        psbt.inputs[i].final_script_witness = Some(vec![sig, pubkey]);
                    }
                }

                let mut ser_psbt = Vec::new();
                psbt.consensus_encode(&mut ser_psbt).expect("serialize psbt");
                self.client.write(msgs::SignWithdrawalReply {
                    psbt: LargeBytes(ser_psbt)
                }).expect("write");
            }
            Message::SignInvoice(m) => {
                let hrp = String::from_utf8(m.hrp).expect("hrp");
                let sig = self.node.sign_invoice_in_parts(&m.u5bytes, &hrp).expect("sign_channel_update");
                let mut sig_slice = [0u8; 65];
                sig_slice.copy_from_slice(&sig);
                self.client.write(msgs::SignInvoiceReply {
                    signature: RecoverableSignature(sig_slice)
                }).expect("write");
            }
            Message::SignNodeAnnouncement(m) => {
                let message = m.announcement[64 + 2..].to_vec();
                let node_sig_der =
                    self.node.sign_node_announcement(&message).expect("sign");
                let sig = secp256k1::Signature::from_der(&node_sig_der).expect("sig");

                self.client.write(msgs::SignNodeAnnouncementReply {
                    node_signature: Signature(sig.serialize_compact()),
                }).expect("write");
            }
            Message::Unknown(u) => unimplemented!("loop {}: unknown message type {}", self.client.id(), u.message_type),
            m => unimplemented!("loop {}: unimplemented message {:?}", self.client.id(), m),
        }
    }

    fn client_id(&self) -> u64 {
        self.client.id()
    }

    fn read(&mut self) -> Result<Message> {
        self.client.read()
    }

    fn write<M: TypedMessage + Serialize>(&mut self, msg: M) -> Result<()> {
        self.client.write(msg)
    }

    fn with_new_client(&mut self, peer_id: PubKey, dbid: u64) -> ChannelHandler<C> {
        let new_client = self.client.new_client();
        ChannelHandler {
            client: new_client,
            node: Arc::clone(&self.node),
            peer_id: PublicKey::from_slice(&peer_id.0).expect("peer_id"),
            dbid,
            channel_id: extract_channel_id(dbid),
        }
    }
}

fn extract_output_path(x: &BTreeMap<bitcoin::util::ecdsa::PublicKey, KeySource>) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    if x.len() > 1 {
        panic!("len > 1");
    }
    let (fingerprint, path) = x.iter().next().unwrap().1;
    let segments: Vec<ChildNumber> = path.clone().into();
    segments.into_iter().map(|c| u32::from(c)).collect()
}

/// Protocol handler
pub(crate) struct ChannelHandler<C: Client> {
    pub(crate) client: C,
    pub(crate) node: Arc<Node>,
    #[allow(dead_code)]
    pub(crate) peer_id: PublicKey,
    #[allow(dead_code)]
    pub(crate) dbid: u64,
    pub(crate) channel_id: ChannelId,
}

impl<C: Client> Handler<C> for ChannelHandler<C> {
    fn handle(&mut self, msg: Message) {
        match msg {
            Message::Memleak(m) => {
                self.client.write(msgs::MemleakReply { result: false }).unwrap();
            }
            Message::Ecdh(m) => {
                // TODO DRY with root handler
                let pubkey =
                    PublicKey::from_slice(&m.point.0).expect("pubkey");
                let secret = self.node.ecdh(&pubkey).as_slice().try_into().unwrap();
                self.client.write(msgs::EcdhReply { secret: Secret(secret) }).expect("write");
            }
            Message::GetPerCommitmentPoint(m)  => {
                let commitment_number = m.commitment_number;
                let res: core::result::Result<(PublicKey, Option<SecretKey>), status::Status> = self.node
                    .with_channel_base(&self.channel_id, |base| {
                        let point = base.get_per_commitment_point(commitment_number)?;
                        let secret = if commitment_number >= 2 {
                            Some(base.get_per_commitment_secret(commitment_number - 2)?)
                        } else {
                            None
                        };
                        Ok((point, secret))
                    });

                let (point, old_secret) = res.expect("per_commit");

                let pointdata = point.serialize().to_vec();

                let old_secret_reply = old_secret.clone().map(|s| Secret(s[..].try_into().unwrap()));
                self.client.write(msgs::GetPerCommitmentPointReply { point: PubKey(point.serialize()), secret: old_secret_reply }).expect("write");
            }
            Message::ReadyChannel(m) => {
                let txid = bitcoin::Txid::from_slice(&m.funding_txid.0).expect("txid");
                let funding_outpoint = OutPoint {
                    txid,
                    vout: m.funding_txout as u32,
                };

                let holder_shutdown_script = if m.local_shutdown_script.is_empty() {
                    None
                } else {
                    Some(
                        Script::deserialize(&m.local_shutdown_script.as_slice()).expect("script"),
                    )
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
                    Some(
                        Script::deserialize(&m.remote_shutdown_script.as_slice()).expect("script"),
                    )
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
                    commitment_type: extract_commitment_type(m.option_static_remotekey, m.option_anchor_outputs),
                };
                self.node.ready_channel(
                    self.channel_id,
                    None,
                    setup,
                    &holder_shutdown_key_path,
                ).expect("ready_channel");

                self.client.write(msgs::ReadyChannelReply {}).expect("write");
            }
            Message::SignRemoteHtlcTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(m.psbt.0.as_slice()).expect("psbt");
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
                    .witness_utxo.as_ref().expect("will only spend witness UTXOs")
                    .value;
                let output_witscript = psbt.outputs[0].
                    witness_script.as_ref().expect("output witscript");
                let sig = self.node
                    .with_ready_channel(&self.channel_id, |chan| {
                        chan.sign_counterparty_htlc_tx(
                            &tx,
                            &remote_per_commitment_point,
                            &redeemscript,
                            htlc_amount_sat,
                            &output_witscript,
                        )
                    }).expect("sign");
                self.client.write(msgs::SignTxReply {
                    signature: BitcoinSignature
                    {
                        signature: Signature(sig.serialize_compact()),
                        sighash: SigHashType::All as u8
                    }
                }).expect("write");
            }
            Message::SignRemoteCommitmentTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(m.psbt.0.as_slice()).expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let witscripts = extract_witscripts(psbt);
                let remote_per_commitment_point =
                    PublicKey::from_slice(&m.remote_per_commitment_point.0).expect("pubkey");
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                // Flip offered and received
                let (offered_htlcs, received_htlcs) = extract_htlcs(&m.htlcs);
                let sig = self.node
                    .with_ready_channel(&self.channel_id, |chan| {
                        chan.sign_counterparty_commitment_tx(
                            &tx,
                            &witscripts,
                            &remote_per_commitment_point,
                            commit_num,
                            feerate_sat_per_kw,
                            offered_htlcs.clone(),
                            received_htlcs.clone(),
                        )
                    }).unwrap();
                self.client.write(msgs::SignTxReply {
                    signature: BitcoinSignature
                    {
                        signature: Signature(sig.serialize_compact()),
                        sighash: SigHashType::All as u8
                    }
                }).expect("write");
            }
            Message::ValidateCommitmentTx(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(m.psbt.0.as_slice()).expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let witscripts = extract_witscripts(psbt);
                let commit_num = m.commitment_number;
                let feerate_sat_per_kw = m.feerate;
                let (received_htlcs, offered_htlcs) = extract_htlcs(&m.htlcs);
                let commit_sig = secp256k1::Signature::from_compact(&m.signature.signature.0).expect("signature");
                assert_eq!(m.signature.sighash, SigHashType::All as u8);
                let htlc_sigs = m.htlc_signatures.iter()
                    .map(|s| {
                        assert_eq!(s.sighash, SigHashType::All as u8);
                        secp256k1::Signature::from_compact(&s.signature.0).expect("signature")
                    })
                    .collect();
                let (next_per_commitment_point, old_secret) =
                    self.node
                        .with_ready_channel(&self.channel_id, |chan| {
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
                        }).expect("ready_channel");
                let old_secret_reply = old_secret.map(|s| Secret(s[..].try_into().unwrap()));
                self.client.write(msgs::ValidateCommitmentTxReply {
                    next_per_commitment_point: PubKey(next_per_commitment_point.serialize()),
                    old_commitment_secret: old_secret_reply,
                }).expect("write");
            }
            Message::ValidateRevocation(m) => {
                let revoke_num = m.commitment_number;
                let old_secret = SecretKey::from_slice(&m.commitment_secret.0).expect("secret");
                self.node.with_ready_channel(&self.channel_id, |chan| {
                    chan.validate_counterparty_revocation(revoke_num, &old_secret)
                }).expect("validate");
                self.client.write(msgs::ValidateRevocationReply {}).expect("write");
            }
            Message::SignPenaltyToUs(m) => {
                let psbt = PartiallySignedTransaction::consensus_decode(m.psbt.0.as_slice()).expect("psbt");
                let mut tx_bytes = m.tx.0.clone();
                let tx = deserialize(&mut tx_bytes).expect("tx");
                let revocation_secret = SecretKey::from_slice(&m.revocation_secret.0).expect("secret");
                let redeemscript = Script::from(m.wscript);
                let input = 0;
                let htlc_amount_sat = psbt.inputs[input]
                    .witness_utxo.as_ref().expect("will only spend witness UTXOs")
                    .value;
                let sig = self
                    .node
                    .with_ready_channel(&self.channel_id, |chan| {
                        chan.sign_justice_sweep(
                            &tx,
                            input,
                            &revocation_secret,
                            &redeemscript,
                            htlc_amount_sat,
                        )
                    }).expect("sign");
                self.client.write(msgs::SignTxReply {
                    signature: BitcoinSignature
                    {
                        signature: Signature(sig.serialize_compact()),
                        sighash: SigHashType::All as u8
                    }
                }).expect("write");
            }
            Message::SignChannelUpdate(m) => {
                let message = m.update[2+64..].to_vec();
                let sig_data_der = self.node.sign_channel_update(&message).expect("sign_channel_update");
                let sig = secp256k1::Signature::from_der(&sig_data_der).expect("sig");
                let mut update = m.update;
                update[2..2+64].copy_from_slice(&sig.serialize_compact());
                self.client.write(msgs::SignChannelUpdateReply { update }).expect("write");
            }
            Message::SignChannelAnnouncement(m) => {
                let message = m.announcement[256 + 2..].to_vec();
                let (node_sig, bitcoin_sig) = self.node.with_ready_channel(&self.channel_id, |chan| {
                    Ok(chan.sign_channel_announcement(&message))
                }).expect("sign");
                self.client.write(msgs::SignChannelAnnouncementReply {
                    node_signature: Signature(node_sig.serialize_compact()),
                    bitcoin_signature: Signature(bitcoin_sig.serialize_compact())
                }).expect("write");
            }
            Message::SignNodeAnnouncement(m) => {
                // TODO DRY (and why is this called in the per-channel handler??)
                let message = m.announcement[64 + 2..].to_vec();
                let node_sig_der =
                    self.node.sign_node_announcement(&message).expect("sign");
                let sig = secp256k1::Signature::from_der(&node_sig_der).expect("sig");

                self.client.write(msgs::SignNodeAnnouncementReply {
                    node_signature: Signature(sig.serialize_compact()),
                }).expect("write");
            }
            Message::Unknown(u) => unimplemented!("cloop {}: unknown message type {}", self.client.id(), u.message_type),
            m => unimplemented!("cloop {}: unimplemented message {:?}", self.client.id(), m),
        }
    }

    fn client_id(&self) -> u64 {
        self.client.id()
    }

    fn read(&mut self) -> Result<Message> {
        self.client.read()
    }

    fn write<M: TypedMessage + Serialize>(&mut self, msg: M) -> Result<()> {
        self.client.write(msg)
    }

    fn with_new_client(&mut self, peer_id: PubKey, dbid: u64) -> ChannelHandler<C> {
        unimplemented!("cannot create a sub-handler from a channel handler");
    }
}

fn extract_channel_id(dbid: u64) -> ChannelId {
    ChannelId(Sha256Hash::hash(&dbid.to_le_bytes()).into_inner())
}

fn extract_pubkey(key: &PubKey) -> PublicKey {
    PublicKey::from_slice(&key.0).expect("pubkey")
}

fn extract_commitment_type(static_remotekey: bool, anchor_outputs: bool) -> CommitmentType {
    if anchor_outputs {
        CommitmentType::Anchors
    } else if static_remotekey {
        CommitmentType::StaticRemoteKey
    } else {
        CommitmentType::Legacy
    }
}

fn extract_witscripts(psbt: PartiallySignedTransaction) -> Vec<Vec<u8>> {
    psbt.outputs.iter()
        .map(|o| o.witness_script.clone().unwrap_or(Script::new()))
        .map(|s| s[..].to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_der() {
        let sig = [83, 1, 22, 118, 14, 225, 143, 45, 119, 59, 51, 81, 117, 109, 12, 76, 141, 142, 137, 167, 117, 28, 98, 150, 245, 134, 254, 105, 172, 236, 170, 4, 24, 195, 101, 175, 186, 97, 224, 127, 128, 202, 94, 58, 56, 171, 51, 106, 153, 217, 229, 22, 217, 94, 169, 47, 55, 71, 237, 36, 128, 102, 148, 61];
        secp256k1::Signature::from_compact(&sig).expect("signature");
    }
}

fn extract_htlcs(htlcs: &Vec<Htlc>) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
    let offered_htlcs: Vec<HTLCInfo2> = htlcs.iter()
        .filter(|h| h.state < 10)
        .map(|h|
            HTLCInfo2 {
                value_sat: h.amount / 1000,
                payment_hash: PaymentHash(h.payment_hash.0),
                cltv_expiry: h.ctlv_expiry
            }
        ).collect();
    let received_htlcs: Vec<HTLCInfo2> = htlcs.iter()
        .filter(|h| h.state >= 10)
        .map(|h|
            HTLCInfo2 {
                value_sat: h.amount / 1000,
                payment_hash: PaymentHash(h.payment_hash.0),
                cltv_expiry: h.ctlv_expiry
            }
        ).collect();
    (received_htlcs, offered_htlcs)
}
