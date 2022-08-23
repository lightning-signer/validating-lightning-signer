use std::any::Any;
use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bit_vec::BitVec;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa::Signature, All, PublicKey, Scalar, Secp256k1, SecretKey,
};
use bitcoin::Transaction;
use lightning::chain::keysinterface::KeysInterface;
use lightning::chain::keysinterface::{BaseSign, Sign};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::ln::PaymentPreimage;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::util::bip32::ChildNumber;
use lightning_signer::lightning;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::util::INITIAL_COMMITMENT_NUMBER;
use log::{debug, error};

use vls_protocol::features::{OPT_ANCHOR_OUTPUTS, OPT_MAX, OPT_STATIC_REMOTEKEY};
use vls_protocol::model::{
    Basepoints, BitcoinSignature, CloseInfo, Htlc, PubKey, Secret, TxId, Utxo,
};
use vls_protocol::msgs::{
    DeBolt, GetChannelBasepoints, GetChannelBasepointsReply, GetPerCommitmentPoint,
    GetPerCommitmentPoint2, GetPerCommitmentPoint2Reply, GetPerCommitmentPointReply, HsmdInit2,
    HsmdInit2Reply, NewChannel, NewChannelReply, ReadyChannel, ReadyChannelReply, SerBolt,
    SignChannelAnnouncement, SignChannelAnnouncementReply, SignCommitmentTxWithHtlcsReply,
    SignInvoice, SignInvoiceReply, SignLocalCommitmentTx2, SignMutualCloseTx2,
    SignRemoteCommitmentTx2, SignTxReply, SignWithdrawal, SignWithdrawalReply,
    ValidateCommitmentTx2, ValidateCommitmentTxReply, ValidateRevocation, ValidateRevocationReply,
};
use vls_protocol::serde_bolt::{LargeBytes, WireString};
use vls_protocol::{model, Error as ProtocolError};

use bitcoin::bech32::u5;
use bitcoin::secp256k1::ecdsa::{self, RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{consensus, EcdsaSighashType, Script, WPubkeyHash};
use lightning::chain::keysinterface::{KeyMaterial, Recipient, SpendableOutputDescriptor};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use lightning::util::ser::{Writeable, Writer};

mod dyn_signer;
pub mod signer_port;

pub use dyn_signer::{DynKeysInterface, DynSigner, InnerSign, SpendableKeysInterface};
use lightning::util::ser::Readable;
pub use signer_port::SignerPort;

#[derive(Debug)]
pub enum Error {
    ProtocolError(ProtocolError),
    TransportError,
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::ProtocolError(e)
    }
}

pub trait Transport: Send + Sync {
    /// Perform a call for the node API
    fn node_call(&self, message: Vec<u8>) -> Result<Vec<u8>, Error>;
    /// Perform a call for the channel API
    fn call(&self, dbid: u64, peer_id: PubKey, message: Vec<u8>) -> Result<Vec<u8>, Error>;
}

#[derive(Clone)]
pub struct SignerClient {
    transport: Arc<dyn Transport>,
    peer_id: [u8; 33],
    dbid: u64,
    channel_keys: ChannelPublicKeys,
    channel_value: u64,
}

fn from_pubkey(pubkey: PubKey) -> PublicKey {
    PublicKey::from_slice(&pubkey.0).unwrap()
}

fn to_pubkey(pubkey: PublicKey) -> PubKey {
    PubKey(pubkey.serialize())
}

fn to_bitcoin_sig(sig: &ecdsa::Signature) -> BitcoinSignature {
    BitcoinSignature {
        signature: model::Signature(sig.serialize_compact()),
        sighash: EcdsaSighashType::All as u8,
    }
}

pub fn call<T: SerBolt, R: DeBolt>(
    dbid: u64,
    peer_id: PubKey,
    transport: &dyn Transport,
    message: T,
) -> Result<R, Error> {
    assert_ne!(dbid, 0, "dbid 0 is reserved");
    let message_ser = message.as_vec();
    debug!("signer call {:?}", message);
    let result_ser = transport.call(dbid, peer_id, message_ser)?;
    let result = R::from_vec(result_ser)?;
    debug!("signer result {:?}", result);
    Ok(result)
}

pub fn node_call<T: SerBolt, R: DeBolt>(transport: &dyn Transport, message: T) -> Result<R, Error> {
    debug!("signer call {:?}", message);
    let message_ser = message.as_vec();
    let result_ser = transport.node_call(message_ser)?;
    let result = R::from_vec(result_ser)?;
    debug!("signer result {:?}", result);
    Ok(result)
}

fn to_htlcs(htlcs: &Vec<HTLCOutputInCommitment>, is_remote: bool) -> Vec<Htlc> {
    let htlcs = htlcs
        .iter()
        .map(|h| Htlc {
            side: if h.offered != is_remote { Htlc::LOCAL } else { Htlc::REMOTE },
            amount: h.amount_msat,
            payment_hash: model::Sha256(h.payment_hash.0),
            ctlv_expiry: h.cltv_expiry,
        })
        .collect();
    htlcs
}

fn dest_wallet_path() -> Vec<u32> {
    let result = vec![1];
    // elsewhere we assume that the path has a single component
    assert_eq!(result.len(), 1);
    result
}

fn dbid_to_channel_id(dbid: u64) -> [u8; 32] {
    let mut res = [0; 32];
    let ser_dbid = dbid.to_le_bytes();
    res[0..8].copy_from_slice(&ser_dbid);
    res
}

fn channel_id_to_dbid(slice: &[u8; 32]) -> u64 {
    let mut s = [0; 8];
    s.copy_from_slice(&slice[0..8]);
    u64::from_le_bytes(s)
}

impl SignerClient {
    fn call<T: SerBolt, R: DeBolt>(&self, message: T) -> Result<R, Error> {
        call(self.dbid, PubKey(self.peer_id), &*self.transport, message).map_err(|e| {
            error!("transport error: {:?}", e);
            e
        })
    }

    fn new(
        transport: Arc<dyn Transport>,
        peer_id: [u8; 33],
        dbid: u64,
        channel_value: u64,
        channel_keys: ChannelPublicKeys,
    ) -> Self {
        SignerClient { transport, peer_id, dbid, channel_keys, channel_value }
    }
}

impl Writeable for SignerClient {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.peer_id.write(writer)?;
        self.dbid.write(writer)?;
        self.channel_keys.write(writer)?;
        self.channel_value.write(writer)?;
        Ok(())
    }
}

impl Sign for SignerClient {}

impl BaseSign for SignerClient {
    fn get_per_commitment_point(&self, idx: u64, _secp_ctx: &Secp256k1<All>) -> PublicKey {
        let message = GetPerCommitmentPoint2 { commitment_number: INITIAL_COMMITMENT_NUMBER - idx };
        let result: GetPerCommitmentPoint2Reply =
            self.call(message).expect("get_per_commitment_point");
        PublicKey::from_slice(&result.point.0).expect("public key")
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        // Getting the point at idx + 2 releases the secret at idx
        let message =
            GetPerCommitmentPoint { commitment_number: INITIAL_COMMITMENT_NUMBER - idx + 2 };
        let result: GetPerCommitmentPointReply =
            self.call(message).expect("get_per_commitment_point");
        let secret = result.secret.expect("secret not released");
        secret.0
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        _preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        // TODO preimage handling
        let tx = holder_tx.trust();
        let htlcs = to_htlcs(tx.htlcs(), false);
        let message = ValidateCommitmentTx2 {
            commitment_number: INITIAL_COMMITMENT_NUMBER - tx.commitment_number(),
            feerate: tx.feerate_per_kw(),
            to_local_value_sat: tx.to_broadcaster_value_sat(),
            to_remote_value_sat: tx.to_countersignatory_value_sat(),
            htlcs,
            signature: to_bitcoin_sig(&holder_tx.counterparty_sig),
            htlc_signatures: holder_tx
                .counterparty_htlc_sigs
                .iter()
                .map(|s| to_bitcoin_sig(s))
                .collect(),
        };
        let _: ValidateCommitmentTxReply = self.call(message).map_err(|_| ())?;
        Ok(())
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.channel_keys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        dbid_to_channel_id(self.dbid)
    }

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        _preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        // TODO preimage handling
        let tx = commitment_tx.trust();
        let htlcs = to_htlcs(tx.htlcs(), true);
        let message = SignRemoteCommitmentTx2 {
            remote_per_commitment_point: to_pubkey(tx.keys().per_commitment_point),
            commitment_number: INITIAL_COMMITMENT_NUMBER - tx.commitment_number(),
            feerate: tx.feerate_per_kw(),
            to_local_value_sat: tx.to_countersignatory_value_sat(),
            to_remote_value_sat: tx.to_broadcaster_value_sat(),
            htlcs,
        };
        let result: SignCommitmentTxWithHtlcsReply = self.call(message).map_err(|_| ())?;
        let signature = Signature::from_compact(&result.signature.signature.0).map_err(|_| ())?;
        let htlc_signatures = result
            .htlc_signatures
            .iter()
            .map(|s| Signature::from_compact(&s.signature.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Ok((signature, htlc_signatures))
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        let message = ValidateRevocation {
            commitment_number: INITIAL_COMMITMENT_NUMBER - idx,
            commitment_secret: Secret(secret[..].try_into().unwrap()),
        };
        let _: ValidateRevocationReply = self.call(message).map_err(|_| ())?;
        Ok(())
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let message = SignLocalCommitmentTx2 {
            commitment_number: INITIAL_COMMITMENT_NUMBER - commitment_tx.commitment_number(),
        };
        let result: SignCommitmentTxWithHtlcsReply = self.call(message).map_err(|_| ())?;
        let signature = Signature::from_compact(&result.signature.signature.0).map_err(|_| ())?;
        let htlc_signatures = result
            .htlc_signatures
            .iter()
            .map(|s| Signature::from_compact(&s.signature.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Ok((signature, htlc_signatures))
    }

    #[cfg(feature = "test_utils")]
    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        _commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        unimplemented!()
    }

    #[allow(unused)]
    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    #[allow(unused)]
    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    #[allow(unused)]
    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    fn sign_closing_transaction(
        &self,
        tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let message = SignMutualCloseTx2 {
            to_local_value_sat: tx.to_holder_value_sat(),
            to_remote_value_sat: tx.to_counterparty_value_sat(),
            local_script: tx.to_holder_script().clone().into_bytes(),
            remote_script: tx.to_counterparty_script().clone().into_bytes(),
            local_wallet_path_hint: dest_wallet_path(),
        };
        let result: SignTxReply = self.call(message).map_err(|_| ())?;
        Ok(Signature::from_compact(&result.signature.signature.0).unwrap())
    }

    fn sign_channel_announcement(
        &self,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Signature), ()> {
        // Prepend a fake prefix to match CLN behavior
        let mut announcement = [0u8; 258].to_vec();
        announcement.extend(msg.encode());
        let message = SignChannelAnnouncement { announcement };
        let result: SignChannelAnnouncementReply = self.call(message).map_err(|_| ())?;
        Ok((
            Signature::from_compact(&result.node_signature.0).unwrap(),
            Signature::from_compact(&result.bitcoin_signature.0).unwrap(),
        ))
    }

    fn ready_channel(&mut self, p: &ChannelTransactionParameters) {
        let funding = p.funding_outpoint.expect("funding should exist at this point");
        let cp = p
            .counterparty_parameters
            .as_ref()
            .expect("counterparty params should exist at this point");

        let mut channel_features = BitVec::from_elem(OPT_MAX, false);
        channel_features.set(OPT_STATIC_REMOTEKEY, true);
        if p.opt_anchors.is_some() {
            channel_features.set(OPT_ANCHOR_OUTPUTS, true);
        }
        let message = ReadyChannel {
            is_outbound: p.is_outbound_from_holder,
            channel_value: self.channel_value,
            push_value: 0, // TODO
            funding_txid: TxId(funding.txid.into_inner().as_slice().try_into().unwrap()),
            funding_txout: funding.index,
            to_self_delay: p.holder_selected_contest_delay,
            local_shutdown_script: vec![], // TODO
            local_shutdown_wallet_index: None,
            remote_basepoints: Basepoints {
                revocation: to_pubkey(cp.pubkeys.revocation_basepoint),
                payment: to_pubkey(cp.pubkeys.payment_point),
                htlc: to_pubkey(cp.pubkeys.htlc_basepoint),
                delayed_payment: to_pubkey(cp.pubkeys.delayed_payment_basepoint),
            },
            remote_funding_pubkey: to_pubkey(cp.pubkeys.funding_pubkey),
            remote_to_self_delay: cp.selected_contest_delay,
            remote_shutdown_script: vec![], // TODO
            channel_type: channel_features.to_bytes(),
        };

        let _: ReadyChannelReply = self.call(message).expect("ready channel");
    }
}

pub struct KeysManagerClient {
    transport: Arc<dyn Transport>,
    next_dbid: AtomicU64,
    key_material: KeyMaterial,
    xpub: ExtendedPubKey,
    node_secret: SecretKey,
}

impl KeysManagerClient {
    /// Create a new VLS client with the given transport
    pub fn new(transport: Arc<dyn Transport>, network: String) -> Self {
        let mut rng = OsRng;
        let mut key_material_bytes = [0; 32];
        rng.fill_bytes(&mut key_material_bytes);

        let init_message = HsmdInit2 {
            derivation_style: KeyDerivationStyle::Native as u8,
            dev_seed: None,
            network_name: WireString(network.into_bytes()),
            dev_allowlist: vec![],
        };
        let result: HsmdInit2Reply = node_call(&*transport, init_message).expect("HsmdInit");
        let xpub = ExtendedPubKey::decode(&result.bip32.0).expect("xpub");
        let node_secret = SecretKey::from_slice(&result.node_secret.0).expect("node secret");

        Self {
            transport,
            next_dbid: AtomicU64::new(1),
            key_material: KeyMaterial(key_material_bytes),
            xpub,
            node_secret,
        }
    }

    pub fn call<T: SerBolt, R: DeBolt>(&self, message: T) -> Result<R, Error> {
        node_call(&*self.transport, message)
    }

    fn get_channel_basepoints(&self, dbid: u64, peer_id: [u8; 33]) -> ChannelPublicKeys {
        let message = GetChannelBasepoints { node_id: PubKey(peer_id), dbid };
        let result: GetChannelBasepointsReply = self.call(message).expect("pubkeys");
        let channel_keys = ChannelPublicKeys {
            funding_pubkey: from_pubkey(result.funding),
            revocation_basepoint: from_pubkey(result.basepoints.revocation),
            payment_point: from_pubkey(result.basepoints.payment),
            delayed_payment_basepoint: from_pubkey(result.basepoints.delayed_payment),
            htlc_basepoint: from_pubkey(result.basepoints.htlc),
        };
        channel_keys
    }

    pub fn sign_onchain_tx(
        &self,
        tx: &Transaction,
        descriptors: &[&SpendableOutputDescriptor],
    ) -> Vec<Vec<Vec<u8>>> {
        let utxos = descriptors.into_iter().map(|d| Self::descriptor_to_utxo(*d)).collect();

        let psbt = PartiallySignedTransaction::from_unsigned_tx(tx.clone()).expect("create PSBT");

        let message = SignWithdrawal { utxos, psbt: LargeBytes(consensus::serialize(&psbt)) };
        let result: SignWithdrawalReply = self.call(message).expect("sign failed");
        let result_psbt: PartiallySignedTransaction =
            consensus::deserialize(&result.psbt.0).expect("deserialize PSBT");
        result_psbt.inputs.into_iter().map(|i| i.final_script_witness.unwrap().to_vec()).collect()
    }

    fn descriptor_to_utxo(d: &SpendableOutputDescriptor) -> Utxo {
        let (amount, keyindex, close_info) = match d {
            // Mutual close - we are spending a non-delayed output to us on the shutdown key
            SpendableOutputDescriptor::StaticOutput { output, .. } =>
                (output.value, dest_wallet_path()[0], None), // FIXME this makes some assumptions
            // We force-closed - we are spending a delayed output to us
            SpendableOutputDescriptor::DelayedPaymentOutput(o) => (
                o.output.value,
                0,
                Some(CloseInfo {
                    channel_id: channel_id_to_dbid(&o.channel_keys_id),
                    peer_id: PubKey([0; 33]),
                    commitment_point: Some(to_pubkey(o.per_commitment_point)),
                    option_anchors: false,
                    csv: o.to_self_delay as u32,
                }),
            ),
            // Remote force-closed - we are spending an non-delayed output to us
            SpendableOutputDescriptor::StaticPaymentOutput(o) => (
                o.output.value,
                0,
                Some(CloseInfo {
                    channel_id: channel_id_to_dbid(&o.channel_keys_id),
                    peer_id: PubKey([0; 33]),
                    commitment_point: None,
                    option_anchors: false,
                    csv: 0,
                }),
            ),
        };
        Utxo {
            txid: TxId([0; 32]),
            outnum: 0,
            amount,
            keyindex,
            is_p2sh: false,
            script: vec![],
            close_info,
        }
    }
}

impl KeysInterface for KeysManagerClient {
    type Signer = SignerClient;

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => {
                unimplemented!("no phantom node support");
            }
        }
        Ok(self.node_secret)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        let mut node_secret = self.get_node_secret(recipient)?;
        if let Some(tweak) = tweak {
            node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
        }
        Ok(SharedSecret::new(other_key, &node_secret))
    }

    fn get_destination_script(&self) -> Script {
        let secp_ctx = Secp256k1::new();
        let wallet_path = dest_wallet_path();
        let mut key = self.xpub;
        for i in wallet_path {
            key = key.ckd_pub(&secp_ctx, ChildNumber::from_normal_idx(i).unwrap()).unwrap();
        }
        let pubkey = key.public_key;
        Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        ShutdownScript::try_from(self.get_destination_script()).expect("script")
    }

    fn get_channel_signer(&self, _inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        let dbid = self.next_dbid.fetch_add(1, Ordering::AcqRel);
        // We don't use the peer_id, because it's not easy to get at this point within the LDK framework.
        // The dbid is unique, so that's enough for our purposes.
        let peer_id = [0u8; 33];

        let message = NewChannel { node_id: PubKey(peer_id.clone()), dbid };
        let _: NewChannelReply = self.call(message).expect("NewChannel");

        let channel_keys = self.get_channel_basepoints(dbid, peer_id);

        SignerClient::new(
            self.transport.clone(),
            peer_id,
            dbid,
            channel_value_satoshis,
            channel_keys,
        )
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut rng = OsRng;
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn read_chan_signer(&self, mut reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        let peer_id = Readable::read(&mut reader)?;
        let dbid = Readable::read(&mut reader)?;
        let channel_keys = Readable::read(&mut reader)?;
        let channel_value = Readable::read(&mut reader)?;

        Ok(SignerClient {
            transport: self.transport.clone(),
            peer_id,
            dbid,
            channel_keys,
            channel_value,
        })
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => {
                unimplemented!("phantom nodes not supported")
            }
        }
        let message = SignInvoice {
            u5bytes: invoice_data.iter().map(|u| u.to_u8()).collect(),
            hrp: hrp_bytes.to_vec(),
        };
        let result: SignInvoiceReply = self.call(message).expect("sign_invoice");
        let rid = RecoveryId::from_i32(result.signature.0[64] as i32).expect("recovery ID");
        let sig = &result.signature.0[0..64];
        RecoverableSignature::from_compact(sig, rid).map_err(|_| ())
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.key_material
    }
}

impl InnerSign for SignerClient {
    fn box_clone(&self) -> Box<dyn InnerSign> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        self.write(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbid_test() {
        assert_eq!(channel_id_to_dbid(&dbid_to_channel_id(0x123456)), 0x123456);
    }
}
