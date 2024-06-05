use std::any::Any;
use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::bech32::u5;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa::Signature, All, PublicKey, Scalar, Secp256k1, SecretKey,
};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{EcdsaSighashType, Script, WPubkeyHash};
use bitcoin::{Transaction, TxOut};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::msgs::DecodeError;
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::ln::msgs::UnsignedGossipMessage;
use lightning::ln::script::ShutdownScript;
use lightning::ln::PaymentPreimage;
use lightning::sign::HTLCDescriptor;
use lightning::sign::{ChannelSigner, EcdsaChannelSigner, NodeSigner, WriteableEcdsaChannelSigner};
use lightning::sign::{EntropySource, SignerProvider};
use lightning::sign::{KeyMaterial, Recipient, SpendableOutputDescriptor};
use lightning::util::ser::Readable;
use lightning::util::ser::{Writeable, Writer};
use lightning_signer::bitcoin;
use lightning_signer::channel::CommitmentType;
use lightning_signer::lightning;
use lightning_signer::signer::derive::KeyDerivationStyle;
use lightning_signer::util::INITIAL_COMMITMENT_NUMBER;
use log::{debug, error};

use vls_protocol::model::{
    Basepoints, BitcoinSignature, CloseInfo, DisclosedSecret, Htlc, PubKey, Utxo,
};
use vls_protocol::msgs::{
    DeBolt, Ecdh, EcdhReply, GetChannelBasepoints, GetChannelBasepointsReply,
    GetPerCommitmentPoint, GetPerCommitmentPoint2, GetPerCommitmentPoint2Reply,
    GetPerCommitmentPointReply, HsmdInit2, HsmdInit2Reply, NewChannel, NewChannelReply, SerBolt,
    SetupChannel, SetupChannelReply, SignChannelAnnouncement, SignChannelAnnouncementReply,
    SignCommitmentTxWithHtlcsReply, SignGossipMessage, SignGossipMessageReply, SignInvoice,
    SignInvoiceReply, SignLocalCommitmentTx2, SignMutualCloseTx2, SignRemoteCommitmentTx2,
    SignTxReply, SignWithdrawal, SignWithdrawalReply, ValidateCommitmentTx2,
    ValidateCommitmentTxReply, ValidateRevocation, ValidateRevocationReply,
};
use vls_protocol::serde_bolt::{Array, ArrayBE, Octets, WireString};
use vls_protocol::{model, Error as ProtocolError};
use vls_protocol_signer::util::commitment_type_to_channel_type;

mod dyn_signer;
pub mod signer_port;

pub use dyn_signer::{DynKeysInterface, DynSigner, InnerSign, SpendableKeysInterface};
pub use signer_port::SignerPort;
use vls_protocol::psbt::StreamedPSBT;

#[derive(Debug)]
pub enum Error {
    Protocol(ProtocolError),
    Transport,
}

pub type ClientResult<T> = Result<T, Error>;

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::Protocol(e)
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

fn to_bitcoin_sig(sig: &Signature) -> BitcoinSignature {
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

fn to_htlcs(htlcs: &Vec<HTLCOutputInCommitment>, is_remote: bool) -> Array<Htlc> {
    let htlcs = htlcs
        .iter()
        .map(|h| Htlc {
            side: if h.offered != is_remote { Htlc::LOCAL } else { Htlc::REMOTE },
            amount: h.amount_msat,
            payment_hash: model::Sha256(h.payment_hash.0),
            ctlv_expiry: h.cltv_expiry,
        })
        .collect();
    Array(htlcs)
}

fn dest_wallet_path() -> ArrayBE<u32> {
    let result = vec![1];
    // elsewhere we assume that the path has a single component
    assert_eq!(result.len(), 1);
    result.into()
}

fn dbid_to_channel_id(dbid: u64) -> [u8; 32] {
    let mut res = [0; 32];
    let ser_dbid = dbid.to_be_bytes();
    res[0..8].copy_from_slice(&ser_dbid);
    res
}

fn channel_id_to_dbid(slice: &[u8; 32]) -> u64 {
    let mut s = [0; 8];
    s.copy_from_slice(&slice[0..8]);
    u64::from_be_bytes(s)
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

impl WriteableEcdsaChannelSigner for SignerClient {}

impl EcdsaChannelSigner for SignerClient {
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
            commitment_secret: DisclosedSecret(secret[..].try_into().unwrap()),
        };
        let _: ValidateRevocationReply = self.call(message).map_err(|_| ())?;
        Ok(())
    }

    fn sign_holder_commitment(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let message = SignLocalCommitmentTx2 {
            commitment_number: INITIAL_COMMITMENT_NUMBER - commitment_tx.commitment_number(),
        };
        let result: SignCommitmentTxWithHtlcsReply = self.call(message).map_err(|_| ())?;
        let signature = Signature::from_compact(&result.signature.signature.0).map_err(|_| ())?;
        let _htlc_signatures = result
            .htlc_signatures
            .iter()
            .map(|s| Signature::from_compact(&s.signature.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Ok(signature)
    }

    fn unsafe_sign_holder_commitment(
        &self,
        _commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
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

    fn sign_holder_htlc_transaction(
        &self,
        _htlc_tx: &Transaction,
        _input: usize,
        _htlc_descriptor: &HTLCDescriptor,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        todo!("sign_holder_htlc_transaction - #381")
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
            local_script: tx.to_holder_script().clone().into_bytes().into(),
            remote_script: tx.to_counterparty_script().clone().into_bytes().into(),
            local_wallet_path_hint: dest_wallet_path(),
        };
        let result: SignTxReply = self.call(message).map_err(|_| ())?;
        Ok(Signature::from_compact(&result.signature.signature.0).unwrap())
    }

    fn sign_holder_anchor_input(
        &self,
        _anchor_tx: &Transaction,
        _input: usize,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        todo!()
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        // Prepend a fake prefix to match CLN behavior
        let mut announcement = [0u8; 258].to_vec();
        announcement.extend(msg.encode());
        let message = SignChannelAnnouncement { announcement: announcement.into() };
        let result: SignChannelAnnouncementReply = self.call(message).map_err(|_| ())?;
        Ok(Signature::from_compact(&result.bitcoin_signature.0).unwrap())
    }
}

impl ChannelSigner for SignerClient {
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
            htlc_signatures: Array(
                holder_tx.counterparty_htlc_sigs.iter().map(|s| to_bitcoin_sig(s)).collect(),
            ),
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

    fn provide_channel_parameters(&mut self, p: &ChannelTransactionParameters) {
        let funding = p.funding_outpoint.expect("funding should exist at this point");
        let cp = p
            .counterparty_parameters
            .as_ref()
            .expect("counterparty params should exist at this point");

        let features = &p.channel_type_features;
        let commitment_type = if features.supports_anchors_zero_fee_htlc_tx() {
            CommitmentType::AnchorsZeroFeeHtlc
        } else if features.supports_anchors_nonzero_fee_htlc_tx() {
            CommitmentType::Anchors
        } else {
            CommitmentType::StaticRemoteKey
        };

        let ser_channel_type = commitment_type_to_channel_type(commitment_type);
        let message = SetupChannel {
            is_outbound: p.is_outbound_from_holder,
            channel_value: self.channel_value,
            push_value: 0, // TODO
            funding_txid: funding.txid,
            funding_txout: funding.index,
            to_self_delay: p.holder_selected_contest_delay,
            local_shutdown_script: Octets::EMPTY, // TODO
            local_shutdown_wallet_index: None,
            remote_basepoints: Basepoints {
                revocation: to_pubkey(cp.pubkeys.revocation_basepoint),
                payment: to_pubkey(cp.pubkeys.payment_point),
                htlc: to_pubkey(cp.pubkeys.htlc_basepoint),
                delayed_payment: to_pubkey(cp.pubkeys.delayed_payment_basepoint),
            },
            remote_funding_pubkey: to_pubkey(cp.pubkeys.funding_pubkey),
            remote_to_self_delay: cp.selected_contest_delay,
            remote_shutdown_script: Octets::EMPTY, // TODO
            channel_type: ser_channel_type.into(),
        };

        let _: SetupChannelReply = self.call(message).expect("setup channel");
    }
}

pub struct KeysManagerClient {
    transport: Arc<dyn Transport>,
    next_dbid: AtomicU64,
    key_material: KeyMaterial,
    xpub: ExtendedPubKey,
    node_id: PublicKey,
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
            dev_allowlist: Array::new(),
        };
        let result: HsmdInit2Reply = node_call(&*transport, init_message).expect("HsmdInit");
        let xpub = ExtendedPubKey::decode(&result.bip32.0).expect("xpub");
        let node_id = PublicKey::from_slice(&result.node_id.0).expect("node id");

        Self {
            transport,
            next_dbid: AtomicU64::new(1),
            key_material: KeyMaterial(key_material_bytes),
            xpub,
            node_id,
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
        assert_eq!(tx.input.len(), descriptors.len());

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(tx.clone()).expect("create PSBT");
        for i in 0..psbt.inputs.len() {
            psbt.inputs[i].witness_utxo = Self::descriptor_to_txout(descriptors[i]);
        }

        let streamed_psbt = StreamedPSBT::new(psbt).into();
        let utxos = Array(descriptors.into_iter().map(|d| Self::descriptor_to_utxo(*d)).collect());

        let message = SignWithdrawal { utxos, psbt: streamed_psbt };
        let result: SignWithdrawalReply = self.call(message).expect("sign failed");
        let psbt = result.psbt.0;
        psbt.inputs.into_iter().map(|i| i.final_script_witness.unwrap().to_vec()).collect()
    }

    fn descriptor_to_txout(d: &SpendableOutputDescriptor) -> Option<TxOut> {
        match d {
            SpendableOutputDescriptor::StaticOutput { output, .. } => Some(output.clone()),
            SpendableOutputDescriptor::DelayedPaymentOutput(o) => Some(o.output.clone()),
            SpendableOutputDescriptor::StaticPaymentOutput(o) => Some(o.output.clone()),
        }
    }

    fn descriptor_to_utxo(d: &SpendableOutputDescriptor) -> Utxo {
        let (outpoint, amount, keyindex, close_info) = match d {
            // Mutual close - we are spending a non-delayed output to us on the shutdown key
            SpendableOutputDescriptor::StaticOutput { output, outpoint } =>
                (outpoint.clone(), output.value, dest_wallet_path()[0], None), // FIXME this makes some assumptions
            // We force-closed - we are spending a delayed output to us
            SpendableOutputDescriptor::DelayedPaymentOutput(o) => (
                o.outpoint,
                o.output.value,
                0,
                Some(CloseInfo {
                    channel_id: channel_id_to_dbid(&o.channel_keys_id),
                    peer_id: PubKey([0; 33]),
                    commitment_point: Some(to_pubkey(o.per_commitment_point)),
                    is_anchors: false,
                    csv: o.to_self_delay as u32,
                }),
            ),
            // Remote force-closed - we are spending an non-delayed output to us
            SpendableOutputDescriptor::StaticPaymentOutput(o) => (
                o.outpoint,
                o.output.value,
                0,
                Some(CloseInfo {
                    channel_id: channel_id_to_dbid(&o.channel_keys_id),
                    peer_id: PubKey([0; 33]),
                    commitment_point: None,
                    is_anchors: false,
                    csv: 0,
                }),
            ),
        };
        let is_in_coinbase = false; // FIXME - set this for real
        Utxo {
            txid: outpoint.txid,
            outnum: outpoint.index as u32,
            amount,
            keyindex,
            is_p2sh: false,
            script: Octets::EMPTY,
            close_info,
            is_in_coinbase,
        }
    }
}

impl EntropySource for KeysManagerClient {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut rng = OsRng;
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}

impl NodeSigner for KeysManagerClient {
    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.key_material
    }
    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => {
                unimplemented!("phantom nodes not supported")
            }
        }
        Ok(self.node_id)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => unimplemented!("PhantomNode"),
        }

        if tweak.is_some() {
            unimplemented!("tweak is not supported");
        }
        let message = Ecdh { point: PubKey(other_key.serialize()) };
        let result: EcdhReply = self.call(message).expect("ecdh");
        Ok(SharedSecret::from_bytes(result.secret.0))
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
            u5bytes: Octets(invoice_data.iter().map(|u| u.to_u8()).collect()),
            hrp: hrp_bytes.to_vec().into(),
        };
        let result: SignInvoiceReply = self.call(message).expect("sign_invoice");
        let rid = RecoveryId::from_i32(result.signature.0[64] as i32).expect("recovery ID");
        let sig = &result.signature.0[0..64];
        RecoverableSignature::from_compact(sig, rid).map_err(|_| ())
    }

    fn sign_bolt12_invoice(
        &self,
        _invoice: &lightning::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        unimplemented!()
    }

    fn sign_bolt12_invoice_request(
        &self,
        _invoice_request: &lightning::offers::invoice_request::UnsignedInvoiceRequest,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        unimplemented!()
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        let message = SignGossipMessage { message: Octets(msg.encode()) };
        let result: SignGossipMessageReply = self.call(message).expect("sign_gossip_message");
        Ok(Signature::from_compact(&result.signature.0).expect("signature"))
    }
}

impl SignerProvider for KeysManagerClient {
    type Signer = SignerClient;

    fn generate_channel_keys_id(
        &self,
        _inbound: bool,
        _channel_value_satoshis: u64,
        _user_channel_id: u128,
    ) -> [u8; 32] {
        let dbid = self.next_dbid.fetch_add(1, Ordering::AcqRel);
        let mut id = [0; 32];
        id[0..8].copy_from_slice(&dbid.to_be_bytes());
        id
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::Signer {
        // We don't use the peer_id, because it's not easy to get at this point within the LDK framework.
        // The dbid is unique, so that's enough for our purposes.
        let peer_id = [0u8; 33];
        let dbid = u64::from_be_bytes(channel_keys_id[0..8].try_into().unwrap());

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

    fn get_destination_script(&self) -> Result<Script, ()> {
        let secp_ctx = Secp256k1::new();
        let wallet_path = dest_wallet_path();
        let mut key = self.xpub;
        for i in wallet_path.iter() {
            key = key.ckd_pub(&secp_ctx, ChildNumber::from_normal_idx(*i).unwrap()).unwrap();
        }
        let pubkey = key.public_key;
        Ok(Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize())))
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        Ok(ShutdownScript::try_from(self.get_destination_script()?).expect("script"))
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
