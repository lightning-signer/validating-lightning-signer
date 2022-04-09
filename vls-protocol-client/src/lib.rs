use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bit_vec::BitVec;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::Transaction;
use lightning::chain::keysinterface::{BaseSign, Sign};
use lightning::chain::keysinterface::KeysInterface;
use lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction, HolderCommitmentTransaction, HTLCOutputInCommitment};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::ln::PaymentPreimage;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::util::bip32::ChildNumber;
use lightning_signer::lightning;
use lightning_signer::util::INITIAL_COMMITMENT_NUMBER;
use log::error;

use vls_protocol::Error as ProtocolError;
use vls_protocol::features::{OPT_ANCHOR_OUTPUTS, OPT_STATIC_REMOTEKEY};
use vls_protocol::model::{Basepoints, Bip32KeyVersion, BlockId, PubKey, Secret, TxId};
use vls_protocol::msgs::{DeBolt, GetChannelBasepoints, GetChannelBasepointsReply, GetPerCommitmentPoint, GetPerCommitmentPointReply, HsmdInit, HsmdInitReply, ReadyChannel, ReadyChannelReply, SerBolt, SignChannelAnnouncement, SignChannelAnnouncementReply, SignInvoice, SignInvoiceReply, ValidateRevocation, ValidateRevocationReply};

use crate::bitcoin::{Script, WPubkeyHash};
use crate::bitcoin::bech32::u5;
use crate::bitcoin::secp256k1::rand::RngCore;
use crate::bitcoin::secp256k1::rand::rngs::OsRng;
use crate::bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
use crate::bitcoin::util::bip32::ExtendedPubKey;
use crate::bitcoin::util::psbt::serialize::Serialize;
use crate::lightning::chain::keysinterface::{KeyMaterial, Recipient};
use crate::lightning::ln::msgs::DecodeError;
use crate::lightning::ln::script::ShutdownScript;
use crate::lightning::util::ser::{Writeable, Writer};

#[derive(Debug)]
pub enum Error {
    ProtocolError(ProtocolError),
    TransportError
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Error::ProtocolError(e)
    }
}

pub trait Transport {
    fn call(&self, message: Vec<u8>) -> Result<Vec<u8>, Error>;
}

pub fn call<T: SerBolt, R: DeBolt>(transport: &dyn Transport, message: T) -> Result<R, Error> {
    let message_ser = message.as_vec();
    let result_ser = transport.call(message_ser)?;
    let result = R::from_vec(result_ser)?;
    Ok(result)
}

#[derive(Clone)]
pub struct SignerClient {
    transport: Arc<dyn Transport>,
    // NOTE this is actually unused by VLS, but it's passed for compatibility with CLN
    peer_id: PublicKey,
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

impl SignerClient {
    fn call<T: SerBolt, R: DeBolt>(&self, message: T) -> Result<R, Error> {
        call(&*self.transport, message)
            .map_err(|e| {
                error!("transport error: {:?}", e);
                e
            })
    }

    fn peer_id(&self) -> PubKey {
        PubKey(self.peer_id.serialize())
    }

    fn new(transport: Arc<dyn Transport>, dbid: u64, channel_value: u64) -> Self {
        // NOTE this is actually unused by VLS, but it's passed for compatibility with CLN
        let peer_id = [3; 33];
        let message = GetChannelBasepoints { node_id: PubKey(peer_id.clone()), dbid };
        let result: GetChannelBasepointsReply = call(&*transport, message).expect("pubkeys");
        let channel_keys = ChannelPublicKeys {
            funding_pubkey: from_pubkey(result.funding),
            revocation_basepoint: from_pubkey(result.basepoints.revocation),
            payment_point: from_pubkey(result.basepoints.payment),
            delayed_payment_basepoint: from_pubkey(result.basepoints.delayed_payment),
            htlc_basepoint: from_pubkey(result.basepoints.htlc)
        };
        SignerClient {
            transport,
            peer_id: PublicKey::from_slice(&peer_id).unwrap(),
            dbid,
            channel_keys,
            channel_value
        }
    }
}

impl Writeable for SignerClient {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        todo!()
    }
}

impl Sign for SignerClient {
}

impl BaseSign for SignerClient {
    fn get_per_commitment_point(&self, idx: u64, _secp_ctx: &Secp256k1<All>) -> PublicKey {
        let message = GetPerCommitmentPoint {
            commitment_number: INITIAL_COMMITMENT_NUMBER - idx
        };
        let result: GetPerCommitmentPointReply = self.call(message).expect("get_per_commitment_point");
        PublicKey::from_slice(&result.point.0).expect("public key")
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        // Getting the point at idx + 2 releases the secret at idx
        let message = GetPerCommitmentPoint {
            commitment_number: INITIAL_COMMITMENT_NUMBER - (idx + 2)
        };
        let result: GetPerCommitmentPointReply = self.call(message).expect("get_per_commitment_point");
        let secret = result.secret.expect("secret not released");
        secret.0
    }

    fn validate_holder_commitment(&self, holder_tx: &HolderCommitmentTransaction, preimages: Vec<PaymentPreimage>) -> Result<(), ()> {
        // TODO phase 2
        todo!()
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.channel_keys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        Sha256Hash::hash(&self.dbid.to_le_bytes()).into_inner()
    }

    fn sign_counterparty_commitment(&self, commitment_tx: &CommitmentTransaction, preimages: Vec<PaymentPreimage>, _secp_ctx: &Secp256k1<All>) -> Result<(Signature, Vec<Signature>), ()> {
        // TODO phase 2
        todo!()
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        let message = ValidateRevocation {
            commitment_number: INITIAL_COMMITMENT_NUMBER - idx,
            commitment_secret: Secret(secret[..].try_into().unwrap())
        };
        let _: ValidateRevocationReply = self.call(message)
            .map_err(|_|())?;
        Ok(())
    }

    fn sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, _secp_ctx: &Secp256k1<All>) -> Result<(Signature, Vec<Signature>), ()> {
        // TODO phase 2
        todo!()
    }

    fn unsafe_sign_holder_commitment_and_htlcs(&self, commitment_tx: &HolderCommitmentTransaction, _secp_ctx: &Secp256k1<All>) -> Result<(Signature, Vec<Signature>), ()> {
        unimplemented!()
    }

    fn sign_justice_revoked_output(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, _secp_ctx: &Secp256k1<All>) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    fn sign_justice_revoked_htlc(&self, justice_tx: &Transaction, input: usize, amount: u64, per_commitment_key: &SecretKey, htlc: &HTLCOutputInCommitment, _secp_ctx: &Secp256k1<All>) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    fn sign_counterparty_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, amount: u64, per_commitment_point: &PublicKey, htlc: &HTLCOutputInCommitment, _secp_ctx: &Secp256k1<All>) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    fn sign_closing_transaction(&self, closing_tx: &ClosingTransaction, _secp_ctx: &Secp256k1<All>) -> Result<Signature, ()> {
        // onchain
        todo!()
    }

    fn sign_channel_announcement(&self, msg: &UnsignedChannelAnnouncement, _secp_ctx: &Secp256k1<All>) -> Result<(Signature, Signature), ()> {
        let message = SignChannelAnnouncement {
            announcement: msg.encode()
        };
        let result: SignChannelAnnouncementReply = self.call(message)
            .map_err(|_|())?;
        Ok((Signature::from_compact(&result.node_signature.0).unwrap(),
            Signature::from_compact(&result.bitcoin_signature.0).unwrap()))
    }

    fn ready_channel(&mut self, p: &ChannelTransactionParameters) {
        let funding = p.funding_outpoint
            .expect("funding should exist at this point");
        let cp = p.counterparty_parameters.as_ref()
            .expect("counterparty params should exist at this point");

        let mut channel_features = BitVec::new();
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
            channel_type: channel_features.to_bytes()
        };

        let _: ReadyChannelReply = self.call(message).expect("ready channel");
    }
}

pub struct KeysManagerClient {
    transport: Arc<dyn Transport>,
    next_dbid: AtomicU64,
    key_material: KeyMaterial,
    xpub: ExtendedPubKey,
    #[allow(unused)]
    node_id: PublicKey,
}

impl KeysManagerClient {
    /// Create a new VLS client with the given transport
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        let mut rng = OsRng::new().unwrap();
        let mut key_material_bytes = [0; 32];
        rng.fill_bytes(&mut key_material_bytes);
        
        let init_message = HsmdInit {
            key_version: Bip32KeyVersion { pubkey_version: 0, privkey_version: 0 },
            chain_params: BlockId([0; 32]),
            encryption_key: None,
            dev_privkey: None,
            dev_bip32_seed: None,
            dev_channel_secrets: None,
            dev_channel_secrets_shaseed: None
        };
        let result: HsmdInitReply = call(&*transport, init_message).expect("HsmdInit");
        let xpub = ExtendedPubKey::decode(&result.bip32.0)
            .expect("xpub");
        let node_id = from_pubkey(result.node_id);
        // TODO node_secret?

        Self {
            transport,
            next_dbid: AtomicU64::new(0),
            key_material: KeyMaterial(key_material_bytes),
            xpub,
            node_id,
        }
    }

    fn call<T: SerBolt, R: DeBolt>(&self, message: T) -> Result<R, Error> {
        call(&*self.transport, message)
    }

    fn dest_wallet_path() -> Vec<u32> {
        vec![1]
    }
}

impl KeysInterface for KeysManagerClient {
    type Signer = SignerClient;

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        todo!()
    }

    fn get_destination_script(&self) -> Script {
        let secp_ctx = Secp256k1::new();
        let wallet_path = Self::dest_wallet_path();
        let mut key = self.xpub;
        for i in wallet_path {
            key = key.ckd_pub(&secp_ctx, ChildNumber::from_normal_idx(i).unwrap()).unwrap();
        }
        let pubkey = key.public_key;
        Script::new_v0_wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        ShutdownScript::try_from(self.get_destination_script()).expect("script")
    }

    fn get_channel_signer(&self, _inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        let dbid = self.next_dbid.fetch_add(1, Ordering::AcqRel);
        SignerClient::new(self.transport.clone(), dbid, channel_value_satoshis)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut rng = OsRng::new().unwrap();
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        todo!()
    }

    fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], recipient: Recipient) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => {
                unimplemented!("phantom nodes not supported")
            }
        }
        let message = SignInvoice {
            u5bytes: invoice_data.iter().map(|u| u.to_u8()).collect(),
            hrp: hrp_bytes.to_vec()
        };
        let result: SignInvoiceReply = self.call(message).expect("sign_invoice");
        let rid = RecoveryId::from_i32(result.signature.0[64] as i32)
            .expect("recovery ID");
        let sig = &result.signature.0[0..64];
        RecoverableSignature::from_compact(sig, rid)
            .map_err(|_| ())
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.key_material
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
