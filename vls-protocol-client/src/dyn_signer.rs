use std::any::Any;

use delegate::delegate;

use crate::bitcoin::Address;
use crate::HTLCDescriptor;
use bitcoin::{secp256k1, Transaction, TxOut};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::sign::ChannelSigner;
use lightning::sign::InMemorySigner;
use lightning::sign::{NodeSigner, Recipient, SignerProvider, SpendableOutputDescriptor};
use lightning::types::payment::PaymentPreimage;
use lightning::util::ser::Readable;
use lightning::util::ser::{Writeable, Writer};
use lightning_invoice::RawBolt11Invoice;
use lightning_signer::bitcoin::secp256k1::All;
use lightning_signer::bitcoin::{self, ScriptBuf};
use lightning_signer::lightning;
use lightning_signer::lightning::ln::inbound_payment::ExpandedKey;
use lightning_signer::lightning_invoice;
use lightning_signer::util::loopback::LoopbackChannelSigner;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, PublicKey, Scalar, Secp256k1, SecretKey};

/// Helper to allow DynSigner to clone itself
pub trait InnerSign: EcdsaChannelSigner + Send + Sync {
    fn box_clone(&self) -> Box<dyn InnerSign>;
    fn as_any(&self) -> &dyn Any;
    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), bitcoin::io::Error>;
}

/// A ChannelSigner derived struct allowing run-time selection of a signer
pub struct DynSigner {
    pub inner: Box<dyn InnerSign>,
}

impl DynSigner {
    pub fn new<S: InnerSign + 'static>(inner: S) -> Self {
        DynSigner { inner: Box::new(inner) }
    }
}

impl Clone for DynSigner {
    fn clone(&self) -> Self {
        DynSigner { inner: self.inner.box_clone() }
    }
}

// This is taken care of by KeysInterface
impl Readable for DynSigner {
    fn read<R: bitcoin::io::Read>(_reader: &mut R) -> Result<Self, DecodeError> {
        unimplemented!()
    }
}

impl EcdsaChannelSigner for DynSigner {
    delegate! {
        to self.inner {
            fn sign_counterparty_commitment(
                &self,
                commitment_tx: &CommitmentTransaction,
                inbound_htlc_preimages: Vec<PaymentPreimage>,
                outbound_htlc_preimages: Vec<PaymentPreimage>,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<(Signature, Vec<Signature>), ()>;

            fn sign_holder_commitment(
                &self,
                commitment_tx: &HolderCommitmentTransaction,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn unsafe_sign_holder_commitment(
                &self,
                commitment_tx: &HolderCommitmentTransaction,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_justice_revoked_output(
                &self,
                justice_tx: &Transaction,
                input: usize,
                amount: u64,
                per_commitment_key: &SecretKey,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_justice_revoked_htlc(
                &self,
                justice_tx: &Transaction,
                input: usize,
                amount: u64,
                per_commitment_key: &SecretKey,
                htlc: &HTLCOutputInCommitment,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_counterparty_htlc_transaction(
                &self,
                htlc_tx: &Transaction,
                input: usize,
                amount: u64,
                per_commitment_point: &PublicKey,
                htlc: &HTLCOutputInCommitment,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_closing_transaction(
                &self,
                closing_tx: &ClosingTransaction,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_channel_announcement_with_funding_key(
                &self,
                msg: &UnsignedChannelAnnouncement,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_holder_anchor_input(
                &self, anchor_tx: &Transaction, input: usize, secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;

            fn sign_holder_htlc_transaction(&self, htlc_tx: &Transaction, input: usize, htlc_descriptor: &HTLCDescriptor, secp_ctx: &Secp256k1<All>) -> Result<Signature, ()>;

            fn sign_splicing_funding_input(
                &self, tx: &Transaction, input_index: usize, input_value: u64,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<Signature, ()>;
        }
    }
}

impl ChannelSigner for DynSigner {
    delegate! {
        to self.inner {
            fn validate_counterparty_revocation(&self, idx: u64, sk: &SecretKey) -> Result<(), ()>;

            fn get_per_commitment_point(
                &self,
                idx: u64,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<PublicKey, ()>;

            fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()>;

            fn validate_holder_commitment(
                &self,
                holder_tx: &HolderCommitmentTransaction,
                preimages: Vec<PaymentPreimage>,
            ) -> Result<(), ()>;

            fn pubkeys(&self) -> &ChannelPublicKeys;

            fn channel_keys_id(&self) -> [u8; 32];

            fn provide_channel_parameters(&mut self, channel_parameters: &ChannelTransactionParameters);
        }
    }
}

impl Writeable for DynSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), bitcoin::io::Error> {
        let inner = self.inner.as_ref();
        let mut buf = Vec::new();
        inner.vwrite(&mut buf)?;
        writer.write_all(&buf)
    }
}

impl InnerSign for InMemorySigner {
    fn box_clone(&self) -> Box<dyn InnerSign> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), bitcoin::io::Error> {
        self.write(writer)
    }
}

impl InnerSign for LoopbackChannelSigner {
    fn box_clone(&self) -> Box<dyn InnerSign> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), bitcoin::io::Error> {
        self.write(writer)
    }
}

pub struct DynKeysInterface {
    pub inner: Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>>,
}

impl DynKeysInterface {
    pub fn new(inner: Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>>) -> Self {
        DynKeysInterface { inner }
    }
}

impl NodeSigner for DynKeysInterface {
    delegate! {
        to self.inner {
            fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()>;
            fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()>;
            fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>;

            fn sign_invoice(
                &self,
                invoice: &RawBolt11Invoice,
                recipient: Recipient,
            ) -> Result<RecoverableSignature, ()>;

            fn sign_bolt12_invoice(
                &self, invoice: &lightning::offers::invoice::UnsignedBolt12Invoice
            ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>;

            fn get_inbound_payment_key(&self) -> ExpandedKey;
        }
    }
}

impl SignerProvider for DynKeysInterface {
    type EcdsaSigner = DynSigner;

    delegate! {
        to self.inner {
            fn get_destination_script(&self, buf: [u8; 32]) -> Result<ScriptBuf, ()>;

            fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()>;

            fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32];

            fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner;

            fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError>;
        }
    }
}

// TODO(devrandom) why is spend_spendable_outputs not in KeysInterface?
pub trait SpendableKeysInterface: NodeSigner + SignerProvider + Send + Sync {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<All>,
    ) -> anyhow::Result<Transaction>;

    /// Swept funds from closed channels are sent here
    /// This is implemented by setting the change destination to spend_spendable_outputs to this address.
    fn get_sweep_address(&self) -> Address;
}

impl SpendableKeysInterface for DynKeysInterface {
    delegate! {
        to self.inner {
            fn spend_spendable_outputs(
                &self,
                descriptors: &[&SpendableOutputDescriptor],
                outputs: Vec<TxOut>,
                change_destination_script: ScriptBuf,
                feerate_sat_per_1000_weight: u32,
                secp_ctx: &Secp256k1<All>,
            ) -> anyhow::Result<Transaction>;

            fn get_sweep_address(&self) -> Address;
        }
    }
}
