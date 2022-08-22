use std::any::Any;
use std::io::Read;

use delegate::delegate;

use bitcoin::bech32::u5;
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::{secp256k1, Script, Transaction, TxOut};
use lightning::chain::keysinterface::BaseSign;
use lightning::chain::keysinterface::InMemorySigner;
use lightning::chain::keysinterface::Sign;
use lightning::chain::keysinterface::{KeyMaterial, KeysInterface, Recipient};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::script::ShutdownScript;
use lightning::ln::PaymentPreimage;
use lightning::util::ser::Readable;
use lightning::util::ser::{Writeable, Writer};
use lightning_signer::bitcoin;
use lightning_signer::lightning;
use lightning_signer::lightning::chain::keysinterface::SpendableOutputDescriptor;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::bitcoin::Address;
use lightning_signer::util::loopback::LoopbackChannelSigner;

/// Helper to allow DynSigner to clone itself
pub trait InnerSign: BaseSign + Send + Sync {
    fn box_clone(&self) -> Box<dyn InnerSign>;
    fn as_any(&self) -> &dyn Any;
    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), ::std::io::Error>;
}

/// A BaseSign derived struct allowing run-time selection of a signer
pub struct DynSigner {
    pub inner: Box<dyn InnerSign>,
}

impl DynSigner {
    pub fn new<S: InnerSign + 'static>(inner: S) -> Self {
        DynSigner { inner: Box::new(inner) }
    }
}

impl Sign for DynSigner {}

impl Clone for DynSigner {
    fn clone(&self) -> Self {
        DynSigner { inner: self.inner.box_clone() }
    }
}

// This is taken care of by KeysInterface
impl Readable for DynSigner {
    fn read<R: Read>(_reader: &mut R) -> Result<Self, DecodeError> {
        unimplemented!()
    }
}

impl BaseSign for DynSigner {
    delegate! {
        to self.inner {
            fn get_per_commitment_point(
                &self,
                idx: u64,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> PublicKey;

            fn release_commitment_secret(&self, idx: u64) -> [u8; 32];

            fn validate_holder_commitment(
                &self,
                holder_tx: &HolderCommitmentTransaction,
                preimages: Vec<PaymentPreimage>,
            ) -> Result<(), ()>;

            fn pubkeys(&self) -> &ChannelPublicKeys;

            fn channel_keys_id(&self) -> [u8; 32];

            fn sign_counterparty_commitment(
                &self,
                commitment_tx: &CommitmentTransaction,
                preimages: Vec<PaymentPreimage>,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<(Signature, Vec<Signature>), ()>;

            fn validate_counterparty_revocation(
                &self, idx: u64, secret: &SecretKey) -> Result<(), ()>;

            fn sign_holder_commitment_and_htlcs(
                &self,
                commitment_tx: &HolderCommitmentTransaction,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<(Signature, Vec<Signature>), ()>;

            #[cfg(feature = "test_utils")]
            fn unsafe_sign_holder_commitment_and_htlcs(
                &self,
                commitment_tx: &HolderCommitmentTransaction,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<(Signature, Vec<Signature>), ()>;

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

            fn sign_channel_announcement(
                &self,
                msg: &UnsignedChannelAnnouncement,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> Result<(Signature, Signature), ()>;

            fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters);
        }
    }
}

impl Writeable for DynSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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

    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), std::io::Error> {
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

    fn vwrite(&self, writer: &mut Vec<u8>) -> Result<(), std::io::Error> {
        self.write(writer)
    }
}

pub struct DynKeysInterface {
    pub inner: Box<dyn SpendableKeysInterface<Signer = DynSigner>>,
}

impl DynKeysInterface {
    pub fn new(inner: Box<dyn SpendableKeysInterface<Signer = DynSigner>>) -> Self {
        DynKeysInterface { inner }
    }
}

impl KeysInterface for DynKeysInterface {
    type Signer = DynSigner;

    delegate! {
        to self.inner {
            fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()>;

            fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()>;

            fn get_destination_script(&self) -> Script;

            fn get_shutdown_scriptpubkey(&self) -> ShutdownScript;

            fn get_channel_signer(
                &self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer;

            fn get_secure_random_bytes(&self) -> [u8; 32];

            fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError>;

            fn sign_invoice(
                &self,
                hrp_bytes: &[u8],
                invoice_data: &[u5],
                recipient: Recipient,
            ) -> Result<RecoverableSignature, ()>;

            fn get_inbound_payment_key_material(&self) -> KeyMaterial;
        }
    }
}

// TODO(devrandom) why is spend_spendable_outputs not in KeysInterface?
pub trait SpendableKeysInterface: KeysInterface + Send + Sync {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> anyhow::Result<Transaction>;

    /// Swept funds from closed channels are sent here
    /// This is implemented by setting the change destination to spend_spendable_outputs to this address.
    fn get_sweep_address(&self) -> Address;

    /// Get the node ID
    fn get_node_id(&self) -> PublicKey;

    /// Sign for the layer-1 wallet
    /// TODO can we use the derivation path in the psbt?
    fn sign_from_wallet(
        &self,
        psbt: &PartiallySignedTransaction,
        derivations: Vec<u32>,
    ) -> PartiallySignedTransaction;
}

impl SpendableKeysInterface for DynKeysInterface {
    delegate! {
        to self.inner {
            fn spend_spendable_outputs(
                &self,
                descriptors: &[&SpendableOutputDescriptor],
                outputs: Vec<TxOut>,
                change_destination_script: Script,
                feerate_sat_per_1000_weight: u32,
                secp_ctx: &Secp256k1<secp256k1::All>,
            ) -> anyhow::Result<Transaction>;

            fn get_sweep_address(&self) -> Address;

            fn get_node_id(&self) -> PublicKey;

            fn sign_from_wallet(&self, psbt: &PartiallySignedTransaction, derivations: Vec<u32>) -> PartiallySignedTransaction;
        }
    }
}
