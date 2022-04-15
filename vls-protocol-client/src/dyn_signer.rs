use std::any::Any;
use std::io::Read;

use bitcoin::bech32::u5;
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signature};
use bitcoin::Script;
use bitcoin::{secp256k1, Transaction};
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
use lightning_signer::bitcoin::TxOut;
use lightning_signer::lightning;
use lightning_signer::lightning::chain::keysinterface::SpendableOutputDescriptor;

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
    fn get_per_commitment_point(
        &self,
        idx: u64,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        self.inner.validate_holder_commitment(holder_tx, preimages)
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner.channel_keys_id()
    }

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        preimages: Vec<PaymentPreimage>,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.sign_counterparty_commitment(commitment_tx, preimages, secp_ctx)
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        self.inner.validate_counterparty_revocation(idx, secret)
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)
    }

    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.unsafe_sign_holder_commitment_and_htlcs(commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_output(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            secp_ctx,
        )
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_htlc(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            htlc,
            secp_ctx,
        )
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(
            htlc_tx,
            input,
            amount,
            per_commitment_point,
            htlc,
            secp_ctx,
        )
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &ClosingTransaction,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_channel_announcement(
        &self,
        msg: &UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Signature), ()> {
        self.inner.sign_channel_announcement(msg, secp_ctx)
    }

    fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
        self.inner.ready_channel(channel_parameters)
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

    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        self.inner.get_node_secret(recipient)
    }

    fn get_destination_script(&self) -> Script {
        self.inner.get_destination_script()
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        self.inner.get_shutdown_scriptpubkey()
    }

    fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        self.inner.get_channel_signer(inbound, channel_value_satoshis)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        self.inner.read_chan_signer(reader)
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        self.inner.sign_invoice(hrp_bytes, invoice_data, recipient)
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.inner.get_inbound_payment_key_material()
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

    fn get_node_id(&self) -> PublicKey;
}

impl SpendableKeysInterface for DynKeysInterface {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> anyhow::Result<Transaction> {
        self.inner.spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
            secp_ctx,
        )
    }

    fn get_sweep_address(&self) -> Address {
        self.inner.get_sweep_address()
    }

    fn get_node_id(&self) -> PublicKey {
        self.inner.get_node_id()
    }
}
