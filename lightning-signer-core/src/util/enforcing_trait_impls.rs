use crate::{Arc, Mutex};
use crate::{IOError, IORead};

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};
use bitcoin::secp256k1::{All, Secp256k1, Signature};
use chain::keysinterface::InMemorySigner;
use core::cmp;
use lightning::chain;
use lightning::chain::keysinterface::BaseSign;
use lightning::ln;
use lightning::ln::chan_utils::{
    ChannelTransactionParameters, CommitmentTransaction, HolderCommitmentTransaction,
    TxCreationKeys,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use ln::chan_utils::{ChannelPublicKeys, HTLCOutputInCommitment};
use ln::msgs;

/// Enforces some rules on Sign calls. Eventually we will
/// probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
#[derive(Clone)]
pub struct EnforcingSigner {
    inner: InMemorySigner,
    state: Arc<Mutex<EnforcementState>>,
}

#[derive(Clone, Debug)]
pub struct EnforcementState {
    pub last_commitment_number: Option<u64>,
}

impl EnforcingSigner {
    pub fn new(inner: InMemorySigner) -> Self {
        let state = EnforcementState {
            last_commitment_number: None,
        };
        EnforcingSigner::new_with_state(inner, state)
    }

    pub fn new_with_state(inner: InMemorySigner, state: EnforcementState) -> EnforcingSigner {
        Self {
            inner,
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn enforcement_state(&self) -> EnforcementState {
        self.state.lock().unwrap().clone()
    }

    pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.counterparty_pubkeys()
    }

    pub fn inner(&self) -> InMemorySigner {
        self.inner.clone()
    }

    // BEGIN NOT TESTED
    pub fn last_commitment_number(&self) -> Option<u64> {
        self.state.lock().unwrap().last_commitment_number
    }
    // END NOT TESTED
}

impl EnforcingSigner {
    // BEGIN NOT TESTED
    #[allow(dead_code)]
    fn check_keys(&self, secp_ctx: &Secp256k1<All>, keys: &TxCreationKeys) {
        // FIXME
        let revocation_base = PublicKey::from_secret_key(secp_ctx, &self.revocation_base_key());
        let htlc_base = PublicKey::from_secret_key(secp_ctx, &self.htlc_base_key());

        let counterparty_pubkeys = self.counterparty_pubkeys();

        let keys_expected = TxCreationKeys::derive_new(
            secp_ctx,
            &keys.per_commitment_point,
            &counterparty_pubkeys.delayed_payment_basepoint,
            &counterparty_pubkeys.htlc_basepoint,
            &revocation_base,
            &htlc_base,
        )
        .unwrap();
        if keys != &keys_expected {
            panic!("derived different per-tx keys")
        }
    }
    // END NOT TESTED

    // TODO leaking secrets below.
    // We don't take advantage of the signing operations in InMemorySigner because that
    // requires phase 2. In particular, the commitment and HTLCs must be signed in one operation.
    pub fn funding_key(&self) -> &SecretKey {
        &self.inner.funding_key
    }
    pub fn revocation_base_key(&self) -> &SecretKey {
        &self.inner.revocation_base_key
    }
    pub fn payment_key(&self) -> &SecretKey {
        &self.inner.payment_key
    }
    pub fn delayed_payment_base_key(&self) -> &SecretKey {
        &self.inner.delayed_payment_base_key
    }
    pub fn htlc_base_key(&self) -> &SecretKey {
        &self.inner.htlc_base_key
    }
}

impl BaseSign for EnforcingSigner {
    fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<All>) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.release_commitment_secret(idx)
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }

    // BEGIN NOT TESTED
    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner.channel_keys_id()
    }
    // END NOT TESTED

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        // FIXME bypass while integrating with c-lightning
        // self.check_keys(secp_ctx, keys);
        let commitment_number = commitment_tx.commitment_number();
        let mut state = self.state.lock().unwrap();
        let last_commitment_number = state.last_commitment_number;
        if let Some(last) = last_commitment_number {
            assert!(
                last == commitment_number || last - 1 == commitment_number,
                "{} doesn't come after {} (backwards counting)", // NOT TESTED
                commitment_number,
                last
            );
            state.last_commitment_number = Some(cmp::min(last, commitment_number));
        } else {
            state.last_commitment_number = Some(commitment_number);
        }

        Ok(self
            .inner
            .sign_counterparty_commitment(commitment_tx, secp_ctx)
            .unwrap())
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        local_commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner
            .sign_holder_commitment_and_htlcs(local_commitment_tx, secp_ctx)
    }

    #[cfg(feature = "test_utils")]
    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        local_commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner
            .unsafe_sign_holder_commitment_and_htlcs(local_commitment_tx, secp_ctx)
    }

    fn sign_justice_transaction(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &Option<HTLCOutputInCommitment>,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_transaction(
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
        secp_ctx: &Secp256k1<All>,
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
        closing_tx: &Transaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        Ok(self
            .inner
            .sign_closing_transaction(closing_tx, secp_ctx)
            .unwrap())
    }

    // BEGIN NOT TESTED
    fn sign_channel_announcement(
        &self,
        msg: &msgs::UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_channel_announcement(msg, secp_ctx)
    }
    // END NOT TESTED

    fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
        self.inner.ready_channel(channel_parameters)
    }
}

// BEGIN NOT TESTED
impl Writeable for EnforcingSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), IOError> {
        self.inner.write(writer)?;
        let last = self.state.lock().unwrap().last_commitment_number;
        last.write(writer)?;
        Ok(())
    }
}
// END NOT TESTED

impl Readable for EnforcingSigner {
    fn read<R: IORead>(reader: &mut R) -> Result<Self, DecodeError> {
        let inner = Readable::read(reader)?;
        let last = Readable::read(reader)?;
        let state = EnforcementState {
            last_commitment_number: last,
        };
        Ok(EnforcingSigner {
            inner,
            state: Arc::new(Mutex::new(state)),
        })
    }
}
