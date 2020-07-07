use std::cmp;
use std::io::Error;
use std::sync::{Arc, Mutex};

use bitcoin::blockdata::transaction::Transaction;
use chain::keysinterface::{ChannelKeys, InMemoryChannelKeys};
use lightning::chain;
use lightning::ln;
use lightning::ln::chan_utils::{LocalCommitmentTransaction, TxCreationKeys};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use ln::chan_utils::{ChannelPublicKeys, HTLCOutputInCommitment};
use ln::msgs;
use secp256k1;
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Secp256k1, Signature};

/// Enforces some rules on ChannelKeys calls. Eventually we will
/// probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
// BEGIN NOT TESTED
#[derive(Clone)]
pub struct EnforcingChannelKeys {
    inner: InMemoryChannelKeys,
    commitment_number_obscure_and_last: Arc<Mutex<(Option<u64>, u64)>>,
}
// END NOT TESTED

impl EnforcingChannelKeys {
    pub fn new(inner: InMemoryChannelKeys) -> Self {
        Self {
            inner,
            commitment_number_obscure_and_last: Arc::new(Mutex::new((None, 0))),
        }
    }

    pub fn remote_pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.remote_pubkeys()
    }

    // BEGIN NOT TESTED
    pub fn inner(&self) -> InMemoryChannelKeys {
        self.inner.clone()
    }
    // END NOT TESTED
}

impl EnforcingChannelKeys {
    // BEGIN NOT TESTED
    #[allow(dead_code)]
    fn check_keys<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        secp_ctx: &Secp256k1<T>,
        keys: &TxCreationKeys,
    ) {
        // FIXME
        let revocation_base = PublicKey::from_secret_key(secp_ctx, &self.revocation_base_key());
        let htlc_base = PublicKey::from_secret_key(secp_ctx, &self.htlc_base_key());

        let remote_points = self.inner.remote_pubkeys();

        let keys_expected = TxCreationKeys::new(
            secp_ctx,
            &keys.per_commitment_point,
            &remote_points.delayed_payment_basepoint,
            &remote_points.htlc_basepoint,
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
    // We don't take advantage of the signing operations in InMemoryChannelKeys because that
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

impl ChannelKeys for EnforcingChannelKeys {
    fn commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.commitment_secret(idx)
    }
    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }
    // BEGIN NOT TESTED
    fn key_derivation_params(&self) -> (u64, u64) {
        self.inner.key_derivation_params()
    }
    // END NOT TESTED

    fn sign_remote_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        feerate_sat_per_kw: u32,
        commitment_tx: &Transaction,
        keys: &TxCreationKeys,
        htlcs: &[&HTLCOutputInCommitment],
        to_self_delay: u16,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        if commitment_tx.input.len() != 1 {
            panic!("lightning commitment transactions have a single input"); // NOT TESTED
        }
        // FIXME bypass while integrating with c-lightning
        // self.check_keys(secp_ctx, keys);
        let obscured_commitment_transaction_number = (commitment_tx.lock_time & 0xffffff) as u64
            | ((commitment_tx.input[0].sequence as u64 & 0xffffff) << 3 * 8);

        {
            let mut commitment_data = self.commitment_number_obscure_and_last.lock().unwrap();
            if commitment_data.0.is_none() {
                commitment_data.0 =
                    Some(obscured_commitment_transaction_number ^ commitment_data.1);
            }
            let commitment_number =
                obscured_commitment_transaction_number ^ commitment_data.0.unwrap();
            assert!(
                commitment_number == commitment_data.1
                    || commitment_number == commitment_data.1 + 1
            );
            commitment_data.1 = cmp::max(commitment_number, commitment_data.1)
        }

        Ok(self
            .inner
            .sign_remote_commitment(
                feerate_sat_per_kw,
                commitment_tx,
                keys,
                htlcs,
                to_self_delay,
                secp_ctx,
            )
            .unwrap())
    }

    fn sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        local_commitment_tx: &LocalCommitmentTransaction,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        self.inner
            .sign_local_commitment(local_commitment_tx, secp_ctx)
    }

    fn unsafe_sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        local_commitment_tx: &LocalCommitmentTransaction,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        self.inner
            .unsafe_sign_local_commitment(local_commitment_tx, secp_ctx)
    }

    fn sign_local_commitment_htlc_transactions<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        local_commitment_tx: &LocalCommitmentTransaction,
        local_csv: u16,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Vec<Option<Signature>>, ()> {
        self.inner
            .sign_local_commitment_htlc_transactions(local_commitment_tx, local_csv, secp_ctx)
    }

    fn sign_justice_transaction<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &Option<HTLCOutputInCommitment>,
        on_remote_tx_csv: u16,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_transaction(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            htlc,
            on_remote_tx_csv,
            secp_ctx,
        )
    }

    fn sign_remote_htlc_transaction<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        self.inner.sign_remote_htlc_transaction(
            htlc_tx,
            input,
            amount,
            per_commitment_point,
            htlc,
            secp_ctx,
        )
    }

    fn sign_closing_transaction<T: secp256k1::Signing>(
        &self,
        closing_tx: &Transaction,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        Ok(self
            .inner
            .sign_closing_transaction(closing_tx, secp_ctx)
            .unwrap())
    }

    // BEGIN NOT TESTED

    fn sign_channel_announcement<T: secp256k1::Signing>(
        &self,
        msg: &msgs::UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        self.inner.sign_channel_announcement(msg, secp_ctx)
    }

    fn set_remote_channel_pubkeys(&mut self, channel_pubkeys: &ChannelPublicKeys) {
        self.inner.set_remote_channel_pubkeys(channel_pubkeys)
    }

    // END NOT TESTED
}

// BEGIN NOT TESTED
impl Writeable for EnforcingChannelKeys {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        self.inner.write(writer)?;
        let (obscure, last) = *self.commitment_number_obscure_and_last.lock().unwrap();
        obscure.write(writer)?;
        last.write(writer)?;
        Ok(())
    }
}
// END NOT TESTED

impl Readable for EnforcingChannelKeys {
    fn read<R: ::std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let inner = Readable::read(reader)?;
        let obscure_and_last = Readable::read(reader)?;
        Ok(EnforcingChannelKeys {
            inner: inner,
            commitment_number_obscure_and_last: Arc::new(Mutex::new(obscure_and_last)),
        })
    }
}
