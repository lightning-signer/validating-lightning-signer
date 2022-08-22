#![allow(missing_docs)]
use core::convert::TryInto;

use bitcoin::bech32::u5;
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{Script, Transaction, TxOut};
use lightning::chain::keysinterface::{
    BaseSign, KeyMaterial, KeysInterface, Recipient, Sign, SpendableOutputDescriptor,
};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::script::ShutdownScript;
use lightning::ln::{chan_utils, PaymentPreimage};
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning_invoice::SignedRawInvoice;

use log::{debug, error, info};

use crate::channel::{ChannelBase, ChannelId, ChannelSetup, CommitmentType};
use crate::io_extras::Error as IOError;
use crate::node::Node;
use crate::prelude::*;
use crate::signer::multi_signer::MultiSigner;
use crate::tx::tx::HTLCInfo2;
use crate::util::crypto_utils::derive_public_key;
use crate::util::status::Status;
use crate::util::INITIAL_COMMITMENT_NUMBER;
use crate::Arc;

/// Adapt MySigner to KeysInterface
pub struct LoopbackSignerKeysInterface {
    pub node_id: PublicKey,
    pub signer: Arc<MultiSigner>,
}

impl LoopbackSignerKeysInterface {
    pub fn get_node(&self) -> Arc<Node> {
        self.signer.get_node(&self.node_id).expect("our node is missing")
    }

    pub fn add_invoice(&self, raw_invoice: SignedRawInvoice) {
        self.get_node().add_invoice(raw_invoice).expect("could not add invoice");
    }

    pub fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Transaction, ()> {
        self.get_node().spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
            secp_ctx,
        )
    }
}

#[derive(Clone)]
pub struct LoopbackChannelSigner {
    pub node_id: PublicKey,
    pub channel_id: ChannelId,
    pub signer: Arc<MultiSigner>,
    pub pubkeys: ChannelPublicKeys,
    pub is_outbound: bool,
    pub channel_value_sat: u64,
}

impl LoopbackChannelSigner {
    fn new(
        node_id: &PublicKey,
        channel_id: &ChannelId,
        signer: Arc<MultiSigner>,
        is_outbound: bool,
        channel_value_sat: u64,
    ) -> LoopbackChannelSigner {
        info!("new channel {:?} {:?}", node_id, channel_id);
        let pubkeys = signer
            .with_channel_base(&node_id, &channel_id, |base| Ok(base.get_channel_basepoints()))
            .map_err(|s| {
                error!("bad status {:?} on channel {}", s, channel_id);
                ()
            })
            .expect("must be able to get basepoints");
        LoopbackChannelSigner {
            node_id: *node_id,
            channel_id: channel_id.clone(),
            signer: signer.clone(),
            pubkeys,
            is_outbound,
            channel_value_sat,
        }
    }

    fn get_channel_setup(&self) -> Result<ChannelSetup, ()> {
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| Ok(chan.setup.clone()))
            .map_err(|s| self.bad_status(s))
    }

    pub fn make_counterparty_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<TxCreationKeys, ()> {
        let pubkeys = &self.pubkeys;
        let setup = self.get_channel_setup()?;
        let counterparty_pubkeys = setup.counterparty_points;
        let keys = TxCreationKeys::derive_new(
            secp_ctx,
            &per_commitment_point,
            &counterparty_pubkeys.delayed_payment_basepoint,
            &counterparty_pubkeys.htlc_basepoint,
            &pubkeys.revocation_basepoint,
            &pubkeys.htlc_basepoint,
        )
        .expect("failed to derive keys");
        Ok(keys)
    }

    fn bad_status(&self, s: Status) {
        error!("bad status {:?} on channel {}", s, self.channel_id);
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let commitment_tx = hct.trust();

        debug!("loopback: sign local txid {}", commitment_tx.built_transaction().txid);

        let commitment_number = INITIAL_COMMITMENT_NUMBER - hct.commitment_number();
        let to_holder_value_sat = hct.to_broadcaster_value_sat();
        let to_counterparty_value_sat = hct.to_countersignatory_value_sat();
        let feerate_per_kw = hct.feerate_per_kw();
        let (offered_htlcs, received_htlcs) =
            LoopbackChannelSigner::convert_to_htlc_info2(hct.htlcs());

        let (sig, htlc_sigs) = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                let result = chan.sign_holder_commitment_tx_phase2_redundant(
                    commitment_number,
                    feerate_per_kw,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )?;
                Ok(result)
            })
            .map_err(|s| self.bad_status(s))?;

        Ok((sig, htlc_sigs))
    }

    fn convert_to_htlc_info2(
        htlcs: &Vec<HTLCOutputInCommitment>,
    ) -> (Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
        let mut offered_htlcs = Vec::new();
        let mut received_htlcs = Vec::new();
        for htlc in htlcs {
            let htlc_info = HTLCInfo2 {
                value_sat: htlc.amount_msat / 1000,
                payment_hash: htlc.payment_hash,
                cltv_expiry: htlc.cltv_expiry,
            };
            if htlc.offered {
                offered_htlcs.push(htlc_info);
            } else {
                received_htlcs.push(htlc_info);
            }
        }
        (offered_htlcs, received_htlcs)
    }

    fn dest_wallet_path() -> Vec<u32> {
        vec![1]
    }

    fn option_anchors(&self) -> bool {
        let setup = self.get_channel_setup().expect("not ready");
        setup.commitment_type == CommitmentType::Anchors
            || setup.commitment_type == CommitmentType::AnchorsZeroFeeHtlc
    }
}

impl Writeable for LoopbackChannelSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), IOError> {
        self.channel_id.inner().write(writer)?;
        self.is_outbound.write(writer)?;
        self.channel_value_sat.write(writer)?;
        Ok(())
    }
}

impl BaseSign for LoopbackChannelSigner {
    fn get_per_commitment_point(&self, idx: u64, _secp_ctx: &Secp256k1<All>) -> PublicKey {
        // signer layer expect forward counting commitment number, but
        // we are passed a backwards counting one
        self.signer
            .with_channel_base(&self.node_id, &self.channel_id, |base| {
                Ok(base.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - idx).unwrap())
            })
            .map_err(|s| self.bad_status(s))
            .unwrap()
    }

    fn release_commitment_secret(&self, commitment_number: u64) -> [u8; 32] {
        // signer layer expect forward counting commitment number, but
        // we are passed a backwards counting one
        let secret = self.signer.with_ready_channel(&self.node_id, &self.channel_id, |chan| {
            let secret = chan
                .get_per_commitment_secret(INITIAL_COMMITMENT_NUMBER - commitment_number)
                .unwrap()[..]
                .try_into()
                .unwrap();
            Ok(secret)
        });
        secret.expect("missing channel")
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        let commitment_number = INITIAL_COMMITMENT_NUMBER - holder_tx.commitment_number();

        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.htlcs_fulfilled(preimages.clone());
                let (offered_htlcs, received_htlcs) =
                    LoopbackChannelSigner::convert_to_htlc_info2(holder_tx.htlcs());
                chan.validate_holder_commitment_tx_phase2(
                    commitment_number,
                    holder_tx.feerate_per_kw(),
                    holder_tx.to_broadcaster_value_sat(),
                    holder_tx.to_countersignatory_value_sat(),
                    offered_htlcs,
                    received_htlcs,
                    &holder_tx.counterparty_sig,
                    &holder_tx.counterparty_htlc_sigs,
                )?;
                Ok(())
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(())
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.pubkeys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                Ok(chan.keys.channel_keys_id())
            })
            .expect("missing channel")
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let trusted_tx = commitment_tx.trust();
        info!(
            "sign_counterparty_commitment {:?} {:?} txid {}",
            self.node_id,
            self.channel_id,
            trusted_tx.built_transaction().txid,
        );

        let (offered_htlcs, received_htlcs) =
            LoopbackChannelSigner::convert_to_htlc_info2(commitment_tx.htlcs());

        // This doesn't actually require trust
        let per_commitment_point = trusted_tx.keys().per_commitment_point;

        let commitment_number = INITIAL_COMMITMENT_NUMBER - commitment_tx.commitment_number();
        let to_holder_value_sat = commitment_tx.to_countersignatory_value_sat();
        let to_counterparty_value_sat = commitment_tx.to_broadcaster_value_sat();
        let feerate_per_kw = commitment_tx.feerate_per_kw();

        let (commitment_sig, htlc_sigs) = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.htlcs_fulfilled(preimages.clone());
                chan.sign_counterparty_commitment_tx_phase2(
                    &per_commitment_point,
                    commitment_number,
                    feerate_per_kw,
                    to_holder_value_sat,
                    to_counterparty_value_sat,
                    offered_htlcs.clone(),
                    received_htlcs.clone(),
                )
            })
            .map_err(|s| self.bad_status(s))?;
        Ok((commitment_sig, htlc_sigs))
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        let forward_idx = INITIAL_COMMITMENT_NUMBER - idx;
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.validate_counterparty_revocation(forward_idx, secret)
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(())
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        Ok(self.sign_holder_commitment_and_htlcs(hct)?)
    }

    #[cfg(feature = "test_utils")]
    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.keys
                    .unsafe_sign_holder_commitment_and_htlcs(hct, secp_ctx)
                    .map_err(|_| Status::internal("could not unsafe-sign"))
            })
            .map_err(|_s| ())
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let setup = self.get_channel_setup()?;
        let counterparty_pubkeys = setup.counterparty_points;

        let (revocation_key, delayed_payment_key) = get_delayed_payment_keys(
            secp_ctx,
            &per_commitment_point,
            &counterparty_pubkeys,
            &self.pubkeys,
        )?;
        let redeem_script = chan_utils::get_revokeable_redeemscript(
            &revocation_key,
            setup.holder_selected_contest_delay,
            &delayed_payment_key,
        );

        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.sign_justice_sweep(
                    justice_tx,
                    input,
                    per_commitment_key,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let tx_keys = self.make_counterparty_tx_keys(&per_commitment_point, secp_ctx)?;
        let redeem_script =
            chan_utils::get_htlc_redeemscript(&htlc, self.option_anchors(), &tx_keys);
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.sign_justice_sweep(
                    justice_tx,
                    input,
                    per_commitment_key,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
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
        let chan_keys = self.make_counterparty_tx_keys(per_commitment_point, secp_ctx)?;
        let redeem_script =
            chan_utils::get_htlc_redeemscript(htlc, self.option_anchors(), &chan_keys);
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();

        // TODO phase 2
        let sig = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.sign_counterparty_htlc_sweep(
                    htlc_tx,
                    input,
                    per_commitment_point,
                    &redeem_script,
                    amount,
                    &wallet_path,
                )
            })
            .map_err(|s| self.bad_status(s))?;

        Ok(sig)
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_closing_transaction(
        &self,
        closing_tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        info!("sign_closing_transaction {:?} {:?}", self.node_id, self.channel_id);

        // TODO error handling is awkward
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                // FIXME - this needs to be supplied
                let holder_wallet_path_hint = vec![];

                chan.sign_mutual_close_tx_phase2(
                    closing_tx.to_holder_value_sat(),
                    closing_tx.to_counterparty_value_sat(),
                    &Some(closing_tx.to_holder_script().clone()),
                    &Some(closing_tx.to_counterparty_script().clone()),
                    &holder_wallet_path_hint,
                )
            })
            .map_err(|_| ())
    }

    fn sign_channel_announcement(
        &self,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Signature), ()> {
        info!("sign_counterparty_commitment {:?} {:?}", self.node_id, self.channel_id);

        let (nsig, bsig) = self
            .signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                Ok(chan.sign_channel_announcement(&msg.encode()))
            })
            .map_err(|s| self.bad_status(s))?;
        Ok((nsig, bsig))
    }

    fn ready_channel(&mut self, parameters: &ChannelTransactionParameters) {
        info!("set_remote_channel_pubkeys {:?} {:?}", self.node_id, self.channel_id);

        // TODO cover local vs remote to_self_delay with a test
        let funding_outpoint = parameters.funding_outpoint.unwrap().into_bitcoin_outpoint();
        let counterparty_parameters = parameters.counterparty_parameters.as_ref().unwrap();
        let setup = ChannelSetup {
            is_outbound: self.is_outbound,
            channel_value_sat: self.channel_value_sat,
            push_value_msat: 0, // TODO
            funding_outpoint,
            holder_selected_contest_delay: parameters.holder_selected_contest_delay,
            holder_shutdown_script: None, // use the signer's shutdown script
            counterparty_points: counterparty_parameters.pubkeys.clone(),
            counterparty_selected_contest_delay: counterparty_parameters.selected_contest_delay,
            counterparty_shutdown_script: None, // TODO
            commitment_type: CommitmentType::StaticRemoteKey, // TODO
        };
        let node = self.signer.get_node(&self.node_id).expect("no such node");

        let holder_shutdown_key_path = vec![];
        node.ready_channel(self.channel_id.clone(), None, setup, &holder_shutdown_key_path)
            .expect("channel already ready or does not exist");
    }
}

impl Sign for LoopbackChannelSigner {}

impl KeysInterface for LoopbackSignerKeysInterface {
    type Signer = LoopbackChannelSigner;

    // TODO secret key leaking
    fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        match recipient {
            Recipient::Node => Ok(self.get_node().get_node_secret()),
            Recipient::PhantomNode => Err(()),
        }
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
        let secp_ctx = Secp256k1::signing_only();
        let wallet_path = LoopbackChannelSigner::dest_wallet_path();
        let pubkey = self.get_node().get_wallet_pubkey(&secp_ctx, &wallet_path).expect("pubkey");
        Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()))
    }

    fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        // FIXME - this method is deprecated
        self.get_node().get_ldk_shutdown_scriptpubkey()
    }

    fn get_channel_signer(&self, is_inbound: bool, channel_value_sat: u64) -> Self::Signer {
        let node = self.signer.get_node(&self.node_id).unwrap();
        let (channel_id, _) = node.new_channel(None, &node).unwrap();
        LoopbackChannelSigner::new(
            &self.node_id,
            &channel_id,
            Arc::clone(&self.signer),
            !is_inbound,
            channel_value_sat,
        )
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.get_node().get_secure_random_bytes()
    }

    fn read_chan_signer(&self, mut reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        let channel_id = ChannelId::new(&Vec::read(&mut reader)?);
        let is_outbound = Readable::read(&mut reader)?;
        let channel_value_sat = Readable::read(&mut reader)?;
        Ok(LoopbackChannelSigner::new(
            &self.node_id,
            &channel_id,
            Arc::clone(&self.signer),
            is_outbound,
            channel_value_sat,
        ))
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[u5],
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => return Err(()),
        };
        self.get_node().sign_invoice(hrp_bytes, invoice_data).map_err(|_| ())
    }

    fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.get_node().get_inbound_payment_key_material()
    }
}

fn get_delayed_payment_keys(
    secp_ctx: &Secp256k1<All>,
    per_commitment_point: &PublicKey,
    a_pubkeys: &ChannelPublicKeys,
    b_pubkeys: &ChannelPublicKeys,
) -> Result<(PublicKey, PublicKey), ()> {
    let revocation_key = chan_utils::derive_public_revocation_key(
        secp_ctx,
        &per_commitment_point,
        &b_pubkeys.revocation_basepoint,
    )
    .map_err(|_| ())?;
    let delayed_payment_key =
        derive_public_key(secp_ctx, &per_commitment_point, &a_pubkeys.delayed_payment_basepoint)
            .map_err(|_| ())?;
    Ok((revocation_key, delayed_payment_key))
}
