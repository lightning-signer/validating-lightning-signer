use std::sync::Arc;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signature, All};
use bitcoin::{Script, Transaction};
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Sign, BaseSign};
use lightning::ln::chan_utils;
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, CommitmentTransaction, HTLCOutputInCommitment,
    HolderCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::util::ser::{Writeable, Writer};

use crate::node::node::{ChannelId, ChannelSetup, CommitmentType};
use crate::server::my_keys_manager::INITIAL_COMMITMENT_NUMBER;
use crate::server::my_signer::MySigner;
use crate::tx::tx::HTLCInfo2;
use crate::util::crypto_utils::{derive_public_key, derive_revocation_pubkey, payload_for_p2wpkh};
use crate::util::status::Status;
use std::io::Error;

/// Adapt MySigner to KeysInterface
pub struct LoopbackSignerKeysInterface {
    pub node_id: PublicKey,
    pub signer: Arc<MySigner>,
    pub backing: KeysManager,
}

#[derive(Clone)]
pub struct LoopbackChannelSigner {
    pub node_id: PublicKey,
    pub channel_id: ChannelId,
    pub signer: Arc<MySigner>,
    pub pubkeys: ChannelPublicKeys,
    pub counterparty_pubkeys: Option<ChannelPublicKeys>,
    pub is_outbound: bool,
    pub channel_value_sat: u64,
    pub local_to_self_delay: u16,
    pub counterparty_to_self_delay: u16,
}

impl LoopbackChannelSigner {
    fn new(
        node_id: &PublicKey,
        channel_id: &ChannelId,
        signer: Arc<MySigner>,
        is_outbound: bool,
        channel_value_sat: u64,
    ) -> LoopbackChannelSigner {
        log_info!(signer, "new channel {:?} {:?}", node_id, channel_id);
        let pubkeys = signer
            .get_channel_basepoints(&node_id, &channel_id)
            .map_err(|s| {
                // BEGIN NOT TESTED
                log_error!(signer, "bad status {:?} on channel {}", s, channel_id);
                ()
                // END NOT TESTED
            })
            .expect("must be able to get basepoints");
        LoopbackChannelSigner {
            node_id: *node_id,
            channel_id: *channel_id,
            signer: signer.clone(),
            pubkeys,
            counterparty_pubkeys: None,
            is_outbound,
            channel_value_sat,
            local_to_self_delay: 0,
            counterparty_to_self_delay: 0,
        }
    }

    pub fn make_counterparty_tx_keys(
        &self,
        per_commitment_point: &PublicKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<TxCreationKeys, ()> {
        let pubkeys = &self.pubkeys;
        let counterparty_pubkeys = self.counterparty_pubkeys.as_ref().ok_or(())?;
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

    // BEGIN NOT TESTED
    fn bad_status(&self, s: Status) {
        let signer = &self.signer;
        log_error!(signer, "bad status {:?} on channel {}", s, self.channel_id);
    }
    // END NOT TESTED

    fn sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let signer = &self.signer;
        let commitment_tx = hct.trust();

        log_debug!(
            signer,
            "loopback: sign local txid {}",
            commitment_tx.built_transaction().txid
        );

        let commitment_number = INITIAL_COMMITMENT_NUMBER - hct.commitment_number();
        let to_holder_value_sat = hct.to_broadcaster_value_sat();
        let to_counterparty_value_sat = hct.to_countersignatory_value_sat();
        let feerate_per_kw = hct.feerate_per_kw();
        let (offered_htlcs, received_htlcs) =
            LoopbackChannelSigner::convert_to_htlc_info2(hct.htlcs());

        let (sig_vec, htlc_sig_vecs) = signer
            .sign_holder_commitment_tx_phase2(
                &self.node_id,
                &self.channel_id,
                commitment_number,
                feerate_per_kw,
                to_holder_value_sat,
                to_counterparty_value_sat,
                offered_htlcs,
                received_htlcs,
            )
            .map_err(|s| self.bad_status(s))?;
        let htlc_sigs = htlc_sig_vecs
            .iter()
            .map(|s| bitcoin_sig_to_signature(s.clone()).unwrap())
            .collect();
        let sig = bitcoin_sig_to_signature(sig_vec).unwrap();
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
}

// BEGIN NOT TESTED
impl Writeable for LoopbackChannelSigner {
    fn write<W: Writer>(&self, _writer: &mut W) -> Result<(), Error> {
        unimplemented!()
    }
}
// END NOT TESTED

fn bitcoin_sig_to_signature(mut res: Vec<u8>) -> Result<Signature, ()> {
    res.pop();
    let sig = Signature::from_der(res.as_slice())
        .map_err(|_e| ()) // NOT TESTED
        .expect("failed to parse the signature we just created");
    Ok(sig)
}

impl BaseSign for LoopbackChannelSigner {
    fn get_per_commitment_point(
        &self,
        idx: u64,
        _secp_ctx: &Secp256k1<All>,
    ) -> PublicKey {
        // signer layer expect forward counting commitment number, but we are passed a backwards counting one
        self.signer
            .get_per_commitment_point(
                &self.node_id,
                &self.channel_id,
                INITIAL_COMMITMENT_NUMBER - idx,
            )
            .map_err(|s| self.bad_status(s))
            .unwrap()
    }

    fn release_commitment_secret(&self, commitment_number: u64) -> [u8; 32] {
        // signer layer expect forward counting commitment number, but we are passed a backwards counting one
        self.signer
            .revoke_commitent(
                &self.node_id,
                &self.channel_id,
                INITIAL_COMMITMENT_NUMBER - commitment_number,
            )
            .map_err(|s| self.bad_status(s))
            .unwrap()
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.pubkeys
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.channel_id.0
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let signer = &self.signer;
        let trusted_tx = commitment_tx.trust();
        log_info!(
            signer,
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

        let (sig_vec, htlc_sig_vecs) = self
            .signer
            .sign_counterparty_commitment_tx_phase2(
                &self.node_id,
                &self.channel_id,
                per_commitment_point,
                commitment_number,
                feerate_per_kw,
                to_holder_value_sat,
                to_counterparty_value_sat,
                offered_htlcs,
                received_htlcs,
            )
            .map_err(|s| self.bad_status(s))?;
        let commitment_sig = bitcoin_sig_to_signature(sig_vec)?;
        let mut htlc_sigs = Vec::with_capacity(commitment_tx.htlcs().len());
        for htlc_sig_vec in htlc_sig_vecs {
            htlc_sigs.push(bitcoin_sig_to_signature(htlc_sig_vec)?);
        }
        Ok((commitment_sig, htlc_sigs))
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        Ok(self.sign_holder_commitment_and_htlcs(hct)?)
    }

    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        hct: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.signer
            .with_ready_channel(&self.node_id, &self.channel_id, |chan| {
                chan.keys
                    .unsafe_sign_holder_commitment_and_htlcs(hct, secp_ctx)
                    .map_err(|_| Status::internal("could not unsafe-sign")) // NOT TESTED
            })
            .map_err(|_s| ()) // NOT TESTED
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
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let counterparty_pubkeys = self.counterparty_pubkeys.as_ref().unwrap();

        let (revocation_key, delayed_payment_key) = get_delayed_payment_keys(
            secp_ctx,
            &per_commitment_point,
            counterparty_pubkeys,
            &self.pubkeys,
        )?;
        let redeem_script = if let Some(ref htlc) = *htlc {
            // BEGIN NOT TESTED
            let tx_keys = self.make_counterparty_tx_keys(&per_commitment_point, secp_ctx)?;
            chan_utils::get_htlc_redeemscript(&htlc, &tx_keys)
        // END NOT TESTED
        } else {
            chan_utils::get_revokeable_redeemscript(
                &revocation_key,
                self.local_to_self_delay,
                &delayed_payment_key,
            )
        };

        // TODO phase 2
        let res = self
            .signer
            .sign_justice_sweep(
                &self.node_id,
                &self.channel_id,
                justice_tx,
                input,
                per_commitment_key,
                redeem_script.to_bytes(),
                amount,
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(res)
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
        let redeem_script = chan_utils::get_htlc_redeemscript(htlc, &chan_keys);

        // TODO phase 2
        let res = self
            .signer
            .sign_counterparty_htlc_sweep(
                &self.node_id,
                &self.channel_id,
                htlc_tx,
                input,
                redeem_script.to_bytes(),
                per_commitment_point,
                amount,
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(res)
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_closing_transaction(
        &self,
        closing_tx: &Transaction,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_closing_transaction {:?} {:?}",
            self.node_id,
            self.channel_id
        );
        let mut to_holder_value = 0;
        let mut to_counterparty_value = 0;
        let local_script = payload_for_p2wpkh(
            &signer
                .get_shutdown_pubkey(&self.node_id)
                .map_err(|s| self.bad_status(s))?,
        )
        .script_pubkey();
        let mut to_counterparty_script = Script::default();
        for out in &closing_tx.output {
            if out.script_pubkey == local_script {
                if to_holder_value > 0 {
                    // BEGIN NOT TESTED
                    log_error!(signer, "multiple to_holder outputs");
                    return Err(());
                    // END NOT TESTED
                }
                to_holder_value = out.value;
            } else {
                if to_counterparty_value > 0 {
                    // BEGIN NOT TESTED
                    log_error!(signer, "multiple to_counterparty outputs");
                    return Err(());
                    // END NOT TESTED
                }
                to_counterparty_value = out.value;
                to_counterparty_script = out.script_pubkey.clone();
            }
        }

        let res = self
            .signer
            .sign_mutual_close_tx_phase2(
                &self.node_id,
                &self.channel_id,
                to_holder_value,
                to_counterparty_value,
                Some(to_counterparty_script),
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(res)
    }

    fn sign_channel_announcement(
        &self,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_counterparty_commitment {:?} {:?}",
            self.node_id,
            self.channel_id
        );
        let res = self
            .signer
            .sign_channel_announcement(&self.node_id, &self.channel_id, &msg.encode())
            .map_err(|s| self.bad_status(s))?
            .1;

        let sig = Signature::from_der(res.as_slice())
            .map_err(|_e| ()) // NOT TESTED
            .expect("failed to parse the signature we just created");
        Ok(sig)
    }

    fn ready_channel(&mut self, parameters: &ChannelTransactionParameters) {
        let signer = &self.signer;
        log_info!(
            signer,
            "set_remote_channel_pubkeys {:?} {:?}",
            self.node_id,
            self.channel_id
        );

        // TODO cover local vs remote to_self_delay with a test
        let funding_outpoint = parameters.funding_outpoint.unwrap().into_bitcoin_outpoint();
        let counterparty_parameters = parameters.counterparty_parameters.as_ref().unwrap();
        let setup = ChannelSetup {
            is_outbound: self.is_outbound,
            channel_value_sat: self.channel_value_sat,
            push_value_msat: 0, // TODO
            funding_outpoint,
            holder_to_self_delay: parameters.holder_selected_contest_delay,
            holder_shutdown_script: None, // use the signer's shutdown script
            counterparty_points: counterparty_parameters.pubkeys.clone(),
            counterparty_to_self_delay: counterparty_parameters.selected_contest_delay,
            counterparty_shutdown_script: Default::default(), // TODO
            commitment_type: CommitmentType::StaticRemoteKey, // TODO
        };
        self.signer
            .ready_channel(&self.node_id, self.channel_id, None, setup)
            .expect("channel already ready or does not exist");
        // Copy some parameters that we need here
        self.counterparty_pubkeys = Some(counterparty_parameters.pubkeys.clone());
        self.local_to_self_delay = parameters.holder_selected_contest_delay;
        self.counterparty_to_self_delay = counterparty_parameters.selected_contest_delay;
    }
}

impl Sign for LoopbackChannelSigner {
}

impl KeysInterface for LoopbackSignerKeysInterface {
    type Signer = LoopbackChannelSigner;

    // TODO secret key leaking
    fn get_node_secret(&self) -> SecretKey {
        self.signer
            .with_node(&self.node_id, |node_opt| {
                node_opt.map_or(Err(()), |n| Ok(n.get_node_secret()))
            })
            .unwrap()
    }

    fn get_destination_script(&self) -> Script {
        self.signer
            .with_node(&self.node_id, |node_opt| {
                node_opt.map_or(Err(()), |n| Ok(n.get_destination_script()))
            })
            .unwrap()
    }

    fn get_shutdown_pubkey(&self) -> PublicKey {
        self.signer
            .with_node(&self.node_id, |node_opt| {
                node_opt.map_or(Err(()), |n| Ok(n.get_shutdown_pubkey()))
            })
            .unwrap()
    }

    fn get_channel_signer(&self, is_inbound: bool, channel_value_sat: u64) -> Self::Signer {
        let channel_id = self.signer.new_channel(&self.node_id, None, None).unwrap();
        LoopbackChannelSigner::new(
            &self.node_id,
            &channel_id,
            Arc::clone(&self.signer),
            !is_inbound,
            channel_value_sat,
        )
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.backing.get_secure_random_bytes()
    }

    // BEGIN NOT TESTED
    fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        unimplemented!()
    }
    // END NOT TESTED
}

fn get_delayed_payment_keys(
    secp_ctx: &Secp256k1<All>,
    per_commitment_point: &PublicKey,
    a_pubkeys: &ChannelPublicKeys,
    b_pubkeys: &ChannelPublicKeys,
) -> Result<(PublicKey, PublicKey), ()> {
    let revocation_key = derive_revocation_pubkey(
        secp_ctx,
        &per_commitment_point,
        &b_pubkeys.revocation_basepoint,
    )
    .map_err(|_| ())?;
    let delayed_payment_key = derive_public_key(
        secp_ctx,
        &per_commitment_point,
        &a_pubkeys.delayed_payment_basepoint,
    )
    .map_err(|_| ())?;
    Ok((revocation_key, delayed_payment_key))
}
