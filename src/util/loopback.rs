use std::sync::Arc;

use bitcoin::{Script, Transaction};
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::chan_utils::{
    build_htlc_transaction, get_htlc_redeemscript, ChannelPublicKeys, HTLCOutputInCommitment,
    LocalCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signature};

use crate::node::node::{ChannelId, ChannelSetup};
use crate::server::my_keys_manager::INITIAL_COMMITMENT_NUMBER;
use crate::server::my_signer::MySigner;
use crate::tx::tx::{get_commitment_transaction_number_obscure_factor, HTLCInfo2};
use crate::util::crypto_utils::{payload_for_p2wpkh, derive_public_revocation_key, derive_public_key};
use lightning::ln::chan_utils;
use lightning::util::ser::Writeable;
use std::collections::HashSet;
use tonic::Status;

/// Adapt MySigner to KeysInterface
pub struct LoopbackSignerKeysInterface {
    pub node_id: PublicKey,
    pub signer: Arc<MySigner>,
}

#[derive(Clone)]
pub struct LoopbackChannelSigner {
    pub node_id: PublicKey,
    pub channel_id: ChannelId,
    pub signer: Arc<MySigner>,
    pub pubkeys: ChannelPublicKeys,
    pub remote_pubkeys: Option<ChannelPublicKeys>,
    pub is_outbound: bool,
    pub channel_value_sat: u64,
    pub local_to_self_delay: u16,
    pub remote_to_self_delay: u16,
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
            remote_pubkeys: None,
            is_outbound,
            channel_value_sat,
            local_to_self_delay: 0,
            remote_to_self_delay: 0,
        }
    }

    pub fn make_remote_tx_keys<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        per_commitment_point: &PublicKey,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<TxCreationKeys, ()> {
        let pubkeys = &self.pubkeys;
        let remote_pubkeys = self.remote_pubkeys.as_ref().ok_or(())?;
        let keys = TxCreationKeys::new(
            secp_ctx,
            &per_commitment_point,
            &remote_pubkeys.delayed_payment_basepoint,
            &remote_pubkeys.htlc_basepoint,
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
}

fn bitcoin_sig_to_signature(mut res: Vec<u8>) -> Result<Signature, ()> {
    res.pop();
    let sig = Signature::from_der(res.as_slice())
        .map_err(|_e| ()) // NOT TESTED
        .expect("failed to parse the signature we just created");
    Ok(sig)
}

impl ChannelKeys for LoopbackChannelSigner {
    fn get_per_commitment_point<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        idx: u64,
        _secp_ctx: &Secp256k1<T>,
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

    fn key_derivation_params(&self) -> (u64, u64) {
        // TODO
        (0, 0)
    }

    // TODO - Couldn't this return a declared error signature?
    fn sign_remote_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        feerate_per_kw: u32,
        commitment_tx: &Transaction,
        keys: &TxCreationKeys,
        htlcs: &[&HTLCOutputInCommitment],
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_remote_commitment {:?} {:?} txid {}",
            self.node_id,
            self.channel_id,
            commitment_tx.txid(),
        );

        let (
            commitment_number,
            to_local_value_sat,
            to_remote_value_sat,
            offered_htlcs,
            received_htlcs,
        ) = self.decode_commitment_tx(commitment_tx, htlcs);

        self.signer
            .additional_setup(
                &self.node_id,
                &self.channel_id,
                commitment_tx.input[0].previous_output,
            )
            .map_err(|s| self.bad_status(s))?;

        let (sig_vec, htlc_sig_vecs) = self
            .signer
            .sign_remote_commitment_tx_phase2(
                &self.node_id,
                &self.channel_id,
                keys.per_commitment_point,
                commitment_number,
                feerate_per_kw,
                to_local_value_sat,
                to_remote_value_sat,
                offered_htlcs,
                received_htlcs,
            )
            .map_err(|s| self.bad_status(s))?;
        let commitment_sig = bitcoin_sig_to_signature(sig_vec)?;
        let mut htlc_sigs = Vec::with_capacity(htlcs.len());
        for htlc_sig_vec in htlc_sig_vecs {
            htlc_sigs.push(bitcoin_sig_to_signature(htlc_sig_vec)?);
        }
        Ok((commitment_sig, htlc_sigs))
    }

    fn sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        lct: &LocalCommitmentTransaction,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let signer = &self.signer;

        for out in &lct.unsigned_tx.output {
            log_debug!(
                signer,
                "loopback: local out script {:?} {}",
                out.script_pubkey,
                out.value
            );
        }
        log_debug!(
            signer,
            "loopback: sign local txid {}",
            lct.unsigned_tx.txid()
        );

        let htlcs: Vec<&HTLCOutputInCommitment> = lct.per_htlc.iter().map(|(h, _)| h).collect();
        let (
            commitment_number,
            to_local_value_sat,
            to_remote_value_sat,
            offered_htlcs,
            received_htlcs,
        ) = self.decode_commitment_tx(&lct.unsigned_tx, htlcs.as_slice());

        let (sig_vec, _htlc_sig_vecs) = signer
            .sign_local_commitment_tx_phase2(
                &self.node_id,
                &self.channel_id,
                commitment_number,
                0, // feerate is not relevant because we are not signing HTLCs
                to_local_value_sat,
                to_remote_value_sat,
                offered_htlcs,
                received_htlcs,
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(sig_vec)
    }

    fn unsafe_sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        _lct: &LocalCommitmentTransaction,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        unimplemented!()
    }

    fn sign_local_commitment_htlc_transactions<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        lct: &LocalCommitmentTransaction,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Vec<Option<Signature>>, ()> {
        let signer = &self.signer;
        let mut ret = Vec::with_capacity(lct.per_htlc.len());

        let htlcs: Vec<&HTLCOutputInCommitment> = lct.per_htlc.iter().map(|(h, _)| h).collect();
        let (commitment_number, _, _, _, _) = self.decode_commitment_tx(&lct.unsigned_tx, &htlcs);

        let per_commitment_point = lct.local_keys.per_commitment_point;
        let remote_pubkeys = self.remote_pubkeys.as_ref().unwrap();
        let (revocation_key, delayed_payment_key) =
            get_delayed_payment_keys(secp_ctx, &per_commitment_point, &self.pubkeys, remote_pubkeys)?;
        for this_htlc in lct.per_htlc.iter() {
            if this_htlc.0.transaction_output_index.is_some() {
                let keys = &lct.local_keys;
                let htlc_tx = build_htlc_transaction(
                    &lct.txid(),
                    lct.feerate_per_kw,
                    self.remote_to_self_delay,
                    &this_htlc.0,
                    &delayed_payment_key,
                    &revocation_key,
                );

                for out in &htlc_tx.output {
                    log_debug!(
                        signer,
                        "loopback: local out htlc script {:?} {}",
                        out.script_pubkey,
                        out.value
                    );
                }
                log_debug!(signer, "loopback: sign local htlc txid {}", htlc_tx.txid());
                let htlc_redeemscript = get_htlc_redeemscript(&this_htlc.0, keys);

                // TODO phase 2
                let res = signer
                    .sign_local_htlc_tx(
                        &self.node_id,
                        &self.channel_id,
                        &htlc_tx,
                        commitment_number,
                        None,
                        htlc_redeemscript.to_bytes(),
                        this_htlc.0.amount_msat / 1000,
                    )
                    .map_err(|s| self.bad_status(s))?;

                ret.push(Some(bitcoin_sig_to_signature(res)?));
            } else {
                ret.push(None); // NOT TESTED
            }
        }
        Ok(ret)
    }

    fn sign_justice_transaction<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &Option<HTLCOutputInCommitment>,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let per_commitment_point = PublicKey::from_secret_key(secp_ctx, per_commitment_key);
        let remote_pubkeys = self.remote_pubkeys.as_ref().unwrap();

        let (revocation_key, delayed_payment_key) =
            get_delayed_payment_keys(secp_ctx, &per_commitment_point, remote_pubkeys, &self.pubkeys)?;
        let redeem_script = if let Some(ref htlc) = *htlc {
            let tx_keys = self.make_remote_tx_keys(&per_commitment_point, secp_ctx)?;
            chan_utils::get_htlc_redeemscript(&htlc, &tx_keys) // NOT TESTED
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
            .sign_penalty_to_us(
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

    fn sign_remote_htlc_transaction<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let chan_keys = self.make_remote_tx_keys(per_commitment_point, secp_ctx)?;
        let redeem_script = chan_utils::get_htlc_redeemscript(htlc, &chan_keys);

        // TODO phase 2
        let res = self
            .signer
            .sign_remote_htlc_to_us(
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
    fn sign_closing_transaction<T: secp256k1::Signing>(
        &self,
        closing_tx: &Transaction,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_closing_transaction {:?} {:?}",
            self.node_id,
            self.channel_id
        );
        let mut to_local_value = 0;
        let mut to_remote_value = 0;
        let local_script = payload_for_p2wpkh(
            &signer
                .get_shutdown_pubkey(&self.node_id)
                .map_err(|s| self.bad_status(s))?,
        )
        .script_pubkey();
        let mut to_remote_script = Script::default();
        for out in &closing_tx.output {
            if out.script_pubkey == local_script {
                if to_local_value > 0 {
                    log_error!(signer, "multiple to_local outputs");
                    return Err(());
                }
                to_local_value = out.value;
            } else {
                if to_remote_value > 0 {
                    log_error!(signer, "multiple to_remote outputs");
                    return Err(());
                }
                to_remote_value = out.value;
                to_remote_script = out.script_pubkey.clone();
            }
        }

        let res = self
            .signer
            .sign_mutual_close_tx_phase2(
                &self.node_id,
                &self.channel_id,
                to_local_value,
                to_remote_value,
                Some(to_remote_script),
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(res)
    }

    fn sign_channel_announcement<T: secp256k1::Signing>(
        &self,
        msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_remote_commitment {:?} {:?}",
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

    fn on_accept(
        &mut self,
        remote_points: &ChannelPublicKeys,
        remote_to_self_delay: u16,
        local_to_self_delay: u16,
    ) {
        let signer = &self.signer;
        log_info!(
            signer,
            "set_remote_channel_pubkeys {:?} {:?}",
            self.node_id,
            self.channel_id
        );

        // TODO cover local vs remote to_self_delay with a test
        let setup = ChannelSetup {
            is_outbound: self.is_outbound,
            channel_value_sat: self.channel_value_sat,
            push_value_msat: 0,                   // TODO
            funding_outpoint: Default::default(), // TODO
            local_to_self_delay,
            local_shutdown_script: None,          // use the signer's shutdown script
            remote_points: remote_points.clone(),
            remote_to_self_delay,
            remote_shutdown_script: Default::default(), // TODO
            option_static_remotekey: true,              // TODO
        };
        self.signer
            .ready_channel(&self.node_id, self.channel_id, setup)
            .expect("channel already ready or does not exist");
        self.remote_pubkeys = Some(remote_points.clone());
        self.local_to_self_delay = local_to_self_delay;
        self.remote_to_self_delay = remote_to_self_delay;
    }
}


impl KeysInterface for LoopbackSignerKeysInterface {
    type ChanKeySigner = LoopbackChannelSigner;

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

    fn get_channel_keys(&self, is_inbound: bool, channel_value_sat: u64) -> Self::ChanKeySigner {
        let channel_id = self.signer.new_channel(&self.node_id, None, None).unwrap();
        LoopbackChannelSigner::new(
            &self.node_id,
            &channel_id,
            Arc::clone(&self.signer),
            !is_inbound,
            channel_value_sat,
        )
    }

    // TODO secret key leaking
    fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
        self.signer
            .with_node(&self.node_id, |node_opt| {
                node_opt.map_or(Err(()), |n| Ok(n.get_onion_rand()))
            })
            .unwrap()
    }

    fn get_channel_id(&self) -> [u8; 32] {
        self.signer
            .with_node(&self.node_id, |node_opt| {
                node_opt.map_or(Err(()), |n| Ok(n.get_channel_id()))
            })
            .unwrap()
    }
}

impl LoopbackChannelSigner {
    /// Adapt phase 1 signing parameters (serialized tx and htlcs) to phase 2 information
    /// (commitment number, local and remote values, HTLCInfo2 objects)
    fn decode_commitment_tx(
        &self,
        commitment_tx: &Transaction,
        htlcs: &[&HTLCOutputInCommitment],
    ) -> (u64, u64, u64, Vec<HTLCInfo2>, Vec<HTLCInfo2>) {
        let mut to_local_value_sat = 0;
        let mut to_remote_value_sat = 0;

        let mut offered_htlcs = Vec::new();
        let mut received_htlcs = Vec::new();
        let htlc_indices: HashSet<u32> = htlcs
            .iter()
            .filter_map(|h| h.transaction_output_index)
            .collect();

        for htlc in htlcs {
            let info = HTLCInfo2 {
                value_sat: htlc.amount_msat / 1000,
                payment_hash: htlc.payment_hash,
                cltv_expiry: htlc.cltv_expiry,
            };
            if htlc.offered {
                offered_htlcs.push(info);
            } else {
                received_htlcs.push(info);
            }
        }

        for (idx, out) in commitment_tx.output.iter().enumerate() {
            if out.script_pubkey.is_v0_p2wsh() {
                if !htlc_indices.contains(&(idx as u32)) {
                    if to_local_value_sat != 0 {
                        panic!("multiple to-local")
                    }
                    to_local_value_sat = out.value;
                }
            } else {
                if to_remote_value_sat != 0 {
                    panic!("multiple to-remote")
                }
                to_remote_value_sat = out.value;
            }
        }

        let obscure_factor = get_commitment_transaction_number_obscure_factor(
            &self.pubkeys.payment_point,
            &self.remote_pubkeys.as_ref().unwrap().payment_point,
            self.is_outbound,
        );

        let commitment_number = (((commitment_tx.input[0].sequence as u64 & 0xffffff) << 3 * 8)
            | (commitment_tx.lock_time as u64 & 0xffffff))
            ^ obscure_factor;

        (
            commitment_number,
            to_local_value_sat,
            to_remote_value_sat,
            offered_htlcs,
            received_htlcs,
        )
    }
}

fn get_delayed_payment_keys<T: secp256k1::Signing + secp256k1::Verification>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    a_pubkeys: &ChannelPublicKeys,
    b_pubkeys: &ChannelPublicKeys)
    -> Result<(PublicKey, PublicKey), ()> {
    let revocation_key =
        derive_public_revocation_key(secp_ctx, &per_commitment_point,
                                     &b_pubkeys.revocation_basepoint)
            .map_err(|_| ())?;
    let delayed_payment_key =
        derive_public_key(secp_ctx, &per_commitment_point,
                          &a_pubkeys.delayed_payment_basepoint)
            .map_err(|_| ())?;
    Ok((revocation_key, delayed_payment_key))
}
