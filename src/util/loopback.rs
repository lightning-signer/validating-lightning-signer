use std::sync::Arc;

use bitcoin::{Script, Transaction};
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::chan_utils::{
    ChannelPublicKeys, HTLCOutputInCommitment, LocalCommitmentTransaction, TxCreationKeys,
};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signature};

use crate::node::node::{ChannelId, ChannelSetup, ChannelSlot};
use crate::server::my_signer::MySigner;
use lightning::util::ser::Writeable;
use tonic::Status;

/// Adapt MySigner to KeysInterface
pub struct LoopbackSignerKeysInterface {
    pub node_id: PublicKey,
    pub signer: Arc<MySigner>,
}

// BEGIN NOT TESTED
#[derive(Clone)]
pub struct LoopbackChannelSigner {
    pub node_id: PublicKey,
    pub channel_id: ChannelId,
    pub signer: Arc<MySigner>,
    pub pubkeys: ChannelPublicKeys,
    pub is_outbound: bool,
    pub channel_value_sat: u64,
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
            .with_channel_slot(node_id, channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(chan)) => Ok(chan.keys.pubkeys().clone()),
                Some(ChannelSlot::Ready(chan)) => Ok(chan.keys.pubkeys().clone()),
            })
            .expect("no such channel");
        LoopbackChannelSigner {
            node_id: *node_id,
            channel_id: *channel_id,
            signer: signer.clone(),
            pubkeys,
            is_outbound,
            channel_value_sat,
        }
    }

    fn unready_channel<T>(&self) -> Result<T, ()> {
        let signer = &self.signer;
        log_error!(signer, "unready channel {}", self.channel_id);
        Err(())
    }

    fn bad_status(&self, s: Status) {
        let signer = &self.signer;
        log_error!(signer, "bad status {:?} on channel {}", s, self.channel_id);
    }
}

fn bitcoin_sig_to_signature(mut res: Vec<u8>) -> Result<Signature, ()> {
    res.pop();
    let sig = Signature::from_der(res.as_slice())
        .map_err(|_e| ())
        .expect("failed to parse the signature we just created");
    Ok(sig)
}

impl ChannelKeys for LoopbackChannelSigner {
    fn commitment_secret(&self, idx: u64) -> [u8; 32] {
        // FIXME implement this in signer to remove this bypass
        self.signer
            .with_channel_slot(&self.node_id, &self.channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(chan)) => Ok(chan.keys.commitment_secret(idx)),
                Some(ChannelSlot::Ready(chan)) => Ok(chan.keys.commitment_secret(idx)),
            })
            .expect("no such channel")
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
        to_self_delay: u16,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        let signer = &self.signer;
        log_info!(
            signer,
            "sign_remote_commitment {:?} {:?}",
            self.node_id,
            self.channel_id
        );
        // FIXME don't bypass the signer here
        // The signer wants output_witscripts for validation - figure out how provide equivalent
        self.signer
            .with_channel_slot(&self.node_id, &self.channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(_)) => self.unready_channel(),
                Some(ChannelSlot::Ready(chan)) => chan
                    .sign_remote_commitment(
                        feerate_per_kw,
                        commitment_tx,
                        &keys.per_commitment_point,
                        htlcs,
                        to_self_delay,
                    )
                    .map_err(|_| ()),
            })
    }

    fn sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        local_commitment_tx: &LocalCommitmentTransaction,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        let res = self
            .signer
            .sign_commitment_tx(
                &self.node_id,
                &self.channel_id,
                &local_commitment_tx.unsigned_tx,
                self.channel_value_sat,
            )
            .map_err(|s| self.bad_status(s))?;
        bitcoin_sig_to_signature(res)
    }

    fn unsafe_sign_local_commitment<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        _local_commitment_tx: &LocalCommitmentTransaction,
        _secp_ctx: &Secp256k1<T>,
    ) -> Result<Signature, ()> {
        unimplemented!()
    }

    fn sign_local_commitment_htlc_transactions<T: secp256k1::Signing + secp256k1::Verification>(
        &self,
        local_commitment_tx: &LocalCommitmentTransaction,
        local_csv: u16,
        secp_ctx: &Secp256k1<T>,
    ) -> Result<Vec<Option<Signature>>, ()> {
        // FIXME don't bypass the signer here
        // The signer wants output_witscripts for validation - figure out how provide equivalent
        self.signer
            .with_channel_slot(&self.node_id, &self.channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(_)) => self.unready_channel(),
                Some(ChannelSlot::Ready(chan)) => chan
                    .keys
                    .sign_local_commitment_htlc_transactions(
                        local_commitment_tx,
                        local_csv,
                        secp_ctx,
                    )
                    .map_err(|_| ()),
            })
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
        // FIXME don't bypass the signer here
        self.signer
            .with_channel_slot(&self.node_id, &self.channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(_)) => self.unready_channel(),
                Some(ChannelSlot::Ready(chan)) => chan
                    .keys
                    .sign_justice_transaction(
                        justice_tx,
                        input,
                        amount,
                        per_commitment_key,
                        htlc,
                        on_remote_tx_csv,
                        secp_ctx,
                    )
                    .map_err(|_| ()),
            })
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
        // FIXME don't bypass the signer here
        self.signer
            .with_channel_slot(&self.node_id, &self.channel_id, |slot| match slot {
                None => Err(()),
                Some(ChannelSlot::Stub(_)) => self.unready_channel(),
                Some(ChannelSlot::Ready(chan)) => chan
                    .keys
                    .sign_remote_htlc_transaction(
                        htlc_tx,
                        input,
                        amount,
                        per_commitment_point,
                        htlc,
                        secp_ctx,
                    )
                    .map_err(|_| ()),
            })
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
        let res = self
            .signer
            .sign_mutual_close_tx(
                &self.node_id,
                &self.channel_id,
                closing_tx,
                self.channel_value_sat,
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
            .map_err(|_e| ())
            .expect("failed to parse the signature we just created");
        Ok(sig)
    }

    fn set_remote_channel_pubkeys(&mut self, remote_points: &ChannelPublicKeys) {
        let signer = &self.signer;
        log_info!(
            signer,
            "set_remote_channel_pubkeys {:?} {:?}",
            self.node_id,
            self.channel_id
        );

        let setup = ChannelSetup {
            is_outbound: self.is_outbound,
            channel_value_sat: self.channel_value_sat,
            push_value_msat: 0,                        // TODO
            funding_outpoint: Default::default(),      // TODO
            local_to_self_delay: 0,                    // TODO
            local_shutdown_script: Default::default(), // TODO
            remote_points: remote_points.clone(),
            remote_to_self_delay: 0,                    // TODO
            remote_shutdown_script: Default::default(), // TODO
            option_static_remotekey: false,             // TODO
        };
        self.signer
            .ready_channel(&self.node_id, self.channel_id, setup)
            .expect("channel already ready or does not exist");
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
