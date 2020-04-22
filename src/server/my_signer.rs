use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin;
use bitcoin::util::bip143;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{Address, Network, Script, SigHashType};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use lightning::chain::keysinterface::{ChannelKeys, KeysInterface};
use lightning::ln::chan_utils::{derive_private_key, ChannelPublicKeys};
use lightning::util::logger::Logger;
use rand::{thread_rng, Rng};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use tonic::Status;

use crate::node::node::{Channel, ChannelId, Node};
use crate::server::my_keys_manager::MyKeysManager;
use crate::tx::tx::{build_close_tx, sign_commitment, CommitmentInfo, HTLCInfo};
use crate::util::crypto_utils::{derive_private_revocation_key, payload_for_p2wpkh};
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;
use crate::util::test_utils::TestLogger;

use super::remotesigner::SpendType;

pub struct MySigner {
    pub logger: Arc<Logger>,
    nodes: Mutex<HashMap<PublicKey, Arc<Node>>>,
}

impl MySigner {
    pub fn new() -> MySigner {
        let test_logger = Arc::new(TestLogger::with_id("server".to_owned()));
        let signer = MySigner {
            logger: test_logger,
            nodes: Mutex::new(HashMap::new()),
        };
        log_info!(signer, "new MySigner");
        signer
    }

    pub fn new_node(&self) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;
        let mut rng = thread_rng();

        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);

        let node = Node::new(&self.logger, &seed, network);
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, Arc::new(node));
        node_id
    }

    pub fn new_node_from_seed(&self, seed: &[u8; 32]) -> PublicKey {
        let secp_ctx = Secp256k1::signing_only();
        let network = Network::Testnet;

        let node = Node::new(&self.logger, seed, network);
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node.keys_manager.get_node_secret());
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node_id, Arc::new(node));
        node_id
    }

    pub fn new_channel(
        &self,
        node_id: &PublicKey,
        channel_value_satoshi: u64,
        opt_channel_nonce: Option<Vec<u8>>,
        opt_channel_id: Option<ChannelId>,
        local_to_self_delay: u16,
        is_outbound: bool,
    ) -> Result<ChannelId, Status> {
        log_info!(self, "new channel {}/{:?}", node_id, opt_channel_id);
        let nodes = self.nodes.lock().unwrap();
        let node = nodes
            .get(node_id)
            .ok_or_else(|| self.internal_error(format!("no such node {}", node_id)))?;
        let mut channels = node.channels();
        let keys_manager = &node.keys_manager;
        let channel_id = opt_channel_id.unwrap_or_else(|| ChannelId(keys_manager.get_channel_id()));
        let channel_nonce = opt_channel_nonce.unwrap_or_else(|| channel_id.0.to_vec());
        if channels.contains_key(&channel_id) {
            log_info!(self, "already have channel ID {}", channel_id); // NOT TESTED
            return Ok(channel_id); // NOT TESTED
        }
        let inmem_keys = keys_manager.get_channel_keys_with_nonce(
            channel_nonce.as_slice(),
            channel_value_satoshi,
            "c-lightning",
        );
        let chan_keys = EnforcingChannelKeys::new(inmem_keys);
        let channel = Channel {
            node: Arc::clone(node),
            logger: Arc::clone(&self.logger),
            keys: chan_keys,
            secp_ctx: Secp256k1::new(),
            channel_value_satoshi,
            local_to_self_delay,
            remote_config: None,
            is_outbound,
        };
        channels.insert(channel_id, channel);
        Ok(channel_id)
    }

    pub fn with_node<F: Sized, T, E>(&self, node_id: &PublicKey, f: F) -> Result<T, E>
    where
        F: Fn(Option<&Node>) -> Result<T, E>,
    {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        f(node.map(|an| an.as_ref()))
    }

    pub fn with_node_do<F: Sized, T>(&self, node_id: &PublicKey, f: F) -> T
    where
        F: Fn(Option<&Node>) -> T,
    {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        f(node.map(|an| an.as_ref()))
    }

    pub fn with_channel<F: Sized, T, E>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, E>
    where
        F: Fn(Option<&mut Channel>) -> Result<T, E>,
    {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or_else(|| f(None), |n| f(n.channels().get_mut(channel_id)))
    }

    pub fn with_existing_channel<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> Result<T, Status>
    where
        F: Fn(&mut Channel) -> Result<T, Status>,
    {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or_else(
            || Err(self.invalid_argument("no such node")),
            |n| {
                let mut guard = n.channels();
                let chan = guard
                    .get_mut(channel_id)
                    .ok_or_else(|| self.invalid_argument("no such channel"))?;
                f(chan)
            },
        )
    }

    pub fn with_channel_do<F: Sized, T>(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        f: F,
    ) -> T
    where
        F: Fn(Option<&mut Channel>) -> T,
    {
        let nodes = self.nodes.lock().unwrap();
        let node = nodes.get(node_id);
        node.map_or_else(|| f(None), |n| f(n.channels().get_mut(channel_id)))
    }

    pub fn channel_exists(&self, node_id: &PublicKey, channel_id: &ChannelId) -> bool {
        self.with_channel_do(node_id, channel_id, |opt_chan| return !opt_chan.is_none())
    }

    pub fn xkey(&self, node_id: &PublicKey) -> Result<ExtendedPrivKey, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| {
                // BEGIN NOT TESTED
                self.invalid_argument(format!("xkey: node_id not found: {}", node_id))
                // END NOT TESTED
            })?;
            Ok(node.get_bip32_key().clone())
        })
    }

    // BEGIN NOT TESTED
    pub fn get_unilateral_close_key(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        opt_commitment_point: &Option<PublicKey>,
    ) -> Result<SecretKey, Status> {
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            let secret_key = match opt_commitment_point {
                Some(commitment_point) => derive_private_key(
                    &chan.secp_ctx,
                    &commitment_point,
                    &chan.keys.payment_base_key(),
                )
                .map_err(|err| {
                    self.internal_error(format!("derive_private_key failed: {}", err))
                })?,
                None => {
                    // option_static_remotekey in effect
                    chan.keys.payment_base_key().clone()
                }
            };
            Ok(secret_key)
        })
    }
    // END NOT TESTED

    pub fn get_channel_basepoints(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        channel_nonce: &Vec<u8>,
    ) -> Result<ChannelPublicKeys, Status> {
        // WORKAROUND - c-lightning calls get_channel_basepoints
        // before new_channel.  Work around this by synthesizing a
        // new_channel call if we don't already have a channel created
        // for this channel_id.
        if !self.channel_exists(node_id, channel_id) {
            let channel_value: u64 = 0;
            // bogus, but this workaround will go away and this is unused in phase 1
            let local_to_self_delay = 0u16;
            self.new_channel(
                node_id,
                channel_value,
                Some(channel_nonce.clone()),
                Some(channel_id.clone()),
                local_to_self_delay,
                false,
            )
            .map_err(|err| self.invalid_argument(format!("failed to create channel: {}", err)))?;
        }

        let retval: Result<ChannelPublicKeys, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                Ok(chan.keys.pubkeys().clone())
            });
        retval
    }

    pub fn sign_local_commitment_tx_phase2(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        commitment_number: u64,
        feerate_per_kw: u64,
        to_local_value: u64,
        to_remote_value: u64,
        offered_htlcs: Vec<HTLCInfo>,
        received_htlcs: Vec<HTLCInfo>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), Status> {
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            let per_commitment_point = chan.get_per_commitment_point(commitment_number);
            let info = chan.build_local_commitment_info(
                &per_commitment_point,
                to_local_value,
                to_remote_value,
                offered_htlcs.clone(),
                received_htlcs.clone(),
            )?;
            let (tx, _scripts, htlcs) =
                chan.build_commitment_tx(&per_commitment_point, commitment_number, &info)?;
            let keys = chan.make_local_tx_keys(&per_commitment_point)?;

            let mut htlc_refs = Vec::new();
            for htlc in htlcs.iter() {
                htlc_refs.push(htlc); // NOT TESTED
            }
            // Although this method has "remote" in the name, it works for local too
            let sigs = chan
                .keys
                .sign_remote_commitment(
                    feerate_per_kw,
                    &tx,
                    &keys,
                    htlc_refs.as_slice(),
                    chan.local_to_self_delay,
                    &chan.secp_ctx,
                )
                .map_err(|_| self.internal_error("failed to sign"))?;
            let mut sig = sigs.0.serialize_der().to_vec();
            sig.push(SigHashType::All as u8);
            let mut htlc_sigs = Vec::new();
            for htlc_signature in sigs.1 {
                // BEGIN NOT TESTED
                let mut htlc_sig = htlc_signature.serialize_der().to_vec();
                htlc_sig.push(SigHashType::All as u8);
                htlc_sigs.push(htlc_sig);
                // END NOT TESTED
            }
            Ok((sig, htlc_sigs))
        })
    }

    pub fn get_ext_pub_key(&self, node_id: &PublicKey) -> Result<ExtendedPubKey, Status> {
        self.with_node(node_id, |opt_node| {
            let secp_ctx = Secp256k1::signing_only();
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let extpubkey = ExtendedPubKey::from_private(&secp_ctx, &node.get_bip32_key());
            Ok(extpubkey)
        })
    }

    pub fn get_shutdown_pubkey(&self, node_id: &PublicKey) -> Result<PublicKey, Status> {
        self.with_node(node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            Ok(node.keys_manager.get_shutdown_pubkey())
        })
    }

    pub fn sign_mutual_close_tx_phase2(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        to_local_value: u64,
        to_remote_value: u64,
    ) -> Result<Vec<u8>, Status> {
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            let shutdown_pubkey = chan.node.keys_manager.get_shutdown_pubkey();
            let remote_config = chan
                .remote_config
                .as_ref()
                .ok_or_else(|| self.invalid_argument("channel not accepted yet"))?;
            // FIXME deserialize script when provided by remote instead of here
            let local_shutdown_script = payload_for_p2wpkh(&shutdown_pubkey).script_pubkey();
            let tx = build_close_tx(
                to_local_value,
                to_remote_value,
                &local_shutdown_script,
                &remote_config.shutdown_script,
                remote_config.funding_outpoint,
            );

            let sig = chan
                .keys
                .sign_closing_transaction(&tx, &chan.secp_ctx)
                .map_err(|_| self.internal_error("could not sign closing tx"))?;
            let mut bitcoin_sig = sig.serialize_der().to_vec();
            bitcoin_sig.push(SigHashType::All as u8);

            Ok(bitcoin_sig)
        })
    }

    // Note: chan.channel_value_satoshi is uninitialized in phase 1, so we get it from caller instead
    pub fn sign_remote_commitment_tx(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        output_witscripts: Vec<Vec<u8>>,
        _remote_per_commitment_point: &PublicKey,
        remote_funding_pubkey: &PublicKey,
        channel_value_satoshi: u64,
    ) -> Result<Vec<u8>, Status> {
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            if tx.output.len() != output_witscripts.len() {
                // BEGIN NOT TESTED
                return Err(self.invalid_argument("len(tx.output) != len(witscripts)"));
                // END NOT TESTED
            }
            // The CommitmentInfo will be used to check policy
            // assertions.
            let mut info = CommitmentInfo::new();
            for ind in 0..tx.output.len() {
                let _res = info
                    .handle_output(&tx.output[ind], output_witscripts[ind].as_slice())
                    .map_err(|ve| self.invalid_argument(ve))?;
            }

            let commitment_sig = sign_commitment(
                &chan.secp_ctx,
                &chan.keys,
                &remote_funding_pubkey,
                &tx,
                channel_value_satoshi,
            )
            .map_err(|err| self.internal_error(format!("sign_commitment failed: {}", err)))?;

            let mut sig = commitment_sig.serialize_der().to_vec();
            sig.push(SigHashType::All as u8);
            Ok(sig)
        })
    }

    pub fn sign_commitment_tx(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        remote_funding_pubkey: &PublicKey,
        funding_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sigvec: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() == 0 {
                    return Err(self.invalid_argument("tx.output.len() == 0")); // NOT TESTED
                }

                let commitment_sig = sign_commitment(
                    &chan.secp_ctx,
                    &chan.keys,
                    &remote_funding_pubkey,
                    &tx,
                    funding_amount,
                )
                .map_err(|err| self.internal_error(format!("sign_commitment failed: {}", err)))?;

                let mut sigvec = commitment_sig.serialize_der().to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        sigvec
    }

    pub fn sign_mutual_close_tx(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        remote_funding_pubkey: &PublicKey,
        funding_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sigvec: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() == 0 {
                    return Err(self.invalid_argument("tx.output.len() == 0")); // NOT TESTED
                }

                let commitment_sig = sign_commitment(
                    &chan.secp_ctx,
                    &chan.keys,
                    &remote_funding_pubkey,
                    &tx,
                    funding_amount,
                )
                .map_err(|err| self.internal_error(format!("sign_commitment failed: {}", err)))?;

                let mut sigvec = commitment_sig.serialize_der().to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        sigvec
    }

    pub fn sign_local_htlc_tx(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        n: u64,
        output_witscripts: Vec<Vec<u8>>,
        htlc_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sigvec: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() != 1 {
                    return Err(self.invalid_argument("tx.output.len() != 1")); // NOT TESTED
                }
                if output_witscripts.len() != 1 {
                    // BEGIN NOT TESTED
                    return Err(self.invalid_argument("output_witscripts.len() != 1"));
                    // END NOT TESTED
                }

                let secp_ctx = Secp256k1::signing_only();

                let per_commitment_point =
                    MyKeysManager::per_commitment_point(&secp_ctx, chan.keys.commitment_seed(), n);

                let htlc_redeemscript = Script::from((&output_witscripts[0]).to_vec());

                let htlc_sighash = Message::from_slice(
                    &bip143::SighashComponents::new(&tx).sighash_all(
                        &tx.input[0],
                        &htlc_redeemscript,
                        htlc_amount,
                    )[..],
                )
                .map_err(|err| self.internal_error(format!("htlc_sighash failed:{}", err)))?;

                let htlc_privkey = derive_private_key(
                    &secp_ctx,
                    &per_commitment_point,
                    &chan.keys.inner.htlc_base_key(),
                )
                .map_err(|err| {
                    self.internal_error(format!("derive htlc_privkey failed: {}", err))
                })?;

                let mut sigvec = secp_ctx
                    .sign(&htlc_sighash, &htlc_privkey)
                    .serialize_der()
                    .to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        sigvec
    }

    pub fn check_future_secret(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        commitment_number: u64,
        suggested: &SecretKey,
    ) -> Result<bool, Status> {
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            let secret = chan.get_per_commitment_secret(commitment_number);
            Ok(suggested[..] == secret[..])
        })
    }

    pub fn sign_delayed_payment_to_us(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        n: u64,
        output_witscripts: Vec<Vec<u8>>,
        htlc_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sigvec: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() != 1 {
                    return Err(self.invalid_argument("tx.output.len() != 1")); // NOT TESTED
                }
                if output_witscripts.len() != 1 {
                    // BEGIN NOT TESTED
                    return Err(self.invalid_argument("output_witscripts.len() != 1"));
                    // END NOT TESTED
                }

                let secp_ctx = Secp256k1::signing_only();

                let per_commitment_point =
                    MyKeysManager::per_commitment_point(&secp_ctx, chan.keys.commitment_seed(), n);

                let htlc_redeemscript = Script::from((&output_witscripts[0]).to_vec());

                let htlc_sighash = Message::from_slice(
                    &bip143::SighashComponents::new(&tx).sighash_all(
                        &tx.input[0],
                        &htlc_redeemscript,
                        htlc_amount,
                    )[..],
                )
                .map_err(|err| self.internal_error(format!("htlc_sighash failed: {}", err)))?;

                let htlc_privkey = derive_private_key(
                    &secp_ctx,
                    &per_commitment_point,
                    &chan.keys.inner.delayed_payment_base_key(),
                )
                .map_err(|err| {
                    // BEGIN NOT TESTED
                    self.internal_error(format!("derive htlc_privkey failed: {}", err))
                    // END NOT TESTED
                })?;

                let mut sigvec = secp_ctx
                    .sign(&htlc_sighash, &htlc_privkey)
                    .serialize_der()
                    .to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        sigvec
    }

    pub fn sign_remote_htlc_tx(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        output_witscripts: Vec<Vec<u8>>,
        remote_per_commitment_point: &PublicKey,
        htlc_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sig: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.output.len() != output_witscripts.len() {
                    // BEGIN NOT TESTED
                    return Err(self.invalid_argument("len(tx.output) != len(witscripts)"));
                    // END NOT TESTED
                }
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("len(tx.input) != 1")); // NOT TESTED
                }
                if tx.output.len() != 1 {
                    return Err(self.invalid_argument("len(tx.output) != 1")); // NOT TESTED
                }

                let secp_ctx = &chan.secp_ctx;

                let htlc_redeemscript = Script::from((&output_witscripts[0]).to_vec());

                let htlc_sighash = Message::from_slice(
                    &bip143::SighashComponents::new(&tx).sighash_all(
                        &tx.input[0],
                        &htlc_redeemscript,
                        htlc_amount,
                    )[..],
                )
                .map_err(|err| self.internal_error(format!("htlc_sighash failed: {}", err)))?;

                let our_htlc_key = derive_private_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.inner.htlc_base_key(),
                )
                .map_err(|err| {
                    // BEGIN NOT TESTED
                    self.internal_error(format!("derive our_htlc_key failed: {}", err))
                    // END NOT TESTED
                })?;

                let sigobj = secp_ctx.sign(&htlc_sighash, &our_htlc_key);
                let mut sig = sigobj.serialize_der().to_vec();
                sig.push(SigHashType::All as u8);
                Ok(sig)
            });
        sig
    }

    pub fn sign_remote_htlc_to_us(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        output_witscripts: Vec<Vec<u8>>,
        remote_per_commitment_point: &PublicKey,
        htlc_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let retval: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() != 1 {
                    return Err(self.invalid_argument("tx.output.len() != 1")); // NOT TESTED
                }
                if output_witscripts.len() != 1 {
                    // BEGIN NOT TESTED
                    return Err(self.invalid_argument("output_witscripts.len() != 1"));
                    // END NOT TESTED
                }

                let secp_ctx = &chan.secp_ctx;

                let redeemscript = Script::from((&output_witscripts[0]).to_vec());

                let sighash = Message::from_slice(
                    &bip143::SighashComponents::new(&tx).sighash_all(
                        &tx.input[0],
                        &redeemscript,
                        htlc_amount,
                    )[..],
                )
                .map_err(|err| self.internal_error(format!("sighash failed: {}", err)))?;

                let privkey = derive_private_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.inner.htlc_base_key(),
                )
                .map_err(|err| self.internal_error(format!("derive privkey failed: {}", err)))?;

                let mut sigvec = secp_ctx.sign(&sighash, &privkey).serialize_der().to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        retval
    }

    pub fn sign_penalty_to_us(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        revocation_secret: &SecretKey,
        output_witscripts: Vec<Vec<u8>>,
        htlc_amount: u64,
    ) -> Result<Vec<u8>, Status> {
        let sigvec: Result<Vec<u8>, Status> =
            self.with_existing_channel(&node_id, &channel_id, |chan| {
                if tx.input.len() != 1 {
                    return Err(self.invalid_argument("tx.input.len() != 1")); // NOT TESTED
                }
                if tx.output.len() != 1 {
                    return Err(self.invalid_argument("tx.output.len() != 1")); // NOT TESTED
                }
                if output_witscripts.len() != 1 {
                    // BEGIN NOT TESTED
                    return Err(self.invalid_argument("output_witscripts.len() != 1"));
                    // END NOT TESTED
                }

                let secp_ctx = &chan.secp_ctx;

                let redeemscript = Script::from((&output_witscripts[0]).to_vec());

                let sighash = Message::from_slice(
                    &bip143::SighashComponents::new(&tx).sighash_all(
                        &tx.input[0],
                        &redeemscript,
                        htlc_amount,
                    )[..],
                )
                .map_err(|err| self.internal_error(format!("sighash failed: {}", err)))?;

                let privkey = derive_private_revocation_key(
                    secp_ctx,
                    revocation_secret,
                    chan.keys.revocation_base_key(),
                )
                .map_err(|err| self.internal_error(format!("derive privkey failed: {}", err)))?;

                let mut sigvec = secp_ctx.sign(&sighash, &privkey).serialize_der().to_vec();
                sigvec.push(SigHashType::All as u8);
                Ok(sigvec)
            });
        sigvec
    }

    pub fn sign_funding_tx(
        &self,
        node_id: &PublicKey,
        _channel_id: &ChannelId,
        tx: &bitcoin::Transaction,
        indices: &Vec<u32>,
        values: &Vec<u64>,
        spendtypes: &Vec<SpendType>,
        uniclosekeys: &Vec<Option<SecretKey>>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Status> {
        let secp_ctx = Secp256k1::signing_only();
        let xkey = self.xkey(node_id)?;

        let mut witvec: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for idx in 0..tx.input.len() {
            let child_index = indices[idx];
            let value = values[idx];
            let privkey = match uniclosekeys[idx] {
                // There was a unilateral_close_key.
                Some(sk) => bitcoin::PrivateKey {
                    compressed: true,
                    network: Network::Testnet,
                    key: sk,
                },
                // Derive the HD key.
                None => {
                    xkey.ckd_priv(&secp_ctx, ChildNumber::from(child_index))
                        .map_err(|err| self.internal_error(format!("ckd_priv failed: {}", err)))?
                        .private_key
                }
            };
            let pubkey = privkey.public_key(&secp_ctx);
            let script_code = Address::p2pkh(&pubkey, privkey.network).script_pubkey();
            let sighash =
                match spendtypes[idx] {
                    SpendType::P2pkh => Message::from_slice(
                        &tx.signature_hash(0, &script_code, 0x01)[..],
                    )
                    .map_err(|err| self.internal_error(format!("p2pkh sighash failed: {}", err))),
                    SpendType::P2wpkh | SpendType::P2shP2wpkh => Message::from_slice(
                        &SighashComponents::new(&tx).sighash_all(
                            &tx.input[idx],
                            &script_code,
                            value,
                        )[..],
                    )
                    .map_err(|err| self.internal_error(format!("p2wpkh sighash failed: {}", err))),
                    // BEGIN NOT TESTED
                    _ => Err(self.invalid_argument(format!(
                        "unsupported spend_type: {}",
                        spendtypes[idx] as i32
                    ))),
                    // END NOT TESTED
                }?;
            let mut sig = secp_ctx
                .sign(&sighash, &privkey.key)
                .serialize_der()
                .to_vec();
            sig.push(SigHashType::All as u8);
            witvec.push((sig, pubkey.key.serialize().to_vec()));
        }
        Ok(witvec)
    }

    // BEGIN NOT TESTED
    pub fn ecdh(&self, node_id: &PublicKey, other_key: &PublicKey) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let our_key = node.keys_manager.get_node_secret();
            let ss = SharedSecret::new(&other_key, &our_key);
            let res = ss[..].to_vec();
            Ok(res)
        })
    }
    // END NOT TESTED

    pub fn sign_channel_announcement(
        &self,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        ca: &Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), Status> {
        let secp_ctx = Secp256k1::signing_only();
        let ca_hash = Sha256dHash::hash(ca);
        let encmsg = ::secp256k1::Message::from_slice(&ca_hash[..])
            .map_err(|err| self.internal_error(format!("encmsg failed: {}", err)))?;
        self.with_existing_channel(&node_id, &channel_id, |chan| {
            let nsigvec = secp_ctx
                .sign(&encmsg, &chan.node.get_node_secret())
                .serialize_der()
                .to_vec();
            let bsigvec = secp_ctx
                .sign(&encmsg, &chan.keys.inner.funding_key())
                .serialize_der()
                .to_vec();
            Ok((nsigvec, bsigvec))
        })
    }

    pub fn sign_node_announcement(
        &self,
        node_id: &PublicKey,
        na: &Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let sig = node.sign_node_announcement(na)?;
            Ok(sig)
        })
    }

    pub fn sign_channel_update(
        &self,
        node_id: &PublicKey,
        cu: &Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let sig = node.sign_channel_update(cu)?;
            Ok(sig)
        })
    }

    pub fn sign_invoice(
        &self,
        node_id: &PublicKey,
        data_part: &Vec<u8>,
        human_readable_part: &String,
    ) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let sig = node.sign_invoice(data_part, human_readable_part)?;
            Ok(sig)
        })
    }

    pub fn sign_message(&self, node_id: &PublicKey, message: &Vec<u8>) -> Result<Vec<u8>, Status> {
        self.with_node(&node_id, |opt_node| {
            let node = opt_node.ok_or_else(|| self.invalid_argument("no such node"))?;
            let sig = node.sign_message(message)?;
            Ok(sig)
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::util::bip143;
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::{OutPoint, TxIn, TxOut};
    use bitcoin_hashes::hash160::Hash as Hash160;
    use lightning::ln::chan_utils::{
        build_htlc_transaction, get_htlc_redeemscript, make_funding_redeemscript,
        HTLCOutputInCommitment, TxCreationKeys,
    };
    use lightning::ln::channelmanager::PaymentHash;
    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use tonic::Code;

    use crate::server::driver::channel_nonce_to_id;
    use crate::tx::script::get_revokeable_redeemscript;
    use crate::util::crypto_utils::{
        derive_public_key, derive_public_revocation_key, public_key_from_raw,
    };
    use crate::util::test_utils::*;

    use super::*;
    use crate::tx::tx::CommitmentInfo2;
    use secp256k1::Signature;

    fn make_channel_pubkeys() -> ChannelPublicKeys {
        ChannelPublicKeys {
            funding_pubkey: make_test_pubkey(104),
            revocation_basepoint: make_test_pubkey(100),
            payment_basepoint: make_test_pubkey(101),
            delayed_payment_basepoint: make_test_pubkey(102),
            htlc_basepoint: make_test_pubkey(103),
        }
    }

    fn init_node_and_channel(signer: &MySigner, channel_value: u64) -> (PublicKey, ChannelId) {
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        (
            node_id,
            signer
                .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
                .expect("new_channel"),
        )
    }

    #[test]
    fn channel_invalid_argument_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);
        let status: Result<(), Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                Err(chan.invalid_argument("testing invalid_argument"))
            });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "testing invalid_argument");
    }

    #[test]
    fn channel_internal_error_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);
        let status: Result<(), Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                Err(chan.internal_error("testing internal_error"))
            });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "testing internal_error");
    }

    #[test]
    fn node_invalid_argument_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, _channel_id) = init_node_and_channel(&signer, channel_value);
        let status: Result<(), Status> = signer.with_node(&node_id, |opt_node| {
            Err(opt_node
                .unwrap()
                .invalid_argument("testing invalid_argument"))
        });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.message(), "testing invalid_argument");
    }

    #[test]
    fn node_internal_error_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, _channel_id) = init_node_and_channel(&signer, channel_value);
        let status: Result<(), Status> = signer.with_node(&node_id, |opt_node| {
            Err(opt_node.unwrap().internal_error("testing internal_error"))
        });
        assert!(status.is_err());
        let err = status.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "testing internal_error");
    }

    #[test]
    fn sign_remote_commitment_tx_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);

        let remote_percommitment_point = make_test_pubkey(10);
        let to_remote_pubkey = make_test_pubkey(1);
        let revocation_key = make_test_pubkey(2);
        let to_local_delayed_key = make_test_pubkey(3);
        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let to_remote_address = payload_for_p2wpkh(&to_remote_pubkey);
        let info = CommitmentInfo2 {
            to_remote_address,
            to_remote_value: 100,
            revocation_key,
            to_local_delayed_key,
            to_local_value: 200,
            to_local_delay: 6,
            offered_htlcs: vec![],
            received_htlcs: vec![],
        };
        let remote_keys = make_channel_pubkeys();
        let (tx, output_scripts, _) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(&remote_keys, 5u16, Script::new(), funding_outpoint);
                chan.build_commitment_tx(&remote_percommitment_point, 23, &info)
            })
            .expect("build_commitment_tx");
        let output_witscripts = output_scripts.iter().map(|s| s.serialize()).collect();
        let ser_signature = signer
            .sign_remote_commitment_tx(
                &node_id,
                &channel_id,
                &tx,
                output_witscripts,
                &remote_percommitment_point,
                &remote_keys.funding_pubkey,
                channel_value,
            )
            .expect("sign");
        assert_eq!(
            hex::encode(tx.txid()),
            "6867b2d5ddff80cc3f52d3206ad7601bc5fb9f0baf2ec8e9a0ddc29ae50fb1c9"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            channel_value,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_remote_commitment_tx_phase2_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);

        let remote_percommitment_point = make_test_pubkey(10);
        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let remote_keys = make_channel_pubkeys();
        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(&remote_keys, 5u16, Script::new(), funding_outpoint);

                let info = chan.build_remote_commitment_info(
                    &remote_percommitment_point,
                    100,
                    200,
                    vec![],
                    vec![],
                )?;

                let (tx, _, _) =
                    chan.build_commitment_tx(&remote_percommitment_point, 23, &info)?;
                assert_eq!(
                    hex::encode(tx.txid()),
                    "f65952efef66e5927e75d21740e6b67cdd64bb23f88aa41fa7853c3e071d6897"
                );
                let (ser_signature, _) = chan.sign_remote_commitment_tx_phase2(
                    &remote_percommitment_point,
                    23,
                    0, // feerate not used
                    100,
                    200,
                    vec![],
                    vec![],
                )?;
                let channel_funding_redeemscript =
                    make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

                check_signature(
                    &tx,
                    0,
                    ser_signature,
                    &funding_pubkey,
                    channel_value,
                    &channel_funding_redeemscript,
                );
                Ok(())
            })
            .expect("sign");
    }

    #[test]
    fn sign_local_commitment_tx_phase2_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);

        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let remote_keys = make_channel_pubkeys();

        let (tx, _, _) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(&remote_keys, 5u16, Script::new(), funding_outpoint);
                let per_commitment_point = chan.get_per_commitment_point(23);
                let info = chan.build_local_commitment_info(
                    &per_commitment_point,
                    100,
                    200,
                    vec![],
                    vec![],
                )?;

                chan.build_commitment_tx(&per_commitment_point, 23, &info)
            })
            .expect("build_commitment_tx");
        let (ser_signature, _) = signer
            .sign_local_commitment_tx_phase2(
                &node_id,
                &channel_id,
                23,
                0, // feerate not used
                100,
                200,
                vec![],
                vec![],
            )
            .expect("sign");
        assert_eq!(
            hex::encode(tx.txid()),
            "4e6b86ac33eb8c14fd5c6b04dda4ec29671f982e53a051ed69919a509e16f17c"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            channel_value,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_mutual_close_tx_phase2_test() {
        let signer = MySigner::new();
        let channel_value = 300;
        let (node_id, channel_id) = init_node_and_channel(&signer, channel_value);

        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let remote_keys = make_channel_pubkeys();

        let remote_shutdown_script = payload_for_p2wpkh(&make_test_pubkey(11)).script_pubkey();
        signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(
                    &remote_keys,
                    5u16,
                    remote_shutdown_script.clone(),
                    funding_outpoint,
                );
                Ok(())
            })
            .unwrap();
        let tx = {
            let shutdown_pubkey = signer.get_shutdown_pubkey(&node_id).unwrap();
            let local_shutdown_script = payload_for_p2wpkh(&shutdown_pubkey).script_pubkey();
            build_close_tx(
                100,
                200,
                &local_shutdown_script,
                &remote_shutdown_script,
                funding_outpoint,
            )
        };
        let ser_signature = signer
            .sign_mutual_close_tx_phase2(&node_id, &channel_id, 100, 200)
            .expect("sign");
        assert_eq!(
            hex::encode(tx.txid()),
            "7d1618688e8a9a4cc09c94f5385a05c92a8b6662ac6e7e77eeb19a0e19070a56"
        );

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);
        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

        check_signature(
            &tx,
            0,
            ser_signature,
            &funding_pubkey,
            channel_value,
            &channel_funding_redeemscript,
        );
    }

    fn get_channel_funding_pubkey(
        signer: &MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                Ok(chan.keys.pubkeys().funding_pubkey)
            });
        res.unwrap()
    }

    fn get_channel_htlc_pubkey(
        signer: &MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        remote_per_commitment_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_public_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.inner.pubkeys().htlc_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn get_channel_delayed_payment_pubkey(
        signer: MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        remote_per_commitment_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_public_key(
                    &secp_ctx,
                    &remote_per_commitment_point,
                    &chan.keys.inner.pubkeys().delayed_payment_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn get_channel_revocation_pubkey(
        signer: MySigner,
        node_id: &PublicKey,
        channel_id: &ChannelId,
        revocation_point: &PublicKey,
    ) -> PublicKey {
        let res: Result<PublicKey, Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                let secp_ctx = &chan.secp_ctx;
                let pubkey = derive_public_revocation_key(
                    secp_ctx,
                    revocation_point, // matches revocation_secret
                    &chan.keys.inner.pubkeys().revocation_basepoint,
                )
                .unwrap();
                Ok(pubkey)
            });
        res.unwrap()
    }

    fn check_signature(
        tx: &bitcoin::Transaction,
        input_idx: usize,
        ser_signature: Vec<u8>,
        pubkey: &PublicKey,
        input_value: u64,
        redeemscript: &Script,
    ) {
        let sighash = Message::from_slice(
            &bip143::SighashComponents::new(&tx).sighash_all(
                &tx.input[input_idx],
                &redeemscript,
                input_value,
            )[..],
        )
        .expect("sighash");
        let mut der_signature = ser_signature.clone();
        der_signature.pop(); // Pop the sighash type byte
        let signature = Signature::from_der(&der_signature).expect("from_der");
        let secp_ctx = Secp256k1::new();
        secp_ctx
            .verify(&sighash, &signature, &pubkey)
            .expect("verify");
    }

    #[test]
    fn new_channel_test() {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = signer
            .new_channel(&node_id, 1000, None, None, 5, true)
            .unwrap();
        signer.with_node_do(&node_id, |node| {
            assert!(node.is_some());
        });
        signer.with_channel_do(&node_id, &channel_id, |chan| {
            assert!(chan.is_some());
        });
    }

    #[test]
    fn bad_channel_lookup_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = ChannelId([1; 32]);
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert!(chan.is_none());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn bad_node_lookup_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex(
            "0101010101010101010101010101010101010101010101010101010101010101",
            &secp_ctx,
        );

        let channel_id = ChannelId([1; 32]);
        signer.with_channel(&node_id, &channel_id, |chan| {
            assert!(chan.is_none());
            Ok(())
        })?;

        signer.with_node(&node_id, |node| {
            assert!(node.is_none());
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn new_channel_bad_node_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = pubkey_from_secret_hex(
            "0101010101010101010101010101010101010101010101010101010101010101",
            &secp_ctx,
        );
        assert!(signer
            .new_channel(&node_id, 1000, None, None, 5, true)
            .is_err());
        Ok(())
    }

    fn check_basepoints(basepoints: &ChannelPublicKeys) {
        assert_eq!(
            hex::encode(basepoints.funding_pubkey.serialize().to_vec()),
            "02868b7bc9b6d307509ed97758636d2d3628970bbd3bd36d279f8d3cde8ccd45ae"
        );
        assert_eq!(
            hex::encode(basepoints.revocation_basepoint.serialize().to_vec()),
            "02982b69bb2d70b083921cbc862c0bcf7761b55d7485769ddf81c2947155b1afe4"
        );
        assert_eq!(
            hex::encode(basepoints.payment_basepoint.serialize().to_vec()),
            "026bb6655b5e0b5ff80d078d548819f57796013b09de8085ddc04b49854ae1e483"
        );
        assert_eq!(
            hex::encode(basepoints.delayed_payment_basepoint.serialize().to_vec()),
            "0291dfb201bc87a2da8c7ffe0a7cf9691962170896535a7fd00d8ee4406a405e98"
        );
        assert_eq!(
            hex::encode(basepoints.htlc_basepoint.serialize().to_vec()),
            "02c0c8ff7278e50bd07d7b80c109621d44f895e216400a7e95b09f544eb3fafee2"
        );
    }

    #[test]
    fn get_channel_basepoints_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;

        let channel_id = signer
            .new_channel(
                &node_id,
                channel_value,
                Some((&channel_nonce).clone()),
                None,
                5,
                true,
            )
            .expect("new_channel");

        let basepoints = signer
            .get_channel_basepoints(&node_id, &channel_id, &channel_nonce)
            .unwrap();

        check_basepoints(&basepoints);
    }

    #[test]
    fn get_channel_basepoints_with_new_channel_workaround_test() {
        // use remotesigner::ChannelNonce;
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_id = channel_nonce_to_id(&channel_nonce);

        // WORKAROUND - Call get_channel_basepoints without first
        // creating the channel.  Channel will get created implicitly.

        let basepoints = signer
            .get_channel_basepoints(&node_id, &channel_id, &channel_nonce)
            .unwrap();

        check_basepoints(&basepoints);
    }

    #[test]
    fn get_per_commitment_point_and_secret_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let (point, secret) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                Ok((
                    chan.get_per_commitment_point(1),
                    chan.get_per_commitment_secret(1),
                ))
            })
            .expect("point");

        let derived_point = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        assert_eq!(point, derived_point);
    }

    #[test]
    fn get_check_future_secret_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let to_self_delay = 0u16;
        let channel_id = signer
            .new_channel(
                &node_id,
                channel_value,
                Some(channel_nonce),
                None,
                to_self_delay,
                true,
            )
            .expect("new_channel");

        let n: u64 = 10;

        let suggested = SecretKey::from_slice(
            hex::decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let correct = signer
            .check_future_secret(&node_id, &channel_id, n, &suggested)
            .expect("correct");
        assert_eq!(correct, true);

        let notcorrect = signer
            .check_future_secret(&node_id, &channel_id, n + 1, &suggested)
            .expect("notcorrect");
        assert_eq!(notcorrect, false);
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let indices = vec![0u32, 1u32];
        let values = vec![100u64, 200u64];

        let input1 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let input2 = TxIn {
            previous_output: OutPoint {
                txid: Default::default(),
                vout: 1,
            },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };
        let mut tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1, input2],
            output: vec![TxOut {
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                value: 300,
            }],
        };
        let spendtypes = vec![SpendType::P2wpkh, SpendType::P2wpkh];
        let uniclosekeys = vec![None, None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 2);

        let address = |n: u32| {
            Address::p2wpkh(
                &xkey
                    .ckd_priv(&secp_ctx, ChildNumber::from(n))
                    .unwrap()
                    .private_key
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        tx.input[1].witness = vec![witvec[1].0.clone(), witvec[1].1.clone()];

        let outs = vec![
            TxOut {
                value: 100,
                script_pubkey: address(0).script_pubkey(),
            },
            TxOut {
                value: 200,
                script_pubkey: address(1).script_pubkey(),
            },
        ];
        println!("{:?}", address(0).script_pubkey());
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2wpkh_test1() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                value: 100,
            }],
        };
        let spendtypes = vec![SpendType::P2wpkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2wpkh(
                &xkey
                    .ckd_priv(&secp_ctx, ChildNumber::from(n))
                    .unwrap()
                    .private_key
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
        };

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_unilateral_close_info_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                value: 100,
            }],
        };
        let spendtypes = vec![SpendType::P2wpkh];

        let uniclosekey = SecretKey::from_slice(
            hex::decode("4220531d6c8b15d66953c46b5c4d67c921943431452d5543d8805b9903c6b858")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let uniclosepubkey = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &uniclosekey).serialize()[..],
        )
        .unwrap();
        let uniclosekeys = vec![Some(uniclosekey)];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        assert_eq!(witvec[0].1, uniclosepubkey.serialize());

        let address = Address::p2wpkh(&uniclosepubkey, Network::Testnet);

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address.script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2pkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                value: 100,
            }],
        };
        let spendtypes = vec![SpendType::P2pkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2pkh(
                &xkey
                    .ckd_priv(&secp_ctx, ChildNumber::from(n))
                    .unwrap()
                    .private_key
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
        };

        tx.input[0].script_sig = Builder::new()
            .push_slice(witvec[0].0.as_slice())
            .push_slice(witvec[0].1.as_slice())
            .into_script();
        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));
        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_funding_tx_p2sh_p2wpkh_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let signer = MySigner::new();
        let node_id = signer.new_node();
        let xkey = signer.xkey(&node_id).expect("xkey");
        let channel_id = ChannelId([1; 32]);
        let txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let indices = vec![0u32];
        let values = vec![100u64];

        let input1 = TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        };

        let mut tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input1],
            output: vec![TxOut {
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
                value: 100,
            }],
        };
        let spendtypes = vec![SpendType::P2shP2wpkh];
        let uniclosekeys = vec![None];

        let witvec = signer
            .sign_funding_tx(
                &node_id,
                &channel_id,
                &tx,
                &indices,
                &values,
                &spendtypes,
                &uniclosekeys,
            )
            .expect("good sigs");
        assert_eq!(witvec.len(), 1);

        let address = |n: u32| {
            Address::p2shwpkh(
                &xkey
                    .ckd_priv(&secp_ctx, ChildNumber::from(n))
                    .unwrap()
                    .private_key
                    .public_key(&secp_ctx),
                Network::Testnet,
            )
        };

        let pubkey = xkey
            .ckd_priv(&secp_ctx, ChildNumber::from(indices[0]))
            .unwrap()
            .private_key
            .public_key(&secp_ctx);

        let keyhash = Hash160::hash(&pubkey.serialize()[..]);

        tx.input[0].script_sig = Builder::new()
            .push_slice(
                Builder::new()
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_slice(&keyhash.into_inner())
                    .into_script()
                    .as_bytes(),
            )
            .into_script();

        tx.input[0].witness = vec![witvec[0].0.clone(), witvec[0].1.clone()];

        println!("{:?}", tx.input[0].script_sig);
        let outs = vec![TxOut {
            value: 100,
            script_pubkey: address(0).script_pubkey(),
        }];
        println!("{:?}", &outs[0].script_pubkey);
        let verify_result = tx.verify(|p| Some(outs[p.vout as usize].clone()));

        assert!(verify_result.is_ok());

        Ok(())
    }

    #[test]
    fn sign_local_htlc_tx_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let commitment_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx_all = Secp256k1::new();

        let n: u64 = 1;

        let per_commitment_point = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                Ok(chan.get_per_commitment_point(n))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let keys = TxCreationKeys::new(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(5), // b_payment_base
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key = derive_public_key(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
        )
        .expect("a_delayed_payment_key");

        let revocation_key =
            derive_public_revocation_key(&secp_ctx_all, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount = 10 * 1000;
        let output_witscripts = vec![htlc_redeemscript.to_bytes()];

        let sigvec = signer
            .sign_local_htlc_tx(
                &node_id,
                &channel_id,
                &htlc_tx,
                n,
                output_witscripts,
                htlc_amount,
            )
            .unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            sigvec,
            &htlc_pubkey,
            htlc_amount,
            &htlc_redeemscript,
        );
    }

    #[test]
    fn sign_delayed_payment_to_us_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let commitment_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx_all = Secp256k1::new();

        let n: u64 = 1;

        let per_commitment_point = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                Ok(chan.get_per_commitment_point(n))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let a_delayed_payment_key = derive_public_key(
            &secp_ctx_all,
            &per_commitment_point,
            &a_delayed_payment_base,
        )
        .expect("a_delayed_payment_key");

        let revocation_pubkey =
            derive_public_revocation_key(&secp_ctx_all, &per_commitment_point, &b_revocation_base)
                .expect("revocation_pubkey");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_pubkey,
        );

        let redeemscript =
            get_revokeable_redeemscript(&revocation_pubkey, to_self_delay, &a_delayed_payment_key);

        let htlc_amount = 10 * 1000;
        let output_witscripts = vec![redeemscript.to_bytes()];

        let sigvec = signer
            .sign_delayed_payment_to_us(
                &node_id,
                &channel_id,
                &htlc_tx,
                n,
                output_witscripts,
                htlc_amount,
            )
            .unwrap();

        let htlc_pubkey = get_channel_delayed_payment_pubkey(
            signer,
            &node_id,
            &channel_id,
            &per_commitment_point,
        );

        check_signature(
            &htlc_tx,
            0,
            sigvec,
            &htlc_pubkey,
            htlc_amount,
            &redeemscript,
        );
    }

    #[test]
    fn sign_remote_htlc_tx_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let commitment_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(5), // b_payment_base
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_public_revocation_key(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount = 10 * 1000;
        let output_witscripts = vec![htlc_redeemscript.to_bytes()];

        let ser_signature = signer
            .sign_remote_htlc_tx(
                &node_id,
                &channel_id,
                &htlc_tx,
                output_witscripts,
                &remote_per_commitment_point,
                htlc_amount,
            )
            .unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &remote_per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount,
            &htlc_redeemscript,
        );
    }

    #[test]
    fn sign_remote_htlc_to_us_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let commitment_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let remote_per_commitment_point = make_test_pubkey(10);

        let per_commitment_point = make_test_pubkey(1);
        let a_delayed_payment_base = make_test_pubkey(2);
        let b_revocation_base = make_test_pubkey(3);

        let secp_ctx = Secp256k1::new();

        let keys = TxCreationKeys::new(
            &secp_ctx,
            &per_commitment_point,
            &a_delayed_payment_base,
            &make_test_pubkey(4), // a_htlc_base
            &b_revocation_base,
            &make_test_pubkey(5), // b_payment_base
            &make_test_pubkey(6),
        ) // b_htlc_base
        .expect("new TxCreationKeys");

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let revocation_key =
            derive_public_revocation_key(&secp_ctx, &per_commitment_point, &b_revocation_base)
                .expect("revocation_key");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_key,
        );

        let htlc_redeemscript = get_htlc_redeemscript(&htlc, &keys);

        let htlc_amount = 10 * 1000;
        let output_witscripts = vec![htlc_redeemscript.to_bytes()];

        let ser_signature = signer
            .sign_remote_htlc_to_us(
                &node_id,
                &channel_id,
                &htlc_tx,
                output_witscripts,
                &remote_per_commitment_point,
                htlc_amount,
            )
            .unwrap();

        let htlc_pubkey =
            get_channel_htlc_pubkey(&signer, &node_id, &channel_id, &remote_per_commitment_point);

        check_signature(
            &htlc_tx,
            0,
            ser_signature,
            &htlc_pubkey,
            htlc_amount,
            &htlc_redeemscript,
        );
    }

    #[test]
    // TODO - same as sign_mutual_close_tx_test
    fn sign_commitment_tx_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let to_self_delay = 5u16;
        let channel_id = signer
            .new_channel(
                &node_id,
                channel_value,
                Some(channel_nonce),
                None,
                to_self_delay,
                true,
            )
            .expect("new_channel");

        let n: u64 = 1;

        let remote_per_commitment_point = make_test_pubkey(10);
        let to_remote_pubkey = make_test_pubkey(1);
        let revocation_key = make_test_pubkey(2);
        let to_local_delayed_key = make_test_pubkey(3);
        let to_remote_address = payload_for_p2wpkh(&to_remote_pubkey);
        let info = CommitmentInfo2 {
            to_remote_address,
            to_remote_value: 100,
            revocation_key,
            to_local_delayed_key,
            to_local_value: 200,
            to_local_delay: 6,
            offered_htlcs: vec![],
            received_htlcs: vec![],
        };
        let remote_keys = make_channel_pubkeys();

        // We only need to call ready_channel in order to use
        // build_commitment_tx, not to call sign_commitment_tx.
        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        let (tx, _, _) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(&remote_keys, to_self_delay, Script::new(), funding_outpoint);
                chan.build_commitment_tx(&remote_per_commitment_point, n, &info)
            })
            .expect("tx");

        let sigvec = signer
            .sign_commitment_tx(
                &node_id,
                &channel_id,
                &tx,
                &remote_keys.funding_pubkey,
                channel_value,
            )
            .unwrap();

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

        check_signature(
            &tx,
            0,
            sigvec,
            &funding_pubkey,
            channel_value,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    // TODO - same as sign_commitment_tx_test
    fn sign_mutual_close_tx_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let to_self_delay = 5u16;
        let channel_id = signer
            .new_channel(
                &node_id,
                channel_value,
                Some(channel_nonce),
                None,
                to_self_delay,
                true,
            )
            .expect("new_channel");

        let n: u64 = 1;

        let remote_per_commitment_point = make_test_pubkey(10);
        let to_remote_pubkey = make_test_pubkey(1);
        let revocation_key = make_test_pubkey(2);
        let to_local_delayed_key = make_test_pubkey(3);
        let to_remote_address = payload_for_p2wpkh(&to_remote_pubkey);
        let info = CommitmentInfo2 {
            to_remote_address,
            to_remote_value: 100,
            revocation_key,
            to_local_delayed_key,
            to_local_value: 200,
            to_local_delay: 6,
            offered_htlcs: vec![],
            received_htlcs: vec![],
        };
        let remote_keys = make_channel_pubkeys();

        // We only need to call ready_channel in order to use
        // build_commitment_tx, not to call sign_mutual_close_tx.
        let funding_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        let (tx, _, _) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                chan.ready(&remote_keys, to_self_delay, Script::new(), funding_outpoint);
                chan.build_commitment_tx(&remote_per_commitment_point, n, &info)
            })
            .expect("tx");

        let sigvec = signer
            .sign_mutual_close_tx(
                &node_id,
                &channel_id,
                &tx,
                &remote_keys.funding_pubkey,
                channel_value,
            )
            .unwrap();

        let funding_pubkey = get_channel_funding_pubkey(&signer, &node_id, &channel_id);

        let channel_funding_redeemscript =
            make_funding_redeemscript(&funding_pubkey, &remote_keys.funding_pubkey);

        check_signature(
            &tx,
            0,
            sigvec,
            &funding_pubkey,
            channel_value,
            &channel_funding_redeemscript,
        );
    }

    #[test]
    fn sign_penalty_to_us_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");

        let commitment_txid = sha256d::Hash::from_slice(&[2u8; 32]).unwrap();
        let feerate_per_kw = 1000;
        let to_self_delay = 32;
        let htlc = HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1 * 1000 * 1000,
            cltv_expiry: 2 << 16,
            payment_hash: PaymentHash([1; 32]),
            transaction_output_index: Some(0),
        };

        let secp_ctx = Secp256k1::new();

        let n: u64 = 1;

        let (per_commitment_point, per_commitment_secret) = signer
            .with_existing_channel(&node_id, &channel_id, |chan| {
                Ok((
                    chan.get_per_commitment_point(n),
                    chan.get_per_commitment_secret(n),
                ))
            })
            .expect("point");

        let a_delayed_payment_base = make_test_pubkey(2);

        let a_delayed_payment_key =
            derive_public_key(&secp_ctx, &per_commitment_point, &a_delayed_payment_base)
                .expect("a_delayed_payment_key");

        let (b_revocation_base_point, b_revocation_base_secret) = make_test_key(42);

        let revocation_pubkey = derive_public_revocation_key(
            &secp_ctx,
            &per_commitment_point,
            &b_revocation_base_point,
        )
        .expect("revocation_pubkey");

        let htlc_tx = build_htlc_transaction(
            &commitment_txid,
            feerate_per_kw,
            to_self_delay,
            &htlc,
            &a_delayed_payment_key,
            &revocation_pubkey,
        );

        let redeemscript =
            get_revokeable_redeemscript(&revocation_pubkey, to_self_delay, &a_delayed_payment_key);

        let htlc_amount = 10 * 1000;
        let output_witscripts = vec![redeemscript.to_bytes()];

        let revocation_secret = derive_private_revocation_key(
            &secp_ctx,
            &per_commitment_secret,
            &b_revocation_base_secret,
        )
        .expect("revocation_secret");

        let revocation_point = PublicKey::from_secret_key(&secp_ctx, &revocation_secret);

        let sigvec = signer
            .sign_penalty_to_us(
                &node_id,
                &channel_id,
                &htlc_tx,
                &revocation_secret,
                output_witscripts,
                htlc_amount,
            )
            .unwrap();

        let pubkey =
            get_channel_revocation_pubkey(signer, &node_id, &channel_id, &revocation_point);

        check_signature(&htlc_tx, 0, sigvec, &pubkey, htlc_amount, &redeemscript);
    }

    #[test]
    fn sign_channel_announcement_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let channel_nonce = "nonce1".as_bytes().to_vec();
        let channel_value = 10 * 1000 * 1000;
        let channel_id = signer
            .new_channel(&node_id, channel_value, Some(channel_nonce), None, 5, true)
            .expect("new_channel");
        let ann = hex::decode("0123456789abcdef").unwrap();
        let (nsigvec, bsigvec) = signer
            .sign_channel_announcement(&node_id, &channel_id, &ann)
            .unwrap();
        let ca_hash = Sha256dHash::hash(&ann);
        let encmsg = ::secp256k1::Message::from_slice(&ca_hash[..]).expect("encmsg");
        let secp_ctx = Secp256k1::new();
        let nsig = Signature::from_der(&nsigvec).expect("nsig");
        secp_ctx
            .verify(&encmsg, &nsig, &node_id)
            .expect("verify nsig");
        let bsig = Signature::from_der(&bsigvec).expect("bsig");
        let _res: Result<(), Status> =
            signer.with_existing_channel(&node_id, &channel_id, |chan| {
                let funding_pubkey =
                    PublicKey::from_secret_key(&secp_ctx, &chan.keys.inner.funding_key());
                Ok(secp_ctx
                    .verify(&encmsg, &bsig, &funding_pubkey)
                    .expect("verify bsig"))
            });
    }

    #[test]
    fn sign_node_announcement_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let ann = hex::decode("000302aaa25e445fef0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b65180265b64c4f554450484f544f2d2e302d3139392d67613237336639642d6d6f646465640000").unwrap();
        let sigvec = signer.sign_node_announcement(&node_id, &ann).unwrap();
        assert_eq!(sigvec, hex::decode("30450221008ef1109b95f127a7deec63b190b72180f0c2692984eaf501c44b6bfc5c4e915502207a6fa2f250c5327694967be95ff42a94a9c3d00b7fa0fbf7daa854ceb872e439").unwrap());
        Ok(())
    }

    #[test]
    fn sign_channel_update_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let cu = hex::decode("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015e42ddc6010000060000000000000000000000010000000a000000003b023380").unwrap();
        let sigvec = signer.sign_channel_update(&node_id, &cu).unwrap();
        assert_eq!(sigvec, hex::decode("3045022100be9840696c868b161aaa997f9fa91a899e921ea06c8083b2e1ea32b8b511948d0220352eec7a74554f97c2aed26950b8538ca7d7d7568b42fd8c6f195bd749763fa5").unwrap());
        Ok(())
    }

    #[test]
    fn sign_invoice_test() -> Result<(), ()> {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let human_readable_part = String::from("lnbcrt1230n");
        let data_part = hex::decode("010f0418090a010101141917110f01040e050f06100003021e1b0e13161c150301011415060204130c0018190d07070a18070a1c1101111e111f130306000d00120c11121706181b120d051807081a0b0f0d18060004120e140018000105100114000b130b01110c001a05041a181716020007130c091d11170d10100d0b1a1b00030e05190208171e16080d00121a00110719021005000405001000").unwrap();
        let rsig = signer
            .sign_invoice(&node_id, &data_part, &human_readable_part)
            .unwrap();
        assert_eq!(rsig, hex::decode("739ffb91aa7c0b3d3c92de1600f7a9afccedc5597977095228232ee4458685531516451b84deb35efad27a311ea99175d10c6cdb458cd27ce2ed104eb6cf806400").unwrap());
        Ok(())
    }

    #[test]
    fn get_ext_pub_key_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let xpub = signer.get_ext_pub_key(&node_id).unwrap();
        assert_eq!(format!("{}", xpub), "tpubDAu312RD7nE6R9qyB4xJk9QAMyi3ppq3UJ4MMUGpB9frr6eNDd8FJVPw27zTVvWAfYFVUtJamgfh5ZLwT23EcymYgLx7MHsU8zZxc9L3GKk");
    }

    #[test]
    fn sign_message_test() {
        let signer = MySigner::new();
        let mut seed = [0; 32];
        seed.copy_from_slice(
            hex::decode("6c696768746e696e672d32000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let node_id = signer.new_node_from_seed(&seed);
        let message = String::from("Testing 1 2 3").into_bytes();
        let mut rsigvec = signer.sign_message(&node_id, &message).unwrap();
        let rid = rsigvec.pop().unwrap() as i32;
        let rsig =
            RecoverableSignature::from_compact(&rsigvec[..], RecoveryId::from_i32(rid).unwrap())
                .unwrap();
        let secp_ctx = Secp256k1::new();
        let mut buffer = String::from("Lightning Signed Message:").into_bytes();
        buffer.extend(message);
        let hash = Sha256dHash::hash(&buffer);
        let encmsg = ::secp256k1::Message::from_slice(&hash[..]).unwrap();
        let sig = rsig.to_standard();
        let pubkey = secp_ctx.recover(&encmsg, &rsig).unwrap();
        assert!(secp_ctx.verify(&encmsg, &sig, &pubkey).is_ok());
        assert!(pubkey == node_id);
    }

    // TODO move this elsewhere
    #[test]
    fn transaction_verify_test() {
        use hex::decode as hex_decode;
        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let spending: bitcoin::Transaction = deserialize(hex_decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();
        let spent1: bitcoin::Transaction = deserialize(hex_decode("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .unwrap().as_slice()).unwrap();
        let spent2: bitcoin::Transaction = deserialize(hex_decode("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .unwrap().as_slice()).unwrap();
        let spent3: bitcoin::Transaction = deserialize(hex_decode("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .unwrap().as_slice()).unwrap();

        println!("{:?}", &spending.txid());
        println!("{:?}", &spent1.txid());
        println!("{:?}", &spent2.txid());
        println!("{:?}", &spent3.txid());
        println!("{:?}", &spent1.output[0].script_pubkey);
        println!("{:?}", &spent2.output[0].script_pubkey);
        println!("{:?}", &spent3.output[0].script_pubkey);

        let mut spent = HashMap::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None // NOT TESTED
            })
            .unwrap();
    }

    // TODO move this elsewhere
    #[test]
    fn bip143_p2wpkh_test() {
        let tx: bitcoin::Transaction = deserialize(hex::decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
            .unwrap().as_slice()).unwrap();
        let secp_ctx = Secp256k1::signing_only();
        let priv2 = SecretKey::from_slice(
            hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let pub2 = bitcoin::PublicKey::from_slice(
            &PublicKey::from_secret_key(&secp_ctx, &priv2).serialize(),
        )
        .unwrap();

        let script_code = Address::p2pkh(&pub2, Network::Testnet).script_pubkey();
        assert_eq!(
            hex::encode(script_code.as_bytes()),
            "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
        );
        let value = 600_000_000;

        let sighash =
            &SighashComponents::new(&tx).sighash_all(&tx.input[1], &script_code, value)[..];
        assert_eq!(
            hex::encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    // TODO move this elsewhere
    #[test]
    fn deser_raw_test() {
        let raw: [u8; 64] = [
            158, 156, 70, 5, 38, 221, 32, 73, 180, 87, 57, 36, 5, 47, 168, 160, 245, 209, 189, 150,
            120, 71, 89, 121, 242, 226, 118, 91, 240, 36, 16, 253, 43, 220, 178, 191, 181, 152,
            246, 154, 176, 43, 194, 95, 165, 0, 61, 9, 214, 95, 90, 144, 62, 135, 181, 82, 32, 196,
            138, 80, 167, 249, 29, 143,
        ];
        let point = public_key_from_raw(&raw).unwrap();
        let secret = SecretKey::from_slice(
            hex::decode("7f4fa93708cb666f507f35ae9967c23f75976ab721cbcf5352bb49c50c8b7458")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let ss = SharedSecret::new(&point, &secret);
        assert_eq!(
            hex::encode(ss[..].to_vec()),
            "08e9c2ce6d882fd3c8166c9c26e748ff3def2c75b717b7709556ec9688515dc9"
        );
        assert_eq!(
            hex::encode(point.serialize().to_vec()),
            "03fd1024f05b76e2f27959477896bdd1f5a0a82f05243957b44920dd2605469c9e"
        );
    }
}
