use crate::prelude::*;
use crate::util::crypto_utils::{hkdf_sha256, sighash_from_heartbeat};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::Network;
use bitcoin::WPubkeyHash;
use bitcoin::{secp256k1, ScriptBuf, Transaction, TxOut, Witness};
use lightning::ln::msgs::{DecodeError, UnsignedGossipMessage};
use lightning::ln::script::ShutdownScript;
use lightning::sign::{
    EntropySource, InMemorySigner, NodeSigner, Recipient, SignerProvider, SpendableOutputDescriptor,
};
use lightning::util::ser::Writeable;

use super::derive::{self, KeyDerivationStyle};
use crate::channel::ChannelId;
use crate::signer::StartingTimeFactory;
use crate::util::byte_utils;
use crate::util::transaction_utils::create_spending_transaction;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, Signature};
use bitcoin::secp256k1::schnorr;
use bitcoin::sighash::{self, EcdsaSighashType};
use lightning::ln::inbound_payment::ExpandedKey;
use lightning_invoice::RawBolt11Invoice;

/// An implementation of [`NodeSigner`]
pub struct MyKeysManager {
    secp_ctx: Secp256k1<secp256k1::All>,
    seed: Vec<u8>,
    key_derivation_style: KeyDerivationStyle,
    network: Network,
    master_key: Xpriv,
    node_secret: SecretKey,
    bolt12_secret: SecretKey,
    persistence_secret: SecretKey,
    inbound_payment_key: ExpandedKey,
    channel_seed_base: [u8; 32],
    account_extended_key: Xpriv,
    destination_script: ScriptBuf,
    ldk_shutdown_pubkey: PublicKey,
    #[allow(dead_code)]
    channel_master_key: Xpriv,
    channel_id_master_key: Xpriv,
    channel_id_child_index: AtomicUsize,

    rand_bytes_master_key: Xpriv,
    rand_bytes_child_index: AtomicUsize,
    rand_bytes_unique_start: Sha256State,

    lnd_basepoint_index: AtomicU32,

    unique_start: Sha256State,
}

impl MyKeysManager {
    /// Construct
    ///
    /// NOTE - it's ok to reconstruct MyKeysManager with a different starting time when restoring
    /// from persisted data.  It is not important to persist the starting_time entropy ...
    pub fn new(
        key_derivation_style: KeyDerivationStyle,
        seed: &[u8],
        network: Network,
        starting_time_factory: &dyn StartingTimeFactory,
    ) -> MyKeysManager {
        let secp_ctx = Secp256k1::new();
        let key_derive = derive::key_derive(key_derivation_style, network);
        let master_key = key_derive.master_key(seed);
        let (_, node_secret) = key_derive.node_keys(seed, &secp_ctx);
        let channel_master_key = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(3).unwrap()])
            .expect("Your RNG is busted");
        let channel_id_master_key = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(5).unwrap()])
            .expect("Your RNG is busted");

        let (starting_time_secs, starting_time_nanos) = starting_time_factory.starting_time();
        let mut unique_start = Sha256::engine();
        unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
        unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
        unique_start.input(seed);

        let channel_seed_base = key_derive.channels_seed(seed);
        let account_extended_key =
            key_derivation_style.get_account_extended_key(&secp_ctx, network, seed);

        let ldk_shutdown_key = account_extended_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(2).unwrap()])
            .expect("Your RNG is busted")
            .to_priv()
            .inner;
        let ldk_shutdown_pubkey = PublicKey::from_secret_key(&secp_ctx, &ldk_shutdown_key);

        let destination_key = account_extended_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(1).unwrap()])
            .expect("Your RNG is busted");

        let destination_script = {
            let pubkey_hash160 = Hash160::hash(
                &Xpub::from_priv(&secp_ctx, &destination_key).public_key.serialize()[..],
            );
            Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&pubkey_hash160.to_byte_array())
                .into_script()
        };

        let rand_bytes_master_key = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(4).unwrap()])
            .expect("Your RNG is busted");
        let inbound_payment_key: SecretKey = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(5).unwrap()])
            .expect("Your RNG is busted")
            .private_key;
        let mut inbound_pmt_key_bytes = [0; 32];
        inbound_pmt_key_bytes.copy_from_slice(&inbound_payment_key[..]);

        let mut rand_bytes_unique_start = Sha256::engine();
        rand_bytes_unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
        rand_bytes_unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
        rand_bytes_unique_start.input(seed);

        let bolt12_secret = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(9735).unwrap()])
            .expect("Your RNG is busted")
            .private_key;

        let persistence_secret = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(9736).unwrap()])
            .expect("Your RNG is busted")
            .private_key;

        let mut res = MyKeysManager {
            secp_ctx,
            seed: seed.to_vec(),
            key_derivation_style,
            network,
            master_key,
            node_secret,
            bolt12_secret,
            persistence_secret,
            inbound_payment_key: ExpandedKey::new(inbound_pmt_key_bytes),
            channel_seed_base,
            account_extended_key,
            destination_script,
            ldk_shutdown_pubkey,
            channel_master_key,
            channel_id_master_key,
            channel_id_child_index: AtomicUsize::new(0),
            rand_bytes_master_key,
            rand_bytes_child_index: AtomicUsize::new(0),
            rand_bytes_unique_start,
            lnd_basepoint_index: AtomicU32::new(0),
            unique_start,
        };

        let secp_seed = res.get_secure_random_bytes();
        res.secp_ctx.seeded_randomize(&secp_seed);
        res
    }

    pub(crate) fn get_node_secret(&self) -> SecretKey {
        self.node_secret
    }

    /// onion reply secret
    pub fn get_onion_reply_secret(&self) -> [u8; 32] {
        return hkdf_sha256(&self.seed, "onion reply secret".as_bytes(), &[]);
    }

    /// BOLT 12 x-only pubkey
    pub fn get_bolt12_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp_ctx, &self.bolt12_secret)
    }

    /// Persistence pubkey
    pub fn get_persistence_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp_ctx, &self.persistence_secret)
    }

    /// Persistence shared secret
    pub fn get_persistence_shared_secret(&self, server_pubkey: &PublicKey) -> [u8; 32] {
        SharedSecret::new(server_pubkey, &self.persistence_secret).secret_bytes()
    }

    /// Persistence auth token
    pub fn get_persistence_auth_token(&self, server_pubkey: &PublicKey) -> [u8; 32] {
        Sha256::hash(&self.get_persistence_shared_secret(server_pubkey)).to_byte_array()
    }

    /// Computes a keypair for BOLT12 signing with optional message-based tweaking
    ///
    /// Based on the BOLT12 specification and c-lightning implementation:
    /// 1. Without tweak message: Uses the node_secret directly
    /// 2. With tweak message only: Takes the bolt12_secret and tweaks it with the message
    /// 3. With tweak message and info: Derives a base secret using HKDF-SHA256 from info
    ///    then computes the tweak from the tweakmessage
    fn get_bolt12_keypair(
        &self,
        opt_info: Option<&[u8]>,
        opt_tweak_message: Option<&[u8]>,
    ) -> Result<Keypair, ()> {
        match (opt_tweak_message, opt_info) {
            (None, _) => Ok(Keypair::from_secret_key(&self.secp_ctx, &self.node_secret)),
            (Some(tweak_message), None) => {
                let pubkey_ser =
                    PublicKey::from_secret_key(&self.secp_ctx, &self.bolt12_secret).serialize();
                let mut sha = Sha256::engine();
                sha.input(&pubkey_ser);
                sha.input(tweak_message);
                let tweak = Scalar::from_be_bytes(*Sha256::from_engine(sha).as_ref())
                    .expect("your RNG is busted");
                let tweaked_secret = self.bolt12_secret.add_tweak(&tweak).map_err(|_| ())?;
                Ok(Keypair::from_secret_key(&self.secp_ctx, &tweaked_secret))
            }
            (Some(tweak_message), Some(info)) => {
                let base_secret = self.derive_secret(info);
                let mut sha = Sha256::engine();
                sha.input(base_secret.as_ref());
                sha.input(tweak_message);
                let tweak = Scalar::from_be_bytes(*Sha256::from_engine(sha).as_ref())
                    .expect("valid tweak value");
                let tweaked_secret = self.node_secret.add_tweak(&tweak).map_err(|_| ())?;
                Ok(Keypair::from_secret_key(&self.secp_ctx, &tweaked_secret))
            }
        }
    }

    fn bolt12_message_hash(
        &self,
        messagename: &[u8],
        fieldname: &[u8],
        merkleroot: &[u8; 32],
    ) -> Sha256 {
        let mut sha = Sha256::engine();
        sha.input("lightning".as_bytes());
        sha.input(messagename);
        sha.input(fieldname);
        let tag_hash = Sha256::from_engine(sha).to_byte_array();
        let mut sha = Sha256::engine();
        sha.input(&tag_hash);
        sha.input(&tag_hash);
        // BIP340 done, compute hash of message
        sha.input(merkleroot);
        Sha256::from_engine(sha)
    }

    /// BOLT 12 sign
    pub fn sign_bolt12(
        &self,
        messagename: &[u8],
        fieldname: &[u8],
        merkleroot: &[u8; 32],
        publictweak_opt: Option<&[u8]>,
    ) -> Result<schnorr::Signature, ()> {
        let sig_hash = self.bolt12_message_hash(messagename, fieldname, merkleroot);
        let kp = self.get_bolt12_keypair(None, publictweak_opt)?;
        let msg = Message::from_digest(sig_hash.to_byte_array());
        Ok(self.secp_ctx.sign_schnorr_no_aux_rand(&msg, &kp))
    }

    /// Bolt 12 (modern) sign
    pub fn sign_bolt12_2(
        &self,
        messagename: &[u8],
        fieldname: &[u8],
        merkleroot: &[u8; 32],
        info: &[u8],
        publictweak_opt: Option<&[u8]>,
    ) -> Result<schnorr::Signature, ()> {
        let sig_hash = self.bolt12_message_hash(messagename, fieldname, merkleroot);
        let kp = self.get_bolt12_keypair(Some(info), publictweak_opt)?;
        let msg = Message::from_digest(sig_hash.to_byte_array());
        Ok(self.secp_ctx.sign_schnorr_no_aux_rand(&msg, &kp))
    }

    /// Derive pseudorandom secret from a derived key
    pub fn derive_secret(&self, info: &[u8]) -> SecretKey {
        // The derived_secrets_base could be precomputed at node startup time.
        let derived_secrets_base = hkdf_sha256(&self.seed, "derived secrets".as_bytes(), &[]);
        let derived_secret = hkdf_sha256(&derived_secrets_base, info, &[]);
        // infallible, 32 bytes
        SecretKey::from_slice(&derived_secret).unwrap()
    }

    /// Get the layer-1 xpub
    pub fn get_account_extended_key(&self) -> &Xpriv {
        &self.account_extended_key
    }

    /// Convert a commitment secret to a commitment point
    pub fn per_commitment_point<X: Signing>(
        secp_ctx: &Secp256k1<X>,
        commitment_secret: &[u8; 32],
    ) -> PublicKey {
        // infallible, 32 bytes
        PublicKey::from_secret_key(secp_ctx, &SecretKey::from_slice(commitment_secret).unwrap())
    }

    // Re-derive existing channel keys
    fn derive_channel_keys(&self, channel_value_sat: u64, keys_id: &[u8; 32]) -> InMemorySigner {
        self.get_channel_keys_with_keys_id(keys_id.clone(), channel_value_sat)
    }

    pub(crate) fn get_channel_keys_with_id(
        &self,
        channel_id: ChannelId,
        channel_value_sat: u64,
    ) -> InMemorySigner {
        let key_derive = derive::key_derive(self.key_derivation_style, self.network);
        // aka channel_seed
        let keys_id = key_derive.keys_id(channel_id, &self.channel_seed_base);

        self.get_channel_keys_with_keys_id(keys_id, channel_value_sat)
    }

    pub(crate) fn get_channel_keys_with_keys_id(
        &self,
        keys_id: [u8; 32],
        channel_value_sat: u64,
    ) -> InMemorySigner {
        let key_derive = derive::key_derive(self.key_derivation_style, self.network);
        let secp_ctx = Secp256k1::new();

        // TODO lnd specific code
        let basepoint_index = self.lnd_basepoint_index.fetch_add(1, Ordering::AcqRel);
        let (
            funding_key,
            revocation_base_key,
            htlc_base_key,
            payment_key,
            delayed_payment_base_key,
            commitment_seed,
        ) = key_derive.channel_keys(
            &self.seed,
            &keys_id,
            basepoint_index,
            &self.master_key,
            &secp_ctx,
        );

        InMemorySigner::new(
            &secp_ctx,
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_sat,
            keys_id,
            self.get_secure_random_bytes(),
        )
    }

    pub(crate) fn get_channel_id(&self) -> ChannelId {
        let mut sha = self.unique_start.clone();

        let child_ix = self.increment_channel_id_child_index();
        let child_privkey = self
            .channel_id_master_key
            .derive_priv(
                &self.secp_ctx,
                &[ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")],
            )
            .expect("Your RNG is busted");
        sha.input(child_privkey.private_key.as_ref());

        let random_bytes = Sha256::from_engine(sha).to_byte_array();

        ChannelId::new(&random_bytes)
    }

    pub(crate) fn increment_channel_id_child_index(&self) -> usize {
        self.channel_id_child_index.fetch_add(1, Ordering::AcqRel)
    }

    /// Creates a Transaction which spends the given descriptors to the given outputs, plus an
    /// output to the given change destination (if sufficient change value remains). The
    /// transaction will have a feerate, at least, of the given value.
    ///
    /// Returns `Err(())` if the output value is greater than the input value minus required fee or
    /// if a descriptor was duplicated.
    ///
    /// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
    ///
    /// May panic if the `SpendableOutputDescriptor`s were not generated by Channels which used
    /// this KeysManager or one of the `InMemorySigner` created by this KeysManager.
    // this function is covered by the integration tests in vls-core-test crate
    pub fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Transaction, ()> {
        let mut spend_tx = create_spending_transaction(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
        )
        .map_err(|_| ())?;
        // Signing the tx
        let mut keys_cache: Map<[u8; 32], InMemorySigner> = Map::new();
        let mut input_idx = 0;
        for outp in descriptors {
            match outp {
                SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                    if !keys_cache.contains_key(&descriptor.channel_keys_id) {
                        let signer = self.derive_channel_keys(
                            descriptor.channel_value_satoshis,
                            &descriptor.channel_keys_id,
                        );
                        keys_cache.insert(descriptor.channel_keys_id, signer);
                    }
                    spend_tx.input[input_idx].witness = Witness::from_slice(
                        &keys_cache
                            .get(&descriptor.channel_keys_id)
                            .unwrap()
                            .sign_counterparty_payment_input(
                                &spend_tx,
                                input_idx,
                                &descriptor,
                                &secp_ctx,
                            )
                            .expect("descriptor not accepted by sign_counterparty_payment_input")
                            .to_vec(),
                    );
                }
                SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                    if !keys_cache.contains_key(&descriptor.channel_keys_id) {
                        let signer = self.derive_channel_keys(
                            descriptor.channel_value_satoshis,
                            &descriptor.channel_keys_id,
                        );
                        keys_cache.insert(descriptor.channel_keys_id, signer);
                    }
                    spend_tx.input[input_idx].witness = keys_cache
                        .get(&descriptor.channel_keys_id)
                        .unwrap()
                        .sign_dynamic_p2wsh_input(&spend_tx, input_idx, &descriptor, &secp_ctx)
                        .expect("descriptor not accepted by sign_dynamic_p2wsh_input");
                }
                SpendableOutputDescriptor::StaticOutput { ref output, .. } => {
                    let derivation_idx =
                        if output.script_pubkey == self.destination_script { 1 } else { 2 };
                    let account_extended_key = self.key_derivation_style.get_account_extended_key(
                        &secp_ctx,
                        self.network,
                        &self.seed,
                    );
                    let secret_key = account_extended_key
                        .derive_priv(
                            &secp_ctx,
                            &[ChildNumber::from_normal_idx(derivation_idx)
                                .expect("key space exhausted")],
                        )
                        .expect("Your RNG is busted");
                    let pubkey =
                        bitcoin::PublicKey::new(Xpub::from_priv(&secp_ctx, &secret_key).public_key);
                    if derivation_idx == 2 {
                        assert_eq!(pubkey.inner, self.ldk_shutdown_pubkey);
                    }
                    let witness_script =
                        bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
                    // unwrap is safe because we formatted the tx ourselves
                    let sighash = Message::from(
                        sighash::SighashCache::new(&spend_tx)
                            .p2wsh_signature_hash(
                                input_idx,
                                &witness_script,
                                output.value,
                                EcdsaSighashType::All,
                            )
                            .unwrap(),
                    );
                    let sig = secp_ctx.sign_ecdsa(&sighash, &secret_key.private_key);
                    let mut sig_ser = sig.serialize_der().to_vec();
                    sig_ser.push(EcdsaSighashType::All as u8);
                    spend_tx.input[input_idx].witness.push(sig_ser);
                    spend_tx.input[input_idx].witness.push(pubkey.inner.serialize().to_vec());
                }
            }
            input_idx += 1;
        }
        Ok(spend_tx)
    }

    /// Sign a heartbeat object
    pub fn sign_heartbeat(&self, ser_heartbeat: &[u8]) -> schnorr::Signature {
        let kp = Keypair::from_secret_key(&self.secp_ctx, &self.account_extended_key.private_key);
        let msg = sighash_from_heartbeat(ser_heartbeat);
        self.secp_ctx.sign_schnorr_no_aux_rand(&msg, &kp)
    }
}

impl EntropySource for MyKeysManager {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut sha = self.rand_bytes_unique_start.clone();

        let child_ix = self.rand_bytes_child_index.fetch_add(1, Ordering::AcqRel);
        let child_privkey = self
            .rand_bytes_master_key
            .derive_priv(
                &self.secp_ctx,
                &[ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted")],
            )
            .expect("Your RNG is busted");
        sha.input(child_privkey.private_key.as_ref());

        sha.input(b"Unique Secure Random Bytes Salt");
        Sha256::from_engine(sha).to_byte_array()
    }
}

impl SignerProvider for MyKeysManager {
    type EcdsaSigner = InMemorySigner;

    fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        // The destination script is chosen by the local node (must be
        // in wallet or allowlisted).
        unimplemented!()
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        Ok(ShutdownScript::new_p2wpkh(&WPubkeyHash::hash(&self.ldk_shutdown_pubkey.serialize())))
    }

    fn generate_channel_keys_id(
        &self,
        _inbound: bool,
        _channel_value_satoshis: u64,
        _user_channel_id: u128,
    ) -> [u8; 32] {
        unimplemented!()
    }

    fn derive_channel_signer(
        &self,
        _channel_value_satoshis: u64,
        _channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        unimplemented!()
    }

    fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        unimplemented!()
    }
}

impl NodeSigner for MyKeysManager {
    fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
        match recipient {
            Recipient::Node => (),
            Recipient::PhantomNode => return Err(()),
        };
        let node_secret = self.get_node_secret();
        let node_id = PublicKey::from_secret_key(&self.secp_ctx, &node_secret);
        Ok(node_id)
    }

    fn sign_gossip_message(&self, msg: UnsignedGossipMessage) -> Result<Signature, ()> {
        let msg_hash = Sha256dHash::hash(&msg.encode()[..]);
        let encmsg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
        let sig = self.secp_ctx.sign_ecdsa(&encmsg, &self.get_node_secret());
        Ok(sig)
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        match recipient {
            Recipient::Node => (),
            Recipient::PhantomNode => return Err(()),
        };
        let mut node_secret = self.get_node_secret();
        if let Some(tweak) = tweak {
            node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
        }
        Ok(SharedSecret::new(other_key, &node_secret))
    }

    fn sign_invoice(
        &self,
        invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => (),
            Recipient::PhantomNode => return Err(()),
        };
        let invoice_preimage = invoice.signable_hash();
        Ok(self.secp_ctx.sign_ecdsa_recoverable(
            &Message::from_digest(Sha256::hash(&invoice_preimage).to_byte_array()),
            &self.get_node_secret(),
        ))
    }

    fn get_inbound_payment_key(&self) -> ExpandedKey {
        self.inbound_payment_key
    }

    fn sign_bolt12_invoice(
        &self,
        _: &lightning::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<schnorr::Signature, ()> {
        todo!("issue 459")
    }
}

#[cfg(test)]
mod tests {
    use crate::util::INITIAL_COMMITMENT_NUMBER;
    use bitcoin::Network::Testnet;
    use core::borrow::Borrow;

    use super::*;
    use crate::util::test_utils::{
        hex_decode, hex_encode, FixedStartingTimeFactory, TEST_CHANNEL_ID,
    };
    use lightning::sign::{ChannelSigner, KeysManager};
    use test_log::test;

    #[test]
    fn shared_secret_test() {
        let server_key = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let server_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &server_key);
        let manager = MyKeysManager::new(
            KeyDerivationStyle::Ldk,
            &[0x11u8; 32],
            Network::Testnet,
            FixedStartingTimeFactory::new(1, 1).borrow(),
        );
        let client_pubkey = manager.get_persistence_pubkey();
        let shared_secret = SharedSecret::new(&client_pubkey, &server_key);
        let shared_secret2 = manager.get_persistence_shared_secret(&server_pubkey);
        assert_eq!(shared_secret.secret_bytes(), shared_secret2);
    }

    #[test]
    fn compare_ldk_keys_manager_test() -> Result<(), ()> {
        let seed = [0x11u8; 32];
        let ldk = KeysManager::new(&seed, 1, 1);
        let my = MyKeysManager::new(
            KeyDerivationStyle::Ldk,
            &seed,
            Network::Testnet,
            FixedStartingTimeFactory::new(1, 1).borrow(),
        );
        assert_eq!(
            ldk.get_node_id(Recipient::Node).unwrap(),
            my.get_node_id(Recipient::Node).unwrap()
        );
        let key_derive = derive::key_derive(KeyDerivationStyle::Ldk, Testnet);
        let channel_id = ChannelId::new(&[33u8; 32]);
        // Get a somewhat random keys_id
        let keys_id = key_derive.keys_id(channel_id, &my.channel_seed_base);
        let ldk_chan = ldk.derive_channel_keys(1000, &keys_id);
        let my_chan = my.derive_channel_keys(1000, &keys_id);
        let secp_ctx = Secp256k1::new();
        assert_eq!(ldk_chan.funding_key, my_chan.funding_key);
        assert_eq!(ldk_chan.revocation_base_key, my_chan.revocation_base_key);
        assert_eq!(ldk_chan.htlc_base_key, my_chan.htlc_base_key);
        assert_eq!(ldk_chan.payment_key, my_chan.payment_key);
        assert_eq!(ldk_chan.delayed_payment_base_key, my_chan.delayed_payment_base_key);
        assert_eq!(ldk_chan.funding_key, my_chan.funding_key);
        assert_eq!(
            ldk_chan.get_per_commitment_point(123, &secp_ctx),
            my_chan.get_per_commitment_point(123, &secp_ctx)
        );
        // a bit redundant, because we checked them all above
        assert!(ldk_chan.pubkeys() == my_chan.pubkeys());
        Ok(())
    }

    #[test]
    fn keys_test_native() -> Result<(), ()> {
        let manager = MyKeysManager::new(
            KeyDerivationStyle::Native,
            &[0u8; 32],
            Network::Testnet,
            FixedStartingTimeFactory::new(0, 0).borrow(),
        );
        assert_eq!(
            hex_encode(&manager.channel_seed_base),
            "ab7f29780659755f14afb82342dc19db7d817ace8c312e759a244648dfc25e53"
        );
        let keys = make_test_keys(manager);
        assert_eq!(
            hex_encode(&keys.funding_key[..]),
            "bf36bee09cc5dd64c8f19e10b258efb1f606722e9ff6fe3267b63e2dbe33dcfc"
        );
        assert_eq!(
            hex_encode(&keys.revocation_base_key[..]),
            "203612ab8275bab7916b8bf895d45b9dbb639b43d904b34d6449214e9855d345"
        );
        assert_eq!(
            hex_encode(&keys.htlc_base_key[..]),
            "517c009452b4baa9df42d6c8cddc966e017d49606524ce7728681b593a5659c1"
        );
        assert_eq!(
            hex_encode(&keys.payment_key[..]),
            "54ce3b75dcc2731604f3db55ecd1520d797a154cc757d6d98c3ffd1e90a9a25a"
        );
        assert_eq!(
            hex_encode(&keys.delayed_payment_base_key[..]),
            "9f5c122778b12ad35f555437d88b76b726ae4e472897af33e22616fb0d0b0a44"
        );
        Ok(())
    }

    fn make_test_keys(manager: MyKeysManager) -> InMemorySigner {
        let channel_id = ChannelId::new(&hex_decode(TEST_CHANNEL_ID[0]).unwrap());
        manager.get_channel_keys_with_id(channel_id, 0)
    }

    #[test]
    fn keys_test_lnd() -> Result<(), ()> {
        let manager = MyKeysManager::new(
            KeyDerivationStyle::Lnd,
            &[0u8; 32],
            Network::Testnet,
            FixedStartingTimeFactory::new(0, 0).borrow(),
        );
        assert_eq!(
            hex_encode(&manager.channel_seed_base),
            "ab7f29780659755f14afb82342dc19db7d817ace8c312e759a244648dfc25e53"
        );
        let mut channel_id = [0u8; 32];
        channel_id[0] = 1u8;
        let keys = make_test_keys(manager);
        assert_eq!(
            hex_encode(&keys.funding_key[..]),
            "0b2f20d28e705daea86a93e6d5646e2f8989956d73c61752e7cf6c4421071e99"
        );
        assert_eq!(
            hex_encode(&keys.revocation_base_key[..]),
            "920c0b18c7d0979dc7119efb1ca520cf6899c92a3236d146968b521a901eac63"
        );
        assert_eq!(
            hex_encode(&keys.htlc_base_key[..]),
            "60deb71963b8574f3c8bf5df2d7b851f9c31a866a1c14bd00dae1263a5f27c55"
        );
        assert_eq!(
            hex_encode(&keys.payment_key[..]),
            "064e32a51f3ed0a41936bd788a80dc91b7521a85da00f02196eddbd32c3d5631"
        );
        assert_eq!(
            hex_encode(&keys.delayed_payment_base_key[..]),
            "47a6c0532b9e593e84d91451104dc6fe10ba4aa30cd7c95ed039916d3e908b10"
        );
        Ok(())
    }

    #[test]
    fn per_commit_test() -> Result<(), ()> {
        let manager = MyKeysManager::new(
            KeyDerivationStyle::Native,
            &[0u8; 32],
            Network::Testnet,
            FixedStartingTimeFactory::new(0, 0).borrow(),
        );
        let mut channel_id = [0u8; 32];
        channel_id[0] = 1u8;
        let keys = make_test_keys(manager);
        assert_eq!(
            hex_encode(&keys.commitment_seed),
            "9fc48da6bc75058283b860d5989ffb802b6395ca28c4c3bb9d1da02df6bb0cb3"
        );

        let secp_ctx = Secp256k1::signing_only();
        let per_commit_point = MyKeysManager::per_commitment_point(
            &secp_ctx,
            &keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 3).unwrap(),
        );
        assert_eq!(
            hex_encode(&per_commit_point.serialize().to_vec()),
            "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
        );
        Ok(())
    }
}
