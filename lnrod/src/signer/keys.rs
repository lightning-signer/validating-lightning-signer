use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, bail, Result};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::{ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash;
use bitcoin::WPubkeyHash;
use bitcoin::{secp256k1, Address, Witness};
use bitcoin::{Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use lightning::ln::msgs::DecodeError;
use lightning::ln::msgs::UnsignedGossipMessage;
use lightning::ln::script::ShutdownScript;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::sign::{
    DelayedPaymentOutputDescriptor, InMemorySigner, Recipient, SpendableOutputDescriptor,
};
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning_signer::bitcoin::sighash::EcdsaSighashType;
use lightning_signer::bitcoin::transaction::Version;
use lightning_signer::bitcoin::Amount;
use lightning_signer::lightning::ln::inbound_payment::ExpandedKey;
use lightning_signer::lightning_invoice::RawBolt11Invoice;
use lightning_signer::util::transaction_utils;
use lightning_signer::util::transaction_utils::MAX_VALUE_MSAT;
use lightning_signer::{bitcoin, lightning};

use crate::signer::test_signer::InMemorySignerFactory;
use crate::{byte_utils, DynSigner, SpendableKeysInterface};

// Copied from keysinterface.rs and decoupled from InMemorySigner

/// Simple KeysInterface implementor that takes a 32-byte seed for use as a BIP 32 extended key
/// and derives keys from that.
///
/// Your node_id is seed/0'
/// ChannelMonitor closes may use seed/1'
/// Cooperative closes may use seed/2'
/// The two close keys may be needed to claim on-chain funds!
pub struct KeysManager {
    secp_ctx: Secp256k1<secp256k1::All>,
    node_secret: SecretKey,
    inbound_payment_key: ExpandedKey,
    destination_script: ScriptBuf,
    shutdown_pubkey: PublicKey,
    channel_master_key: Xpriv,
    channel_child_index: AtomicUsize,

    rand_bytes_master_key: Xpriv,
    rand_bytes_child_index: AtomicUsize,
    rand_bytes_unique_start: Sha256State,

    seed: [u8; 32],
    starting_time_secs: u64,
    starting_time_nanos: u32,
    sweep_address: Address,
    pub factory: InMemorySignerFactory,
}

impl KeysManager {
    /// Constructs a KeysManager from a 32-byte seed. If the seed is in some way biased (eg your
    /// CSRNG is busted) this may panic (but more importantly, you will possibly lose funds).
    /// starting_time isn't strictly required to actually be a time, but it must absolutely,
    /// without a doubt, be unique to this instance. ie if you start multiple times with the same
    /// seed, starting_time must be unique to each run. Thus, the easiest way to achieve this is to
    /// simply use the current time (with very high precision).
    ///
    /// The seed MUST be backed up safely prior to use so that the keys can be re-created, however,
    /// obviously, starting_time should be unique every time you reload the library - it is only
    /// used to generate new ephemeral key data (which will be stored by the individual channel if
    /// necessary).
    ///
    /// Note that the seed is required to recover certain on-chain funds independent of
    /// ChannelMonitor data, though a current copy of ChannelMonitor data is also required for any
    /// channel, and some on-chain during-closing funds.
    ///
    /// Note that until the 0.1 release there is no guarantee of backward compatibility between
    /// versions. Once the library is more fully supported, the docs will be updated to include a
    /// detailed description of the guarantee.
    pub fn new(
        seed: &[u8; 32],
        starting_time_secs: u64,
        starting_time_nanos: u32,
        sweep_address: Address,
    ) -> Self {
        let secp_ctx = Secp256k1::new();
        // Note that when we aren't serializing the key, network doesn't matter
        let master_key = Xpriv::new_master(Network::Testnet, seed).expect("your RNG is busted");
        let node_secret = master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(0).unwrap()])
            .expect("Your RNG is busted")
            .private_key;
        let destination_script = match master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(1).unwrap()])
        {
            Ok(destination_key) => {
                let wpubkey_hash = WPubkeyHash::hash(
                    &Xpub::from_priv(&secp_ctx, &destination_key).public_key.serialize(),
                );
                Builder::new()
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_slice(&wpubkey_hash)
                    .into_script()
            }
            Err(_) => panic!("Your RNG is busted"),
        };
        let shutdown_pubkey = match master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(2).unwrap()])
        {
            Ok(shutdown_key) => Xpub::from_priv(&secp_ctx, &shutdown_key).public_key,
            Err(_) => panic!("Your RNG is busted"),
        };
        let channel_master_key = master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(3).unwrap()])
            .expect("Your RNG is busted");
        let rand_bytes_master_key = master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(4).unwrap()])
            .expect("Your RNG is busted");

        let mut rand_bytes_unique_start = Sha256Hash::engine();
        rand_bytes_unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
        rand_bytes_unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
        rand_bytes_unique_start.input(seed);

        let inbound_payment_key: SecretKey = master_key
            .derive_priv(&secp_ctx, &vec![ChildNumber::from_hardened_idx(5).unwrap()])
            .expect("Your RNG is busted")
            .private_key;
        let mut inbound_pmt_key_bytes = [0; 32];
        inbound_pmt_key_bytes.copy_from_slice(inbound_payment_key.as_ref());

        let factory = InMemorySignerFactory::new(&seed);

        let mut res = KeysManager {
            secp_ctx,
            node_secret,

            inbound_payment_key: ExpandedKey::new(inbound_pmt_key_bytes),
            destination_script,
            shutdown_pubkey,

            channel_master_key,
            channel_child_index: AtomicUsize::new(0),

            rand_bytes_master_key,
            rand_bytes_child_index: AtomicUsize::new(0),
            rand_bytes_unique_start,

            seed: *seed,
            starting_time_secs,
            starting_time_nanos,
            factory,
            sweep_address,
        };
        let secp_seed = res.get_secure_random_bytes();
        res.secp_ctx.seeded_randomize(&secp_seed);
        res
    }
    /// Derive an old Sign containing per-channel secrets based on a key derivation parameters.
    ///
    /// Key derivation parameters are accessible through a per-channel secrets
    /// Sign::channel_keys_id and is provided inside DynamicOuputP2WSH in case of
    /// onchain output detection for which a corresponding delayed_payment_key must be derived.
    pub fn derive_channel_keys(
        &self,
        channel_value_satoshis: u64,
        params: &[u8; 32],
    ) -> InMemorySigner {
        self.factory.derive_channel_keys(&self.channel_master_key, channel_value_satoshis, params)
    }
}

impl SignerProvider for KeysManager {
    type EcdsaSigner = DynSigner;

    fn get_destination_script(&self, _: [u8; 32]) -> Result<ScriptBuf, ()> {
        Ok(self.destination_script.clone())
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        Ok(ShutdownScript::new_p2wpkh(&WPubkeyHash::hash(&self.shutdown_pubkey.serialize())))
    }

    fn generate_channel_keys_id(
        &self,
        _inbound: bool,
        _channel_value_satoshis: u64,
        _user_channel_id: u128,
    ) -> [u8; 32] {
        let child_ix = self.channel_child_index.fetch_add(1, Ordering::AcqRel);
        assert!(child_ix <= std::u32::MAX as usize);
        let mut id = [0; 32];
        id[0..8].copy_from_slice(&byte_utils::be64_to_array(child_ix as u64));
        id[8..16].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_nanos as u64));
        id[16..24].copy_from_slice(&byte_utils::be64_to_array(self.starting_time_secs));
        id
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        DynSigner::new(self.derive_channel_keys(channel_value_satoshis, &channel_keys_id))
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        let mut cursor = std::io::Cursor::new(reader);
        // TODO(devrandom) make this polymorphic
        let signer = InMemorySigner::read(&mut cursor, self)?;
        Ok(DynSigner { inner: Box::new(signer) })
    }
}

impl EntropySource for KeysManager {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut sha = self.rand_bytes_unique_start.clone();

        let child_ix = self.rand_bytes_child_index.fetch_add(1, Ordering::AcqRel);
        let child_privkey =
            self.rand_bytes_master_key
                .derive_priv(
                    &self.secp_ctx,
                    &vec![ChildNumber::from_hardened_idx(child_ix as u32)
                        .expect("key space exhausted")],
                )
                .expect("Your RNG is busted");
        sha.input(child_privkey.private_key.as_ref());

        sha.input(b"Unique Secure Random Bytes Salt");
        Sha256Hash::from_engine(sha).to_byte_array()
    }
}

impl NodeSigner for KeysManager {
    fn get_inbound_payment_key(&self) -> ExpandedKey {
        self.inbound_payment_key
    }

    fn get_node_id(&self, recipient: Recipient) -> std::result::Result<PublicKey, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => panic!("phantom node not supported"),
        }
        Ok(PublicKey::from_secret_key(&self.secp_ctx, &self.node_secret))
    }

    fn ecdh(
        &self,
        recipient: Recipient,
        other_key: &PublicKey,
        tweak: Option<&Scalar>,
    ) -> Result<SharedSecret, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => panic!("phantom node not supported"),
        }
        let mut node_secret = self.node_secret.clone();
        if let Some(tweak) = tweak {
            node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
        }
        Ok(SharedSecret::new(other_key, &node_secret))
    }

    fn sign_invoice(
        &self,
        raw_invoice: &RawBolt11Invoice,
        recipient: Recipient,
    ) -> Result<RecoverableSignature, ()> {
        match recipient {
            Recipient::Node => {}
            Recipient::PhantomNode => panic!("phantom node not supported"),
        }
        let node_secret = self.node_secret.clone();
        let hash = raw_invoice.signable_hash();
        let message = secp256k1::Message::from_digest(hash);
        Ok(self.secp_ctx.sign_ecdsa_recoverable(&message, &node_secret))
    }

    fn sign_gossip_message(
        &self,
        msg: UnsignedGossipMessage,
    ) -> std::result::Result<Signature, ()> {
        let encoded = &msg.encode()[..];
        let msg_hash = Sha256dHash::hash(encoded);
        let encmsg = Message::from_digest(msg_hash.to_byte_array());
        Ok(self.secp_ctx.sign_ecdsa(&encmsg, &self.node_secret))
    }

    fn sign_bolt12_invoice(
        &self,
        _invoice: &UnsignedBolt12Invoice,
    ) -> Result<secp256k1::schnorr::Signature, ()> {
        todo!()
    }
}

impl SpendableKeysInterface for KeysManager {
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
    /// this KeysManager or one of the `DynSigner` created by this KeysManager.
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Transaction> {
        let mut input = Vec::new();
        let mut input_value = Amount::ZERO;
        let mut witness_weight = 0;
        let mut output_set = HashSet::with_capacity(descriptors.len());
        for outp in descriptors {
            match outp {
                SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                    input.push(TxIn {
                        previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::default(),
                    });
                    witness_weight += descriptor.max_witness_length();
                    input_value += descriptor.output.value;
                    if !output_set.insert(descriptor.outpoint) {
                        bail!("Descriptor was duplicated");
                    }
                }
                SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                    input.push(TxIn {
                        previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence(descriptor.to_self_delay as u32),
                        witness: Witness::default(),
                    });
                    witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
                    input_value += descriptor.output.value;
                    if !output_set.insert(descriptor.outpoint) {
                        bail!("Descriptor was duplicated");
                    }
                }
                SpendableOutputDescriptor::StaticOutput {
                    ref outpoint,
                    ref output,
                    channel_keys_id: _,
                } => {
                    input.push(TxIn {
                        previous_output: outpoint.into_bitcoin_outpoint(),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::default(),
                    });
                    witness_weight += 1 + 73 + 34;
                    input_value += output.value;
                    if !output_set.insert(*outpoint) {
                        bail!("Descriptor was duplicated");
                    }
                }
            }
            if input_value > Amount::from_sat(MAX_VALUE_MSAT / 1000) {
                bail!("Input value greater than max satoshis");
            }
        }
        let mut spend_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output: outputs,
        };
        transaction_utils::maybe_add_change_output(
            &mut spend_tx,
            input_value.to_sat(),
            witness_weight,
            feerate_sat_per_1000_weight,
            change_destination_script,
        )
        .map_err(|_| anyhow!("failed to add change output"))?;

        let mut keys_cache: Option<(InMemorySigner, [u8; 32])> = None;
        let mut input_idx = 0;
        for outp in descriptors {
            match outp {
                SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                    if keys_cache.is_none()
                        || keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
                    {
                        keys_cache = Some((
                            self.derive_channel_keys(
                                descriptor.channel_value_satoshis,
                                &descriptor.channel_keys_id,
                            ),
                            descriptor.channel_keys_id,
                        ));
                    }
                    spend_tx.input[input_idx].witness = keys_cache
                        .as_ref()
                        .unwrap()
                        .0
                        .sign_counterparty_payment_input(
                            &spend_tx,
                            input_idx,
                            &descriptor,
                            &secp_ctx,
                        )
                        .unwrap();
                }
                SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                    if keys_cache.is_none()
                        || keys_cache.as_ref().unwrap().1 != descriptor.channel_keys_id
                    {
                        keys_cache = Some((
                            self.derive_channel_keys(
                                descriptor.channel_value_satoshis,
                                &descriptor.channel_keys_id,
                            ),
                            descriptor.channel_keys_id,
                        ));
                    }
                    spend_tx.input[input_idx].witness = keys_cache
                        .as_ref()
                        .unwrap()
                        .0
                        .sign_dynamic_p2wsh_input(&spend_tx, input_idx, &descriptor, &secp_ctx)
                        .unwrap();
                }
                SpendableOutputDescriptor::StaticOutput { ref output, .. } => {
                    let derivation_idx =
                        if output.script_pubkey == self.destination_script { 1 } else { 2 };
                    let secret = {
                        // Note that when we aren't serializing the key, network doesn't matter
                        match Xpriv::new_master(Network::Testnet, &self.seed) {
                            Ok(master_key) => {
                                match master_key.derive_priv(
                                    &secp_ctx,
                                    &vec![ChildNumber::from_hardened_idx(derivation_idx)
                                        .expect("key space exhausted")],
                                ) {
                                    Ok(key) => key,
                                    Err(_) => panic!("Your RNG is busted"),
                                }
                            }
                            Err(_) => panic!("Your rng is busted"),
                        }
                    };
                    let pubkey =
                        bitcoin::PublicKey::new(Xpub::from_priv(&secp_ctx, &secret).public_key);
                    if derivation_idx == 2 {
                        assert_eq!(pubkey.inner, self.shutdown_pubkey);
                    }
                    let witness_script = Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
                    let sighash = secp256k1::Message::from_digest_slice(
                        &sighash::SighashCache::new(&spend_tx)
                            .p2wsh_signature_hash(
                                input_idx,
                                &witness_script,
                                output.value,
                                EcdsaSighashType::All,
                            )
                            .unwrap()
                            .as_ref(),
                    )
                    .unwrap();
                    let sig = secp_ctx.sign_ecdsa(&sighash, &secret.private_key);
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

    fn get_sweep_address(&self) -> Address {
        self.sweep_address.clone()
    }
}

#[cfg(test)]
mod tests {}
