use crate::prelude::*;
use core::convert::{TryFrom, TryInto};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256::HashEngine as Sha256State;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signing};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, SigHashType, Transaction, TxIn, TxOut};
use bitcoin::{Network, Script};
use lightning::chain::keysinterface::{
    DelayedPaymentOutputDescriptor, InMemorySigner, KeysInterface, SpendableOutputDescriptor,
    StaticPaymentOutputDescriptor,
};

use crate::node::ChannelId;
use crate::util::crypto_utils::{
    channels_seed, derive_key_lnd, get_account_extended_key_lnd, get_account_extended_key_native,
    hkdf_sha256, hkdf_sha256_keys, node_keys_lnd, node_keys_native,
};
use crate::util::transaction_utils::MAX_VALUE_MSAT;
use crate::util::{byte_utils, transaction_utils};
use bitcoin::secp256k1::recovery::RecoverableSignature;
use bitcoin::util::bip143;
use lightning::ln::msgs::DecodeError;
use hashbrown::HashSet;

#[derive(Clone, Copy, Debug)] // NOT TESTED
pub enum KeyDerivationStyle {
    Native = 1,
    Lnd = 2,
}

impl TryFrom<u8> for KeyDerivationStyle {
    type Error = ();

    // BEGIN NOT TESTED
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use KeyDerivationStyle::{Lnd, Native};
        match v {
            x if x == Native as u8 => Ok(Native),
            x if x == Lnd as u8 => Ok(Lnd),
            _ => Err(()),
        }
    }
    // END NOT TESTED
}

pub trait KeyDerivationParam {
    fn get_key_path_len(&self) -> usize;
}

impl KeyDerivationStyle {
    pub fn get_key_path_len(&self) -> usize {
        // BEGIN NOT TESTED
        match self {
            // END NOT TESTED
            // c-lightning uses a single BIP32 chain for both external
            // and internal (change) addresses.
            KeyDerivationStyle::Native => 1,
            // lnd uses two BIP32 branches, one for external and one
            // for internal (change) addresses.
            KeyDerivationStyle::Lnd => 2, // NOT TESTED
        }
    }

    pub fn get_account_extended_key(
        &self,
        secp_ctx: &Secp256k1<secp256k1::SignOnly>,
        network: Network,
        seed: &[u8],
    ) -> ExtendedPrivKey {
        match self {
            KeyDerivationStyle::Native => get_account_extended_key_native(secp_ctx, network, seed),
            KeyDerivationStyle::Lnd => get_account_extended_key_lnd(secp_ctx, network, seed),
        }
    }
}

pub struct MyKeysManager {
    secp_ctx: Secp256k1<secp256k1::SignOnly>,
    seed: Vec<u8>,
    key_derivation_style: KeyDerivationStyle,
    network: Network,
    master_key: ExtendedPrivKey,
    node_secret: SecretKey,
    channel_seed_base: [u8; 32],
    account_extended_key: ExtendedPrivKey,
    destination_script: Script,
    shutdown_pubkey: PublicKey,
    #[allow(dead_code)]
    channel_master_key: ExtendedPrivKey,
    channel_id_master_key: ExtendedPrivKey,
    channel_id_child_index: AtomicUsize,

    rand_bytes_master_key: ExtendedPrivKey,
    rand_bytes_child_index: AtomicUsize,
    rand_bytes_unique_start: Sha256State,

    lnd_basepoint_index: AtomicU32,

    unique_start: Sha256State,

    id_to_nonce: Mutex<Map<ChannelId, Vec<u8>>>,
}

impl MyKeysManager {
    pub fn new(
        key_derivation_style: KeyDerivationStyle,
        seed: &[u8],
        network: Network,
        starting_time_secs: u64,
        starting_time_nanos: u32,
    ) -> MyKeysManager {
        let secp_ctx = Secp256k1::signing_only();
        match ExtendedPrivKey::new_master(network.clone(), seed) {
            Ok(master_key) => {
                let (_, node_secret) = match key_derivation_style {
                    KeyDerivationStyle::Native => node_keys_native(&secp_ctx, seed),
                    KeyDerivationStyle::Lnd => {
                        node_keys_lnd(&secp_ctx, network.clone(), master_key)
                    }
                };
                let destination_script = match master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(1).unwrap())
                {
                    Ok(destination_key) => {
                        let pubkey_hash160 = Hash160::hash(
                            &ExtendedPubKey::from_private(&secp_ctx, &destination_key)
                                .public_key
                                .key
                                .serialize()[..],
                        );
                        Builder::new()
                            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                            .push_slice(&pubkey_hash160.into_inner())
                            .into_script()
                    }
                    Err(_) => panic!("Your RNG is busted"), // NOT TESTED
                };
                let shutdown_pubkey = match master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap())
                {
                    Ok(shutdown_key) => {
                        ExtendedPubKey::from_private(&secp_ctx, &shutdown_key)
                            .public_key
                            .key
                    }
                    Err(_) => panic!("Your RNG is busted"), // NOT TESTED
                };
                let channel_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap())
                    .expect("Your RNG is busted");
                let channel_id_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(5).unwrap())
                    .expect("Your RNG is busted");

                let mut unique_start = Sha256::engine();
                unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
                unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
                unique_start.input(seed);

                let channel_seed_base = channels_seed(seed);
                let account_extended_key =
                    key_derivation_style.get_account_extended_key(&secp_ctx, network, seed);

                let rand_bytes_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(4).unwrap())
                    .expect("Your RNG is busted");

                let mut rand_bytes_unique_start = Sha256::engine();
                rand_bytes_unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
                rand_bytes_unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
                rand_bytes_unique_start.input(seed);

                let mut res = MyKeysManager {
                    secp_ctx,
                    seed: seed.to_vec(),
                    key_derivation_style,
                    network,
                    master_key,
                    node_secret,
                    channel_seed_base,
                    account_extended_key,
                    destination_script,
                    shutdown_pubkey,
                    channel_master_key,
                    channel_id_master_key,
                    channel_id_child_index: AtomicUsize::new(0),
                    rand_bytes_master_key,
                    rand_bytes_child_index: AtomicUsize::new(0),
                    rand_bytes_unique_start,
                    lnd_basepoint_index: AtomicU32::new(0),
                    unique_start,
                    id_to_nonce: Mutex::new(Map::new()),
                };

                let secp_seed = res.get_secure_random_bytes();
                res.secp_ctx.seeded_randomize(&secp_seed);
                res
            }
            Err(_) => panic!("Your rng is busted"), // NOT TESTED
        }
    }

    /// Get the layer-1 xpub
    pub fn get_account_extended_key(&self) -> &ExtendedPrivKey {
        &self.account_extended_key
    }

    /// Convert a commitment secret to a commitment point
    pub fn per_commitment_point<X: Signing>(
        secp_ctx: &Secp256k1<X>,
        commitment_secret: &[u8; 32],
    ) -> PublicKey {
        PublicKey::from_secret_key(secp_ctx, &SecretKey::from_slice(commitment_secret).unwrap())
    }

    // Re-derive existing channel keys
    fn derive_channel_keys(
        &self,
        channel_value_sat: u64,
        channel_id_slice: &[u8; 32],
    ) -> InMemorySigner {
        let channel_id = ChannelId(*channel_id_slice);
        let nonce = {
            let id_to_nonce = self.id_to_nonce.lock().unwrap();
            id_to_nonce
                .get(&channel_id)
                .expect("unknown channel ID")
                .clone()
        };
        self.get_channel_keys_with_id(channel_id, nonce.as_slice(), channel_value_sat)
    }

    pub(crate) fn get_channel_keys_with_id(
        &self,
        channel_id: ChannelId,
        channel_nonce: &[u8],
        channel_value_sat: u64,
    ) -> InMemorySigner {
        let res = match self.key_derivation_style {
            KeyDerivationStyle::Native => self.get_channel_keys_with_nonce_native(
                channel_id,
                channel_nonce,
                channel_value_sat,
            ),
            KeyDerivationStyle::Lnd => {
                self.get_channel_keys_with_nonce_lnd(channel_id, channel_nonce, channel_value_sat)
            }
        };
        self.id_to_nonce
            .lock()
            .unwrap()
            .insert(channel_id, channel_nonce.to_vec());
        res
    }

    fn get_channel_keys_with_nonce_native(
        &self,
        channel_id: ChannelId,
        channel_nonce: &[u8],
        channel_value_sat: u64,
    ) -> InMemorySigner {
        let hkdf_info = "c-lightning";
        let channel_seed = hkdf_sha256(
            &self.channel_seed_base,
            "per-peer seed".as_bytes(),
            channel_nonce,
        );

        let keys_buf = hkdf_sha256_keys(&channel_seed, hkdf_info.as_bytes(), &[]);
        let mut ndx = 0;
        let funding_key = SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let revocation_base_key = SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let htlc_base_key = SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let payment_key = SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let delayed_payment_base_key = SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let commitment_seed = keys_buf[ndx..ndx + 32].try_into().unwrap();
        let secp_ctx = Secp256k1::signing_only();
        InMemorySigner::new(
            &secp_ctx,
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_sat,
            channel_id.0,
        )
    }

    fn get_channel_keys_with_nonce_lnd(
        &self,
        channel_id: ChannelId,
        channel_nonce: &[u8],
        channel_value_sat: u64,
    ) -> InMemorySigner {
        // FIXME - How does lnd generate it's commitment seed? This is a stripped
        // native (really c-lightning) version.
        //
        let hkdf_info = "c-lightning";
        let channel_seed = hkdf_sha256(
            &self.channel_seed_base,
            "per-peer seed".as_bytes(),
            channel_nonce,
        );
        let keys_buf = hkdf_sha256_keys(&channel_seed, hkdf_info.as_bytes(), &[]);
        let mut ndx = 0;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        let commitment_seed = keys_buf[ndx..ndx + 32].try_into().unwrap();

        let secp_ctx = Secp256k1::signing_only();

        // These need to match the constants defined in lnd/keychain/derivation.go
        // KeyFamilyMultiSig KeyFamily = 0
        // KeyFamilyRevocationBase = 1
        // KeyFamilyHtlcBase KeyFamily = 2
        // KeyFamilyPaymentBase KeyFamily = 3
        // KeyFamilyDelayBase KeyFamily = 4
        let basepoint_index = self.lnd_basepoint_index.fetch_add(1, Ordering::AcqRel);
        let (_, funding_key) =
            derive_key_lnd(&secp_ctx, self.network, self.master_key, 0, basepoint_index);
        let (_, revocation_base_key) =
            derive_key_lnd(&secp_ctx, self.network, self.master_key, 1, basepoint_index);
        let (_, htlc_base_key) =
            derive_key_lnd(&secp_ctx, self.network, self.master_key, 2, basepoint_index);
        let (_, payment_key) =
            derive_key_lnd(&secp_ctx, self.network, self.master_key, 3, basepoint_index);
        let (_, delayed_payment_base_key) =
            derive_key_lnd(&secp_ctx, self.network, self.master_key, 4, basepoint_index);

        InMemorySigner::new(
            &secp_ctx,
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_sat,
            channel_id.0,
        )
    }

    pub fn get_channel_id(&self) -> [u8; 32] {
        let mut sha = self.unique_start.clone();

        let child_ix = self.increment_channel_id_child_index();
        let child_privkey = self
            .channel_id_master_key
            .ckd_priv(
                &self.secp_ctx,
                ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted"),
            )
            .expect("Your RNG is busted");
        sha.input(&child_privkey.private_key.key[..]);

        Sha256::from_engine(sha).into_inner()
    }

    pub fn increment_channel_id_child_index(&self) -> usize {
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
    pub fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: Script,
        feerate_sat_per_1000_weight: u32,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Transaction, ()> {
        let mut input = Vec::new();
        let mut input_value = 0;
        let mut witness_weight = 0;
        let mut output_set = HashSet::with_capacity(descriptors.len());
        for outp in descriptors {
            match outp {
                SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                    input.push(TxIn {
                        previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                        script_sig: Script::new(),
                        sequence: 0,
                        witness: Vec::new(),
                    });
                    witness_weight += StaticPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
                    input_value += descriptor.output.value;
                    if !output_set.insert(descriptor.outpoint) {
                        return Err(());
                    }
                }
                SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                    input.push(TxIn {
                        previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                        script_sig: Script::new(),
                        sequence: descriptor.to_self_delay as u32,
                        witness: Vec::new(),
                    });
                    witness_weight += DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
                    input_value += descriptor.output.value;
                    if !output_set.insert(descriptor.outpoint) {
                        return Err(());
                    }
                }
                SpendableOutputDescriptor::StaticOutput {
                    ref outpoint,
                    ref output,
                } => {
                    input.push(TxIn {
                        previous_output: outpoint.into_bitcoin_outpoint(),
                        script_sig: Script::new(),
                        sequence: 0,
                        witness: Vec::new(),
                    });
                    witness_weight += 1 + 73 + 34;
                    input_value += output.value;
                    if !output_set.insert(*outpoint) {
                        return Err(());
                    }
                }
            }
            if input_value > MAX_VALUE_MSAT / 1000 {
                return Err(());
            }
        }
        let mut spend_tx = Transaction {
            version: 2,
            lock_time: 0,
            input,
            output: outputs,
        };
        transaction_utils::maybe_add_change_output(
            &mut spend_tx,
            input_value,
            witness_weight,
            feerate_sat_per_1000_weight,
            change_destination_script,
        )?;

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
                    let derivation_idx = if output.script_pubkey == self.destination_script {
                        1
                    } else {
                        2
                    };
                    let secret = {
                        // Note that when we aren't serializing the key, network doesn't matter
                        match ExtendedPrivKey::new_master(Network::Testnet, &self.seed) {
                            Ok(master_key) => {
                                match master_key.ckd_priv(
                                    &secp_ctx,
                                    ChildNumber::from_hardened_idx(derivation_idx)
                                        .expect("key space exhausted"),
                                ) {
                                    Ok(key) => key,
                                    Err(_) => panic!("Your RNG is busted"),
                                }
                            }
                            Err(_) => panic!("Your rng is busted"),
                        }
                    };
                    let pubkey = ExtendedPubKey::from_private(&secp_ctx, &secret).public_key;
                    if derivation_idx == 2 {
                        assert_eq!(pubkey.key, self.shutdown_pubkey);
                    }
                    let witness_script =
                        bitcoin::Address::p2pkh(&pubkey, Network::Testnet).script_pubkey();
                    let sighash = ::bitcoin::secp256k1::Message::from_slice(
                        &bip143::SigHashCache::new(&spend_tx).signature_hash(
                            input_idx,
                            &witness_script,
                            output.value,
                            SigHashType::All,
                        )[..],
                    )
                    .unwrap();
                    let sig = secp_ctx.sign(&sighash, &secret.private_key.key);
                    spend_tx.input[input_idx]
                        .witness
                        .push(sig.serialize_der().to_vec());
                    spend_tx.input[input_idx].witness[0].push(SigHashType::All as u8);
                    spend_tx.input[input_idx]
                        .witness
                        .push(pubkey.key.serialize().to_vec());
                }
            }
            input_idx += 1;
        }
        Ok(spend_tx)
    }
}

impl KeysInterface for MyKeysManager {
    type Signer = InMemorySigner;

    fn get_node_secret(&self) -> SecretKey {
        self.node_secret.clone()
    }

    fn get_destination_script(&self) -> Script {
        self.destination_script.clone()
    }

    fn get_shutdown_pubkey(&self) -> PublicKey {
        self.shutdown_pubkey.clone()
    }

    // BEGIN NOT TESTED
    fn get_channel_signer(&self, _inbound: bool, _channel_value_sat: u64) -> InMemorySigner {
        unimplemented!();
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        let mut sha = self.rand_bytes_unique_start.clone();

        let child_ix = self.rand_bytes_child_index.fetch_add(1, Ordering::AcqRel);
        let child_privkey = self
            .rand_bytes_master_key
            .ckd_priv(
                &self.secp_ctx,
                ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted"),
            )
            .expect("Your RNG is busted");
        sha.input(&child_privkey.private_key.key[..]);

        sha.input(b"Unique Secure Random Bytes Salt");
        Sha256::from_engine(sha).into_inner()
    }

    fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        unimplemented!()
    }

    fn sign_invoice(&self, _invoice_preimage: Vec<u8>) -> Result<RecoverableSignature, ()> {
        unimplemented!()
    }
    // END NOT TESTED
}

#[cfg(test)]
mod tests {
    use crate::util::INITIAL_COMMITMENT_NUMBER;

    use super::*;
    use lightning::chain::keysinterface::BaseSign;

    use test_env_log::test;
    use crate::util::test_utils::hex_encode;

    #[test]
    fn keys_test_native() -> Result<(), ()> {
        let manager = MyKeysManager::new(
            KeyDerivationStyle::Native,
            &[0u8; 32],
            Network::Testnet,
            0,
            0,
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
        let channel_id = ChannelId([0u8; 32]);
        let mut channel_nonce = [0u8; 32];
        channel_nonce[0] = 1u8;
        manager.get_channel_keys_with_id(channel_id, &channel_nonce, 0)
    }

    #[test]
    fn keys_test_lnd() -> Result<(), ()> {
        let manager =
            MyKeysManager::new(KeyDerivationStyle::Lnd, &[0u8; 32], Network::Testnet, 0, 0);
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
            0,
            0,
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
            &keys.release_commitment_secret(INITIAL_COMMITMENT_NUMBER - 3),
        );
        assert_eq!(
            hex_encode(&per_commit_point.serialize().to_vec()),
            "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
        );
        Ok(())
    }
}
