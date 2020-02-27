use std::convert::TryInto;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::{Network, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::hash160::Hash as Hash160;
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::sha256::HashEngine as Sha256State;
use lightning::chain::keysinterface::{InMemoryChannelKeys, KeysInterface};
use lightning::util::logger::Logger;
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};

use crate::util::byte_utils;
use crate::util::crypto_utils::{bip32_key, build_commitment_secret, channels_seed, hkdf_sha256, hkdf_sha256_keys, node_keys};

pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

pub struct MyKeysManager {
    secp_ctx: Secp256k1<secp256k1::SignOnly>,
    node_secret: SecretKey,
    channel_seed_base: [u8; 32],
    bip32_key: ExtendedPrivKey,
    destination_script: Script,
    shutdown_pubkey: PublicKey,
    #[allow(dead_code)]
    channel_master_key: ExtendedPrivKey,
    #[allow(dead_code)]
    channel_child_index: AtomicUsize,
    session_master_key: ExtendedPrivKey,
    session_child_index: AtomicUsize,
    channel_id_master_key: ExtendedPrivKey,
    channel_id_child_index: AtomicUsize,

    unique_start: Sha256State,
    #[allow(dead_code)]
    logger: Arc<Logger>,
}

impl MyKeysManager {
    pub fn new(
        seed: &[u8; 32],
        network: Network,
        logger: Arc<Logger>,
        starting_time_secs: u64,
        starting_time_nanos: u32,
    ) -> MyKeysManager {
        let secp_ctx = Secp256k1::signing_only();
        match ExtendedPrivKey::new_master(network.clone(), seed) {
            Ok(master_key) => {
                let (_, node_secret) = node_keys(&secp_ctx, seed);
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
                    Err(_) => panic!("Your RNG is busted"),
                };
                let shutdown_pubkey = match master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(2).unwrap())
                {
                    Ok(shutdown_key) => {
                        ExtendedPubKey::from_private(&secp_ctx, &shutdown_key)
                            .public_key
                            .key
                    }
                    Err(_) => panic!("Your RNG is busted"),
                };
                let channel_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(3).unwrap())
                    .expect("Your RNG is busted");
                let session_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(4).unwrap())
                    .expect("Your RNG is busted");
                let channel_id_master_key = master_key
                    .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(5).unwrap())
                    .expect("Your RNG is busted");

                let mut unique_start = Sha256::engine();
                unique_start.input(&byte_utils::be64_to_array(starting_time_secs));
                unique_start.input(&byte_utils::be32_to_array(starting_time_nanos));
                unique_start.input(seed);

                let channel_seed_base = channels_seed(seed);
                let bip32_key = bip32_key(&secp_ctx, network, seed);

                MyKeysManager {
                    secp_ctx,
                    node_secret,
                    channel_seed_base,
                    bip32_key,
                    destination_script,
                    shutdown_pubkey,
                    channel_master_key,
                    channel_child_index: AtomicUsize::new(0),
                    session_master_key,
                    session_child_index: AtomicUsize::new(0),
                    channel_id_master_key,
                    channel_id_child_index: AtomicUsize::new(0),

                    unique_start,
                    logger,
                }
            }
            Err(_) => panic!("Your rng is busted"),
        }
    }

    pub fn get_bip32_key(&self) -> &ExtendedPrivKey {
        &self.bip32_key
    }

    pub fn per_commitment_secret(commitment_seed: &[u8; 32], idx: u64) -> SecretKey {
        build_commitment_secret(commitment_seed, INITIAL_COMMITMENT_NUMBER - idx)
    }

    pub fn per_commitment_point(secp_ctx: &Secp256k1<SignOnly>, commitment_seed: &[u8; 32], idx: u64) -> PublicKey {
        PublicKey::from_secret_key(secp_ctx, &MyKeysManager::per_commitment_secret(commitment_seed, idx))
    }

    pub(crate) fn get_channel_keys_with_nonce(&self, channel_nonce: &[u8],
                                              channel_value_satoshis: u64,
                                              hkdf_info: &str) -> InMemoryChannelKeys {
        let channel_seed = hkdf_sha256(
            &self.channel_seed_base,
            "per-peer seed".as_bytes(),
            channel_nonce,
        );

        let keys_buf =
            hkdf_sha256_keys(&channel_seed, hkdf_info.as_bytes(), &[]);
        let mut ndx = 0;
        let funding_key =
            SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let revocation_base_key =
            SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let htlc_base_key =
            SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let payment_base_key =
            SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let delayed_payment_base_key =
            SecretKey::from_slice(&keys_buf[ndx..ndx + 32]).unwrap();
        ndx += 32;
        let commitment_seed = keys_buf[ndx..ndx + 32].try_into().unwrap();
        let secp_ctx = Secp256k1::signing_only();

        InMemoryChannelKeys::new(
            &secp_ctx,
            funding_key,
            revocation_base_key,
            payment_base_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_satoshis,
        )
    }
}

impl KeysInterface for MyKeysManager {
    type ChanKeySigner = InMemoryChannelKeys;

    fn get_node_secret(&self) -> SecretKey {
        self.node_secret.clone()
    }

    fn get_destination_script(&self) -> Script {
        self.destination_script.clone()
    }

    fn get_shutdown_pubkey(&self) -> PublicKey {
        self.shutdown_pubkey.clone()
    }

    fn get_channel_keys(&self, channel_id: [u8; 32],
                        _inbound: bool, channel_value_satoshis: u64) -> InMemoryChannelKeys {
        self.get_channel_keys_with_nonce(&channel_id, channel_value_satoshis, "rust-lightning-signer")
    }

    fn get_onion_rand(&self) -> (SecretKey, [u8; 32]) {
        let mut sha = self.unique_start.clone();

        let child_ix = self.session_child_index.fetch_add(1, Ordering::AcqRel);
        let child_privkey = self
            .session_master_key
            .ckd_priv(
                &self.secp_ctx,
                ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted"),
            )
            .expect("Your RNG is busted");
        sha.input(&child_privkey.private_key.key[..]);

        let mut rng_seed = sha.clone();
        // Not exactly the most ideal construction, but the second value will get fed into
        // ChaCha so it is another step harder to break.
        rng_seed.input(b"RNG Seed Salt");
        sha.input(b"Session Key Salt");
        (
            SecretKey::from_slice(&Sha256::from_engine(sha).into_inner())
                .expect("Your RNG is busted"),
            Sha256::from_engine(rng_seed).into_inner(),
        )
    }

    fn get_channel_id(&self) -> [u8; 32] {
        let mut sha = self.unique_start.clone();

        let child_ix = self.channel_id_child_index.fetch_add(1, Ordering::AcqRel);
        let child_privkey = self
            .channel_id_master_key
            .ckd_priv(
                &self.secp_ctx,
                ChildNumber::from_hardened_idx(child_ix as u32).expect("key space exhausted"),
            )
            .expect("Your RNG is busted");
        sha.input(&child_privkey.private_key.key[..]);

        (Sha256::from_engine(sha).into_inner())
    }
}

#[cfg(test)]
mod tests {
    use lightning::chain::keysinterface::ChannelKeys;

    use crate::util::test_utils::TestLogger;

    use super::*;

    fn logger() -> Arc<Logger> {
        Arc::new(TestLogger::with_id("server".to_owned()))
    }

    #[test]
    fn keys_test() -> Result<(), ()> {
        let manager = MyKeysManager::new(&[0u8; 32], Network::Testnet, logger(), 0, 0);
        assert!(
            hex::encode(manager.channel_seed_base)
                == "ab7f29780659755f14afb82342dc19db7d817ace8c312e759a244648dfc25e53"
        );
        let mut channel_id = [0u8; 32];
        channel_id[0] = 1u8;
        let keys = manager.get_channel_keys_with_nonce(&channel_id, 0, "c-lightning");
        assert!(
            hex::encode(&keys.funding_key()[..])
                == "bf36bee09cc5dd64c8f19e10b258efb1f606722e9ff6fe3267b63e2dbe33dcfc"
        );
        assert!(
            hex::encode(&keys.revocation_base_key()[..])
                == "203612ab8275bab7916b8bf895d45b9dbb639b43d904b34d6449214e9855d345"
        );
        assert!(
            hex::encode(&keys.htlc_base_key()[..])
                == "517c009452b4baa9df42d6c8cddc966e017d49606524ce7728681b593a5659c1"
        );
        assert!(
            hex::encode(&keys.payment_base_key()[..])
                == "54ce3b75dcc2731604f3db55ecd1520d797a154cc757d6d98c3ffd1e90a9a25a"
        );
        assert!(
            hex::encode(&keys.delayed_payment_base_key()[..])
                == "9f5c122778b12ad35f555437d88b76b726ae4e472897af33e22616fb0d0b0a44"
        );
        Ok(())
    }

    #[test]
    fn per_commit_test() -> Result<(), ()> {
        let manager = MyKeysManager::new(&[0u8; 32], Network::Testnet, logger(), 0, 0);
        let mut channel_id = [0u8; 32];
        channel_id[0] = 1u8;
        let keys = manager.get_channel_keys_with_nonce(&channel_id, 0, "c-lightning");
        assert!(
            hex::encode(&keys.commitment_seed())
                == "9fc48da6bc75058283b860d5989ffb802b6395ca28c4c3bb9d1da02df6bb0cb3"
        );

        let secp_ctx = Secp256k1::signing_only();
        let per_commit_point = MyKeysManager::per_commitment_point(&secp_ctx, keys.commitment_seed(), 3);
        assert!(
            hex::encode(per_commit_point.serialize().to_vec())
                == "03b5497ca60ff3165908c521ea145e742c25dedd14f5602f3f502d1296c39618a5"
        );
        Ok(())
    }
}
