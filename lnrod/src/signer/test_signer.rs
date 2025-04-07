use std::fs;
use std::fs::File;
use std::io::Write;

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{Address, Network};
use lightning::sign::InMemorySigner;
use lightning_signer::{bitcoin, lightning};

use crate::signer::keys::KeysManager;
use crate::{byte_utils, DynSigner, SpendableKeysInterface};
use rand::{thread_rng, RngCore};
use std::time::SystemTime;

pub struct InMemorySignerFactory {
    seed: [u8; 32],
    secp_ctx: Secp256k1<All>,
}

impl InMemorySignerFactory {
    pub fn derive_channel_keys(
        &self,
        channel_master_key: &Xpriv,
        channel_value_satoshis: u64,
        params: &[u8; 32],
    ) -> InMemorySigner {
        let chan_id = byte_utils::slice_to_be64(&params[0..8]);
        assert!(chan_id <= std::u32::MAX as u64); // Otherwise the params field wasn't created by us
        let mut unique_start = Sha256::engine();
        unique_start.input(params);
        unique_start.input(&self.seed);

        // We only seriously intend to rely on the channel_master_key for true secure
        // entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
        // starting_time provided in the constructor) to be unique.
        let child_privkey = channel_master_key
            .derive_priv(
                &self.secp_ctx,
                &ChildNumber::from_hardened_idx(chan_id as u32).expect("key space exhausted"),
            )
            .expect("Your RNG is busted");
        unique_start.input(child_privkey.private_key.as_ref());

        let seed = Sha256::from_engine(unique_start).to_byte_array();

        let commitment_seed = {
            let mut sha = Sha256::engine();
            sha.input(&seed);
            sha.input(&b"commitment seed"[..]);
            Sha256::from_engine(sha).to_byte_array()
        };
        macro_rules! key_step {
            ($info: expr, $prev_key: expr) => {{
                let mut sha = Sha256::engine();
                sha.input(&seed);
                sha.input(&$prev_key[..]);
                sha.input(&$info[..]);
                SecretKey::from_slice(&Sha256::from_engine(sha).to_byte_array())
                    .expect("SHA-256 is busted")
            }};
        }
        let funding_key = key_step!(b"funding key", commitment_seed);
        let revocation_base_key = key_step!(b"revocation base key", funding_key);
        let payment_key = key_step!(b"payment key", revocation_base_key);
        let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
        let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);
        let unique_start = key_step!(b"unique start", commitment_seed).secret_bytes();

        let signer = InMemorySigner::new(
            &self.secp_ctx,
            funding_key,
            revocation_base_key,
            payment_key,
            delayed_payment_base_key,
            htlc_base_key,
            commitment_seed,
            channel_value_satoshis,
            params.clone(),
            unique_start,
        );

        signer
    }

    pub fn new(seed: &[u8; 32]) -> Self {
        InMemorySignerFactory { seed: seed.clone(), secp_ctx: Secp256k1::new() }
    }
}

pub(crate) fn make_signer(
    _network: Network,
    ldk_data_dir: String,
    sweep_address: Address,
) -> Box<dyn SpendableKeysInterface<EcdsaSigner = DynSigner>> {
    // The key seed that we use to derive the node privkey (that corresponds to the node pubkey) and
    // other secret key material.
    let cur = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let keys_seed_path = format!("{}/keys_seed", ldk_data_dir.clone());
    let seed = if let Ok(seed) = fs::read(keys_seed_path.clone()) {
        assert_eq!(seed.len(), 32);
        let mut key = [0; 32];
        key.copy_from_slice(&seed);
        key
    } else {
        let mut key = [0; 32];
        thread_rng().fill_bytes(&mut key);
        let mut f = File::create(keys_seed_path).unwrap();
        f.write_all(&key).expect("Failed to write node keys seed to disk");
        f.sync_all().expect("Failed to sync node keys seed to disk");
        key
    };

    let manager: KeysManager =
        KeysManager::new(&seed, cur.as_secs(), cur.subsec_nanos(), sweep_address);
    Box::new(manager)
}
