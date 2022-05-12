use crate::channel::ChannelId;
use crate::util::crypto_utils::{hkdf_sha256, hkdf_sha256_keys};
use alloc::boxed::Box;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{secp256k1, secp256k1::Secp256k1, Network};
use core::convert::{TryFrom, TryInto};

/// Derive keys for nodes and channels
pub trait KeyDerive {
    /// Derive master key
    fn master_key(&self, seed: &[u8]) -> ExtendedPrivKey;
    /// Derive node key
    fn node_keys(
        &self,
        seed: &[u8],
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (PublicKey, SecretKey);
    /// Derive LDK keys_id from the channel_id and a seed base
    /// The seed_base
    fn keys_id(&self, channel_id: ChannelId, channel_seed_base: &[u8; 32]) -> [u8; 32] {
        hkdf_sha256(channel_seed_base, "per-peer seed".as_bytes(), channel_id.as_slice())
    }

    /// A base for channel keys
    fn channels_seed(&self, seed: &[u8]) -> [u8; 32] {
        hkdf_sha256(seed, "peer seed".as_bytes(), &[])
    }

    /// Derive channel keys.
    /// funding_key, revocation_base_key, htlc_base_key, payment_key, delayed_payment_base_key, commitment_seed
    fn channel_keys(
        &self,
        keys_id: &[u8; 32],
        basepoint_index: u32,
        master_key: &ExtendedPrivKey,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]);
}

/// CLN compatible derivation
pub struct NativeKeyDerive {
    network: Network,
}

impl KeyDerive for NativeKeyDerive {
    fn master_key(&self, seed: &[u8]) -> ExtendedPrivKey {
        let master_seed = hkdf_sha256(seed, "bip32 seed".as_bytes(), &[]);
        ExtendedPrivKey::new_master(self.network.clone(), &master_seed).expect("Your RNG is busted")
    }

    fn node_keys(
        &self,
        seed: &[u8],
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (PublicKey, SecretKey) {
        let node_private_bytes = hkdf_sha256(seed, "nodeid".as_bytes(), &[]);
        let node_secret_key = SecretKey::from_slice(&node_private_bytes).unwrap();
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret_key);
        (node_id, node_secret_key)
    }

    fn channel_keys(
        &self,
        keys_id: &[u8; 32],
        _basepoint_index: u32,
        _master_key: &ExtendedPrivKey,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let hkdf_info = "c-lightning";
        let keys_buf = hkdf_sha256_keys(keys_id, hkdf_info.as_bytes(), &[]);
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
        (
            funding_key,
            revocation_base_key,
            htlc_base_key,
            payment_key,
            delayed_payment_base_key,
            commitment_seed,
        )
    }
}

/// LND compatible derivation
pub struct LndKeyDerive {
    network: Network,
}

impl KeyDerive for LndKeyDerive {
    fn master_key(&self, seed: &[u8]) -> ExtendedPrivKey {
        ExtendedPrivKey::new_master(self.network, seed).expect("Your RNG is busted")
    }

    fn node_keys(
        &self,
        seed: &[u8],
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (PublicKey, SecretKey) {
        let key_family_node_key = 6;
        let index = 0;
        let master = self.master_key(seed);
        derive_key_lnd(secp_ctx, self.network, &master, key_family_node_key, index)
    }

    fn channel_keys(
        &self,
        keys_id: &[u8; 32],
        basepoint_index: u32,
        master_key: &ExtendedPrivKey,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let hkdf_info = "c-lightning";
        let keys_buf = hkdf_sha256_keys(keys_id, hkdf_info.as_bytes(), &[]);
        let mut ndx = 0;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        ndx += 32;
        let commitment_seed = keys_buf[ndx..ndx + 32].try_into().unwrap();

        let secp_ctx = Secp256k1::new();

        // These need to match the constants defined in lnd/keychain/derivation.go
        // KeyFamilyMultiSig KeyFamily = 0
        // KeyFamilyRevocationBase = 1
        // KeyFamilyHtlcBase KeyFamily = 2
        // KeyFamilyPaymentBase KeyFamily = 3
        // KeyFamilyDelayBase KeyFamily = 4
        let (_, funding_key) =
            derive_key_lnd(&secp_ctx, self.network, master_key, 0, basepoint_index);
        let (_, revocation_base_key) =
            derive_key_lnd(&secp_ctx, self.network, master_key, 1, basepoint_index);
        let (_, htlc_base_key) =
            derive_key_lnd(&secp_ctx, self.network, master_key, 2, basepoint_index);
        let (_, payment_key) =
            derive_key_lnd(&secp_ctx, self.network, master_key, 3, basepoint_index);
        let (_, delayed_payment_base_key) =
            derive_key_lnd(&secp_ctx, self.network, master_key, 4, basepoint_index);
        (
            funding_key,
            revocation_base_key,
            htlc_base_key,
            payment_key,
            delayed_payment_base_key,
            commitment_seed,
        )
    }
}

/// Construct a key deriver based on the style
pub fn key_derive(style: KeyDerivationStyle, network: Network) -> Box<dyn KeyDerive> {
    match style {
        KeyDerivationStyle::Native => Box::new(NativeKeyDerive { network }),
        KeyDerivationStyle::Lnd => Box::new(LndKeyDerive { network }),
    }
}

/// The key derivation style
#[derive(Clone, Copy, Debug)]
pub enum KeyDerivationStyle {
    /// Our preferred style, C-lightning compatible
    Native = 1,
    /// The LND style
    Lnd = 2,
}

impl TryFrom<u8> for KeyDerivationStyle {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use KeyDerivationStyle::{Lnd, Native};
        match v {
            x if x == Native as u8 => Ok(Native),
            x if x == Lnd as u8 => Ok(Lnd),
            _ => Err(()),
        }
    }
}

impl KeyDerivationStyle {
    pub(crate) fn get_key_path_len(&self) -> usize {
        match self {
            // c-lightning uses a single BIP32 chain for both external
            // and internal (change) addresses.
            KeyDerivationStyle::Native => 1,
            // lnd uses two BIP32 branches, one for external and one
            // for internal (change) addresses.
            KeyDerivationStyle::Lnd => 2,
        }
    }

    pub(crate) fn get_account_extended_key(
        &self,
        secp_ctx: &Secp256k1<secp256k1::All>,
        network: Network,
        seed: &[u8],
    ) -> ExtendedPrivKey {
        match self {
            KeyDerivationStyle::Native => get_account_extended_key_native(secp_ctx, network, seed),
            KeyDerivationStyle::Lnd => get_account_extended_key_lnd(secp_ctx, network, seed),
        }
    }
}

// This function will panic if the ExtendedPrivKey::new_master fails.
// Only use where failure is an option (ie, startup).
pub(crate) fn get_account_extended_key_native(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    node_seed: &[u8],
) -> ExtendedPrivKey {
    let bip32_seed = hkdf_sha256(node_seed, "bip32 seed".as_bytes(), &[]);
    let master = ExtendedPrivKey::new_master(network.clone(), &bip32_seed).unwrap();
    master
        .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
}

// This function will panic if the ExtendedPrivKey::new_master fails.
// Only use where failure is an option (ie, startup).
pub(crate) fn get_account_extended_key_lnd(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    node_seed: &[u8],
) -> ExtendedPrivKey {
    // Must match btcsuite/btcwallet/waddrmgr/scoped_manager.go
    let master = ExtendedPrivKey::new_master(network.clone(), node_seed).unwrap();
    let purpose = 84;
    let cointype = 0;
    let account = 0;
    master
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(purpose).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(cointype).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(account).unwrap())
        .unwrap()
}

pub(crate) fn derive_key_lnd(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    master: &ExtendedPrivKey,
    key_family: u32,
    index: u32,
) -> (PublicKey, SecretKey) {
    let bip43purpose = 1017;
    #[rustfmt::skip]
    let coin_type = match network {
        bitcoin::Network::Bitcoin => 0,
        bitcoin::Network::Testnet => 1,
        bitcoin::Network::Regtest => 1,
        bitcoin::Network::Signet => 1,
    };
    let branch = 0;
    let node_ext_prv = master
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(bip43purpose).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(coin_type).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_hardened_idx(key_family).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(branch).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(index).unwrap())
        .unwrap();
    let node_ext_pub = &ExtendedPubKey::from_private(&secp_ctx, &node_ext_prv);
    (node_ext_pub.public_key.key, node_ext_prv.private_key.key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::Network::Testnet;

    #[test]
    fn node_keys_native_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::new();
        let derive = key_derive(KeyDerivationStyle::Native, Testnet);
        let (node_id, _) = derive.node_keys(&[0u8; 32], &secp_ctx);
        let node_id_bytes = node_id.serialize().to_vec();
        assert_eq!(
            node_id_bytes.to_hex(),
            "02058e8b6c2ad363ec59aa136429256d745164c2bdc87f98f0a68690ec2c5c9b0b"
        );
        Ok(())
    }

    #[test]
    fn node_keys_lnd_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::new();
        let derive = key_derive(KeyDerivationStyle::Lnd, Testnet);
        let (node_id, _) = derive.node_keys(&[0u8; 32], &secp_ctx);
        let node_id_bytes = node_id.serialize().to_vec();
        assert_eq!(
            node_id_bytes.to_hex(),
            "0287a5eab0a005ea7f08a876257b98868b1e5b5a9167385904396743faa61a4745"
        );
        Ok(())
    }

    #[test]
    fn get_account_extended_key_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::new();
        let key = get_account_extended_key_native(&secp_ctx, Network::Testnet, &[0u8; 32]);
        assert_eq!(format!("{}", key), "tprv8ejySXSgpWvEBguEGNFYNcHz29W7QxEodgnwbfLzBCccBnxGAq4vBkgqUYPGR5EnCbLvJE7YQsod6qpid85JhvAfizVpqPg3WsWB6UG3fEL");
        Ok(())
    }

    #[test]
    fn channels_seed_test() -> Result<(), ()> {
        let derive = key_derive(KeyDerivationStyle::Native, Testnet);

        let seed = derive.channels_seed(&[0u8; 32]);
        assert_eq!(
            seed.to_hex(),
            "ab7f29780659755f14afb82342dc19db7d817ace8c312e759a244648dfc25e53"
        );
        Ok(())
    }
}
