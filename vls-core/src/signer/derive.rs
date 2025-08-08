use alloc::boxed::Box;

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{secp256k1, secp256k1::Secp256k1, Network};

use crate::channel::ChannelId;
use crate::util::byte_utils;
use crate::util::crypto_utils::{hkdf_sha256, hkdf_sha256_keys};

/// Derive keys for nodes and channels
pub trait KeyDerive {
    /// Derive master key
    fn master_key(&self, seed: &[u8]) -> Xpriv;
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
        seed: &[u8],
        keys_id: &[u8; 32],
        basepoint_index: u32,
        master_key: &Xpriv,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]);
}

/// CLN compatible derivation
#[derive(Clone, Debug)]
pub struct NativeKeyDerive {
    network: Network,
}

impl NativeKeyDerive {
    /// network value.
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

impl KeyDerive for NativeKeyDerive {
    fn master_key(&self, seed: &[u8]) -> Xpriv {
        let master_seed = hkdf_sha256(seed, "bip32 seed".as_bytes(), &[]);
        Xpriv::new_master(self.network, &master_seed).expect("Your RNG is busted")
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
        _seed: &[u8],
        keys_id: &[u8; 32],
        _basepoint_index: u32,
        _master_key: &Xpriv,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let hkdf_info = "c-lightning";
        let keys_buf: [u8; 192] = hkdf_sha256_keys(keys_id, hkdf_info.as_bytes(), &[]);

        // unwraps below are safe because the keys_buf is 192 bytes long
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

/// LDK compatible derivation
pub struct LdkKeyDerive {
    network: Network,
}

impl KeyDerive for LdkKeyDerive {
    fn master_key(&self, seed: &[u8]) -> Xpriv {
        Xpriv::new_master(self.network, &seed).expect("Your RNG is busted")
    }

    fn node_keys(
        &self,
        seed: &[u8],
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (PublicKey, SecretKey) {
        let master = self.master_key(seed);
        let node_secret_key = master
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(0).unwrap()])
            .expect("Your RNG is busted")
            .private_key;
        let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret_key);
        (node_id, node_secret_key)
    }

    fn channel_keys(
        &self,
        seed: &[u8],
        keys_id: &[u8; 32],
        _basepoint_index: u32,
        master_key: &Xpriv,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let chan_id = byte_utils::slice_to_be64(&keys_id[0..8]);
        assert!(chan_id <= core::u32::MAX as u64); // Otherwise the params field wasn't created by us
        let mut unique_start = Sha256::engine();
        unique_start.input(keys_id);
        unique_start.input(seed);

        let channel_master_key = master_key
            .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(3).unwrap()])
            .expect("Your RNG is busted");

        // We only seriously intend to rely on the channel_master_key for true secure
        // entropy, everything else just ensures uniqueness. We rely on the unique_start (ie
        // starting_time provided in the constructor) to be unique.
        let child_privkey = channel_master_key
            .derive_priv(
                secp_ctx,
                &[ChildNumber::from_hardened_idx(chan_id as u32).expect("key space exhausted")],
            )
            .expect("Your RNG is busted");
        unique_start.input(child_privkey.private_key.as_ref());

        let channel_seed = Sha256::from_engine(unique_start).to_byte_array();

        let commitment_seed = {
            let mut sha = Sha256::engine();
            sha.input(&channel_seed);
            sha.input(&b"commitment seed"[..]);
            Sha256::from_engine(sha).to_byte_array()
        };
        macro_rules! key_step {
            ($info: expr, $prev_key: expr) => {{
                let mut sha = Sha256::engine();
                sha.input(&channel_seed);
                sha.input(&$prev_key[..]);
                sha.input(&$info[..]);
                SecretKey::from_slice(Sha256::from_engine(sha).as_ref()).unwrap()
            }};
        }
        let funding_key = key_step!(b"funding key", commitment_seed);
        let revocation_base_key = key_step!(b"revocation base key", funding_key);
        let payment_key = key_step!(b"payment key", revocation_base_key);
        let delayed_payment_base_key = key_step!(b"delayed payment base key", payment_key);
        let htlc_base_key = key_step!(b"HTLC base key", delayed_payment_base_key);
        (
            funding_key,
            revocation_base_key,
            htlc_base_key,
            payment_key,
            delayed_payment_base_key,
            commitment_seed,
        )
    }

    fn keys_id(&self, channel_id: ChannelId, channel_seed_base: &[u8; 32]) -> [u8; 32] {
        let mut res =
            hkdf_sha256(channel_seed_base, "per-peer seed".as_bytes(), channel_id.as_slice());
        // The stock KeysManager requires the first four bytes of the keys ID to be zero,
        // and the byte after that to be 127 or less.  The big-endian interpretation is used as
        // a derivation index, and it must be less than 2^31.
        res[0] = 0;
        res[1] = 0;
        res[2] = 0;
        res[3] = 0;
        res[4] &= 0x7f;
        res
    }
}

/// LND compatible derivation
pub struct LndKeyDerive {
    network: Network,
}

impl KeyDerive for LndKeyDerive {
    fn master_key(&self, seed: &[u8]) -> Xpriv {
        Xpriv::new_master(self.network, seed).expect("Your RNG is busted")
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
        _seed: &[u8],
        keys_id: &[u8; 32],
        basepoint_index: u32,
        master_key: &Xpriv,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> (SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let hkdf_info = "c-lightning";
        let keys_buf: [u8; 192] = hkdf_sha256_keys(keys_id, hkdf_info.as_bytes(), &[]);

        // unwraps below are safe because the keys_buf is 192 bytes long
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
        KeyDerivationStyle::Ldk => Box::new(LdkKeyDerive { network }),
        KeyDerivationStyle::Lnd => Box::new(LndKeyDerive { network }),
    }
}

/// The key derivation style
///
/// NOTE - This enum should be kept in sync with the grpc definition in `remotesigner.proto`
/// and `convert_node_config` in `driver.rs`
#[derive(Clone, Copy, Debug)]
pub enum KeyDerivationStyle {
    /// Our preferred style, C-lightning compatible
    Native = 1,
    /// LDK compatible
    Ldk = 2,
    /// The LND style
    Lnd = 3,
}

impl TryFrom<u8> for KeyDerivationStyle {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use KeyDerivationStyle::{Ldk, Lnd, Native};
        match v {
            x if x == Native as u8 => Ok(Native),
            x if x == Ldk as u8 => Ok(Ldk),
            x if x == Lnd as u8 => Ok(Lnd),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for KeyDerivationStyle {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.pad(match *self {
            KeyDerivationStyle::Native => "native",
            KeyDerivationStyle::Ldk => "ldk",
            KeyDerivationStyle::Lnd => "lnd",
        })
    }
}

impl core::str::FromStr for KeyDerivationStyle {
    type Err = ();
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(KeyDerivationStyle::Native),
            "ldk" => Ok(KeyDerivationStyle::Ldk),
            "lnd" => Ok(KeyDerivationStyle::Lnd),
            _ => Err(()),
        }
    }
}

impl KeyDerivationStyle {
    pub(crate) fn get_key_path_len(&self) -> Option<usize> {
        match self {
            // CLN uses a single BIP32 chain for both external
            // and internal (change) addresses.
            KeyDerivationStyle::Native => Some(1),
            // LDK can use any BIP32 chain for both external
            // and internal addresses based on the implementation.
            KeyDerivationStyle::Ldk => None,
            // lnd uses two BIP32 branches, one for external and one
            // for internal (change) addresses.
            KeyDerivationStyle::Lnd => Some(2),
        }
    }

    pub(crate) fn get_account_extended_key(
        &self,
        secp_ctx: &Secp256k1<secp256k1::All>,
        network: Network,
        seed: &[u8],
    ) -> Xpriv {
        match self {
            KeyDerivationStyle::Native => get_account_extended_key_native(secp_ctx, network, seed),
            KeyDerivationStyle::Ldk => get_account_extended_key_native(secp_ctx, network, seed),
            KeyDerivationStyle::Lnd => get_account_extended_key_lnd(secp_ctx, network, seed),
        }
    }
}

// This function will panic if the Xpriv::new_master fails.
// Only use where failure is an option (ie, startup).
pub(crate) fn get_account_extended_key_native(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    node_seed: &[u8],
) -> Xpriv {
    let bip32_seed = hkdf_sha256(node_seed, "bip32 seed".as_bytes(), &[]);
    let master = Xpriv::new_master(network, &bip32_seed).unwrap();
    master
        .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(0).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(0).unwrap()])
        .unwrap()
}

// This function will panic if the Xpriv::new_master fails.
// Only use where failure is an option (ie, startup).
pub(crate) fn get_account_extended_key_lnd(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    node_seed: &[u8],
) -> Xpriv {
    // Must match btcsuite/btcwallet/waddrmgr/scoped_manager.go
    let master = Xpriv::new_master(network, node_seed).unwrap();
    let purpose = 84;
    let cointype = 0;
    let account = 0;
    master
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(purpose).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(cointype).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(account).unwrap()])
        .unwrap()
}

pub(crate) fn derive_key_lnd(
    secp_ctx: &Secp256k1<secp256k1::All>,
    network: Network,
    master: &Xpriv,
    key_family: u32,
    index: u32,
) -> (PublicKey, SecretKey) {
    let bip43purpose = 1017;
    #[rustfmt::skip]
    let coin_type = match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Regtest => 1,
        Network::Signet => 1,
        _ => unreachable!(),
    };
    let branch = 0;
    let node_ext_prv = master
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(bip43purpose).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(coin_type).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_hardened_idx(key_family).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(branch).unwrap()])
        .unwrap()
        .derive_priv(&secp_ctx, &[ChildNumber::from_normal_idx(index).unwrap()])
        .unwrap();
    let node_ext_pub = &Xpub::from_priv(&secp_ctx, &node_ext_prv);
    (node_ext_pub.public_key, node_ext_prv.private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network::Testnet;
    use hex;

    struct ExpectedValues {
        master_key: &'static str,
        node_secret_key: &'static str,
        node_id: &'static str,
        channels_seed: &'static str,
        keys_id: &'static str,
        funding_key: &'static str,
        commitment_seed: &'static str,
        account_extended_key: &'static str,
    }

    #[test]
    fn test_key_path_len() {
        assert_eq!(Some(1), KeyDerivationStyle::Native.get_key_path_len());
        assert_eq!(Some(2), KeyDerivationStyle::Lnd.get_key_path_len());
        assert_eq!(None, KeyDerivationStyle::Ldk.get_key_path_len());
    }

    #[test]
    fn test_derivation() {
        let tests = [
            (
                KeyDerivationStyle::Native,
                ExpectedValues {
                    master_key: "tprv8ZgxMBicQKsPfBjs724zXetsAfo8GqUTLKFgWsb92txrGoW9De1DTABH7htVkp1jS9ZhNws7do3UNPZreZru8MNXvWDrTxoecc2wnTYrb4S",
                    node_secret_key: "aae7ec5943df6bf7f26773729b3ac9a12ee428bbc4e6e2fbd27f3cf78cfe6d86",
                    node_id: "026f61d7ee82f937f9697f4f3e44bfaaa25849cc4f526b3a57326130eba6346002",
                    channels_seed: "7e273adccc072169f5a1cb1aee23a2d6986b6cbbeff4f0995d2762ac7c0b2511",
                    keys_id: "36814b08b8410cf33c02217de2c24f800b46642355d5c4be3a78c7d5d924af38",
                    funding_key: "b70812d9d05617ac829ffa666bd0a7ddbbd5303b562fa2ead2a842440333eff4",
                    commitment_seed: "fd8c46daa8eda9211b6cf4461003c8cc6aaa98024b438779f08254e4e67ae60c",
                    account_extended_key: "tprv8eoZddcAfpUQZNYYcJEVkpyfpss9vmBPvFMQ3CZrAxhoKpc6cM36XQJZ8jRbSuH7bouYBbKL6iQ5F4W3H2sh6NobCi4A9CJ3LJEUfDvmKib",
                },
            ),
            (
                KeyDerivationStyle::Ldk,
                ExpectedValues {
                    master_key: "tprv8ZgxMBicQKsPdDdJFAqvG3mt4VqsVV125X4vsor5NxK366upt6qvovLQqaCi5SJiCE1aLkt3HtxsnTpzeGu27kPC5RUCr4h3oPBPYnAvhdE",
                    node_secret_key: "31bbbef9e06c9ffe3fec8fa24030bccd561ca8e92dded97af7cea6ca3ac85a84",
                    node_id: "0355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c23",
                    channels_seed: "7e273adccc072169f5a1cb1aee23a2d6986b6cbbeff4f0995d2762ac7c0b2511",
                    keys_id: "0000000038410cf33c02217de2c24f800b46642355d5c4be3a78c7d5d924af38",
                    funding_key: "6c0816a87b3a49abcf9fb4d8f2dfa8fd422a26c80ed1c8ca125a5ef2b028308b",
                    commitment_seed: "4589ed83ea68e56ce041918fdd17bd3bb47ca8bcc992f8be1495da0a05a54ba5",
                    account_extended_key: "tprv8eoZddcAfpUQZNYYcJEVkpyfpss9vmBPvFMQ3CZrAxhoKpc6cM36XQJZ8jRbSuH7bouYBbKL6iQ5F4W3H2sh6NobCi4A9CJ3LJEUfDvmKib",
                },
            ),
            (
                KeyDerivationStyle::Lnd,
                ExpectedValues {
                    master_key: "tprv8ZgxMBicQKsPdDdJFAqvG3mt4VqsVV125X4vsor5NxK366upt6qvovLQqaCi5SJiCE1aLkt3HtxsnTpzeGu27kPC5RUCr4h3oPBPYnAvhdE",
                    node_secret_key: "a0794f0889ab261bd7ebdd8f33bfcea8497a0c429c58bde6e60ef157923fa787",
                    node_id: "02be197c34dccb4c23a6312404b78f8570519105f79dea0bdc947200354b6d1d34",
                    channels_seed: "7e273adccc072169f5a1cb1aee23a2d6986b6cbbeff4f0995d2762ac7c0b2511",
                    keys_id: "36814b08b8410cf33c02217de2c24f800b46642355d5c4be3a78c7d5d924af38",
                    funding_key: "78575e487b25b2cb527a0a67596841e4663e3b37c1da8015f290d1b951d701c2",
                    commitment_seed: "fd8c46daa8eda9211b6cf4461003c8cc6aaa98024b438779f08254e4e67ae60c",
                    account_extended_key: "tprv8fwV3nqr6mWFtQMxEmSGN9gbgxaoNzRms4dVeFSp3nG8chPHTmHA6razFaCUrtStcczbFDpazwBnsLkQ2uXK7rR9SxW3L92E7k6ZwTiMpwZ",
                },
            ),
        ];

        for (style, expected) in tests {
            let secp_ctx = Secp256k1::new();
            let seed = [0x01; 32];
            let channel_id = ChannelId::new(&[0x01; 32]);
            let channel_seed_base = [0x02; 32];
            let keys_id = [0u8; 32];
            let derive = key_derive(style, Testnet);

            // Test master_key
            let master_key = derive.master_key(&seed);
            assert_eq!(
                master_key.to_string(),
                expected.master_key,
                "master_key mismatch for {}",
                style
            );

            // Test node_keys
            let (node_id, node_secret_key) = derive.node_keys(&seed, &secp_ctx);
            assert_eq!(
                hex::encode(node_secret_key.secret_bytes()),
                expected.node_secret_key,
                "node_secret_key mismatch for {}",
                style
            );
            assert_eq!(node_id.to_string(), expected.node_id, "node_id mismatch for {}", style);

            // Test channels_seed
            let channels_seed = derive.channels_seed(&seed);
            assert_eq!(
                hex::encode(channels_seed),
                expected.channels_seed,
                "channels_seed mismatch for {}",
                style
            );

            // Test keys_id
            let keys_id_result = derive.keys_id(channel_id.clone(), &channel_seed_base);
            assert_eq!(
                hex::encode(keys_id_result),
                expected.keys_id,
                "keys_id mismatch for {}",
                style
            );

            // Test channel_keys
            let (funding_key, _, _, _, _, commitment_seed) =
                derive.channel_keys(&seed, &keys_id, 0, &master_key, &secp_ctx);
            assert_eq!(
                hex::encode(funding_key.secret_bytes()),
                expected.funding_key,
                "funding_key mismatch for {}",
                style
            );
            assert_eq!(
                hex::encode(commitment_seed),
                expected.commitment_seed,
                "commitment_seed mismatch for {}",
                style
            );

            // Test get_account_extended_key
            let account_key = style.get_account_extended_key(&secp_ctx, Testnet, &seed);
            assert_eq!(
                account_key.to_string(),
                expected.account_extended_key,
                "account_extended_key mismatch for {}",
                style
            );
        }
    }
}
