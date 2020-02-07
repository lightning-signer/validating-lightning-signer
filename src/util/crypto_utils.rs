use bitcoin::Network;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin_hashes::Hash;
use bitcoin_hashes::sha256::Hash as Sha256Bitcoin;
use crypto::hkdf::{hkdf_expand, hkdf_extract};
use crypto::sha2::Sha256;
use secp256k1::{Error, PublicKey, Secp256k1, SecretKey, SignOnly};

pub fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let digest = Sha256::new();
    let mut prk = [0u8; 32];
    hkdf_extract(digest, salt, secret, &mut prk);
    let mut result = [0u8; 32];
    hkdf_expand(digest, &prk, info, &mut result);
    result
}

pub fn hkdf_sha256_keys(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32 * 6] {
    let digest = Sha256::new();
    let mut prk = [0u8; 32];
    hkdf_extract(digest, salt, secret, &mut prk);
    let mut result = [0u8; 32 * 6];
    hkdf_expand(digest, &prk, info, &mut result);
    result
}

pub fn channels_seed(node_seed: &[u8]) -> [u8; 32] {
    hkdf_sha256(node_seed, "peer seed".as_bytes(), &[])
}

pub fn node_keys(secp_ctx: &Secp256k1<SignOnly>, node_seed: &[u8]) -> (PublicKey, SecretKey) {
    let node_private_bytes = hkdf_sha256(node_seed, "nodeid".as_bytes(), &[]);
    let node_secret_key = SecretKey::from_slice(&node_private_bytes).unwrap();
    let node_id = PublicKey::from_secret_key(&secp_ctx, &node_secret_key);
    (node_id, node_secret_key)
}

pub fn bip32_key(secp_ctx: &Secp256k1<SignOnly>, network: Network, node_seed: &[u8]) -> ExtendedPrivKey {
    let bip32_seed = hkdf_sha256(node_seed, "bip32 seed".as_bytes(), &[]);
    let master = ExtendedPrivKey::new_master(network.clone(), &bip32_seed).unwrap();
    master.ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
        .ckd_priv(&secp_ctx, ChildNumber::from_normal_idx(0).unwrap())
        .unwrap()
}

/// idx should start at INITIAL_COMMITMENT_NUMBER and count backwards
pub fn build_commitment_secret(commitment_seed: &[u8; 32], idx: u64) -> SecretKey {
    let mut res: [u8; 32] = commitment_seed.clone();
    for i in 0..48 {
        let bitpos = 47 - i;
        if idx & (1 << bitpos) == (1 << bitpos) {
            res[bitpos / 8] ^= 1 << (bitpos & 7);
            res = Sha256Bitcoin::hash(&res).into_inner();
        }
    }
    SecretKey::from_slice(&res).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_keys_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let (node_id, _) = node_keys(&secp_ctx, &[0u8; 32]);
        let node_id_bytes = node_id.serialize().to_vec();
        assert!(
            hex::encode(&node_id_bytes)
                == "02058e8b6c2ad363ec59aa136429256d745164c2bdc87f98f0a68690ec2c5c9b0b"
        );
        Ok(())
    }

    #[test]
    fn channels_seed_test() -> Result<(), ()> {
        let seed = channels_seed(&[0u8; 32]);
        assert!(
            hex::encode(&seed)
                == "ab7f29780659755f14afb82342dc19db7d817ace8c312e759a244648dfc25e53"
        );
        Ok(())
    }

    #[test]
    fn bip32_key_test() -> Result<(), ()> {
        let secp_ctx = Secp256k1::signing_only();
        let key = bip32_key(&secp_ctx, Network::Testnet, &[0u8; 32]);
        assert!(format!("{}", key) == "tprv8ejySXSgpWvEBguEGNFYNcHz29W7QxEodgnwbfLzBCccBnxGAq4vBkgqUYPGR5EnCbLvJE7YQsod6qpid85JhvAfizVpqPg3WsWB6UG3fEL");
        Ok(())
    }
}

pub fn public_key_from_raw(raw: &[u8]) -> Result<PublicKey, Error> {
    let mut x = raw[0..32].to_vec();
    x.reverse();
    let mut y = raw[32..64].to_vec();
    y.reverse();
    let mut z = x;
    z.append(&mut y);
    z.insert(0, 4u8);
    PublicKey::from_slice(z.as_slice())
}
