use crate::prelude::*;
use bitcoin::hashes::sha256::Hash as BitcoinSha256;
use bitcoin::hashes::{sha256d, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::{
    self, ecdsa::Signature, schnorr, Message, PublicKey, Secp256k1, SecretKey,
};
use bitcoin::sighash::{EcdsaSighashType, TapSighash};
use bitcoin::taproot::TapTweakHash;
use bitcoin::PrivateKey;
use lightning::ln::channel_keys::{RevocationBasepoint, RevocationKey};

fn hkdf_extract_expand(salt: &[u8], secret: &[u8], info: &[u8], output: &mut [u8]) {
    let mut hmac = HmacEngine::<BitcoinSha256>::new(salt);
    hmac.input(secret);
    let prk = Hmac::from_engine(hmac).to_byte_array();

    let mut t = [0; 32];
    let mut n: u8 = 0;

    for chunk in output.chunks_mut(32) {
        let mut hmac = HmacEngine::<BitcoinSha256>::new(&prk[..]);
        n = n.checked_add(1).expect("HKDF size limit exceeded.");
        if n != 1 {
            hmac.input(&t);
        }
        hmac.input(&info);
        hmac.input(&[n]);
        t = Hmac::from_engine(hmac).to_byte_array();
        chunk.copy_from_slice(&t);
    }
}

/// derive a secret from another secret using HKDF-SHA256
pub fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    hkdf_extract_expand(salt, secret, info, &mut result);
    result
}

pub(crate) fn hkdf_sha256_keys(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32 * 6] {
    let mut result = [0u8; 32 * 6];
    hkdf_extract_expand(salt, secret, info, &mut result);
    result
}

pub(crate) fn derive_public_key<T: secp256k1::Signing>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    base_point: &PublicKey,
) -> Result<PublicKey, secp256k1::Error> {
    let mut sha = BitcoinSha256::engine();
    sha.input(&per_commitment_point.serialize());
    sha.input(&base_point.serialize());
    let res = BitcoinSha256::from_engine(sha).to_byte_array();

    let hashkey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&res)?);
    base_point.combine(&hashkey)
}

/// Convert a [Signature] to Bitcoin signature bytes, with SIGHASH_ALL
pub fn signature_to_bitcoin_vec(sig: Signature) -> Vec<u8> {
    let mut sigvec = sig.serialize_der().to_vec();
    sigvec.push(EcdsaSighashType::All as u8);
    sigvec
}

/// Convert a [Signature] to Bitcoin signature bytes, with SIGHASH_ALL
pub fn schnorr_signature_to_bitcoin_vec(sig: schnorr::Signature) -> Vec<u8> {
    // taproot sighash type defaults to ALL
    let mut sigvec = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE);
    sigvec.extend_from_slice(&sig[..]);
    sigvec
}

/// Convert a Bitcoin signature bytes, with the specified EcdsaSighashType, to [Signature]
pub fn bitcoin_vec_to_signature(
    sigvec: &[u8],
    sighash_type: EcdsaSighashType,
) -> Result<Signature, secp256k1::Error> {
    let len = sigvec.len();
    if len == 0 {
        return Err(secp256k1::Error::InvalidSignature);
    }
    let mut sv = sigvec.to_vec();
    let mode = sv.pop().ok_or_else(|| secp256k1::Error::InvalidSignature)?;
    if mode != sighash_type as u8 {
        return Err(secp256k1::Error::InvalidSignature);
    }
    Ok(Signature::from_der(&sv[..])?)
}

/// Use the provided seed, or generate a random one
pub fn maybe_generate_seed(seed_opt: Option<[u8; 32]>) -> [u8; 32] {
    seed_opt.unwrap_or_else(generate_seed)
}

/// Generate a seed
pub fn generate_seed() -> [u8; 32] {
    #[cfg(feature = "std")]
    {
        use secp256k1::rand::RngCore;
        let mut seed = [0; 32];
        let mut rng = secp256k1::rand::rngs::OsRng;
        rng.fill_bytes(&mut seed);
        seed
    }
    #[cfg(not(feature = "std"))]
    unimplemented!("no RNG available in no_std environments yet");
}

/// Hash the serialized heartbeat message for signing
pub fn sighash_from_heartbeat(ser_heartbeat: &[u8]) -> Message {
    let mut sha = BitcoinSha256::engine();
    sha.input("vls".as_bytes());
    sha.input("heartbeat".as_bytes());
    sha.input(ser_heartbeat);
    let hash = BitcoinSha256::from_engine(sha);
    Message::from_digest(hash.to_byte_array())
}

pub(crate) fn ecdsa_sign(
    secp_ctx: &Secp256k1<secp256k1::All>,
    privkey: &PrivateKey,
    sighash: sha256d::Hash,
) -> Signature {
    let message = Message::from_digest(sighash.to_byte_array());
    secp_ctx.sign_ecdsa(&message, &privkey.inner)
}

pub(crate) fn taproot_sign(
    secp_ctx: &Secp256k1<secp256k1::All>,
    privkey: &PrivateKey,
    sighash: TapSighash,
    aux_rand: &[u8; 32],
) -> schnorr::Signature {
    let message = Message::from(sighash);
    let keypair = secp256k1::Keypair::from_secret_key(secp_ctx, &privkey.inner);
    let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, None);
    let tweaked_keypair = keypair.add_xonly_tweak(secp_ctx, &tweak.to_scalar()).unwrap();

    secp_ctx.sign_schnorr_with_aux_rand(&message, &tweaked_keypair, aux_rand)
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalent of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
pub(crate) fn derive_public_revocation_key<T: secp256k1::Verification>(
    secp_ctx: &Secp256k1<T>,
    per_commitment_point: &PublicKey,
    countersignatory_revocation_base_point: &RevocationBasepoint,
) -> Result<RevocationKey, ()> {
    let revocation_key = RevocationKey::from_basepoint(
        secp_ctx,
        &countersignatory_revocation_base_point,
        per_commitment_point,
    );
    Ok(revocation_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf() {
        let secret = [1u8];
        let info = [2u8];
        let salt = [3u8];
        let mut output = [0u8; 32 * 6];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(hex::encode(output), "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0efbbb13e74af4687137801e1628d1d1876d251b31d1321383568a9387da7c0baa7dee83ba374bba3774ef01140e4c4293791a512e536764bf4405aea511be32d5fd71a0b7a7ef3638312e476eb323fbac5f3d549ccf0fe0eabb38fe7bc16ad01db2288e57de45eabecd561ede4dc89164099ed7f0b0db5250e2b377e2aa84f520838612dccbde870f7b06a1e03f3cd79d30da717c55e15442a0b4dd02aafcd86");
        let mut output = [0u8; 32];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(
            hex::encode(output),
            "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0"
        );
    }

    #[test]
    fn test_schnorr_signature_to_bitcoin_vec() {
        let test_signature_bytes: Vec<u8> = vec![0; 64];

        let test_signature = schnorr::Signature::from_slice(&test_signature_bytes).unwrap();

        let result = schnorr_signature_to_bitcoin_vec(test_signature);

        assert_eq!(test_signature_bytes, result);
    }

    #[test]
    fn test_bitcoin_vec_to_signature() {
        let sighash_type = EcdsaSighashType::All;
        let sigvec: Vec<u8> = vec![];

        let result = bitcoin_vec_to_signature(&sigvec, sighash_type);

        assert_eq!(result, Err(secp256k1::Error::InvalidSignature));

        let mut sigvec = hex::decode(
            "304402202e1f64d831e89e2b4a0dc8565cb2d0a4d6061a89f9b48f2c26d5ac0b3b9a0bb102200c8d396f8b2e9c6c623bebc015c47f1f41e8824fabe7cb028f174a0e5df3c0a0"
        ).unwrap();

        sigvec.push(1 as u8);

        let result = bitcoin_vec_to_signature(&sigvec, sighash_type).unwrap();

        sigvec.pop();

        let parsed_signature = Signature::from_der(&sigvec).expect("valid DER signature");

        assert_eq!(result, parsed_signature);
    }

    #[test]
    fn test_maybe_generate_seed() {
        let known_seed: [u8; 32] = [1; 32];

        let result = maybe_generate_seed(Some(known_seed));

        assert_eq!(result, known_seed);

        let result = maybe_generate_seed(None);

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_taproot_sign() {
        let secp = Secp256k1::new();

        let privkey_bytes =
            hex::decode("d8d3a3140ba89f14144b0dfe40e04220e02ed68736a5773e050a3c4116b1e31c")
                .unwrap();
        let secret_key =
            SecretKey::from_slice(&privkey_bytes).expect("32 bytes, within curve order");

        let privkey = PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);

        let sighash = TapSighash::hash(&[0]);

        let aux_rand: [u8; 32] = [0u8; 32];

        let signature = taproot_sign(&secp, &privkey, sighash, &aux_rand);

        let expected_signature_hex =
            "14262eb13409cd8928536ab60f431b95193d2d9c7cc476e9f43e8b8f98a8d5a8c38d3edc7bf43c389a12c9e5fad9485ee5d59df2d35f46c3f77ca07197ee1db2";

        assert_eq!(expected_signature_hex, signature.to_string());
    }
}
