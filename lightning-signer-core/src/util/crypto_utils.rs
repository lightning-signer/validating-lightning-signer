use crate::prelude::*;
use bitcoin::hashes::hash160::Hash as BitcoinHash160;
use bitcoin::hashes::sha256::Hash as BitcoinSha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::address::{Payload, WitnessVersion};
use bitcoin::{EcdsaSighashType, Script};

fn hkdf_extract_expand(salt: &[u8], secret: &[u8], info: &[u8], output: &mut [u8]) {
    let mut hmac = HmacEngine::<BitcoinSha256>::new(salt);
    hmac.input(secret);
    let prk = Hmac::from_engine(hmac).into_inner();

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
        t = Hmac::from_engine(hmac).into_inner();
        chunk.copy_from_slice(&t);
    }
}

pub(crate) fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
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
    let res = BitcoinSha256::from_engine(sha).into_inner();

    let hashkey = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&res)?);
    base_point.combine(&hashkey)
}

pub(crate) fn payload_for_p2wpkh(key: &PublicKey) -> Payload {
    let mut hash_engine = BitcoinHash160::engine();
    hash_engine.input(&key.serialize());
    Payload::WitnessProgram {
        version: WitnessVersion::V0,
        program: BitcoinHash160::from_engine(hash_engine)[..].to_vec(),
    }
}

pub(crate) fn payload_for_p2wsh(script: &Script) -> Payload {
    let mut hash_engine = BitcoinSha256::engine();
    hash_engine.input(&script[..]);
    Payload::WitnessProgram {
        version: WitnessVersion::V0,
        program: BitcoinSha256::from_engine(hash_engine)[..].to_vec(),
    }
}

/// Convert a [Signature] to Bitcoin signature bytes, with SIGHASH_ALL
pub fn signature_to_bitcoin_vec(sig: Signature) -> Vec<u8> {
    let mut sigvec = sig.serialize_der().to_vec();
    sigvec.push(EcdsaSighashType::All as u8);
    sigvec
}

/// Convert a Bitcoin signature bytes, with the specified EcdsaSighashType, to [Signature]
pub fn bitcoin_vec_to_signature(
    sigvec: &Vec<u8>,
    sighash_type: EcdsaSighashType,
) -> Result<Signature, bitcoin::secp256k1::Error> {
    let len = sigvec.len();
    if len == 0 {
        return Err(bitcoin::secp256k1::Error::InvalidSignature);
    }
    let mut sv = sigvec.clone();
    let mode = sv.pop().ok_or_else(|| bitcoin::secp256k1::Error::InvalidSignature)?;
    if mode != sighash_type as u8 {
        return Err(bitcoin::secp256k1::Error::InvalidSignature);
    }
    Ok(Signature::from_der(&sv[..])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::ToHex;

    #[test]
    fn test_hkdf() {
        let secret = [1u8];
        let info = [2u8];
        let salt = [3u8];
        let mut output = [0u8; 32 * 6];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(output.to_vec().to_hex(), "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0efbbb13e74af4687137801e1628d1d1876d251b31d1321383568a9387da7c0baa7dee83ba374bba3774ef01140e4c4293791a512e536764bf4405aea511be32d5fd71a0b7a7ef3638312e476eb323fbac5f3d549ccf0fe0eabb38fe7bc16ad01db2288e57de45eabecd561ede4dc89164099ed7f0b0db5250e2b377e2aa84f520838612dccbde870f7b06a1e03f3cd79d30da717c55e15442a0b4dd02aafcd86");
        let mut output = [0u8; 32];
        hkdf_extract_expand(&salt, &secret, &info, &mut output);
        assert_eq!(
            output.to_vec().to_hex(),
            "13a04658302cc5173a8077f2f296662a7a3ddb2359be92770b13e0b9e63a23d0"
        );
    }
}
