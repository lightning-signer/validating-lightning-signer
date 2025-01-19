#[cfg(feature = "crypt")]
use crate::chacha20::ChaCha20;
use crate::Value;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::{Hash, HashEngine, Hmac, HmacEngine};
use log::error;

pub fn prepare_value_for_put(secret: &[u8], key: &str, value: &mut Value) {
    append_hmac_to_value(secret, key, value.version, &mut value.value);
    #[cfg(feature = "crypt")]
    crypt_value(secret, key, value.version, &mut value.value);
}

pub fn append_hmac_to_value(secret: &[u8], key: &str, version: i64, value: &mut Vec<u8>) {
    let hmac = compute_hmac(secret, key, &version, &value);
    value.append(&mut hmac.to_vec());
}

#[cfg(feature = "crypt")]
pub fn crypt_value(secret: &[u8], key: &str, version: i64, value: &mut [u8]) {
    let mut engine = Sha256Hash::engine();
    engine.input(key.as_bytes());
    engine.input(&version.to_be_bytes());
    let hash = Sha256Hash::from_engine(engine);
    let mut nonce = [0u8; 12];
    nonce[0..12].copy_from_slice(&hash[0..12]);

    let mut chacha = ChaCha20::new(secret, &nonce);
    chacha.process_in_place(value);
}

pub fn process_value_from_get(secret: &[u8], key: &str, value: &mut Value) -> Result<(), ()> {
    #[cfg(feature = "crypt")]
    crypt_value(secret, key, value.version, &mut value.value);
    remove_and_check_hmac(secret, key, value.version, &mut value.value)?;
    Ok(())
}

pub fn remove_and_check_hmac(
    secret: &[u8],
    key: &str,
    version: i64,
    value: &mut Vec<u8>,
) -> Result<(), ()> {
    if value.len() < 32 {
        error!("value too short to have an HMAC");
        return Err(());
    }
    let expected_hmac = value.split_off(value.len() - 32);
    let hmac = compute_hmac(secret, key, &version, &value);
    if hmac == expected_hmac.as_slice() {
        Ok(())
    } else {
        Err(())
    }
}

fn compute_hmac(secret: &[u8], key: &str, version: &i64, value: &[u8]) -> [u8; 32] {
    let mut hmac = HmacEngine::<Sha256Hash>::new(secret);
    add_to_hmac(key, version, value, &mut hmac);
    Hmac::from_engine(hmac).to_byte_array()
}

/// Add key, version (8 bytes big endian) and value to HMAC
pub fn add_to_hmac(key: &str, version: &i64, value: &[u8], hmac: &mut HmacEngine<Sha256Hash>) {
    hmac.input(key.as_bytes());
    hmac.input(&version.to_be_bytes());
    hmac.input(&value);
}

/// Compute a client/server HMAC - which proves the client or server initiated this
/// call and no replay occurred.
pub fn compute_shared_hmac(secret: &[u8], nonce: &[u8], kvs: &[(String, Value)]) -> Vec<u8> {
    let mut hmac_engine = HmacEngine::<Sha256Hash>::new(&secret);
    hmac_engine.input(secret);
    hmac_engine.input(nonce);
    for (key, value) in kvs {
        add_to_hmac(&key, &value.version, &value.value, &mut hmac_engine);
    }
    Hmac::from_engine(hmac_engine).to_byte_array().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_processing_test() {
        let secret = [3u8; 32];
        let key = "test/key";
        let value = Value { version: 12, value: "test value".as_bytes().to_vec() };
        let mut v = Value { version: value.version, value: value.value.clone() };
        prepare_value_for_put(&secret, key, &mut v);
        assert_ne!(v.value, value.value);
        process_value_from_get(&secret, key, &mut v).unwrap();
        assert_eq!(v.value, value.value);
    }

    #[test]
    fn test_hmac() {
        let key = [11u8; 32];
        let orig_value = vec![1u8, 2, 3];
        let mut value = orig_value.clone();
        append_hmac_to_value(&key, "x", 123, &mut value);
        remove_and_check_hmac(&key, "x", 123, &mut value).expect("hmac check failed");
        assert_eq!(value, orig_value);

        let mut value = orig_value.clone();
        append_hmac_to_value(&key, "x", 123, &mut value);
        value[0] = 0;
        remove_and_check_hmac(&key, "x", 123, &mut value).expect_err("hmac check should fail");

        let mut value = orig_value.clone();
        append_hmac_to_value(&key, "x", 123, &mut value);
        remove_and_check_hmac(&key, "x", 122, &mut value).expect_err("hmac check should fail");

        let mut value = orig_value.clone();
        append_hmac_to_value(&key, "x", 123, &mut value);
        remove_and_check_hmac(&key, "x1", 123, &mut value).expect_err("hmac check should fail");
    }
}
