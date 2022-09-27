use crate::Value;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::{Hash, HashEngine, Hmac, HmacEngine};
use log::{error, info};
use secp256k1::{rand, SecretKey};
use std::path::PathBuf;
use std::{env, fs};

const STATE_DIR: &str = ".lss";

pub fn state_file_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home_dir = dirs::home_dir().ok_or("home directory not found")?;
    let mut state_dir = home_dir.clone();
    state_dir.push(STATE_DIR);
    if !state_dir.exists() {
        fs::create_dir(&state_dir)?;
    }
    let mut file = state_dir;
    file.push(name);
    Ok(file)
}

pub fn init_secret_key(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let id_file = state_file_path(path)?;
    if id_file.exists() {
        info!("{} already exists", id_file.display());
        return Ok(());
    }
    let priv_key = SecretKey::new(&mut rand::thread_rng());
    fs::write(id_file, hex::encode(&priv_key[..]))?;
    info!("Initialized secret key in {}", path);
    Ok(())
}

pub fn read_secret_key(path: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let file = state_file_path(path)?;
    let key_hex = fs::read_to_string(file).map_err(|_| "not initialized - use init command")?;
    Ok(SecretKey::from_slice(&hex::decode(key_hex)?)?)
}

pub fn read_public_key(path: &str) -> Result<secp256k1::PublicKey, Box<dyn std::error::Error>> {
    let secret_key = read_secret_key(path)?;
    let secp = secp256k1::Secp256k1::new();
    Ok(secp256k1::PublicKey::from_secret_key(&secp, &secret_key))
}

pub fn append_hmac_to_value(mut value: Vec<u8>, key: &str, version: i64, secret: &[u8]) -> Vec<u8> {
    let hmac = compute_hmac(key, &version, secret, &value);
    value.append(&mut hmac.to_vec());
    value
}

pub fn remove_and_check_hmac(
    mut value: Vec<u8>,
    key: &str,
    version: i64,
    secret: &[u8],
) -> Result<Vec<u8>, ()> {
    if value.len() < 32 {
        error!("value too short to have an HMAC");
        return Err(());
    }
    let expected_hmac = value.split_off(value.len() - 32);
    let hmac = compute_hmac(key, &version, secret, &value);
    if hmac == expected_hmac.as_slice() {
        Ok(value)
    } else {
        Err(())
    }
}

fn compute_hmac(key: &str, version: &i64, secret: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hmac = HmacEngine::<Sha256Hash>::new(secret);
    add_to_hmac(key, version, value, &mut hmac);
    Hmac::from_engine(hmac).into_inner()
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
    Hmac::from_engine(hmac_engine).into_inner().to_vec()
}

pub fn setup_logging(who: &str, level_arg: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    use std::str::FromStr;

    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());
    let who = who.to_string();
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                who,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .level_for("sled", log::LevelFilter::Info)
        .chain(std::io::stdout())
        // .chain(fern::log_file("/tmp/output.log")?)
        .apply()
        .expect("log config");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        let key = [11u8; 32];
        let orig_value = vec![1u8, 2, 3];
        let value_with_hmac = append_hmac_to_value(orig_value.clone(), "x", 123, &key);
        let value =
            remove_and_check_hmac(value_with_hmac, "x", 123, &key).expect("hmac check failed");
        assert_eq!(value, orig_value);

        let mut value = append_hmac_to_value(orig_value.clone(), "x", 123, &key);
        value[0] = 0;
        remove_and_check_hmac(value, "x", 123, &key).expect_err("hmac check should fail");

        let value = append_hmac_to_value(orig_value.clone(), "x", 123, &key);
        remove_and_check_hmac(value, "x", 122, &key).expect_err("hmac check should fail");

        let value = append_hmac_to_value(orig_value.clone(), "x", 123, &key);
        remove_and_check_hmac(value, "x1", 123, &key).expect_err("hmac check should fail");
    }
}
