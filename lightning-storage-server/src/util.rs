use secp256k1::{rand, SecretKey};
use std::fs;
use std::path::PathBuf;

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
        return Err("already initialized".into());
    }
    let priv_key = SecretKey::new(&mut rand::thread_rng());
    fs::write(id_file, hex::encode(&priv_key[..]))?;
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
