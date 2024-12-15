use fern::colors::{Color, ColoredLevelConfig};
use log::info;
use secp256k1::{rand, SecretKey};
use std::{env, fs, path::PathBuf, str::FromStr};
use time::{macros::format_description, OffsetDateTime};

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

// Would prefer to use now_local but https://rustsec.org/advisories/RUSTSEC-2020-0071
// Also, https://time-rs.github.io/api/time/struct.OffsetDateTime.html#method.now_local
fn tstamp() -> String {
    OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
        ))
        .expect("formatted tstamp")
}

pub fn setup_logging(who: &str, level_arg: &str) {
    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());
    let who = who.to_string();
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
                who,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .level_for("redb", log::LevelFilter::Info)
        .level_for("tower", log::LevelFilter::Info)
        .level_for("hyper", log::LevelFilter::Info)
        .chain(std::io::stdout())
        // .chain(fern::log_file("/tmp/output.log")?)
        .apply()
        .expect("log config");
}
