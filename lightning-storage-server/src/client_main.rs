use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use clap::{App, Arg, ArgMatches};
use client::driver;
use lightning_storage_server::client;
use lightning_storage_server::client::auth::Auth;
use lightning_storage_server::client::driver::ClientError;
use lightning_storage_server::util::{
    init_secret_key, read_public_key, read_secret_key, setup_logging, state_file_path,
};
use secp256k1::{PublicKey, SecretKey};
use std::fs;

const CLIENT_APP_NAME: &str = "lss-cli";

#[tokio::main]
async fn ping_subcommand(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let result = driver::Client::ping(rpc_url, "hello").await?;
    println!("ping result: {}", result);
    Ok(())
}

fn secret_key() -> Result<SecretKey, Box<dyn std::error::Error>> {
    read_secret_key("client-key")
}

fn public_key() -> Result<PublicKey, Box<dyn std::error::Error>> {
    read_public_key("client-key")
}

fn server_public_key() -> Result<PublicKey, Box<dyn std::error::Error>> {
    let server_pubkey_file = state_file_path("server-pubkey")?;
    let server_pubkey_hex = fs::read_to_string(server_pubkey_file)?;
    Ok(PublicKey::from_slice(&hex::decode(server_pubkey_hex)?)?)
}

#[tokio::main]
async fn init_subcommand(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    init_secret_key("client-key")?;
    let server_key = driver::Client::init(rpc_url).await?;
    let server_pubkey_file = state_file_path("server-pubkey")?;
    fs::write(server_pubkey_file, hex::encode(&server_key.serialize()))?;
    Ok(())
}

fn info_subcommand(_rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    match public_key() {
        Ok(pk) => println!("public key: {}", hex::encode(pk.serialize())),
        Err(_) => println!("not initialized"),
    }
    match server_public_key() {
        Ok(pk) => println!("server public key: {}", hex::encode(pk.serialize())),
        Err(_) => println!("server public key not initialized"),
    }
    Ok(())
}

// Auth and hmac secret
fn make_auth() -> Result<(Auth, Vec<u8>), Box<dyn std::error::Error>> {
    let secret_key = secret_key()?;
    let hmac_secret = Sha256Hash::hash(&secret_key[..]).into_inner();
    let auth = Auth::new_for_client(secret_key, server_public_key()?);
    Ok((auth, hmac_secret.to_vec()))
}

#[tokio::main]
async fn get_subcommand(
    rpc_url: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix = matches.value_of_t("prefix")?;
    let (auth, hmac_secret) = make_auth()?;
    let mut client = driver::Client::new(rpc_url, auth.clone()).await?;
    let res = client.get(auth, &hmac_secret, prefix).await?;
    for (key, value) in res {
        println!("key: {}, version: {} value: {}", key, value.version, hex::encode(value.value));
    }
    Ok(())
}

#[tokio::main]
async fn put_subcommand(
    rpc_url: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = matches.value_of_t("key")?;
    let version = matches.value_of_t("version")?;
    let value_hex: String = matches.value_of_t("value")?;
    let value = hex::decode(value_hex).unwrap();
    let (auth, hmac_secret) = make_auth()?;
    let mut client = driver::Client::new(rpc_url, auth.clone()).await?;

    match client.put(auth, &hmac_secret, key, version, value).await {
        Ok(()) => Ok(()),
        Err(ClientError::PutConflict(conflicts)) => {
            for (key, value) in conflicts {
                println!(
                    "conflict key: {}, version: {} value: {}",
                    key,
                    value.version,
                    hex::encode(value.value)
                );
            }
            Err("put conflict".into())
        }
        Err(e) => Err(e.into()),
    }
}

fn parse_rpc_url(matches: &ArgMatches) -> String {
    let raw_rpc_value = matches.value_of("rpc").expect("rpc");

    let rpc_url = match raw_rpc_value.parse::<u16>() {
        Ok(_) => {
            // Port number suplied.
            let mut base_url = String::from("http://127.0.0.1:");
            base_url.push_str(raw_rpc_value);
            base_url
        }
        Err(_) => match url::Url::parse(raw_rpc_value) {
            Ok(_) => String::from(raw_rpc_value),
            _ => panic!("Invalid rpc_value"),
        },
    };
    rpc_url
}

fn make_get_subapp() -> App<'static> {
    App::new("get")
        .about("get all keys/values at a key prefix")
        .arg(Arg::new("prefix").takes_value(true).required(true).about("key prefix"))
}

fn make_put_subapp() -> App<'static> {
    App::new("put")
        .about("put a versioned key/value")
        .arg(Arg::new("key").takes_value(true).required(true))
        .arg(Arg::new("version").takes_value(true).required(true).about("integer version"))
        .arg(Arg::new("value").takes_value(true).required(true).about("hex value"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::new(CLIENT_APP_NAME)
        .about("a CLI utility which communicates with a running Validating Lightning Signer server via gRPC")
        .arg(
            Arg::new("rpc")
            .about("Either port number or uri")
                .short('c')
                .long("rpc")
                .takes_value(true)
                .global(true)
                .default_value("http://127.0.0.1:55551")
                .validator(|value| {
                    let is_port = value.parse::<u16>().is_ok();
                    let is_url = url::Url::parse(value).is_ok();
                    if is_port || is_url {
                        Ok("")
                    } else {
                        Err("Value is neither a port number nor a valid uri.")
                    }
                }),
        )
        .subcommand(App::new("ping"))
        .subcommand(App::new("init"))
        .subcommand(App::new("info"))
        .subcommand(make_get_subapp())
        .subcommand(make_put_subapp());
    let matches = app.clone().get_matches();

    setup_logging("lss-cli", "info");

    let rpc_url = parse_rpc_url(&matches);
    let rpc = rpc_url.as_str();

    match matches.subcommand() {
        Some(("ping", _)) => ping_subcommand(rpc)?,
        Some(("init", _)) => init_subcommand(rpc)?,
        Some(("info", _)) => info_subcommand(rpc)?,
        Some(("get", submatches)) => get_subcommand(rpc, submatches)?,
        Some(("put", submatches)) => put_subcommand(rpc, submatches)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => panic!("missing command, try 'help'"),
    };
    Ok(())
}
