use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use clap::{Arg, ArgMatches, Command};
use lightning_storage_server::client::{ClientError, PrivAuth, PrivClient};
use lightning_storage_server::Value;
use lssd::util::setup_logging;
use lssd::util::{init_secret_key, read_public_key, read_secret_key, state_file_path};
use secp256k1::{PublicKey, SecretKey};
use std::fs;

const CLIENT_APP_NAME: &str = "lss-cli";

#[tokio::main]
async fn ping_subcommand(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let result = PrivClient::ping(rpc_url, "hello").await?;
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
    let (server_key, _version) = PrivClient::get_info(rpc_url).await?;
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
fn make_auth() -> Result<(PrivAuth, Vec<u8>), Box<dyn std::error::Error>> {
    let secret_key = secret_key()?;
    let hmac_secret = Sha256Hash::hash(&secret_key[..]).to_byte_array();
    let auth = PrivAuth::new_for_client(&secret_key, &server_public_key()?);
    Ok((auth, hmac_secret.to_vec()))
}

#[tokio::main]
async fn get_subcommand(
    rpc_url: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix = matches.get_one::<String>("prefix").unwrap();
    let (auth, hmac_secret) = make_auth()?;
    let mut client = PrivClient::new(rpc_url, auth.clone()).await?;
    let res = client.get(&hmac_secret, prefix.to_owned()).await?;
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
    let key = matches.get_one::<String>("key").unwrap();
    let version = *matches.get_one::<i64>("version").unwrap();
    let value_hex = matches.get_one::<String>("value").unwrap();

    let value = hex::decode(value_hex).unwrap();
    let (auth, hmac_secret) = make_auth()?;
    let mut client = PrivClient::new(rpc_url, auth.clone()).await?;

    match client.put(&hmac_secret, vec![(key.to_owned(), Value { version, value })]).await {
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
    let raw_rpc_value = matches.get_one::<String>("rpc").expect("rpc");

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

fn make_get_subapp() -> Command {
    Command::new("get")
        .about("get all keys/values at a key prefix")
        .arg(Arg::new("prefix").num_args(1).required(true).help("key prefix"))
}

fn make_put_subapp() -> Command {
    Command::new("put")
        .about("put a versioned key/value")
        .arg(Arg::new("key").num_args(1).required(true))
        .arg(Arg::new("version").num_args(1).required(true).help("integer version"))
        .arg(Arg::new("value").num_args(1).required(true).help("hex value"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Command::new(CLIENT_APP_NAME)
        .about("a CLI utility which communicates with a running Validating Lightning Signer server via gRPC")
        .arg(
            Arg::new("rpc")
            .help("Either port number or uri")
                .short('c')
                .long("rpc")
                .num_args(1)
                .global(true)
                .default_value("http://127.0.0.1:55551")
                .value_parser(|value: &str| {
                    let is_port = value.parse::<u16>().is_ok();
                    let is_url = url::Url::parse(value).is_ok();
                    if is_port || is_url {
                        Ok("")
                    } else {
                        Err("Value is neither a port number nor a valid uri.")
                    }
                }),
        )
        .subcommand(Command::new("ping"))
        .subcommand(Command::new("init"))
        .subcommand(Command::new("info"))
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
