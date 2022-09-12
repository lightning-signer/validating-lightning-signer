use lightning_storage_server::client;

use client::driver;

use clap::{App, Arg, ArgMatches};

#[tokio::main]
async fn ping_subcommand(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connect to {}", rpc_url);
    let mut client = driver::connect(rpc_url).await?;
    driver::ping(&mut client).await
}

#[tokio::main]
async fn get_subcommand(
    rpc_url: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connect to {}", rpc_url);
    let mut client = driver::connect(rpc_url).await?;
    let prefix = matches.value_of_t("prefix")?;
    driver::get(&mut client, prefix).await
}

#[tokio::main]
async fn put_subcommand(
    rpc_url: &str,
    matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connect to {}", rpc_url);
    let mut client = driver::connect(rpc_url).await?;
    let key = matches.value_of_t("key")?;
    let version = matches.value_of_t("version")?;
    let value_hex: String = matches.value_of_t("value")?;
    let value = hex::decode(value_hex).unwrap();
    driver::put(&mut client, key, version, value).await
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

const CLIENT_APP_NAME: &str = "lss-cli";

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
        .subcommand(make_get_subapp())
        .subcommand(make_put_subapp());
    let matches = app.clone().get_matches();

    let rpc_url = parse_rpc_url(&matches);
    let rpc = rpc_url.as_str();

    match matches.subcommand() {
        Some(("ping", _)) => ping_subcommand(rpc)?,
        Some(("get", submatches)) => get_subcommand(rpc, submatches)?,
        Some(("put", submatches)) => put_subcommand(rpc, submatches)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => panic!("missing command, try 'help'"),
    };
    Ok(())
}
