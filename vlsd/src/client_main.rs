extern crate clap;

#[macro_use]
mod client;

use client::driver;

use std::io;

use clap::{App, Arg, ArgMatches};

use bip39::Mnemonic;
use lightning_signer_server::NETWORK_NAMES;
use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, CLIENT_APP_NAME};

fn make_test_subapp() -> App<'static> {
    App::new("test").help("run a test scenario").subcommand(App::new("integration"))
}

#[tokio::main]
async fn test_subcommand(
    matches: &ArgMatches,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect(rpc_url).await?;

    match matches.subcommand() {
        Some(("integration", _)) => driver::integration_test(&mut client).await?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_test_subapp().print_help()?
        }
    };
    Ok(())
}

#[tokio::main]
async fn ping_subcommand(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connect to {}", rpc_url);
    let mut client = driver::connect(rpc_url).await?;
    driver::ping(&mut client).await
}

fn make_node_subapp() -> App<'static> {
    App::new("node")
        .help("control a node")
        .subcommand(
            App::new("new")
                .help("Add a new node to the signer.  Outputs the node ID to stdout and the mnemonic to stderr.")
                .arg(Arg::new("mnemonic")
                     .help("read mnemonic from stdin")
                     .long("mnemonic")
                     .short('m')
                     .takes_value(false))
                .arg(Arg::new("network")
                     .help("network name")
                     .long("network")
                     .takes_value(true)
                     .possible_values(NETWORK_NAMES)
                     .default_value(NETWORK_NAMES[0]),
                )
        )
        .subcommand(App::new("list").help("List configured nodes."))
}

#[tokio::main]
async fn node_subcommand(
    matches: &ArgMatches,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect(rpc_url).await?;

    match matches.subcommand() {
        Some(("new", matches)) => {
            let network_name = matches.value_of_t("network").expect("network");
            if matches.is_present("mnemonic") {
                let mut buf = String::new();
                io::stdin().read_line(&mut buf).expect("stdin");
                let mnemonic = Mnemonic::parse(buf.trim())?;
                driver::new_node_with_mnemonic(&mut client, mnemonic, network_name).await?
            } else {
                driver::new_node(&mut client, network_name).await?
            }
        }
        Some(("list", _)) => driver::list_nodes(&mut client).await?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_node_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_chan_subapp() -> App<'static> {
    App::new("channel")
        .alias("chan")
        .help("control a channel")
        .subcommand(
            App::new("new")
                .help("Add a new channel to a node.  Outputs the channel ID.")
                .arg(
                    Arg::new("no-nonce")
                        .help("generate the nonce on the server")
                        .long("no-nonce")
                        .takes_value(false),
                )
                .arg(
                    Arg::new("nonce")
                        .takes_value(true)
                        .help("optional nonce, otherwise one will be generated and displayed"),
                ),
        )
        .subcommand(App::new("list").help("List channels in a node"))
}

#[tokio::main]
async fn chan_subcommand(
    matches: &ArgMatches,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect(rpc_url).await?;
    // TODO give a nice error message if node_id is missing
    let node_id = hex::decode(matches.value_of("node").expect("missing node_id"))?;

    match matches.subcommand() {
        Some(("new", matches)) =>
            driver::new_channel(
                &mut client,
                node_id,
                matches.value_of("nonce"),
                matches.is_present("no-nonce"),
            )
            .await?,
        Some(("list", _)) => driver::list_channels(&mut client, node_id).await?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_chan_subapp().print_help()?
        }
    };
    Ok(())
}

fn make_allowlist_subapp() -> App<'static> {
    App::new("allowlist")
        .alias("alst")
        .help("manage allowlists")
        .subcommand(App::new("list").help("List allowlisted addresses for a node"))
        .subcommand(
            App::new("add").help("Add address to the node's allowlist").arg(
                Arg::new("address")
                    .takes_value(true)
                    .required(true)
                    .help("address to add to the allowlist"),
            ),
        )
        .subcommand(
            App::new("remove").help("Remove address from the node's allowlist").arg(
                Arg::new("address")
                    .takes_value(true)
                    .required(true)
                    .help("address to remove from the allowlist"),
            ),
        )
}

#[tokio::main]
async fn alst_subcommand(
    matches: &ArgMatches,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect(rpc_url).await?;
    // TODO give a nice error message if node_id is missing
    let node_id = hex::decode(matches.value_of("node").expect("missing node_id"))?;

    match matches.subcommand() {
        Some(("list", _)) => driver::list_allowlist(&mut client, node_id).await?,
        Some(("add", matches)) => {
            let addrs = vec![matches.value_of("address").expect("missing address").to_string()];
            driver::add_allowlist(&mut client, node_id, addrs).await?
        }
        Some(("remove", matches)) => {
            let addrs = vec![matches.value_of("address").expect("missing address").to_string()];
            driver::remove_allowlist(&mut client, node_id, addrs).await?
        }
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_allowlist_subapp().print_help()?
        }
    };
    Ok(())
}

fn parse_rpc_url(name: &str, matches: &ArgMatches) -> String {
    let raw_rpc_value = matches.value_of(name).expect(name);

    match raw_rpc_value.parse::<u16>() {
        Ok(_) => {
            // Port number suplied.
            let mut base_url = String::from("http://127.0.0.1:");
            base_url.push_str(raw_rpc_value);
            base_url
        }
        Err(_) => match url::Url::parse(raw_rpc_value) {
            Ok(_) => String::from(raw_rpc_value),
            _ => panic!("Invalid RPC URL"),
        },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_subapp = make_test_subapp();
    let node_subapp = make_node_subapp();
    let chan_subapp = make_chan_subapp();
    let alst_subapp = make_allowlist_subapp();
    let app = App::new(CLIENT_APP_NAME)
        .help("a CLI utility which communicates with a running Validating Lightning Signer server via gRPC")
        .arg(
            Arg::new("node")
                .short('n')
                .long("node")
                .takes_value(true)
                .global(true)
                .validator(|v| hex::decode(v)),
        )
        .arg(
            Arg::new("bitcoin")
            .help("Either port number or URL of the Bitcoin RPC server")
                .short('c')
                .long("bitcoin")
                .takes_value(true)
                .global(true)
                .default_value_ifs(CLAP_NETWORK_URL_MAPPING)
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
        .subcommand(test_subapp)
        .subcommand(node_subapp)
        .subcommand(chan_subapp)
        .subcommand(alst_subapp)
        .subcommand(App::new("ping"));
    let matches = app.clone().get_matches();

    let rpc_url = parse_rpc_url("bitcoin", &matches);
    let rpc = rpc_url.as_str();
    println!("Rpc: {}", rpc_url);

    match matches.subcommand() {
        Some(("test", submatches)) => test_subcommand(submatches, rpc)?,
        Some(("ping", _)) => ping_subcommand(rpc)?,
        Some(("node", submatches)) => node_subcommand(submatches, rpc)?,
        Some(("channel", submatches)) => chan_subcommand(submatches, rpc)?,
        Some(("allowlist", submatches)) => alst_subcommand(submatches, rpc)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => panic!("unmatched command?!"),
    };
    Ok(())
}
