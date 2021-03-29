// BEGIN NOT TESTED

extern crate clap;
use clap::{App, Arg, ArgMatches};

use lightning_signer::client::driver;

fn make_test_subapp() -> App<'static> {
    App::new("test")
        .about("run a test scenario")
        .subcommand(App::new("integration"))
}

#[tokio::main]
async fn test_subcommand(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;

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
async fn ping_subcommand() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;
    driver::ping(&mut client).await
}

fn make_node_subapp() -> App<'static> {
    App::new("node")
        .about("control a node")
        .subcommand(App::new("new").about("Add a new node to the signer.  Outputs the node ID to stdout and the mnemonic to stderr."))
        .subcommand(App::new("list").about("List configured nodes."))
}

#[tokio::main]
async fn node_subcommand(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;

    match matches.subcommand() {
        Some(("new", _)) => driver::new_node(&mut client).await?,
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
        .about("control a channel")
        .subcommand(App::new("new").about("Add a new channel to a node.  Outputs the channel ID."))
        .subcommand(App::new("list").about("List channels in a node"))
}

#[tokio::main]
async fn chan_subcommand(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;
    // TODO give a nice error message if node_id is missing
    let node_id = hex::decode(matches.value_of("node").expect("missing node_id"))?;

    match matches.subcommand() {
        Some(("new", _)) => driver::new_channel(&mut client, node_id).await?,
        Some(("list", _)) => driver::list_channels(&mut client, node_id).await?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => {
            println!("missing sub-command");
            make_chan_subapp().print_help()?
        }
    };
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_subapp = make_test_subapp();
    let node_subapp = make_node_subapp();
    let chan_subapp = make_chan_subapp();
    let app = App::new("client")
        .about("a CLI utility which communicates with a running Lightning Signer server via gRPC")
        .arg(
            Arg::new("node")
                .short('n')
                .long("node")
                .takes_value(true)
                .global(true)
                .validator(|v| hex::decode(v)),
        )
        .subcommand(test_subapp)
        .subcommand(node_subapp)
        .subcommand(chan_subapp)
        .subcommand(App::new("ping"));
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some(("test", submatches)) => test_subcommand(submatches)?,
        Some(("ping", _)) => ping_subcommand()?,
        Some(("node", submatches)) => node_subcommand(submatches)?,
        Some(("channel", submatches)) => chan_subcommand(submatches)?,
        Some((name, _)) => panic!("unimplemented command {}", name),
        None => panic!("unmatched command?!"),
    };
    Ok(())
}

// END NOT TESTED
