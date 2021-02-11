// FILE NOT TESTED

extern crate clap;
use clap::{App, ArgMatches};

use lightning_signer::client::driver;

fn make_test_subapp() -> App<'static> {
    App::new("test")
        .about("run a test scenario")
        .subcommand(App::new("integration"))
}

#[tokio::main]
async fn test_subcommand(matches: &ArgMatches, mut app: App) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;

    match matches.subcommand() {
        Some(("integration", _)) => driver::integration_test(&mut client).await?,
        _ => { println!("missing sub-command"); app.print_help()?},
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
        .subcommand(App::new("new").about("Add a new node to the signer"))
}

#[tokio::main]
async fn node_subcommand(matches: &ArgMatches, mut app: App) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = driver::connect().await?;

    match matches.subcommand() {
        Some(("new", _)) => driver::new_node(&mut client).await?,
        _ => { println!("missing sub-command"); app.print_help()?},
    };
    Ok(())
}


// BEGIN NOT TESTED
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_subapp = make_test_subapp();
    let node_subapp = make_node_subapp();
    let mut app = App::new("client")
        .about("a CLI utility which communicates with a running Lightning Signer server via gRPC")
        .subcommand(test_subapp.clone())
        .subcommand(node_subapp.clone())
        .subcommand(App::new("ping"));
    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some(("test", submatches)) => test_subcommand(submatches, test_subapp)?,
        Some(("ping", _)) => ping_subcommand()?,
        Some(("node", submatches)) => node_subcommand(submatches, node_subapp)?,
        _ => app.print_help()?,
    };
    Ok(())
}
// END NOT TESTED
