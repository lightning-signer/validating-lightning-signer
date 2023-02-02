use crate::config::{parse_args_and_config, SignerArgs};
use bitcoind_client::BlockExplorerType;
use clap::{CommandFactory, ErrorKind, Parser};
use grpc::signer::make_handler;
use grpc::signer::start_signer;
use http::Uri;
use lightning_signer::bitcoin::Network;
use log::*;
use std::fs;
use std::process::exit;
use util::setup_logging;
use vls_protocol_signer::handler::Handler;
use vls_proxy::recovery::{direct::DirectRecoveryKeys, recover_close};
use vls_proxy::GIT_DESC;

pub mod client;
pub mod config;
pub mod connection;
pub mod grpc;
pub mod tx_util;
pub mod util;

#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
struct Args {
    #[clap(
        short,
        long,
        value_parser,
        help = "node RPC endpoint",
        required_unless_present_any(&["recover-close", "git-desc"]),
        value_name = "URL"
    )]
    pub(crate) connect: Option<Uri>,
    #[clap(flatten)]
    pub(crate) signer_args: SignerArgs,
}

pub fn main() {
    let bin_name = "vlsd2";
    let our_args: Args = parse_args_and_config();

    let args = our_args.signer_args;

    // short-circuit if we're just printing the git desc
    if args.git_desc {
        println!("{} git_desc={}", bin_name, GIT_DESC);
        exit(0);
    }

    let network = args.network;
    let datadir = args.datadir.clone();
    let datapath = format!("{}/{}", datadir, network.to_string());
    fs::create_dir_all(&datapath).expect("mkdir datapath");
    setup_logging(&datapath, &bin_name, "debug");
    info!("{} git_desc={} starting", bin_name, GIT_DESC);

    if let Some(ref address) = args.recover_close {
        let recover_type = match args.recover_type.as_str() {
            "bitcoind" => BlockExplorerType::Bitcoind,
            "esplora" => BlockExplorerType::Esplora,
            _ => panic!("unknown recover type"),
        };
        let root_handler = make_handler(&datadir, &args);
        let node = root_handler.node().clone();
        node.set_allowlist(&[address.to_string()]).expect("add destination to allowlist");
        let keys = DirectRecoveryKeys { node };
        recover_close(network, recover_type, args.recover_rpc, &address, keys);
        return;
    }

    if our_args.connect.is_none() {
        Args::command()
            .error(ErrorKind::MissingRequiredArgument, "missing --connect argument")
            .exit();
    }

    let uri = our_args.connect.expect("connect URL");
    if network == Network::Bitcoin && args.integration_test {
        panic!("integration-test mode not supported on mainnet");
    }
    start_signer(&datadir, uri, &args);
}
