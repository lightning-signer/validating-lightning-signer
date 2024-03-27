use bitcoind_client::BlockExplorerType;
use clap::{CommandFactory, ErrorKind, Parser};
use config::{parse_args_and_config, HasSignerArgs, SignerArgs};
use grpc::signer::make_handler;
use grpc::signer::start_signer;
use http::Uri;
use lightning_signer::bitcoin::Network;
use recovery::{direct::DirectRecoveryKeys, recover_close, recover_l1};
use std::fs;
use util::abort_on_panic;
use util::observability::init_tracing_subscriber;
use vls_proxy::config::DEFAULT_DIR;
use vls_proxy::*;

#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
struct Args {
    #[clap(
        short,
        long,
        value_parser,
        help = "node RPC endpoint",
        required_unless_present_any(&["recover-to", "git-desc"]),
        value_name = "URL"
    )]
    pub(crate) connect: Option<Uri>,
    #[clap(flatten)]
    pub(crate) signer_args: SignerArgs,
}

impl HasSignerArgs for Args {
    fn signer_args(&self) -> &SignerArgs {
        &self.signer_args
    }
}

#[tokio::main(worker_threads = 2)]
pub async fn main() {
    abort_on_panic();
    let bin_name = "vlsd2";
    let our_args: Args = parse_args_and_config(bin_name);

    let args = our_args.signer_args;

    let network = args.network;
    let datadir = args.datadir.clone().unwrap_or(format!(
        "{}/{DEFAULT_DIR}",
        dirs::home_dir().expect("Home directory not found").to_str().unwrap()
    ));
    let datapath = format!("{}/{}", datadir, network.to_string());
    fs::create_dir_all(&datapath).expect("mkdir datapath");

    let _tracing_guard = init_tracing_subscriber(&datapath, &bin_name).expect("failed to initalize tracing subscriber");

    tracing::info!("{} git_desc={} starting", bin_name, GIT_DESC);

    if let Some(ref address) = args.recover_to {
        let recover_type = match args.recover_type.as_str() {
            "bitcoind" => BlockExplorerType::Bitcoind,
            "esplora" => BlockExplorerType::Esplora,
            _ => panic!("unknown recover type"),
        };
        let root_handler = make_handler(&datadir, &args);
        let node = root_handler.node().clone();
        if address != "none" {
            node.set_allowlist(&[address.to_string()]).expect("add destination to allowlist");
        }
        let keys = DirectRecoveryKeys { node };
        if let Some(max_index) = args.recover_l1_range {
            recover_l1(network, recover_type, args.recover_rpc, &address, keys, max_index);
        } else {
            recover_close(network, recover_type, args.recover_rpc, &address, keys);
        }
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
    start_signer(&datadir, uri, &args).await;
}
