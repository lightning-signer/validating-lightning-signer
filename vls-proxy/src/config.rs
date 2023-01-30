use clap::{CommandFactory, Parser};
use lightning_signer::bitcoin::Network;
use std::{env, fs};
use toml::value::{Table, Value};
use url::Url;

use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, NETWORK_NAMES};

const DEFAULT_DIR: &str = ".lightning-signer";

// only used for usage display
#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
pub(crate) struct InitialArgs {
    #[clap(short = 'f', long, value_parser, help = "configuration file")]
    config: Option<String>,
}

// note that value_parser gives us clap 4 forward compatibility
#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
pub(crate) struct SignerArgs {
    #[clap(flatten)]
    initial_args: InitialArgs,
    #[clap(long, help = "print git desc version and exit")]
    pub(crate) git_desc: bool,
    #[clap(short, long, value_parser, default_value = DEFAULT_DIR, help = "data directory", value_name = "DIR")]
    pub(crate) datadir: String,
    #[clap(short, long, value_parser,
        value_name = "NETWORK",
        possible_values = NETWORK_NAMES,
        default_value = NETWORK_NAMES[0]
    )]
    pub(crate) network: Network,
    #[clap(
        long,
        value_parser,
        help = "use integration test mode, reading/writing hsm_secret from CWD"
    )]
    pub(crate) integration_test: bool,
    #[clap(
        long,
        value_parser,
        help = "block explorer/bitcoind RPC endpoint - used for broadcasting recovery transactions",
        default_value_ifs(CLAP_NETWORK_URL_MAPPING),
        value_name = "URL"
    )]
    pub(crate) recover_rpc: Option<Url>,
    #[clap(
        long,
        value_parser,
        help = "block explorer type - used for broadcasting recovery transactions",
        value_name = "TYPE",
        default_value = "bitcoind",
        possible_values = &["bitcoind", "esplora"]
    )]
    pub(crate) recover_type: String,
    #[clap(
        long,
        value_parser,
        help = "send a force-close transaction to the given address",
        value_name = "BITCOIN_ADDRESS"
    )]
    pub(crate) recover_close: Option<String>,
}

pub(crate) fn parse_args_and_config<A: Parser>() -> A {
    // can't type-safe parse the initial args, because we want ignore_errors
    // but not when flattening into the higher level config.
    // further down we do use type-safe parsing for A.
    let initial_cmd = InitialArgs::command().ignore_errors(true);
    let initial_matches = initial_cmd.get_matches();

    let config_opt = initial_matches.value_of("config").map(|s| s.to_string());

    let args = if let Some(config) = config_opt {
        // prepend config file to args
        let contents = fs::read_to_string(config).unwrap();
        let config: Table = toml::from_str(contents.as_str()).unwrap();
        let config_iter = config
            .into_iter()
            .flat_map(|(k, value)| {
                let vals = convert_toml_value(k, value);
                vals.into_iter()
            })
            .map(|(k, v)| format!("--{}={}", k, v).to_string());
        let args_iter: Vec<_> =
            env::args().take(1).chain(config_iter).chain(env::args().skip(1)).collect();
        A::parse_from(args_iter.into_iter())
    } else {
        A::parse()
    };

    args
}

fn convert_toml_value(key: String, value: Value) -> Vec<(String, String)> {
    match value {
        Value::String(s) => vec![(key, s)],
        Value::Integer(v) => vec![(key, v.to_string())],
        Value::Float(v) => vec![(key, v.to_string())],
        Value::Boolean(v) => vec![(key, v.to_string())],
        Value::Datetime(v) => vec![(key, v.to_string())],
        Value::Array(a) =>
            a.into_iter().flat_map(|v| convert_toml_value(key.clone(), v)).collect::<Vec<_>>(),
        Value::Table(_) => vec![],
    }
}
