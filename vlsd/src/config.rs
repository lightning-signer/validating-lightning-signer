use clap::{error::ErrorKind, Parser};
use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::bitcoin::Network;
use lightning_signer::policy::filter::{FilterResult, FilterRule};
use lightning_signer::policy::simple_validator::OptionizedSimplePolicy;
use lightning_signer::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{env, fs};
use toml::value::{Table, Value};
use url::Url;

pub use vls_util::config::{CLAP_NETWORK_URL_MAPPING, DEFAULT_DIR, NETWORK_NAMES};

pub const RPC_SERVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const RPC_SERVER_PORT: u16 = 8011;
pub const RPC_SERVER_ENDPOINT: &'static str = "http://127.0.0.1:8011";

pub trait HasSignerArgs {
    fn signer_args(&self) -> &SignerArgs;
}

// only used for usage display
#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
pub struct InitialArgs {
    #[clap(
        short = 'f',
        long,
        value_parser,
        help = "configuration file - MUST be the first argument",
        value_name = "FILE"
    )]
    config: Option<String>,
}

// note that value_parser gives us clap 4 forward compatibility
#[derive(Parser, Debug)]
#[clap(about, long_about = None, args_override_self = true)]
pub struct SignerArgs {
    #[clap(flatten)]
    initial_args: InitialArgs,

    #[clap(long, help = "print git desc version and exit")]
    pub git_desc: bool,

    #[clap(long, help = "LSS RPC endpoint")]
    pub lss: Option<Url>,

    #[clap(long, help = "dump LSS contents and exit")]
    pub dump_lss: bool,

    #[clap(long, help = "initialize LSS from local storage and exit.  LSS must be empty.")]
    pub init_lss: bool,

    #[clap(long, help = "dump local storage contents and exit")]
    pub dump_storage: bool,

    #[clap(
        long,
        help = "set the logging level",
        value_name = "LEVEL",
        default_value = "info",
        value_parser = ["off", "error", "warn", "info", "debug", "trace"],
    )]
    pub log_level: String,

    #[clap(short, long, value_parser, help = "data directory", value_name = "DIR")]
    pub datadir: Option<String>,

    #[clap(
        short,
        long,
        value_name = "NETWORK",
        default_value = NETWORK_NAMES[0],
        value_parser = Network::from_str,
    )]
    pub network: Network,

    #[clap(
        long,
        value_parser,
        help = "use integration test mode, reading/writing hsm_secret from CWD"
    )]
    pub integration_test: bool,

    #[clap(
        long,
        value_parser,
        help = "block explorer/bitcoind RPC endpoint - used for broadcasting recovery transactions",
        value_name = "URL",
        default_value_ifs(CLAP_NETWORK_URL_MAPPING)
    )]
    pub recover_rpc: Option<Url>,

    #[clap(
        long,
        value_parser = ["bitcoind", "esplora"],
        help = "block explorer type - used for broadcasting recovery transactions",
        value_name = "TYPE",
        default_value = "bitcoind",
    )]
    pub recover_type: String,

    #[clap(
        long,
        value_parser,
        help = "recover funds to the given address.  By default, l2 funds are recovered (force-close), but you can also recover l1 funds by specifying --recover-l1-range.  You can also perform a dry-run by specifying --recover-to=none.",
        value_name = "BITCOIN_ADDRESS"
    )]
    pub recover_to: Option<String>,

    #[clap(
        long,
        value_parser = clap::value_parser!(u32),
        help = "recover l1 funds by sweeping BIP32 addresses up to the given derivation index",
        value_name = "RANGE"
    )]
    pub recover_l1_range: Option<u32>,

    #[clap(long, value_parser = parse_velocity_control_spec, help = "global velocity control e.g. hour:10000 (satoshi)")]
    pub velocity_control: Option<VelocityControlSpec>,

    #[clap(long, value_parser = parse_velocity_control_spec, help = "fee velocity control e.g. hour:10000 (satoshi)")]
    pub fee_velocity_control: Option<VelocityControlSpec>,

    #[clap(long, value_parser = parse_filter_rule, help = "policy filter rule, e.g. 'policy-channel-safe-mode:warn' or 'policy-channel-*:error'")]
    pub policy_filter: Vec<FilterRule>,

    #[clap(
        long,
        help = "rpc server's bind address",
        default_value_t = RPC_SERVER_ADDRESS,
        value_parser
    )]
    pub rpc_server_address: IpAddr,

    #[clap(
        long,
        help = "rpc server's port",
        default_value_t = RPC_SERVER_PORT,
        value_parser
    )]
    pub rpc_server_port: u16,

    #[clap(long, help = "rpc server admin username", value_parser)]
    pub rpc_user: Option<String>,

    #[clap(long, help = "rpc server admin password", value_parser)]
    pub rpc_pass: Option<String>,

    #[clap(long, help = "rpc server admin cookie file path", value_parser)]
    pub rpc_cookie: Option<PathBuf>,

    #[clap(short, help = "public key of trusted TXO oracle", value_parser)]
    pub trusted_oracle_pubkey: Vec<PublicKey>,

    #[clap(skip)]
    pub policy: OptionizedSimplePolicy,
}

impl HasSignerArgs for SignerArgs {
    fn signer_args(&self) -> &SignerArgs {
        self
    }
}

pub fn parse_args_and_config<A: Parser + HasSignerArgs>(bin_name: &str) -> A {
    let env_args = env::args().collect::<Vec<_>>();
    parse_args_and_config_from(bin_name, &env_args).unwrap_or_else(|e| match e.kind() {
        ErrorKind::DisplayVersion => exit(0), // exit directly because no Command
        _ => e.exit(),
    })
}

#[derive(Clone)]
struct ConfigIterator {
    args_stack: Arc<Mutex<Vec<Vec<String>>>>,
}

impl ConfigIterator {
    fn new(args: &[String]) -> Self {
        assert!(args.len() > 0, "at least one arg");
        ConfigIterator { args_stack: Arc::new(Mutex::new(vec![args.iter().cloned().collect()])) }
    }

    fn do_next(args_stack: &mut MutexGuard<Vec<Vec<String>>>) -> Option<String> {
        loop {
            if args_stack.is_empty() {
                return None;
            }
            let args = &mut args_stack[0];
            if !args.is_empty() {
                let arg = args.remove(0);
                return Some(arg);
            }
            args_stack.remove(0);
        }
    }
}

impl Iterator for ConfigIterator {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut args_stack = self.args_stack.lock().unwrap();
        let arg = Self::do_next(&mut args_stack);
        if let Some(arg) = arg {
            if arg.starts_with("--config=") {
                let path = arg.split('=').nth(1).unwrap();
                let configs = toml_to_configs(path.as_ref());
                args_stack.insert(0, configs);
                return Self::do_next(&mut args_stack);
            } else if arg == "--config" || arg == "-f" {
                let path_opt = Self::do_next(&mut args_stack);
                if let Some(path) = path_opt {
                    let configs = toml_to_configs(path.as_ref());
                    args_stack.insert(0, configs);
                    return Self::do_next(&mut args_stack);
                } else {
                    println!("--config must be followed by a path");
                    // let clap handle the error
                    return Some(arg);
                }
            }
            return Some(arg);
        } else {
            return None;
        }
    }
}

pub fn parse_args_and_config_from<A: Parser + HasSignerArgs>(
    bin_name: &str,
    env_args: &[String],
) -> Result<A, clap::Error> {
    let args_iter = ConfigIterator::new(env_args);
    let args = A::try_parse_from(args_iter)?;

    // short-circuit if we're just printing the git desc
    if args.signer_args().git_desc {
        println!("{} git_desc={}", bin_name, vls_util::GIT_DESC);
        // Don't exit here because this is called by unit tests
        return Err(clap::Error::raw(ErrorKind::DisplayVersion, ""));
    }

    Ok(args)
}

fn toml_to_configs(path: &OsStr) -> Vec<String> {
    let contents = fs::read_to_string(path).unwrap();
    let config: Table = toml::from_str(contents.as_str()).unwrap();
    let configs = config
        .into_iter()
        .flat_map(|(k, value)| {
            let vals = convert_toml_value(k, value);
            vals.into_iter()
        })
        .map(|(k, v)| format!("--{}={}", k, v).to_string())
        .collect();
    configs
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

fn parse_velocity_control_spec(spec: &str) -> Result<VelocityControlSpec, String> {
    let mut parts = spec.splitn(2, ':');
    let interval_type_str = parts.next().ok_or("missing duration")?;
    let interval_type = match interval_type_str {
        "hour" => VelocityControlIntervalType::Hourly,
        "day" => VelocityControlIntervalType::Daily,
        "unlimited" => return Ok(VelocityControlSpec::UNLIMITED),
        _ => return Err(format!("unknown interval type: {}", interval_type_str)),
    };
    let limit: u64 = parts
        .next()
        .ok_or("missing limit")?
        .to_string()
        .parse()
        .map_err(|_| "non-integer limit")?;
    Ok(VelocityControlSpec { interval_type, limit_msat: limit })
}

fn parse_filter_rule(spec: &str) -> Result<FilterRule, String> {
    let mut parts = spec.splitn(2, ':');
    let mut tag: String = parts.next().ok_or("missing filter")?.to_string();
    let is_prefix = if tag.ends_with('*') {
        tag.pop();
        true
    } else {
        false
    };
    let action_str = parts.next().ok_or("missing level")?;
    let action = match action_str {
        "error" => FilterResult::Error,
        "warn" => FilterResult::Warn,
        _ => return Err(format!("unknown filter action {}", action_str)),
    };
    Ok(FilterRule { tag, action, is_prefix })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_velocity_control_spec_test() {
        match parse_velocity_control_spec("hour:100").unwrap().interval_type {
            VelocityControlIntervalType::Hourly => {}
            _ => panic!("unexpected interval type"),
        }
        match parse_velocity_control_spec("day:100").unwrap().interval_type {
            VelocityControlIntervalType::Daily => {}
            _ => panic!("unexpected interval type"),
        }
        match parse_velocity_control_spec("unlimited").unwrap().interval_type {
            VelocityControlIntervalType::Unlimited => {}
            _ => panic!("unexpected interval type"),
        }
        assert!(parse_velocity_control_spec("hour").is_err());
        assert!(parse_velocity_control_spec("hour:").is_err());
        assert!(parse_velocity_control_spec("hour:foo").is_err());
        assert!(parse_velocity_control_spec("foo:100").is_err());
    }

    #[test]
    fn parse_filter_rule_test() {
        assert!(parse_filter_rule("policy-channel-safe-mode:warn").is_ok());
        assert!(parse_filter_rule("policy-channel-safe-mode:foo").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode:").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode:*").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode-*:warn").is_ok());
    }

    #[test]
    fn git_desc_test() {
        let env_args: Vec<String> =
            vec!["vlsd", "--git-desc"].into_iter().map(|s| s.to_string()).collect();
        let args_res: Result<SignerArgs, _> = parse_args_and_config_from("", &env_args);
        assert!(args_res.is_err());
    }

    #[test]
    fn clap_test() {
        let env_args: Vec<String> = vec!["vlsd"].into_iter().map(|s| s.to_string()).collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert!(args.policy_filter.is_empty());
        assert!(args.velocity_control.is_none());
        assert!(args.fee_velocity_control.is_none());

        let env_args: Vec<String> = vec![
            "vlsd",
            "--datadir=/tmp/vlsd",
            "--network=regtest",
            "--integration-test",
            "--recover-rpc=http://localhost:3000",
            "--policy-filter",
            "policy-channel-safe-mode:warn",
            "--velocity-control",
            "hour:100",
            "--recover-to",
            "abc123",
            "--recover-l1-range",
            "100",
            "--rpc-server-address",
            "127.0.0.1",
            "--rpc-server-port",
            "8011",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir.unwrap(), "/tmp/vlsd");
        assert_eq!(args.policy_filter.len(), 1);
        assert!(args.velocity_control.is_some());
        assert_eq!(args.network, Network::Regtest);
        assert!(args.integration_test);
        assert_eq!(args.recover_rpc.unwrap().as_str(), "http://localhost:3000/");
        assert_eq!(args.recover_type, "bitcoind");
        assert_eq!(args.recover_to.unwrap().as_str(), "abc123");
        assert_eq!(args.recover_l1_range, Some(100));
        assert_eq!(args.rpc_server_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(args.rpc_server_port, 8011);
    }

    #[test]
    fn clap_with_config_file_test() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "datadir = \"/tmp/vlsd\"\n
            velocity-control = \"day:222\"\n
            network = \"regtest\"\n"
        )
        .unwrap();
        let env_args: Vec<String> =
            vec!["vlsd", "--config", file.path().to_str().unwrap(), "--network=bitcoin"]
                .into_iter()
                .map(|s| s.to_string())
                .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir.unwrap(), "/tmp/vlsd");
        assert!(args.velocity_control.is_some());
        // command line args override config file
        assert_eq!(args.network, Network::Bitcoin);

        let env_args: Vec<String> =
            vec!["vlsd", "--network=bitcoin", "--config", file.path().to_str().unwrap()]
                .into_iter()
                .map(|s| s.to_string())
                .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir.unwrap(), "/tmp/vlsd");
        assert!(args.velocity_control.is_some());
        // config file overrides command line because it comes last
        assert_eq!(args.network, Network::Regtest);
    }
}
