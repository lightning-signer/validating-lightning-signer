use clap::{ErrorKind, Parser};
use lightning_signer::bitcoin::Network;
use lightning_signer::policy::filter::{FilterResult, FilterRule};
use lightning_signer::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{env, fs};
use toml::value::{Table, Value};
use url::Url;

/// Network names
pub const NETWORK_NAMES: &[&str] = &["testnet", "regtest", "signet", "bitcoin"];

/// Useful with clap's `Arg::default_value_ifs`
pub const CLAP_NETWORK_URL_MAPPING: &[(&str, Option<&str>, Option<&str>)] = &[
    ("network", Some("bitcoin"), Some("http://user:pass@127.0.0.1:8332")),
    ("network", Some("testnet"), Some("http://user:pass@127.0.0.1:18332")),
    ("network", Some("regtest"), Some("http://user:pass@127.0.0.1:18443")),
    ("network", Some("signet"), Some("http://user:pass@127.0.0.1:18443")),
];

const DEFAULT_DIR: &str = ".lightning-signer";

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
#[clap(about, long_about = None)]
pub struct SignerArgs {
    #[clap(flatten)]
    initial_args: InitialArgs,

    #[clap(long, help = "print git desc version and exit")]
    pub git_desc: bool,

    #[clap(
        long,
        value_parser,
        help = "set the logging level",
        value_name = "LEVEL",
        default_value = "debug",
        possible_values = &["off", "error", "warn", "info", "debug", "trace"],
    )]
    pub log_level: String,

    #[clap(short, long, value_parser, default_value = DEFAULT_DIR, help = "data directory", value_name = "DIR")]
    pub datadir: String,

    #[clap(short, long, value_parser,
        value_name = "NETWORK",
        possible_values = NETWORK_NAMES,
        default_value = NETWORK_NAMES[0]
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
        default_value_ifs(CLAP_NETWORK_URL_MAPPING),
        value_name = "URL"
    )]
    pub recover_rpc: Option<Url>,

    #[clap(
        long,
        value_parser,
        help = "block explorer type - used for broadcasting recovery transactions",
        value_name = "TYPE",
        default_value = "bitcoind",
        possible_values = &["bitcoind", "esplora"]
    )]
    pub recover_type: String,

    #[clap(
        long,
        value_parser,
        help = "recover funds by force-closing channels and sweeping funds to the given address",
        value_name = "BITCOIN_ADDRESS"
    )]
    pub recover_close: Option<String>,

    #[clap(long, value_parser=parse_velocity_control_spec, help = "global velocity control e.g. hour:10000 (satoshi)")]
    pub velocity_control: Option<VelocityControlSpec>,

    #[clap(long, value_parser=parse_filter_rule, help = "policy filter rule, e.g. 'policy-channel-safe-mode:warn' or 'policy-channel-*:error'")]
    pub policy_filter: Vec<FilterRule>,
}

impl HasSignerArgs for SignerArgs {
    fn signer_args(&self) -> &SignerArgs {
        self
    }
}

pub fn parse_args_and_config<A: Parser + HasSignerArgs>(bin_name: &str) -> A {
    let env_args = env::args().collect::<Vec<_>>();
    parse_args_and_config_from(bin_name, &env_args).unwrap_or_else(|e| e.exit())
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
        println!("{} git_desc={}", bin_name, crate::GIT_DESC);
        // signal caller to exit
        return Err(clap::Error::raw(ErrorKind::DisplayHelp, ""));
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
    Ok(VelocityControlSpec { interval_type, limit })
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
            vec!["vlsd2", "--git-desc"].into_iter().map(|s| s.to_string()).collect();
        let args_res: Result<SignerArgs, _> = parse_args_and_config_from("", &env_args);
        assert!(args_res.is_err());
    }

    #[test]
    fn clap_test() {
        let env_args: Vec<String> = vec!["vlsd2"].into_iter().map(|s| s.to_string()).collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert!(args.policy_filter.is_empty());
        assert!(args.velocity_control.is_none());

        let env_args: Vec<String> = vec![
            "vlsd2",
            "--datadir=/tmp/vlsd2",
            "--network=regtest",
            "--integration-test",
            "--recover-rpc=http://localhost:3000",
            "--policy-filter",
            "policy-channel-safe-mode:warn",
            "--velocity-control",
            "hour:100",
            "--recover-close",
            "abc123",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir, "/tmp/vlsd2");
        assert_eq!(args.policy_filter.len(), 1);
        assert!(args.velocity_control.is_some());
        assert_eq!(args.network, Network::Regtest);
        assert!(args.integration_test);
        assert_eq!(args.recover_rpc.unwrap().as_str(), "http://localhost:3000/");
        assert_eq!(args.recover_type, "bitcoind");
        assert_eq!(args.recover_close.unwrap().as_str(), "abc123");
    }

    #[test]
    fn clap_with_config_file_test() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "datadir = \"/tmp/vlsd2\"\n\
        velocity-control = \"day:222\"\n\
        network = \"regtest\"\n\
        "
        )
        .unwrap();
        let env_args: Vec<String> =
            vec!["vlsd2", "--config", file.path().to_str().unwrap(), "--network=bitcoin"]
                .into_iter()
                .map(|s| s.to_string())
                .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir, "/tmp/vlsd2");
        assert!(args.velocity_control.is_some());
        // command line args override config file
        assert_eq!(args.network, Network::Bitcoin);

        let env_args: Vec<String> =
            vec!["vlsd2", "--network=bitcoin", "--config", file.path().to_str().unwrap()]
                .into_iter()
                .map(|s| s.to_string())
                .collect();
        let args: SignerArgs = parse_args_and_config_from("", &env_args).unwrap();
        assert_eq!(args.datadir, "/tmp/vlsd2");
        assert!(args.velocity_control.is_some());
        // config file overrides command line because it comes last
        assert_eq!(args.network, Network::Regtest);
    }
}
