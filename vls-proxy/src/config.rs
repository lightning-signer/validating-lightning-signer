use clap::{CommandFactory, Parser};
use lightning_signer::bitcoin::Network;
use lightning_signer::policy::filter::{FilterResult, FilterRule};
use lightning_signer::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};
use std::{env, fs};
use toml::value::{Table, Value};
use url::Url;

use lightning_signer_server::{CLAP_NETWORK_URL_MAPPING, NETWORK_NAMES};

const DEFAULT_DIR: &str = ".lightning-signer";

// only used for usage display
#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
pub struct InitialArgs {
    #[clap(short = 'f', long, value_parser, help = "configuration file")]
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
        help = "send a force-close transaction to the given address",
        value_name = "BITCOIN_ADDRESS"
    )]
    pub recover_close: Option<String>,

    #[clap(long, value_parser=parse_velocity_control_spec, help = "global velocity control e.g. hour:10000 (satoshi)")]
    pub velocity_control: Option<VelocityControlSpec>,

    #[clap(long, value_parser=parse_filter_rule, help = "policy filter rule, e.g. 'policy-channel-safe-mode:warn' or 'policy-channel-*:error'")]
    pub policy_filter: Vec<FilterRule>,
}

pub fn parse_args_and_config<A: Parser>() -> A {
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

    #[test]
    fn test_parse_velocity_control_spec() {
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
    fn test_parse_filter_rule() {
        assert!(parse_filter_rule("policy-channel-safe-mode:warn").is_ok());
        assert!(parse_filter_rule("policy-channel-safe-mode:foo").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode:").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode:*").is_err());
        assert!(parse_filter_rule("policy-channel-safe-mode-*:warn").is_ok());
    }
}
