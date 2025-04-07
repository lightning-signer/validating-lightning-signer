use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;

use anyhow::Result;
use clap::{App, Arg, ArgMatches};
use lightning_signer::bitcoin::Network;
use url::Url;

use lnrod::admin;
use lnrod::config::Config;
use lnrod::log_utils::{parse_log_level_filter, LOG_LEVEL_FILTER_NAMES};
use lnrod::node::NodeBuildArgs;
use lnrod::signer::SIGNER_NAMES;

fn main() -> Result<()> {
    let app = App::new("lnrod")
        .help("Lightning Rod Node")
        .arg(
            Arg::new("lnport")
                .help("Lightning peer listen port")
                .short('l')
                .long("lnport")
                .default_value("9901")
                .validator(|s| s.parse::<u16>())
                .takes_value(true),
        )
        .arg(
            Arg::new("rpcport")
                .help("Lightning peer listen port")
                .short('p')
                .long("rpcport")
                .default_value("8801")
                .validator(|s| s.parse::<u16>())
                .takes_value(true),
        )
        .arg(
            Arg::new("vlsport")
                .help("vlsd RPC port")
                .long("vlsport")
                .default_value("50051")
                .validator(|s| s.parse::<u16>())
                .takes_value(true),
        )
        .arg(
            Arg::new("datadir")
                .short('d')
                .long("datadir")
                .default_value("data")
                .help("data directory")
                .takes_value(true),
        )
        .arg(
            Arg::new("config")
                .short('f')
                .long("config")
                .help("config file, default DATADIR/config")
                .takes_value(true),
        )
        .arg(
            Arg::new("bitcoin")
                .help("Bitcoin RPC endpoint")
                .short('b')
                .long("bitcoin")
                .default_value("http://user:pass@localhost:18443")
                .takes_value(true),
        )
        .arg(Arg::new("regtest").long("regtest"))
        .arg(Arg::new("signet").long("signet"))
        .arg(Arg::new("tor").long("tor"))
        .arg(
            Arg::new("name")
                .long("name")
                .takes_value(true)
                .help("node name for p2p announcements, up to 32 bytes")
                .validator(|v| if v.len() <= 32 { Ok(()) } else { Err("more than 32 bytes long") }),
        )
        .arg(
            Arg::new("logleveldisk")
                .help("logging level to disk")
                .short('v')
                .long("log-level-disk")
                .possible_values(&LOG_LEVEL_FILTER_NAMES)
                .default_value("DEBUG")
                .takes_value(true),
        )
        .arg(
            Arg::new("loglevelconsole")
                .help("logging level to console")
                .short('V')
                .long("log-level-console")
                .possible_values(&LOG_LEVEL_FILTER_NAMES)
                .default_value("INFO")
                .takes_value(true),
        )
        .arg(
            Arg::new("signer")
                .help("signer name - use vls for a remote Validating Lightning Signer")
                .long("signer")
                .possible_values(SIGNER_NAMES)
                .default_value(SIGNER_NAMES[0])
                .takes_value(true),
        )
        .arg(Arg::new("dump-config").long("dump-config"));
    let matches = app.clone().get_matches();

    let config = if matches.is_present("config") {
        get_config(&matches, &matches.value_of_t("config").unwrap())
    } else {
        Config::default()
    };

    if matches.is_present("dump-config") {
        println!("{}", toml::to_string(&config).unwrap());
        return Ok(());
    }

    let data_dir = arg_value_or_config("datadir", &matches, &config.data_dir);

    let bitcoin_url =
        Url::parse(arg_value_or_config("bitcoin", &matches, &config.bitcoin_rpc).as_str())?;

    // Network can be specified on the command line or in the config file
    let network = if matches.occurrences_of("regtest") > 0 || config.regtest.unwrap_or(false) {
        Network::Regtest
    } else if matches.occurrences_of("signet") > 0 || config.signet.unwrap_or(false) {
        Network::Signet
    } else {
        Network::Testnet
    };

    let console_log_level = parse_log_level_filter(arg_value_or_config(
        "loglevelconsole",
        &matches,
        &config.log_level_console,
    ))
    .expect("log-level-console");
    let disk_log_level = parse_log_level_filter(arg_value_or_config(
        "logleveldisk",
        &matches,
        &config.log_level_disk,
    ))
    .expect("log-level-disk");

    let peer_listening_port = arg_value_or_config("lnport", &matches, &config.ln_port);
    let rpc_port = arg_value_or_config("rpcport", &matches, &config.rpc_port);
    let vls_port = arg_value_or_config("vlsport", &matches, &config.vls_port);

    let signer_name = arg_value_or_config("signer", &matches, &config.signer);

    let tor = arg_value_or_config_bool("tor", &matches, &config.tor);
    let name = maybe_arg_value_or_config("name", &matches, &config.name);

    let args = NodeBuildArgs {
        bitcoind_rpc_username: bitcoin_url.username().to_string(),
        bitcoind_rpc_password: bitcoin_url.password().unwrap_or("").to_string(),
        bitcoind_rpc_host: bitcoin_url.host_str().expect("host").to_string(),
        bitcoind_rpc_port: bitcoin_url.port().expect("port"),
        bitcoind_rpc_path: bitcoin_url.path().to_string(),
        storage_dir_path: data_dir,
        peer_listening_port,
        vls_port,
        network,
        disk_log_level,
        console_log_level,
        signer_name,
        tor,
        name,
        config,
    };

    admin::driver::start(rpc_port, args).expect("gRPC driver start");
    Ok(())
}

fn arg_value_or_config<T: Clone + FromStr>(
    name: &str,
    matches: &ArgMatches,
    config_value: &Option<T>,
) -> T
where
    <T as FromStr>::Err: std::fmt::Display,
{
    let arg = matches.value_of_t_or_exit(name);
    if matches.occurrences_of(name) > 0 {
        arg
    } else {
        config_value.clone().unwrap_or(arg)
    }
}

fn arg_value_or_config_bool(name: &str, matches: &ArgMatches, config_value: &Option<bool>) -> bool {
    if matches.occurrences_of(name) > 0 {
        true
    } else {
        config_value.clone().unwrap_or(false)
    }
}

fn maybe_arg_value_or_config<T: Clone + FromStr>(
    name: &str,
    matches: &ArgMatches,
    config_value: &Option<T>,
) -> Option<T>
where
    <T as FromStr>::Err: std::fmt::Display,
{
    matches.value_of_t(name).ok().or_else(|| config_value.clone())
}

fn get_config(matches: &ArgMatches, config_path: &String) -> Config {
    let config_exists = Path::new(&config_path).exists();
    if matches.is_present("config") && !config_exists {
        panic!("missing config file");
    }
    let config: Config = if config_exists {
        let contents = read_to_string(config_path).unwrap();
        toml::from_str(contents.as_str()).unwrap()
    } else {
        Default::default()
    };
    config
}
