#[cfg(feature = "main")]
use clap::{App, Arg, ArgMatches};
use log::info;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{env, fs};

use lightning_signer::bitcoin::Network;
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::Arc;
use tokio::runtime::{self, Runtime};

pub fn read_allowlist() -> Vec<String> {
    let allowlist_path_res = env::var("ALLOWLIST");
    if let Ok(allowlist_path) = allowlist_path_res {
        let file =
            File::open(&allowlist_path).expect(format!("open {} failed", &allowlist_path).as_str());
        BufReader::new(file).lines().map(|l| l.expect("line")).collect()
    } else {
        Vec::new()
    }
}

pub fn read_integration_test_seed() -> Option<[u8; 32]> {
    let result = fs::read("hsm_secret");
    if let Ok(data) = result {
        Some(data.as_slice().try_into().expect("hsm_secret wrong length"))
    } else {
        None
    }
}

#[cfg(feature = "main")]
pub fn setup_logging(who: &str, level_arg: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    use std::str::FromStr;

    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());
    let who = who.to_string();
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                who,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .level_for("sled", log::LevelFilter::Info)
        .chain(std::io::stdout())
        // .chain(fern::log_file("/tmp/output.log")?)
        .apply()
        .expect("log config");
}

#[cfg(feature = "main")]
pub fn add_hsmd_args(app: App) -> App {
    app.arg(
        Arg::new("dev-disconnect")
            .about("ignored dev flag")
            .long("dev-disconnect")
            .takes_value(true),
    )
    .arg(Arg::from("--log-io ignored dev flag"))
    .arg(Arg::from("--version show a dummy version"))
}

#[cfg(feature = "main")]
pub fn handle_hsmd_version(matches: &ArgMatches) -> bool {
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        true
    } else {
        false
    }
}

pub fn bitcoind_rpc_url() -> String {
    env::var("BITCOIND_RPC_URL").expect("env var BITCOIND_RPC_URL")
}

pub fn vls_network() -> String {
    env::var("VLS_NETWORK").expect("env var VLS_NETWORK")
}

pub fn create_runtime(thread_name: &str) -> Runtime {
    let thrname = thread_name.to_string();
    std::thread::spawn(|| {
        runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name(thrname)
            .worker_threads(2) // for debugging
            .build()
    })
    .join()
    .expect("runtime join")
    .expect("runtime")
}

/// Make a standard validation factory, allowing VLS_PERMISSIVE env var to override
pub fn make_validator_factory(network: Network) -> Arc<SimpleValidatorFactory> {
    let mut policy = make_simple_policy(network);

    let warn_only =
        env::var("VLS_PERMISSIVE").map(|s| s.parse().expect("VLS_PERMISSIVE parse")).unwrap_or(0);
    if warn_only == 1 {
        info!("VLS_PERMISSIVE: ALL POLICY ERRORS ARE REPORTED AS WARNINGS");
        policy.filter = PolicyFilter::new_permissive();
    } else {
        info!("VLS_ENFORCING: ALL POLICY ERRORS ARE ENFORCED");
    }

    Arc::new(SimpleValidatorFactory::new_with_policy(policy))
}
