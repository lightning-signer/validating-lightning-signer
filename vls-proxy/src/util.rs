use clap::{arg, AppSettings};
#[cfg(feature = "main")]
use clap::{App, Arg, ArgMatches};
use log::*;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{env, fs};
use std::path::{Path, PathBuf};
use time::macros::format_description;
use time::OffsetDateTime;
use tokio::runtime::{self, Runtime};

use lightning_signer::bitcoin::Network;
use lightning_signer::policy::filter::PolicyFilter;
use lightning_signer::policy::simple_validator::{make_simple_policy, SimpleValidatorFactory};
use lightning_signer::util::crypto_utils::generate_seed;
use lightning_signer::util::velocity::VelocityControlSpec;
use lightning_signer::Arc;

#[macro_export]
macro_rules! log_pretty {
    ($level:ident, $err:expr) => {
        #[cfg(not(feature = "log_pretty_print"))]
        $level!("{:?}", $err);
        #[cfg(feature = "log_pretty_print")]
        $level!("{:#?}", $err);
    };

    ($level:ident, $err:expr, $self:expr) => {
        #[cfg(not(feature = "log_pretty_print"))]
        $level!("{:?}: {:?}", $self.client_id, $err);
        #[cfg(feature = "log_pretty_print")]
        $level!("{:?}: {:#?}", $self.client_id, $err);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)+) => {
        log_pretty!(error, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_request {
    ($($arg:tt)+) => {
        log_pretty!(debug, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_reply {
    ($reply_bytes:expr) => {
        if log::log_enabled!(log::Level::Debug) {
            let reply = msgs::from_vec($reply_bytes.clone()).expect("parse reply failed");
            log_pretty!(debug, reply);
        }
    };
    ($reply_bytes:expr, $self:expr) => {
        if log::log_enabled!(log::Level::Debug) {
            let reply = msgs::from_vec($reply_bytes.clone()).expect("parse reply failed");
            log_pretty!(debug, reply, $self);
        }
    };
}

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

pub fn read_integration_test_seed<P: AsRef<Path>>(datadir: P) -> Option<[u8; 32]> {
    let path = PathBuf::from(datadir.as_ref()).join("hsm_secret");
    warn!("reading integration hsm_secret from {:?}", path);
    let result = fs::read(path);
    if let Ok(data) = result {
        Some(data.as_slice().try_into().expect("hsm_secret wrong length"))
    } else {
        None
    }
}

fn write_integration_test_seed<P: AsRef<Path>>(datadir: P, seed: &[u8; 32]) {
    let path = PathBuf::from(datadir.as_ref()).join("hsm_secret");
    warn!("writing integration hsm_secret to {:?}", path);
    fs::write(path, seed).expect("writing hsm_secret");
}

/// Read integration test seed, and generate/persist it if it's missing
pub fn integration_test_seed_or_generate(seeddir: Option<PathBuf>) -> [u8; 32] {
    let seeddir = seeddir.unwrap_or(PathBuf::from("."));
    match read_integration_test_seed(&seeddir) {
        None => {
            let seed = generate_seed();
            write_integration_test_seed(&seeddir, &seed);
            seed
        }
        Some(seed) => seed,
    }
}

#[cfg(feature = "main")]
pub fn setup_logging(datadir: &str, who: &str, level_arg: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    use std::str::FromStr;

    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());
    let logfile = format!("{}/{}.log", datadir, who.to_string());
    let who = who.to_string();
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
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
        .chain(fern::log_file(logfile).expect("log file"))
        .apply()
        .expect("log config");
}

#[cfg(feature = "main")]
pub fn add_hsmd_args(app: App) -> App {
    app.setting(AppSettings::NoAutoVersion)
        .arg(
            Arg::new("dev-disconnect")
                .help("ignored dev flag")
                .long("dev-disconnect")
                .takes_value(true),
        )
        .arg(Arg::new("log-io").long("log-io").help("ignored dev flag"))
        .arg(arg!(--version "show a dummy version"))
        .arg(Arg::new("git-desc").long("git-desc").help("print git desc version and exit"))
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
    make_validator_factory_with_filter(network, None)
}

/// Make a standard validation factory, with an optional filter specification,
/// allowing VLS_PERMISSIVE env var to override
pub fn make_validator_factory_with_filter(
    network: Network,
    filter_opt: Option<PolicyFilter>,
) -> Arc<SimpleValidatorFactory> {
    make_validator_factory_with_filter_and_velocity(
        network,
        filter_opt,
        VelocityControlSpec::UNLIMITED,
    )
}

/// Make a standard validation factory, with an optional filter specification,
/// allowing VLS_PERMISSIVE env var to override, and a global velocity control
pub fn make_validator_factory_with_filter_and_velocity(
    network: Network,
    filter_opt: Option<PolicyFilter>,
    velocity_spec: VelocityControlSpec,
) -> Arc<SimpleValidatorFactory> {
    let mut policy = make_simple_policy(network);
    policy.global_velocity_control = velocity_spec;

    if env::var("VLS_PERMISSIVE") == Ok("1".to_string()) {
        warn!("VLS_PERMISSIVE: ALL POLICY ERRORS ARE REPORTED AS WARNINGS");
        policy.filter = PolicyFilter::new_permissive();
    } else {
        if let Some(f) = filter_opt {
            policy.filter.merge(f);
        }
        info!("VLS_ENFORCING: ALL POLICY ERRORS ARE ENFORCED");
    }

    Arc::new(SimpleValidatorFactory::new_with_policy(policy))
}

/// Determine if we should auto approve payments
pub fn should_auto_approve() -> bool {
    if env::var("VLS_PERMISSIVE") == Ok("1".to_string()) {
        warn!("VLS_PERMISSIVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        true
    } else if env::var("VLS_AUTOAPPROVE") == Ok("1".to_string()) {
        warn!("VLS_AUTOAPPROVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        true
    } else {
        info!("VLS_ENFORCING: ALL INVOICES, KEYSENDS, AND PAYMENTS REQUIRE APPROVAL");
        false
    }
}

/// Abort on panic.
/// Use this instead of `panic = abort` in Cargo.toml, which doesn't show
/// nice backtraces.
pub fn abort_on_panic() {
    let old = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        old(info);
        std::process::abort();
    }));
}

// Would prefer to use now_local but https://rustsec.org/advisories/RUSTSEC-2020-0071
// Also, https://time-rs.github.io/api/time/struct.OffsetDateTime.html#method.now_local
pub fn tstamp() -> String {
    OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
        ))
        .expect("formatted tstamp")
}
