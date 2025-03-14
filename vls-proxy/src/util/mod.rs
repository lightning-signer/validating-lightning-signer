mod env_var;
mod r#macro;
pub mod observability;
mod rpc_cookie;
mod testing;
mod validation;

pub use rpc_cookie::get_rpc_credentials;

#[cfg(feature = "otlp")]
mod otlp;

pub use env_var::*;
pub use testing::*;
pub use validation::*;

use clap::arg;
#[cfg(feature = "main")]
use clap::{Arg, ArgAction, ArgMatches, Command};
use log::*;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use time::{macros::format_description, OffsetDateTime};
use tokio::runtime::{self, Runtime};

pub fn line_filter(line: &str) -> Option<String> {
    let whitespace_removed = line.trim();
    if whitespace_removed.is_empty() {
        return None;
    }
    let comment_removed = whitespace_removed.split('#').next()?.trim();
    if comment_removed.is_empty() {
        return None;
    }
    Some(comment_removed.to_string())
}

pub fn read_allowlist() -> Vec<String> {
    if let Ok(allowlist_path) = env::var("REMOTE_SIGNER_ALLOWLIST") {
        return read_allowlist_path(&allowlist_path);
    }
    Vec::new()
}

pub fn read_allowlist_path(path: &str) -> Vec<String> {
    let file = File::open(path).expect(format!("open {} failed", path).as_str());
    let allowlist: Vec<String> =
        BufReader::new(file).lines().filter_map(|l| line_filter(&l.expect("line"))).collect();

    allowlist
}

#[cfg(feature = "main")]
pub fn setup_logging<P: AsRef<Path>>(datadir: P, who: &str, level_arg: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    use std::str::FromStr;

    // Should we support seperate console and file log levels?
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());

    // file
    let who_clone = who.to_string();
    let logfile = datadir.as_ref().join(format!("{}.log", who));
    let file_config = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
                who_clone,
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .chain(fern::log_file(logfile).expect("file log config"));

    // console
    let who_clone = who.to_string();
    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let console_config = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
                who_clone,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .chain(std::io::stdout());

    fern::Dispatch::new().chain(console_config).chain(file_config).apply().expect("log config");
}

#[cfg(feature = "main")]
pub fn add_hsmd_args(app: Command) -> Command {
    app.version("1.0.0")
        .disable_version_flag(true)
        .arg(
            Arg::new("dev-disconnect")
                .action(ArgAction::SetTrue)
                .help("ignored dev flag")
                .long("dev-disconnect"),
        )
        .arg(
            Arg::new("developer")
                .long("developer")
                .action(ArgAction::SetTrue)
                .help("ignored dev flag"),
        )
        .arg(Arg::new("log-io").long("log-io").action(ArgAction::SetTrue).help("ignored dev flag"))
        .arg(arg!(--version "show a dummy version"))
        .arg(
            Arg::new("git-desc")
                .long("git-desc")
                .help("print git desc version and exit")
                .action(ArgAction::SetTrue),
        )
}

#[cfg(feature = "main")]
pub fn handle_hsmd_version(matches: &ArgMatches) -> bool {
    if matches.contains_id("version") {
        // Pretend to be the right version, given to us by an env var
        let version = vls_cln_version();
        println!("{}", version);
        true
    } else {
        false
    }
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

/// Determine if we should auto approve payments
pub fn should_auto_approve() -> bool {
    if compare_env_var("VLS_PERMISSIVE", "1") {
        warn!("VLS_PERMISSIVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        return true;
    }

    if compare_env_var("VLS_AUTOAPPROVE", "1") {
        warn!("VLS_AUTOAPPROVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        return true;
    }

    info!("VLS_ENFORCING: ALL INVOICES, KEYSENDS, AND PAYMENTS REQUIRE APPROVAL");
    false
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
#[cfg(feature = "main")]
pub fn tstamp() -> String {
    OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
        ))
        .expect("formatted tstamp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn line_filter_test() {
        assert_eq!(line_filter("#"), None);
        assert_eq!(
            line_filter("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z # comment"),
            Some("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string())
        );
        assert_eq!(line_filter("   "), None);
        assert_eq!(line_filter("   #   "), None);
        assert_eq!(
            line_filter("   tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z   "),
            Some("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string())
        );
    }

    #[test]
    fn read_allowlist_test() {
        let test_file_content = "\
        # Sample Allowlist
        tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z
        tb1qexampleaddress1234567890123456789012345678

        # Another comment line after blank line
    ";
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "{}", test_file_content).unwrap();
        let allowlist = read_allowlist_path(temp_file.path().to_str().unwrap());
        assert_eq!(
            allowlist,
            vec![
                "tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string(),
                "tb1qexampleaddress1234567890123456789012345678".to_string(),
            ]
        );
        temp_file.close().unwrap();
    }
}
