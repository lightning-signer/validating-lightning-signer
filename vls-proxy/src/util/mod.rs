mod env_var;

pub use env_var::*;

#[cfg(feature = "main")]
use clap::{Arg, ArgAction, ArgMatches, Command};
use tokio::runtime::{self, Runtime};

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
        .arg(
            Arg::new("log-io").long("log-io").action(ArgAction::SetTrue).help(
                "ignored flag to set log level as we rely on `RUST_LOG` environment variable",
            ),
        )
        .arg(
            Arg::new("log-trace").long("log-trace").action(ArgAction::SetTrue).help(
                "ignored flag to set log level as we rely on `RUST_LOG` environment variable",
            ),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::SetTrue)
                .help("show a dummy version"),
        )
        .arg(
            Arg::new("git-desc")
                .long("git-desc")
                .help("print git desc version and exit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("datadir")
                .long("datadir")
                .help("data directory")
                .action(ArgAction::Set)
                .default_value(".")
                .value_name("DIR"),
        )
}

#[cfg(feature = "main")]
pub fn handle_hsmd_version(matches: &ArgMatches) -> bool {
    if matches.get_flag("version") {
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
