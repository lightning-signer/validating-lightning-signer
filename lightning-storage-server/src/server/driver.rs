use std::{env, process};

use clap::{App, Arg};
use log::{info, warn};

use crate::server::LightningStorageServer;
use crate::server::StorageServer;
use crate::Database;

pub const SERVER_APP_NAME: &str = "lssd";

#[tokio::main(worker_threads = 2)]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} {} starting", SERVER_APP_NAME, process::id());
    let app = App::new(SERVER_APP_NAME)
        .about(
            "Validating Lightning Signer with a gRPC interface.  Persists to .lightning-signer .",
        )
        .arg(
            Arg::new("interface")
                .about("the interface to listen on (ip v4 or v6)")
                .short('i')
                .long("interface")
                .takes_value(true)
                .value_name("0.0.0.0")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .about("the port to listen")
                .short('p')
                .long("port")
                .takes_value(true)
                .default_value("55551"),
        )
        .arg(
            Arg::new("datadir")
                .about("data directory")
                .long("datadir")
                .takes_value(true)
                .default_value(".lss"),
        );
    let matches = app.get_matches();

    setup_logging("lssd", "info");

    let addr =
        format!("{}:{}", matches.value_of("interface").unwrap(), matches.value_of("port").unwrap())
            .parse()?;
    let datadir = matches.value_of("datadir").unwrap();
    let database = Database::new(datadir).unwrap();
    let server = StorageServer { database };
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();

    ctrlc::set_handler(move || {
        warn!("ctrl-C");
        shutdown_trigger.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let service = tonic::transport::Server::builder()
        .add_service(LightningStorageServer::new(server))
        .serve_with_shutdown(addr, shutdown_signal);
    info!("{} {} ready on {} datadir {}", SERVER_APP_NAME, process::id(), addr, datadir);
    service.await?;
    info!("{} {} finished", SERVER_APP_NAME, process::id());
    Ok(())
}

fn setup_logging(who: &str, level_arg: &str) {
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
