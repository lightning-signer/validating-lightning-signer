use std::process;

use clap::{App, Arg};
use log::{info, warn};

use crate::database::postgres;
use crate::database::sled::SledDatabase;
use crate::server::LightningStorageServer;
use crate::server::StorageServer;
use crate::util::{init_secret_key, read_public_key, read_secret_key, setup_logging};

pub const SERVER_APP_NAME: &str = "lssd";

#[tokio::main(worker_threads = 2)]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} {} starting", SERVER_APP_NAME, process::id());
    let app = App::new(SERVER_APP_NAME)
        .about("Lightning Storage Server with a gRPC interface.")
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
        )
        .arg(
            Arg::new("database")
                .long("database")
                .about("specify DB backend")
                .takes_value(true)
                .default_value("sled")
                .possible_values(&["sled", "postgres"]),
        );
    let matches = app.get_matches();

    setup_logging("lssd", "info");

    let addr =
        format!("{}:{}", matches.value_of("interface").unwrap(), matches.value_of("port").unwrap())
            .parse()?;
    let home_dir = dirs::home_dir().ok_or("home directory not found")?;
    let datadir_opt = matches.value_of("datadir").unwrap();
    let mut datadir = home_dir;
    datadir.push(datadir_opt);

    // ignore failure - we may be already initialized
    let _ = init_secret_key("server_key");
    let secret_key = read_secret_key("server_key")?;
    let public_key = read_public_key("server_key")?;

    let database: Box<dyn crate::database::Database> = match matches.value_of("database") {
        Some("postgres") => Box::new(postgres::new().await.unwrap()),
        None | Some("sled") => Box::new(SledDatabase::new(datadir.clone()).await.unwrap()),
        Some(v) => Err(format!("unsupported option for --database: {}", v))?,
    };

    let server = StorageServer { database, public_key, secret_key };
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();

    ctrlc::set_handler(move || {
        warn!("ctrl-C");
        shutdown_trigger.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let service = tonic::transport::Server::builder()
        .add_service(LightningStorageServer::new(server))
        .serve_with_shutdown(addr, shutdown_signal);
    info!("{} {} ready on {} datadir {}", SERVER_APP_NAME, process::id(), addr, datadir.display());
    service.await?;
    info!("{} {} finished", SERVER_APP_NAME, process::id());
    Ok(())
}
