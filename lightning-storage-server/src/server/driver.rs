use std::process;

use clap::{App, Arg};
use log::{info, warn};

use crate::database::sled::SledDatabase;
use crate::server::LightningStorageServer;
use crate::server::StorageServer;
use crate::util::{init_secret_key, read_public_key, read_secret_key, setup_logging};
use tonic::transport::{server::ServerTlsConfig, Identity};

pub const SERVER_APP_NAME: &str = "lssd";

fn configure_tls(
    server: tonic::transport::Server,
    matches: &clap::ArgMatches,
    datadir: &std::path::PathBuf,
) -> Result<tonic::transport::Server, Box<dyn std::error::Error>> {
    if !matches.is_present("grpc-tls-key") {
        return Ok(server);
    }

    let mut key_file = datadir.clone();
    key_file.push(matches.value_of("grpc-tls-key").unwrap());
    let key = std::fs::read(key_file).map_err(|_| "could not read key file")?;

    let mut cert_file = home_dir;
    cert_file.push(matches.value_of("grpc-tls-certificate").unwrap());
    let cert = std::fs::read(cert_file).map_err(|_| "could not read certificate file")?;

    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);

    Ok(server.tls_config(tls_config)?)
}

#[tokio::main(worker_threads = 2)]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} {} starting", SERVER_APP_NAME, process::id());
    let app = App::new(SERVER_APP_NAME)
        .about("Lightning Storage Server with a gRPC interface.  Persists to ~/.lss .")
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
            Arg::new("grpc-tls-certificate")
                .about("Server identity certificate")
                .long("grpc-tls-certificate")
                .takes_value(true)
                .requires("grpc-tls-key"),
        )
        .arg(
            Arg::new("grpc-tls-key")
                .long("grpc-tls-key")
                .about("Server identity key")
                .takes_value(true)
                .requires("grpc-tls-certificate"),
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
    let home_dir = dirs::home_dir().ok_or("home directory not found")?;
    let datadir_opt = matches.value_of("datadir").unwrap();
    let mut datadir = home_dir;
    datadir.push(datadir_opt);

    // ignore failure - we may be already initialized
    let _ = init_secret_key("server_key");
    let secret_key = read_secret_key("server_key")?;
    let public_key = read_public_key("server_key")?;

    let database = Box::new(SledDatabase::new(datadir.clone()).await.unwrap());
    let server = StorageServer { database, public_key, secret_key };
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();

    ctrlc::set_handler(move || {
        warn!("ctrl-C");
        shutdown_trigger.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let service = tonic::transport::Server::builder();

    let service = configure_tls(service, &matches, &datadir)?
        .add_service(LightningStorageServer::new(server))
        .serve_with_shutdown(addr, shutdown_signal);
    info!("{} {} ready on {} datadir {}", SERVER_APP_NAME, process::id(), addr, datadir.display());
    service.await?;
    info!("{} {} finished", SERVER_APP_NAME, process::id());
    Ok(())
}
