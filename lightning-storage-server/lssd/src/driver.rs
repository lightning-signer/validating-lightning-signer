use std::process;

use clap::{App, Arg};
use log::{info, warn};

#[cfg(not(feature = "dangerous-flags"))]
use log::error;

#[cfg(feature = "postgres")]
use crate::database::postgres;
use crate::database::redb::RedbDatabase;
use crate::util::setup_logging;
use crate::util::{init_secret_key, read_public_key, read_secret_key};
use crate::LightningStorageServer;
use crate::StorageServer;
use tonic::transport::{server::ServerTlsConfig, Identity};

pub const SERVER_APP_NAME: &str = "lssd";
#[cfg(feature = "postgres")]
const DATABASES: [&str; 2] = ["redb", "postgres"];
#[cfg(not(feature = "postgres"))]
const DATABASES: [&str; 1] = ["redb"];

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

    let mut cert_file = datadir.clone();
    cert_file.push(matches.value_of("grpc-tls-certificate").unwrap());
    let cert = std::fs::read(cert_file).map_err(|_| "could not read certificate file")?;

    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);

    let tls_config = match matches.value_of("grpc-tls-authority") {
        None => tls_config,
        Some(p) => {
            let mut ca_file = datadir.clone();
            ca_file.push(p);
            let ca = std::fs::read(ca_file).map_err(|_| "could not read key file")?;
            tls_config.client_ca_root(tonic::transport::Certificate::from_pem(ca))
        }
    };

    Ok(server.tls_config(tls_config)?)
}

#[tokio::main(worker_threads = 2)]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} {} starting", SERVER_APP_NAME, process::id());
    let app = App::new(SERVER_APP_NAME)
        .help("Lightning Storage Server with a gRPC interface.")
        .arg(
            Arg::new("interface")
                .help("the interface to listen on (ip v4 or v6)")
                .short('i')
                .long("interface")
                .takes_value(true)
                .value_name("0.0.0.0")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .help("the port to listen")
                .short('p')
                .long("port")
                .takes_value(true)
                .default_value("55551"),
        )
        .arg(
            Arg::new("grpc-tls-certificate")
                .help("Server identity certificate")
                .long("grpc-tls-certificate")
                .takes_value(true)
                .requires("grpc-tls-key"),
        )
        .arg(
            Arg::new("grpc-tls-key")
                .long("grpc-tls-key")
                .help("Server identity key")
                .takes_value(true)
                .requires("grpc-tls-certificate"),
        )
        .arg(
            Arg::new("grpc-tls-authority")
                .long("grpc-tls-authority")
                .help("Certificate authority to verify client certificates (requires TLS to be configured with --grpc-tls-key and --grpc-tls-certificate)")
                .takes_value(true)
                .requires_all(&["grpc-tls-certificate", "grpc-tls-key"]),
        )
        .arg(
            Arg::new("cleardb")
                .help("clear the database on startup")
                .short('c')
                .long("cleardb")
                .takes_value(false),
        )
        .arg(
            Arg::new("datadir")
                .help("data directory")
                .long("datadir")
                .takes_value(true)
                .default_value(".lss"),
        )
        .arg(
            Arg::new("database")
                .long("database")
                .help("specify DB backend")
                .takes_value(true)
                .default_value("redb")
                .possible_values(&DATABASES),
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

    let clear_db = matches.is_present("cleardb");

    #[cfg(not(feature = "dangerous-flags"))]
    if clear_db {
        error!("--cleardb is a dangerous flag and is only available with the dangerous-flags compilation feature");
        return Err("flag not available".into());
    }

    let database: Box<dyn crate::database::Database> = match matches.value_of("database") {
        #[cfg(feature = "postgres")]
        Some("postgres") => Box::new(
            if clear_db { postgres::new_and_clear().await } else { postgres::new().await }.unwrap(),
        ),
        Some("redb") => Box::new(
            if clear_db {
                RedbDatabase::new_and_clear(datadir.clone()).await
            } else {
                RedbDatabase::new(datadir.clone()).await
            }
            .unwrap_or_else(|err| panic!("trouble opening redb in {:?}: {}", datadir, err)),
        ),
        None => panic!("database not specified, even though there is a default value"),
        Some(v) => Err(format!("unsupported option for --database: {}", v))?,
    };

    let server = StorageServer { database, public_key, secret_key };
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();
    ctrlc::set_handler(move || {
        warn!("ctrlc handler triggering shutdown");
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
