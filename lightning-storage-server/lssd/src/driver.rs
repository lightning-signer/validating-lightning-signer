use std::process;

use clap::{value_parser, Arg, ArgAction, Command};
use log::{info, warn};

#[cfg(not(feature = "dangerous-flags"))]
use log::error;

#[cfg(feature = "etcd")]
use crate::database::etcd::{EtcdDatabase, ETCD_PASSWORD, ETCD_URLS, ETCD_USERNAME};
#[cfg(feature = "postgres")]
use crate::database::postgres;
use crate::database::redb::RedbDatabase;
use crate::util::setup_logging;
use crate::util::{init_secret_key, read_public_key, read_secret_key};
use crate::LightningStorageServer;
use crate::StorageServer;
use tonic::transport::{server::ServerTlsConfig, Identity};

pub const SERVER_APP_NAME: &str = "lssd";
#[cfg(all(not(feature = "postgres"), not(feature = "etcd")))]
const DATABASES: [&str; 1] = ["redb"];
#[cfg(all(feature = "postgres", not(feature = "etcd")))]
const DATABASES: [&str; 2] = ["redb", "postgres"];
#[cfg(all(feature = "etcd", not(feature = "postgres")))]
const DATABASES: [&str; 2] = ["redb", "etcd"];
#[cfg(all(feature = "etcd", feature = "postgres"))]
const DATABASES: [&str; 3] = ["redb", "postgres", "etcd"];

fn configure_tls(
    server: tonic::transport::Server,
    matches: &clap::ArgMatches,
    datadir: &std::path::PathBuf,
) -> Result<tonic::transport::Server, Box<dyn std::error::Error>> {
    if !matches.contains_id("grpc-tls-key") {
        return Ok(server);
    }

    let mut key_file = datadir.clone();
    key_file.push(matches.get_one::<String>("grpc-tls-key").unwrap());
    let key = std::fs::read(key_file).map_err(|_| "could not read key file")?;

    let mut cert_file = datadir.clone();
    cert_file.push(matches.get_one::<String>("grpc-tls-certificate").unwrap());
    let cert = std::fs::read(cert_file).map_err(|_| "could not read certificate file")?;

    let identity = Identity::from_pem(cert, key);
    let tls_config = ServerTlsConfig::new().identity(identity);

    let tls_config = match matches.get_one::<String>("grpc-tls-authority") {
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
    let app = Command::new(SERVER_APP_NAME)
        .about("Lightning Storage Server with a gRPC interface.")
        .arg(
            Arg::new("interface")
                .help("the interface to listen on (ip v4 or v6)")
                .short('i')
                .long("interface")
                .num_args(1)
                .value_name("0.0.0.0")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("port")
                .help("the port to listen")
                .short('p')
                .long("port")
                .num_args(1)
                .value_parser(value_parser!(usize))
                .default_value("55551"),
        )
        .arg(
            Arg::new("grpc-tls-certificate")
                .help("Server identity certificate")
                .long("grpc-tls-certificate")
                .num_args(1)
                .requires("grpc-tls-key"),
        )
        .arg(
            Arg::new("grpc-tls-key")
                .long("grpc-tls-key")
                .help("Server identity key")
                .num_args(1)
                .requires("grpc-tls-certificate"),
        )
        .arg(
            Arg::new("grpc-tls-authority")
                .long("grpc-tls-authority")
                .help("Certificate authority to verify client certificates (requires TLS to be configured with --grpc-tls-key and --grpc-tls-certificate)")
                .num_args(1)
                .requires_all(&["grpc-tls-certificate", "grpc-tls-key"]),
        )
        .arg(
            Arg::new("cleardb")
                .help("clear the database on startup")
                .short('c')
                .long("cleardb")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("datadir")
                .help("data directory")
                .long("datadir")
                .num_args(1)
                .default_value(".lss"),
        )
        .arg(
            Arg::new("database")
                .long("database")
                .help("specify DB backend")
                .num_args(1)
                .default_value("redb")
                .value_parser(DATABASES),
        );
    let matches = app.get_matches();

    setup_logging("lssd", "info");

    let addr = format!(
        "{}:{}",
        matches.get_one::<String>("interface").unwrap(),
        matches.get_one::<usize>("port").unwrap()
    )
    .parse()?;
    let home_dir = dirs::home_dir().ok_or("home directory not found")?;
    let datadir_opt = matches.get_one::<String>("datadir").unwrap();
    let mut datadir = home_dir;
    datadir.push(datadir_opt);

    // ignore failure - we may be already initialized
    let _ = init_secret_key("server_key");
    let secret_key = read_secret_key("server_key")?;
    let public_key = read_public_key("server_key")?;

    let clear_db = matches.get_flag("cleardb");

    #[cfg(not(feature = "dangerous-flags"))]
    if clear_db {
        error!("--cleardb is a dangerous flag and is only available with the dangerous-flags compilation feature");
        return Err("flag not available".into());
    }

    let database: Box<dyn crate::database::Database> = match matches.get_one::<String>("database") {
        #[cfg(feature = "postgres")]
        Some(db) if db.as_str() == "postgres" => Box::new(
            if clear_db { postgres::new_and_clear().await } else { postgres::new().await }.unwrap(),
        ),
        Some(db) if db.as_str() == "redb" => Box::new(
            if clear_db {
                RedbDatabase::new_and_clear(datadir.clone()).await
            } else {
                RedbDatabase::new(datadir.clone()).await
            }
            .unwrap_or_else(|err| panic!("trouble opening redb in {:?}: {}", datadir, err)),
        ),
        #[cfg(feature = "etcd")]
        Some(db) if db.as_str() == "etcd" => {
            let etcd_url_raw =
                std::env::var(ETCD_URLS).ok().unwrap_or("http://localhost:2379".to_string());
            let etcd_url = etcd_url_raw.split(",").collect();
            let etcd_user = std::env::var(ETCD_USERNAME).ok();
            let etcd_password = std::env::var(ETCD_PASSWORD).ok();

            let auth_credentials = if etcd_user != None && etcd_password != None {
                Some((etcd_user.unwrap(), etcd_password.unwrap()))
            } else {
                None
            };

            let etcd = EtcdDatabase::new(etcd_url, auth_credentials).await?;
            if clear_db {
                etcd.clear().await?;
            }
            Box::new(etcd)
        }
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
