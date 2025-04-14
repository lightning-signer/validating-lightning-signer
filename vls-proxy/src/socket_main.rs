//! A drop-in replacement for hsmd, acting as a gRPC server for VLS
//!
//! Note that this gRPC protocol is different from the native VLS gRPC protocol.  This
//! protocol is a thin wrapper on top of the CLN hsmd wire protocol.  It also connects in the
//! opposite direction (signer -> node), which makes it more convenient if the signer is behind
//! NAT.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use clap::Command;
#[allow(unused_imports)]
use log::{error, info, warn};
use tokio::task::spawn_blocking;
use url::Url;

use lightning_signer::bitcoin::Network;

use vls_frontend::frontend::{
    DummySourceFactory, FileSourceFactory, HTTPSourceFactory, SourceFactory,
};
use vls_frontend::Frontend;

use client::UnixClient;
use connection::{open_parent_fd, UnixConnection};
use grpc::adapter::HsmdService;
use grpc::incoming::TcpIncoming;
use grpc::signer_loop::{GrpcSignerPort, SignerLoop};
use portfront::SignerPortFront;
use util::{add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version, vls_network};
use vls_proxy::grpc::signer_loop::InitMessageCache;
use vls_proxy::util::observability::init_tracing_subscriber;
use vls_proxy::util::txoo_source_url;
use vls_proxy::*;
use vlsd::util::{abort_on_panic, setup_logging};

/// Implement hsmd replacement that listens to connections from vlsd2.
#[tokio::main(worker_threads = 2)]
pub async fn main() {
    abort_on_panic();
    let parent_fd = open_parent_fd();

    let app = make_clap_app();
    let matches = app.get_matches();

    if matches.get_flag("git-desc") {
        println!("remote_hsmd_socket git_desc={}", GIT_DESC);
        return;
    }
    if handle_hsmd_version(&matches) {
        return;
    }

    let datadir: &String =
        matches.get_one::<String>("datadir").expect("datadir is always set using default argument");

    init_tracing_subscriber(datadir, "remote_hsmd_socket")
        .expect("failed to initalize traicng subscriber");
    info!("remote_hsmd_socket git_desc={} starting", GIT_DESC);

    // Unfortunately, we can't easily be passed arguments, so use env vars to configure
    let port = env::var("VLS_PORT").map(|s| s.parse().expect("VLS_PORT parse")).unwrap_or(7701);
    let addr = env::var("VLS_BIND")
        .map(|s| s.parse().expect("VLS_BIND parse"))
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let sock_addr = SocketAddr::from((addr, port));

    // Note that this is unsafe if we use the wrong fd
    let conn = UnixConnection::new(parent_fd);
    let client = UnixClient::new(conn);
    start_server(sock_addr, client).await;
}

fn make_clap_app() -> Command {
    let app = Command::new("signer")
        .about("CLN:socket - listens for a vlsd2 connection on port 7701 (or VLS_PORT if set)");
    add_hsmd_args(app)
}

// hsmd replacement entry point
async fn start_server(addr: SocketAddr, client: UnixClient) {
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();
    let trigger1 = shutdown_trigger.clone();
    ctrlc::set_handler(move || {
        warn!("ctrlc handler triggering shutdown");
        trigger1.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let init_message_cache = Arc::new(Mutex::new(InitMessageCache::new()));
    let server = HsmdService::new(
        shutdown_trigger.clone(),
        shutdown_signal.clone(),
        init_message_cache.clone(),
    );

    let incoming = TcpIncoming::new(addr, false).await.expect("listen incoming"); // new_from_std seems to be infallible

    let network = vls_network().parse::<Network>().expect("malformed vls network");
    let sender = server.sender();
    let signer_port = Arc::new(GrpcSignerPort::new(sender.clone()));
    let source_factory: Arc<dyn SourceFactory> = match txoo_source_url() {
        Some(url) => match Url::parse(&url) {
            Ok(http_url) => Arc::new(HTTPSourceFactory::new(http_url, network)),
            Err(_) => Arc::new(FileSourceFactory::new(url, network)),
        },
        None => Arc::new(DummySourceFactory::new(".", network)),
    };
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port.clone(), network)),
        source_factory,
        Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
        shutdown_signal.clone(),
    );
    frontend.start();

    // Start the UNIX fd listener loop
    let shutdown_signal_clone = shutdown_signal.clone();
    let mut signer_loop = SignerLoop::new(
        client,
        signer_port,
        shutdown_trigger,
        shutdown_signal_clone,
        init_message_cache.clone(),
    );
    spawn_blocking(move || signer_loop.start());

    // Start the gRPC listener loop - the signer will connect to us
    info!("starting gRPC service on {}", addr);
    server.start(incoming, shutdown_signal).await.expect("error while serving");
    info!("stopping gRPC service");
}

#[cfg(test)]
#[cfg(feature = "test_cli")]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use predicates::prelude::*;
    use tempfile::TempDir;

    #[test]
    fn test_make_clap_app() {
        make_clap_app();
    }

    #[test]
    fn test_remote_hsmd_cli_normal() {
        let tempdir: TempDir = TempDir::new().unwrap();
        let mut cmd = Command::cargo_bin("remote_hsmd_socket").unwrap();
        let assert = cmd
            .arg("--developer")
            .arg(format!("--datadir={}", tempdir.path().display()))
            .env("VLS_NETWORK", "bitcoin")
            .env("BITCOIND_RPC_URL", "http://localhost:18332")
            .assert();

        assert.stdout(
            predicate::str::is_match("remote_hsmd_socket git_desc=v0.13.0\\S+ starting").unwrap(),
        );
    }

    #[test]
    fn test_remote_hsmd_cli_version() {
        let mut cmd = Command::cargo_bin("remote_hsmd_socket").unwrap();
        let assert = cmd.arg("--version").env("VLS_CLN_VERSION", "1.0").assert();

        assert.success().stdout("1.0\n");
    }

    #[test]
    fn test_remote_hsmd_cli_git_desc() {
        let mut cmd = Command::cargo_bin("remote_hsmd_socket").unwrap();
        let assert = cmd.arg("--git-desc").assert();

        assert
            .success()
            .stdout(predicate::str::is_match("remote_hsmd_socket git_desc=v0.13.0\\S+").unwrap());
    }
}
