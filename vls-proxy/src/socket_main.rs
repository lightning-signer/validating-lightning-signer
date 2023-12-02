//! A drop-in replacement for hsmd, acting as a gRPC server for VLS
//!
//! Note that this gRPC protocol is different from the native VLS gRPC protocol.  This
//! protocol is a thin wrapper on top of the CLN hsmd wire protocol.  It also connects in the
//! opposite direction (signer -> node), which makes it more convenient if the signer is behind
//! NAT.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use clap::App;
#[allow(unused_imports)]
use log::{error, info, warn};
use tokio::task::spawn_blocking;
use url::Url;

use lightning_signer::bitcoin::Network;

use vls_frontend::frontend::SourceFactory;
use vls_frontend::Frontend;

use client::UnixClient;
use connection::{open_parent_fd, UnixConnection};
use grpc::adapter::HsmdService;
use grpc::incoming::TcpIncoming;
use grpc::signer_loop::{GrpcSignerPort, SignerLoop};
use portfront::SignerPortFront;
use util::{
    abort_on_panic, add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version, setup_logging,
    vls_network,
};
use vls_proxy::*;

/// Implement hsmd replacement that listens to connections from vlsd2.
pub fn main() {
    abort_on_panic();
    let parent_fd = open_parent_fd();

    let app = make_clap_app();
    let matches = app.get_matches();
    if matches.is_present("git-desc") {
        println!("remote_hsmd_socket git_desc={}", GIT_DESC);
        return;
    }
    if handle_hsmd_version(&matches) {
        return;
    }

    setup_logging(".", "remote_hsmd_socket", "info");
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
    start_server(sock_addr, client);
}

fn make_clap_app() -> App<'static> {
    let app = App::new("signer")
        .about("CLN:socket - listens for a vlsd2 connection on port 7701 (or VLS_PORT if set)");
    add_hsmd_args(app)
}

// hsmd replacement entry point
#[tokio::main(worker_threads = 2)]
async fn start_server(addr: SocketAddr, client: UnixClient) {
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();
    let trigger1 = shutdown_trigger.clone();
    ctrlc::set_handler(move || {
        warn!("ctrlc handler triggering shutdown");
        trigger1.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let server = HsmdService::new(shutdown_trigger.clone(), shutdown_signal.clone());

    let incoming = TcpIncoming::new(addr, false, None).expect("listen incoming"); // new_from_std seems to be infallible

    let network = vls_network().parse::<Network>().expect("malformed vls network");
    let sender = server.sender();
    let signer_port = Arc::new(GrpcSignerPort::new(sender.clone()));
    let source_factory = Arc::new(SourceFactory::new(".", network));
    let frontend = Frontend::new(
        Arc::new(SignerPortFront::new(signer_port.clone(), network)),
        source_factory,
        Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
        shutdown_signal.clone(),
    );
    frontend.start();

    // Start the UNIX fd listener loop
    let shutdown_signal_clone = shutdown_signal.clone();
    spawn_blocking(move || {
        let mut signer_loop =
            SignerLoop::new(client, signer_port, shutdown_trigger, shutdown_signal_clone);
        signer_loop.start()
    });

    // Start the gRPC listener loop - the signer will connect to us
    info!("starting gRPC service on {}", addr);
    server.start(incoming, shutdown_signal).await.expect("error while serving");
    info!("stopping gRPC service");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_clap_app() {
        make_clap_app();
    }
}
