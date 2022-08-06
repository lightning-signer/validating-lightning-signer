//! This implements two binaries:
//!
//! - A drop-in replacement for hsmd acting as a gRPC server
//! - A VLS signer, acting as a gRPC client
//!
//! Note that the gRPC protocol is different from the native VLS gRPC protocol.  This
//! protocol is a thin wrapper on top of the CLN hsmd wire protocol.  It also connects in the
//! opposite direction (signer -> node), which makes it more convenient if the signer is behind
//! NAT.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::process::exit;
use std::sync::Arc;

use clap::{App, AppSettings};
#[allow(unused_imports)]
use log::{error, info};
use nix::unistd::{fork, ForkResult};
use tokio::task::spawn_blocking;
use url::Url;

use lightning_signer::bitcoin::Network;

use client::UnixClient;
use connection::{open_parent_fd, UnixConnection};
use grpc::adapter::HsmdService;
use grpc::incoming::TcpIncoming;
use grpc::signer::start_signer_localhost;
use grpc::signer_loop::{GrpcSignerPort, SignerLoop};
use vls_frontend::Frontend;
use vls_proxy::portfront::SignerPortFront;
use vls_proxy::util::{
    add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version, setup_logging, vls_network,
};
use vls_proxy::*;

pub mod grpc;

/// Implement both the hsmd replacement and the signer in a single binary.
/// The signer is forked off as a separate process.
pub fn main() {
    let parent_fd = open_parent_fd();

    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("CLN:socket test - for use with the CLN integration test suite");
    let app = add_hsmd_args(app);
    let matches = app.get_matches();
    if handle_hsmd_version(&matches) {
        return;
    }

    let (listener, addr) = allocate_port();

    // Fork off the signer process.
    // The listener is closed in the child process.
    let listener = unsafe { spawn_signer(listener, addr.port()) };

    setup_logging("hsmd  ", "debug");

    // Note that this is unsafe if we use the wrong fd
    let conn = UnixConnection::new(parent_fd);
    let client = UnixClient::new(conn);
    start_server(listener, addr, client);
}

// hsmd replacement entry point
#[tokio::main(worker_threads = 2)]
async fn start_server(listener: TcpListener, addr: SocketAddr, client: UnixClient) {
    let (shutdown_trigger, shutdown_signal) = triggered::trigger();

    let server = HsmdService::new(shutdown_trigger.clone(), shutdown_signal.clone());
    let trigger1 = shutdown_trigger.clone();
    ctrlc::set_handler(move || {
        trigger1.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let incoming = TcpIncoming::new_from_std(listener, false, None).expect("listen incoming"); // new_from_std seems to be infallible

    let network = vls_network().parse::<Network>().expect("malformed vls network");
    let sender = server.sender();
    let signer_port = GrpcSignerPort::new(sender.clone());
    let frontend = Frontend::new(
        Arc::new(SignerPortFront { signer_port: Box::new(signer_port), network }),
        Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
    );
    frontend.start();

    // Start the UNIX fd listener loop
    spawn_blocking(|| {
        let mut signer_loop = SignerLoop::new(client, sender, shutdown_trigger);
        signer_loop.start()
    });

    // Start the gRPC listener loop - the signer will connect to us
    info!("starting gRPC service on port {}", addr.port());
    server.start(incoming, shutdown_signal).await.expect("error while serving");
    info!("stopping gRPC service");
}

unsafe fn spawn_signer(listener: TcpListener, port: u16) -> TcpListener {
    match fork() {
        Ok(ForkResult::Parent { child, .. }) => {
            info!("child pid {}", child);
            listener
        }
        Ok(ForkResult::Child) => {
            info!("in child");
            drop(listener);
            setup_logging("signer", "debug");
            start_signer_localhost(port);
            exit(0);
        }
        Err(_) => {
            panic!("failed to fork")
        }
    }
}

fn allocate_port() -> (TcpListener, SocketAddr) {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let addr = SocketAddrV4::new(loopback, 0);
    let listener = TcpListener::bind(addr).expect("bind"); // this should be infallible
    let addr = listener.local_addr().expect("local");
    (listener, addr)
}
