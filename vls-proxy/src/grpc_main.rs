//! This implements two binaries:
//!
//! - A drop-in replacement for hsmd acting as a gRPC server
//! - A VLS signer, acting as a gRPC client
//!
//! Note that the gRPC protocol is different from the native VLS gRPC protocol.  This
//! protocol is a thin wrapper on top of the CLN hsmd wire protocol.  It also connects in the
//! opposite direction (signer -> node), which makes it more convenient if the signer is behind
//! NAT.

use std::env;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::process::exit;

use clap::{App, AppSettings, Arg};
#[allow(unused_imports)]
use log::{error, info};
use nix::unistd::{fork, ForkResult};
use tokio::task::spawn_blocking;

use client::UnixClient;
use connection::{open_parent_fd, UnixConnection};
use grpc::adapter::HsmdService;
use grpc::incoming::TcpIncoming;
use grpc::signer::start_signer_localhost;
use grpc::signer_loop::SignerLoop;
use vls_proxy::util::setup_logging;
use vls_proxy::*;

pub mod grpc;

/// Implement both the hsmd replacement and the signer in a single binary.
/// The signer is forked off as a separate process.
pub fn main() {
    let parent_fd = open_parent_fd();

    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(
            Arg::new("dev-disconnect")
                .about("ignored dev flag")
                .long("dev-disconnect")
                .takes_value(true),
        )
        .arg(Arg::from("--log-io ignored dev flag"))
        .arg(Arg::from("--version show a dummy version"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
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

    let server = HsmdService::new(shutdown_trigger.clone());
    let trigger1 = shutdown_trigger.clone();
    ctrlc::set_handler(move || {
        trigger1.trigger();
    })
    .expect("Error setting Ctrl-C handler");

    let incoming = TcpIncoming::new_from_std(listener, false, None).expect("listen incoming"); // new_from_std seems to be infallible

    let sender = server.sender();

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
