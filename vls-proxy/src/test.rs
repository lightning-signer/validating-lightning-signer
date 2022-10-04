use std::sync::Arc;

use lightning_signer::bitcoin::{secp256k1, Network};
use lightning_signer::node::NodeServices;
use lightning_signer::persist::DummyPersister;
use lightning_signer::persist::Persist;
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult};
use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;

use vls_protocol_signer::handler::RootHandlerBuilder;
use vls_protocol_signer::vls_protocol::model::PubKey;
use vls_protocol_signer::vls_protocol::msgs;
use vls_proxy::util::make_validator_factory;

use crate::client::{Client, UnixClient};
use crate::connection::UnixConnection;

fn run_parent(conn: UnixConnection) {
    let mut client = UnixClient::new(conn);
    println!("parent: start");
    client.write(msgs::Memleak {}).unwrap();
    println!("parent: {:?}", client.read());
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (_, key) = secp.generate_keypair(&mut rng);

    client
        .write(msgs::ClientHsmFd { peer_id: PubKey(key.serialize()), dbid: 0, capabilities: 0 })
        .unwrap();
    println!("parent: {:?}", client.read());
    let fd = client.recv_fd().expect("fd");
    println!("parent: received fd {}", fd);
    let mut client1 = UnixClient::new(UnixConnection::new(fd));
    client1.write(msgs::Memleak {}).unwrap();
    println!("parent: client1 {:?}", client1.read());
}

#[tokio::main]
async fn do_child(conn: UnixConnection) {
    let network = Network::Regtest;

    let client = UnixClient::new(conn);
    let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
    let seed = Some([0; 32]);
    let starting_time_factory = ClockStartingTimeFactory::new();
    let validator_factory = make_validator_factory(network);
    let clock = Arc::new(StandardClock());
    let looper = crate::Looper { cloud: None };
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let (handler, _muts) =
        RootHandlerBuilder::new(network, client.id(), services).seed_opt(seed).build();
    looper.root_signer_loop(client, handler).await
}

pub(crate) fn run_test() {
    println!("starting test");
    let (fd3, fd4) =
        socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
    assert_eq!(fd3, 3);
    assert_eq!(fd4, 4);
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            println!("child pid {}", child);
            close(fd3).unwrap();
            let conn = UnixConnection::new(fd4);
            run_parent(conn);
        }
        Ok(ForkResult::Child) => {
            close(fd4).unwrap();
            let conn = UnixConnection::new(fd3);
            do_child(conn);
        }
        Err(_) => {}
    }
}
