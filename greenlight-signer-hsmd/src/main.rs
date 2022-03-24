use std::convert::TryInto;
use std::os::unix::io::RawFd;
use std::{env, fs, thread};

use clap::{App, AppSettings, Arg};
use env_logger::Env;
use log::{error, info};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use nix::unistd::{close, fork, ForkResult};
use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;

use connection::UnixConnection;
use greenlight_protocol::model::PubKey;
use greenlight_protocol::{msgs, msgs::Message, Error, Result};
use greenlight_signer::greenlight_protocol;
use lightning_signer::persist::{DummyPersister, Persist};
use lightning_signer::Arc;

use crate::client::{Client, UnixClient};
use greenlight_signer::handler::{Handler, RootHandler};
use lightning_signer_server::persist::persist_json::KVJsonPersister;
use std::fs::File;
use std::io::{BufRead, BufReader};

mod client;
mod connection;

fn run_parent(fd: RawFd) {
    let mut client = UnixClient::new(UnixConnection::new(fd));
    info!("parent: start");
    client.write(msgs::Memleak {}).unwrap();
    info!("parent: {:?}", client.read());
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (_, key) = secp.generate_keypair(&mut rng);

    client
        .write(msgs::ClientHsmFd { peer_id: PubKey(key.serialize()), dbid: 0, capabilities: 0 })
        .unwrap();
    info!("parent: {:?}", client.read());
    let fd = client.recv_fd().expect("fd");
    info!("parent: received fd {}", fd);
    let mut client1 = UnixClient::new(UnixConnection::new(fd));
    client1.write(msgs::Memleak {}).unwrap();
    info!("parent: client1 {:?}", client1.read());
}

fn signer_loop<C: 'static + Client, H: Handler>(client: C, handler: H) {
    let id = handler.client_id();
    let pid = std::process::id();
    info!("loop {} {}: start", pid, id);
    match do_signer_loop(client, handler) {
        Ok(()) => info!("loop {} {}: done", pid, id),
        Err(Error::Eof) => info!("loop {} {}: ending", pid, id),
        Err(e) => error!("loop {} {}: error {:?}", pid, id, e),
    }
}

fn do_signer_loop<C: 'static + Client, H: Handler>(mut client: C, handler: H) -> Result<()> {
    loop {
        let msg = client.read()?;
        info!("loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
        match msg {
            Message::ClientHsmFd(m) => {
                client.write(msgs::ClientHsmFdReply {}).unwrap();
                let new_client = client.new_client();
                info!("new client {} {} -> {}", std::process::id(), handler.client_id(), new_client.id());
                let handler = handler.for_new_client(new_client.id(), m.peer_id, m.dbid);
                thread::spawn(move || signer_loop(new_client, handler));
            }
            msg => {
                let reply = handler.handle(msg).expect("handle");
                let v = reply.vec_serialize();
                client.write_vec(v).unwrap();
                info!("replied {} {}", std::process::id(), handler.client_id());
            }
        }
    }
}

pub fn main() {
    setup_logging("info");
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(
            Arg::new("--dev-disconnect")
                .about("ignored dev flag")
                .long("dev-disconnect")
                .takes_value(true),
        )
        .arg(Arg::from("--log-io ignored dev flag"))
        .arg(Arg::from("--version show a dummy version"))
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        return;
    }
    if matches.is_present("test") {
        run_test();
    } else {
        let conn = UnixConnection::new(3);
        let client = UnixClient::new(conn);
        let persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("signer.kv"));
        let allowlist = read_allowlist();
        let handler =
            RootHandler::new(client.id(), read_integration_test_seed(), persister, allowlist);
        signer_loop(client, handler);
    }
}

fn read_allowlist() -> Vec<String> {
    let allowlist_path_res = env::var("ALLOWLIST");
    if let Ok(allowlist_path) = allowlist_path_res {
        let file =
            File::open(&allowlist_path).expect(format!("open {} failed", &allowlist_path).as_str());
        BufReader::new(file).lines().map(|l| l.expect("line")).collect()
    } else {
        Vec::new()
    }
}

fn read_integration_test_seed() -> Option<[u8; 32]> {
    let result = fs::read("hsm_secret");
    if let Ok(data) = result {
        Some(data.as_slice().try_into().expect("hsm_secret wrong length"))
    } else {
        None
    }
}

fn run_test() {
    info!("starting test");
    let (fd3, fd4) =
        socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty()).unwrap();
    assert_eq!(fd3, 3);
    assert_eq!(fd4, 4);
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            info!("child pid {}", child);
            close(fd3).unwrap();
            run_parent(fd4)
        }
        Ok(ForkResult::Child) => {
            close(fd4).unwrap();
            let conn = UnixConnection::new(fd3);
            let client = UnixClient::new(conn);
            let persister: Arc<dyn Persist> = Arc::new(DummyPersister {});
            let seed = Some([0; 32]);
            let handler = RootHandler::new(client.id(), seed, persister, vec![]);
            signer_loop(client, handler)
        }
        Err(_) => {}
    }
}

fn setup_logging(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}
