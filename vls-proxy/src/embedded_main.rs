//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

use clap::{App, AppSettings, Arg};

#[allow(unused_imports)]
use log::{error, info};
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};

use connection::UnixConnection;
use lightning_signer::bitcoin::Network;
use lightning_signer::persist::Persist;
use lightning_signer::Arc;

use lightning_signer_server::persist::persist_json::KVJsonPersister;
use util::read_allowlist;
use vls_protocol_signer::vls_protocol::model::Secret;
use vls_protocol_signer::vls_protocol::msgs::{self, Message};
use vls_protocol_signer::vls_protocol::serde_bolt;
use vls_protocol_signer::vls_protocol::serde_bolt::WireString;

use vls_proxy::client::UnixClient;
use vls_proxy::util::{read_integration_test_seed, setup_logging};
use vls_proxy::*;

struct SerialWrap {
    inner: File,
    peek: Option<u8>,
}

impl SerialWrap {
    fn new(inner: File) -> Self {
        let fd = inner.as_raw_fd();
        let mut termios = tcgetattr(fd).expect("tcgetattr");
        cfmakeraw(&mut termios);
        tcsetattr(fd, SetArg::TCSANOW, &termios).expect("tcsetattr");
        Self { inner, peek: None }
    }
}

impl serde_bolt::Read for SerialWrap {
    type Error = serde_bolt::Error;

    fn read(&mut self, mut buf: &mut [u8]) -> serde_bolt::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut nread = 0;

        if let Some(p) = self.peek.take() {
            buf[0] = p;
            nread += 1;
            let len = buf.len();
            buf = &mut buf[1..len];
        }

        // Not well documented in serde_bolt, but we are expected to block
        // until we can read the whole buf or until we get to EOF.
        while !buf.is_empty() {
            let n = self.inner.read(buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
            if n == 0 {
                // we are at EOF
                return if nread != 0 { Ok(nread) } else { Err(serde_bolt::Error::Eof) };
            }
            nread += n;
            let len = buf.len();
            buf = &mut buf[n..len];
        }
        Ok(nread)
    }

    fn peek(&mut self) -> serde_bolt::Result<Option<u8>> {
        if self.peek.is_some() {
            return Ok(self.peek);
        }
        let mut buf = [0; 1];
        let n = self.inner.read(&mut buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
        if n == 1 {
            self.peek = Some(buf[0]);
        }
        Ok(self.peek)
    }
}

impl serde_bolt::Write for SerialWrap {
    type Error = serde_bolt::Error;

    fn write_all(&mut self, buf: &[u8]) -> serde_bolt::Result<()> {
        self.inner.write_all(&buf).map_err(|e| serde_bolt::Error::Message(e.to_string()))?;
        Ok(())
    }
}

fn run_test(serial_port: String) -> anyhow::Result<()> {
    info!("connecting to {}", serial_port);
    let file = File::options().read(true).write(true).open(serial_port)?;
    let mut serial = SerialWrap::new(file);
    let mut id = 0u16;
    let allowlist =
        read_allowlist().into_iter().map(|s| WireString(s.as_bytes().to_vec())).collect::<Vec<_>>();
    let seed = read_integration_test_seed().map(|s| Secret(s)).or(Some(Secret([1; 32]))); // FIXME remove this
    info!("allowlist {:?} seed {:?}", allowlist, seed);
    let init = msgs::HsmdInit2 {
        derivation_style: 0,
        network_name: WireString(Network::Testnet.to_string().as_bytes().to_vec()),
        dev_seed: seed,
        dev_allowlist: allowlist,
    };
    msgs::write(&mut serial, init).expect("write init");
    let init_reply: msgs::HsmdInit2Reply =
        msgs::read_message(&mut serial).expect("failed to read init reply message");
    info!("init reply {:?}", init_reply);

    loop {
        let ping = msgs::Ping { id, message: WireString("ping".as_bytes().to_vec()) };
        msgs::write(&mut serial, ping).expect("write");
        let reply = msgs::read(&mut serial).expect("read");
        match reply {
            Message::Pong(p) => {
                info!("got reply {} {}", p.id, String::from_utf8(p.message.0).unwrap());
                assert_eq!(p.id, id);
            }
            _ => {
                panic!("unknown response");
            }
        }
        id += 1;
    }
}

pub fn main() -> anyhow::Result<()> {
    setup_logging("hsmd  ", "info");
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
        .arg(Arg::from("--test run a test against the embedded device"));
    let matches = app.get_matches();
    if matches.is_present("version") {
        // Pretend to be the right version, given to us by an env var
        let version =
            env::var("GREENLIGHT_VERSION").expect("set GREENLIGHT_VERSION to match c-lightning");
        println!("{}", version);
        return Ok(());
    }

    let serial_port = env::var("VLS_SERIAL_PORT").unwrap_or("/dev/ttyACM1".to_string());

    if matches.is_present("test") {
        run_test(serial_port)?;
    } else {
        let conn = UnixConnection::new(3);
        let _client = UnixClient::new(conn);
        let _persister: Arc<dyn Persist> = Arc::new(KVJsonPersister::new("remote_hsmd_vls.kv"));
        let _allowlist = read_allowlist();
    }

    Ok(())
}
