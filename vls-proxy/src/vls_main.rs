//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::collections::BTreeMap;
use std::env;
use std::sync::Mutex;

use clap::{App, AppSettings, Arg};
use log::{error, info};
use url::Url;

use client::{Client, UnixClient};
use connection::UnixConnection;
use lightning_signer::bitcoin::hashes::sha256::Hash as Sha256Hash;
use lightning_signer::bitcoin::hashes::Hash;
use lightning_signer::bitcoin::secp256k1::SecretKey;
use lightning_signer::bitcoin::Network;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{Mutations, Persist};
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::util::crypto_utils::hkdf_sha256;
use lightning_signer::Arc;
use lightning_signer_server::nodefront::SingleFront;
use lightning_signer_server::persist::kv_json::KVJsonPersister;
use lightning_signer_server::persist::thread_memo_persister::ThreadMemoPersister;
use lightning_storage_server::client::auth::Auth;
use lightning_storage_server::client::driver::Client as LssClient;
use lightning_storage_server::Value;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};
use tokio::task::block_in_place;
use util::read_allowlist;
use vls_frontend::Frontend;
use vls_protocol::{msgs, msgs::Message, Error as ProtocolError};
use vls_protocol_signer::handler::{ChannelHandler, Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol;

mod test;
use vls_proxy::util::{
    add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version, integration_test_seed_or_generate,
    make_validator_factory, setup_logging, vls_network,
};
use vls_proxy::*;

/// WARNING: this does not ensure atomicity if mutated from different threads
pub struct Cloud {
    lss_client: AsyncMutex<LssClient>,
    state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    auth: Auth,
    hmac_secret: [u8; 32],
}

impl Cloud {
    async fn init_state(&self) {
        let mut lss_client = self.lss_client.lock().await;
        let state =
            lss_client.get(self.auth.clone(), &self.hmac_secret, "".to_string()).await.unwrap();
        let mut local = self.state.lock().unwrap();
        for (key, value) in state.into_iter() {
            local.insert(key, (value.version as u64, value.value));
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
    #[error("LSS error")]
    Client(#[from] lightning_storage_server::client::driver::ClientError),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone)]
pub struct Looper {
    pub cloud: Option<Arc<Cloud>>,
}

impl Looper {
    async fn store(&self, muts: Mutations) -> Result<()> {
        if let Some(cloud) = &self.cloud {
            let lss_client = cloud.lss_client.lock().await;
            Self::store_with_client(muts, cloud, lss_client).await?;
        }
        Ok(())
    }

    async fn store_with_client(
        muts: Mutations,
        cloud: &Arc<Cloud>,
        mut client: MutexGuard<'_, LssClient>,
    ) -> Result<()> {
        if !muts.is_empty() {
            let kvs = muts
                .into_iter()
                .map(|(key, (version, value))| (key, Value { version: version as i64, value }))
                .collect();
            client.put(cloud.auth.clone(), &cloud.hmac_secret, kvs).await?;
        }
        Ok(())
    }

    async fn root_signer_loop(&self, client: UnixClient, handler: RootHandler) {
        let id = handler.client_id();
        let pid = std::process::id();
        info!("root loop {} {}: start", pid, id);
        match self.do_root_signer_loop(client, handler).await {
            Ok(()) => info!("root loop {} {}: done", pid, id),
            Err(Error::Protocol(ProtocolError::Eof)) => info!("loop {} {}: ending", pid, id),
            Err(e) => error!("root loop {} {}: error {:?}", pid, id, e),
        }
    }

    async fn do_root_signer_loop(
        &self,
        mut client: UnixClient,
        handler: RootHandler,
    ) -> Result<()> {
        loop {
            let msg = block_in_place(|| client.read())?;
            info!("loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
            match msg {
                Message::ClientHsmFd(m) => {
                    block_in_place(|| client.write(msgs::ClientHsmFdReply {}))?;
                    let new_client = client.new_client();
                    info!(
                        "new client {} client_id={} dbid={} -> {}",
                        std::process::id(),
                        handler.client_id(),
                        m.dbid,
                        new_client.id()
                    );
                    if m.dbid > 0 {
                        let handler = handler.for_new_client(new_client.id(), m.peer_id, m.dbid);
                        let looper1 = self.clone();
                        tokio::task::spawn(async move {
                            looper1.channel_signer_loop(new_client, handler).await
                        });
                    } else {
                        let handler = handler.clone();
                        let looper1 = self.clone();
                        tokio::task::spawn(async move {
                            looper1.root_signer_loop2(new_client, handler).await
                        });
                    }
                }
                msg => {
                    self.do_handle(&handler, &mut client, msg).await?;
                    info!("replied {} {}", std::process::id(), handler.client_id());
                }
            }
        }
    }

    // we can't use root_signer_loop when we get ClientHsmFd with dbid=0 because async does not allow recursion
    async fn root_signer_loop2(&self, client: UnixClient, handler: RootHandler) {
        let id = handler.client_id();
        let pid = std::process::id();
        info!("root loop 2 {} {}: start", pid, id);
        match self.do_root_signer_loop2(client, handler).await {
            Ok(()) => info!("root loop 2 {} {}: done", pid, id),
            Err(Error::Protocol(ProtocolError::Eof)) => info!("root loop 2 {} {}: ending", pid, id),
            Err(e) => error!("root loop 2 {} {}: error {:?}", pid, id, e),
        }
    }

    async fn do_root_signer_loop2(
        &self,
        mut client: UnixClient,
        handler: RootHandler,
    ) -> Result<()> {
        loop {
            let msg = block_in_place(|| client.read())?;
            info!("loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
            match msg {
                Message::ClientHsmFd(_) => {
                    unimplemented!("unexpected ClientHsmFd on secondary root loop");
                }
                msg => {
                    self.do_handle(&handler, &mut client, msg).await?;
                    info!("replied {} {}", std::process::id(), handler.client_id());
                }
            }
        }
    }

    async fn channel_signer_loop(&self, client: UnixClient, handler: ChannelHandler) {
        let id = handler.client_id();
        let pid = std::process::id();
        info!("chan loop {} {} {}: start", pid, id, handler.dbid);
        match self.do_channel_signer_loop(client, handler).await {
            Ok(()) => info!("chan loop {} {}: done", pid, id),
            Err(Error::Protocol(ProtocolError::Eof)) => info!("chan loop {} {}: ending", pid, id),
            Err(e) => error!("chan loop {} {}: error {:?}", pid, id, e),
        }
    }

    async fn do_channel_signer_loop(
        &self,
        mut client: UnixClient,
        handler: ChannelHandler,
    ) -> Result<()> {
        loop {
            let msg = block_in_place(|| client.read())?;
            info!("chan loop {} {}: got {:x?}", std::process::id(), handler.client_id(), msg);
            self.do_handle(&handler, &mut client, msg).await?;
            info!("replied {} {}", std::process::id(), handler.client_id());
        }
    }

    async fn do_handle<H: Handler>(
        &self,
        handler: &H,
        client: &mut UnixClient,
        msg: Message,
    ) -> Result<()> {
        let reply = if let Some(cloud) = self.cloud.as_ref() {
            // Note: we lock early because we actually need a global lock right now,
            // since cloud.state is not atomic.  In particular, if one request
            // advances a version of a key, another request might advance the same
            // version again, but may write to the cloud before the first.
            // TODO(devrandom) evaluate atomicity
            let lss_client = cloud.lss_client.lock().await;
            let (reply, muts) = handler.handle(msg).expect("handle");
            Self::store_with_client(muts, cloud, lss_client).await?;
            reply
        } else {
            let (reply, muts) = handler.handle(msg).expect("handle");
            assert!(muts.is_empty(), "got memorized mutations, but not persisting to cloud");
            reply
        };

        block_in_place(|| client.write_vec(reply.as_vec()))?;

        Ok(())
    }
}

// Note: this can't be async, or fds > 2 will be allocated
pub fn main() {
    let app = App::new("signer")
        .setting(AppSettings::NoAutoVersion)
        .about("Greenlight lightning-signer")
        .arg(Arg::from("--test run a test emulating lightningd/hsmd"));
    let app = add_hsmd_args(app);
    let matches = app.get_matches();
    if handle_hsmd_version(&matches) {
        return;
    }
    if matches.is_present("test") {
        test::run_test();
    } else {
        start();
    }
}

// small number of threads to ease debugging
#[tokio::main(worker_threads = 2)]
async fn start() {
    setup_logging("hsmd  ", "info");
    let conn = UnixConnection::new(3);
    let client = UnixClient::new(conn);
    let allowlist = read_allowlist();
    let network = vls_network().parse::<Network>().expect("malformed vls network");
    let starting_time_factory = ClockStartingTimeFactory::new();
    let validator_factory = make_validator_factory(network);
    let clock = Arc::new(StandardClock());
    let seed = integration_test_seed_or_generate();
    let persister = make_persister();
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let handler_builder =
        RootHandlerBuilder::new(network, client.id(), services, seed).allowlist(allowlist);

    let looper = make_looper(&seed).await;

    let handler = if let Some(cloud) = looper.cloud.as_ref() {
        cloud.init_state().await;
        let handler_builder = handler_builder.lss_state(cloud.state.clone());
        let (handler, muts) = handler_builder.build();
        looper.store(muts).await.expect("store during build");
        handler
    } else {
        let (handler, muts) = handler_builder.build();
        assert!(muts.is_empty(), "got memorized mutations, but not persisting to cloud");
        handler
    };

    let frontend = Frontend::new(
        Arc::new(SingleFront { node: Arc::clone(&handler.node) }),
        Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
    );

    tokio::task::spawn(async move { block_in_place(|| frontend.start()) });

    looper.root_signer_loop(client, handler).await;
}

fn make_persister() -> Arc<dyn Persist> {
    if env::var("VLS_LSS").is_ok() {
        Arc::new(ThreadMemoPersister {})
    } else {
        Arc::new(KVJsonPersister::new("remote_hsmd_vls.kv"))
    }
}

async fn make_looper(seed: &[u8; 32]) -> Looper {
    let cloud = if let Ok(uri) = env::var("VLS_LSS") {
        let private_bytes = hkdf_sha256(seed, "storage-client-id".as_bytes(), &[]);
        let client_key = SecretKey::from_slice(&private_bytes).unwrap();
        let hmac_secret = Sha256Hash::hash(&client_key[..]).into_inner();

        let server_id = LssClient::init(&uri).await.expect("failed to init LSS");
        info!("connected to LSS provider {}", server_id);

        let auth = Auth::new_for_client(client_key, server_id);
        let lss_client = AsyncMutex::new(
            LssClient::new(&uri, auth.clone()).await.expect("failed to connect to LSS"),
        );
        let state = Arc::new(Mutex::new(Default::default()));
        let cloud = Cloud { lss_client, state, auth, hmac_secret };
        Some(Arc::new(cloud))
    } else {
        None
    };
    Looper { cloud }
}
