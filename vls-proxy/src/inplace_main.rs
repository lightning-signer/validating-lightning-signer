//! A single-binary hsmd drop-in replacement for CLN, using the VLS library

use std::collections::BTreeMap;
use std::env;
use std::sync::Mutex;

use clap::{arg, App};
use log::{error, info};
use url::Url;

use bitcoin::Network;
use lightning_signer::bitcoin;
use lightning_signer::node::NodeServices;
use lightning_signer::persist::{ExternalPersistHelper, Mutations, Persist, SimpleEntropy};
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::signer::ClockStartingTimeFactory;
use lightning_signer::util::clock::StandardClock;
use lightning_signer::Arc;
use lightning_storage_server::client::Auth;
use nodefront::SingleFront;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::block_in_place;
use vls_frontend::external_persist::lss::Client as LssClient;
use vls_frontend::external_persist::ExternalPersist;
use vls_frontend::frontend::SourceFactory;
use vls_frontend::{external_persist, Frontend};
use vls_persist::kv_json::KVJsonPersister;
use vls_persist::thread_memo_persister::ThreadMemoPersister;
use vls_protocol::{msgs, msgs::Message, Error as ProtocolError};
use vls_protocol_signer::approver::WarningPositiveApprover;
use vls_protocol_signer::handler::{ChannelHandler, Handler, RootHandler, RootHandlerBuilder};
use vls_protocol_signer::vls_protocol;

use client::{Client, UnixClient};
use connection::UnixConnection;
use util::{
    abort_on_panic, add_hsmd_args, bitcoind_rpc_url, handle_hsmd_version,
    integration_test_seed_or_generate, make_validator_factory_with_filter, read_allowlist,
    setup_logging, should_auto_approve, vls_network,
};
use vls_proxy::*;

mod test;

/// WARNING: this does not ensure atomicity if mutated from different threads
pub struct Cloud {
    lss_client: AsyncMutex<Box<dyn ExternalPersist>>,
    state: Arc<Mutex<BTreeMap<String, (u64, Vec<u8>)>>>,
    helper: ExternalPersistHelper,
}

impl Cloud {
    async fn init_state(&self) {
        let lss_client = self.lss_client.lock().await;
        let entropy = SimpleEntropy::new();
        let mut helper = self.helper.clone();
        let nonce = helper.new_nonce(&entropy);
        let (muts, server_hmac) = lss_client.get("".to_string(), &nonce).await.unwrap();
        let success = helper.check_hmac(&muts, server_hmac);
        assert!(success, "server hmac mismatch on get");
        let mut local = self.state.lock().unwrap();
        for (key, version_value) in muts.into_iter() {
            local.insert(key, version_value);
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
    #[error("LSS error")]
    Client(#[from] external_persist::Error),
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
            Self::store_with_client(muts, &*lss_client, &cloud.helper).await?;
        }
        Ok(())
    }

    async fn store_with_client(
        muts: Mutations,
        client: &Box<dyn ExternalPersist>,
        helper: &ExternalPersistHelper,
    ) -> Result<()> {
        if !muts.is_empty() {
            let client_hmac = helper.client_hmac(&muts);
            client.put(muts, &client_hmac).await?;
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
        info!("chan loop {} {} {}: start", pid, id, handler.dbid());
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
            Self::store_with_client(muts, &*lss_client, &cloud.helper).await?;
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
    abort_on_panic();
    let app = make_clap_app();
    let matches = app.get_matches();
    if handle_hsmd_version(&matches) {
        return;
    }
    if matches.is_present("git-desc") {
        println!("remote_hsmd_inplace git_desc={}", GIT_DESC);
    } else if matches.is_present("test") {
        test::run_test();
    } else {
        start();
    }
}

fn make_clap_app() -> App<'static> {
    let app = App::new("signer")
        .about("Validating Lightning Signer")
        .arg(arg!(--test "run a test emulating lightningd/hsmd"));
    add_hsmd_args(app)
}

// small number of threads to ease debugging
#[tokio::main(worker_threads = 2)]
async fn start() {
    setup_logging(".", "remote_hsmd_inplace", "info");
    info!("remote_hsmd_inplace git_desc={} starting", GIT_DESC);
    let conn = UnixConnection::new(3);
    let client = UnixClient::new(conn);
    let allowlist = read_allowlist();
    let network = vls_network().parse::<Network>().expect("malformed vls network");
    let starting_time_factory = ClockStartingTimeFactory::new();
    // TODO(236)
    let filter =
        PolicyFilter { rules: vec![FilterRule::new_warn("policy-channel-safe-type-anchors")] };
    let validator_factory = make_validator_factory_with_filter(network, Some(filter));
    let clock = Arc::new(StandardClock());
    let seed = integration_test_seed_or_generate(None);
    let persister = make_persister();
    let services = NodeServices { validator_factory, starting_time_factory, persister, clock };
    let mut handler_builder =
        RootHandlerBuilder::new(network, client.id(), services, seed).allowlist(allowlist);
    if should_auto_approve() {
        handler_builder = handler_builder.approver(Arc::new(WarningPositiveApprover()));
    }

    let looper = make_looper(&handler_builder).await;

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

    let source_factory = Arc::new(SourceFactory::new(".", network));
    let frontend = Frontend::new(
        Arc::new(SingleFront { node: Arc::clone(&handler.node()) }),
        source_factory,
        Url::parse(&bitcoind_rpc_url()).expect("malformed rpc url"),
    );

    tokio::task::spawn(async move { block_in_place(|| frontend.start()) });

    looper.root_signer_loop(client, handler).await;
}

fn make_persister() -> Arc<dyn Persist> {
    if env::var("VLS_LSS").is_ok() {
        Arc::new(ThreadMemoPersister {})
    } else {
        Arc::new(KVJsonPersister::new("remote_hsmd_inplace.kv"))
    }
}

async fn make_looper(builder: &RootHandlerBuilder) -> Looper {
    let cloud = if let Ok(uri) = env::var("VLS_LSS") {
        let (keys_manager, node_id) = builder.build_keys_manager();
        let client_id = keys_manager.get_persistence_pubkey();
        let server_pubkey = LssClient::get_server_pubkey(&uri).await.expect("failed to get pubkey");
        let shared_secret = keys_manager.get_persistence_shared_secret(&server_pubkey);
        let auth_token = keys_manager.get_persistence_auth_token(&server_pubkey);
        let helper = ExternalPersistHelper::new(shared_secret);
        let auth = Auth { client_id, token: auth_token.to_vec() };

        let client =
            LssClient::new(&uri, &server_pubkey, auth).await.expect("failed to connect to LSS");
        info!("connected to LSS provider {} for node {}", server_pubkey, node_id);

        let lss_client = AsyncMutex::new(Box::new(client) as Box<dyn ExternalPersist>);
        let state = Arc::new(Mutex::new(Default::default()));
        let cloud = Cloud { lss_client, state, helper };
        Some(Arc::new(cloud))
    } else {
        None
    };
    Looper { cloud }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_clap_app() {
        make_clap_app();
    }
}
