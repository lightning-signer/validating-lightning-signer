use jsonrpsee::{
    server::{RpcModule, Server},
    types::{error::ErrorCode, ErrorObject},
};
use lightning_signer::node::Node;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;

use crate::GIT_DESC;

use super::InfoModel;
use tracing::*;

#[derive(Debug)]
pub enum RpcMethods {
    Info,
    Version,
    AllowlistDisplay,
    AllowlistAdd,
    AllowlistRemove,
}

impl RpcMethods {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Version => "version",
            Self::AllowlistDisplay => "allowlist_display",
            Self::AllowlistAdd => "allowlist_add",
            Self::AllowlistRemove => "allowlist_remove",
        }
    }
}

pub async fn start_rpc_server(
    node: Arc<Node>,
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    shutdown_signal: triggered::Listener,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let mut module = RpcModule::new(node);
    module.register_method(RpcMethods::Info.as_str(), |_, context| {
        info!("rpc_server: info");
        let height = context.get_chain_height();
        let channels = context.channels().values().len() as u32;
        Ok::<_, ErrorObject>(InfoModel::new(height, channels, GIT_DESC.to_string()))
    })?;

    module.register_method(RpcMethods::Version.as_str(), |_, _| {
        Ok::<_, ErrorObject>(GIT_DESC.to_string())
    })?;

    module.register_method(RpcMethods::AllowlistDisplay.as_str(), |_, context| {
        return match context.allowlist() {
            Ok(allowlist) => Ok(allowlist),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        };
    })?;

    module.register_method(RpcMethods::AllowlistAdd.as_str(), |params, context| {
        info!("rpc_server: allow list add, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.add_allowlist(&[address.clone()]) {
            Ok(_) => {
                trace!("successfully added address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to add address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    module.register_method(RpcMethods::AllowlistRemove.as_str(), |params, context| {
        info!("rpc_server: allow list remove, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.remove_allowlist(&[address.clone()]) {
            Ok(_) => {
                trace!("successfully removed address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to remove address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    let auth_middleware = tower::ServiceBuilder::new()
        .layer(tower_http::auth::AddAuthorizationLayer::basic(username, password));

    let server = Server::builder()
        .set_http_middleware(auth_middleware)
        .build(SocketAddr::new(ip, port))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(module);
    info!("rpc_server: listening on {} on port {}", addr, port);

    let join_handle = tokio::spawn(async move {
        shutdown_signal.await;
        handle.stop().expect("not already stopped");
        handle.stopped().await;
    });

    Ok((addr, join_handle))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::sync::Arc;

    use crate::{
        config::{SignerArgs, RPC_SERVER_ADDRESS, RPC_SERVER_PORT},
        grpc::signer::make_handler,
    };

    use super::start_rpc_server;

    #[tokio::test]
    async fn test_rpc_server() {
        let temp_dir = tempfile::tempdir_in(".").unwrap();
        let datadir = temp_dir.path().to_str().unwrap();

        let ip = RPC_SERVER_ADDRESS.to_string();
        let port = RPC_SERVER_PORT.to_string();
        let args = vec![
            "signer",
            "--network",
            "regtest",
            "--datadir",
            datadir,
            "--rpc-server-address",
            &ip,
            "--rpc-server-port",
            &port,
        ];
        let signer_args = SignerArgs::parse_from(&args);

        let root_handler = make_handler(datadir, &signer_args);
        let (shutdown_trigger, shutdown_signal) = triggered::trigger();
        match start_rpc_server(
            Arc::clone(root_handler.node()),
            signer_args.rpc_server_address,
            signer_args.rpc_server_port,
            "user",
            "password",
            shutdown_signal,
        )
        .await
        {
            Ok((addr, join_handle)) => {
                println!("rpc server started at {}", addr);
                shutdown_trigger.trigger();
                join_handle.await.unwrap();
            }
            Err(e) => {
                println!("rpc server failed to start: {}", e);
                assert!(false);
            }
        }
    }
}
