use jsonrpsee::{
    server::{RpcModule, Server},
    types::ErrorObject,
};
use lightning_signer::node::Node;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::task::JoinHandle;

use crate::GIT_DESC;

use super::InfoModel;

pub enum RpcMethods {
    Info,
}

impl RpcMethods {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
        }
    }
}

pub async fn start_rpc_server(
    node: Arc<Node>,
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let server = Server::builder().build(SocketAddr::new(ip, port)).await?;

    let mut module = RpcModule::new(node);
    module.register_method(RpcMethods::Info.as_str(), |_, context| {
        let height = context.get_chain_height();
        let channels = context.channels().values().len() as u32;
        Ok::<_, ErrorObject>(InfoModel::new(height, channels, GIT_DESC.to_string()))
    })?;

    let addr = server.local_addr()?;
    let handle = server.start(module);

    let join_handle = tokio::spawn(handle.stopped());

    Ok((addr, join_handle))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::sync::Arc;

    use vls_protocol_signer::handler::Handler;

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
        match start_rpc_server(Arc::clone(root_handler.node()), RPC_SERVER_ADDRESS, RPC_SERVER_PORT)
            .await
        {
            Ok((addr, join_handle)) => {
                println!("rpc server started at {}", addr);

                join_handle.abort();
            }
            Err(e) => {
                println!("rpc server failed to start: {}", e);
                assert!(false);
            }
        }
    }
}
