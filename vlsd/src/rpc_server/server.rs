use crate::rpc_server::address_generation::DEFAULT_GAP_LIMIT;

use super::address_generation::DEFAULT_ADDRESS_COUNT;
use anyhow::Result;
use jsonrpsee::{
    server::{RpcModule, Server},
    types::{error::ErrorCode, ErrorObject},
};
use lightning_signer::util::status::Status;
use lightning_signer::wallet::Wallet;
use lightning_signer::{bitcoin::bip32::DerivationPath, node::Node};
use log::{error, info};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use super::address_generation::{generate_addresses, verify_address_derivation};
use super::model::{
    AddressListRequest, AddressListResponse, AddressType, AddressVerifyRequest,
    AddressVerifyResponse, InfoModel,
};

use vls_util::GIT_DESC;

/// The `RpcServer` handles incoming RPC requests and dispatches them
/// to the appropriate handlers. It holds a reference to the `Node`
/// to perform core operations.
pub struct RpcServer {
    pub node: Arc<Node>,
}

impl RpcServer {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    /// Handles the `info` request, returning basic information about the node.
    pub fn handle_info(&self) -> Result<InfoModel, Status> {
        info!("Handling info request");
        let height = self.node.get_chain_height();
        let channels = self.node.get_channels().len() as u32;
        Ok(InfoModel::new(height, channels, GIT_DESC.to_owned()))
    }

    /// Handles the `address_list` request.
    ///
    /// It generates a list of addresses based on the specified types and count.
    /// If no types are provided, it defaults to `Native`.
    pub fn handle_address_list(
        &self,
        request: AddressListRequest,
    ) -> Result<AddressListResponse, Status> {
        info!("Handling address_list request: {:?}", request);

        let count = request.count.unwrap_or(DEFAULT_ADDRESS_COUNT);
        let addresses = generate_addresses(
            &self.node,
            request.address_type.unwrap_or(AddressType::Native),
            request.start.unwrap_or(0),
            count,
            &request.path.unwrap_or(DerivationPath::master()),
        )?;

        Ok(AddressListResponse { addresses, network: self.node.network().to_string() })
    }

    /// Handles the `address_verify` request.
    ///
    /// This function can verify the path by searching through standard BIP paths.
    pub fn handle_address_verify(
        &self,
        request: AddressVerifyRequest,
    ) -> Result<AddressVerifyResponse, Status> {
        info!("Handling address_verify request: {:?}", request);

        let result = verify_address_derivation(
            &self.node,
            &request.address,
            request.start.unwrap_or(0),
            request.limit.unwrap_or(DEFAULT_GAP_LIMIT),
            &request.path.unwrap_or(DerivationPath::master()),
        );

        match result {
            Ok(info) => Ok(AddressVerifyResponse {
                address: request.address,
                valid: if info.is_some() { true } else { false },
                address_info: info,
            }),
            Err(e) => {
                error!("Failed to verify address: {}", e);
                Err(e)
            }
        }
    }
}

#[derive(Debug)]
pub enum RpcMethods {
    Info,
    Version,
    AllowlistDisplay,
    AllowlistAdd,
    AllowlistRemove,
    AddressList,
    AddressVerify,
}

impl RpcMethods {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Version => "version",
            Self::AllowlistDisplay => "allowlist_display",
            Self::AllowlistAdd => "allowlist_add",
            Self::AllowlistRemove => "allowlist_remove",
            Self::AddressList => "address_list",
            Self::AddressVerify => "address_verify",
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
    let rpc_server = RpcServer::new(node);
    let mut module = RpcModule::new(rpc_server);

    module.register_method(RpcMethods::Info.as_str(), |_, context, _| {
        info!("rpc_server: info");
        match context.handle_info() {
            Ok(info) => Ok(info),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::Version.as_str(), |_, _, _| {
        Ok::<_, ErrorObject>(GIT_DESC.to_string())
    })?;

    module.register_method(RpcMethods::AllowlistDisplay.as_str(), |_, context, _| {
        return match context.node.allowlist() {
            Ok(allowlist) => Ok(allowlist),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        };
    })?;

    module.register_method(RpcMethods::AllowlistAdd.as_str(), |params, context, _| {
        info!("rpc_server: allow list add, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.node.add_allowlist(&[address.clone()]) {
            Ok(_) => {
                info!("successfully added address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to add address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    module.register_method(RpcMethods::AllowlistRemove.as_str(), |params, context, _| {
        info!("rpc_server: allow list remove, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.node.remove_allowlist(&[address.clone()]) {
            Ok(_) => {
                info!("successfully removed address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to remove address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    module.register_method(RpcMethods::AddressList.as_str(), |params, context, _| {
        info!("rpc_server: address_list, params {:?}", params);
        let request: AddressListRequest = params.parse().map_err(|_| ErrorCode::InvalidParams)?;
        match context.handle_address_list(request) {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::AddressVerify.as_str(), |params, context, _| {
        info!("rpc_server: address_verify, params {:?}", params);
        let request: AddressVerifyRequest = params.parse().map_err(|_| ErrorCode::InvalidParams)?;
        match context.handle_address_verify(request) {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    let auth_middleware = ServiceBuilder::new()
        .layer(tower_http::auth::AddAuthorizationLayer::basic(username, password));

    let server = Server::builder()
        .set_http_middleware(auth_middleware)
        .http_only()
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
    use std::str::FromStr;

    use super::*;
    use jsonrpsee::types::Params;
    use lightning_signer::util::{
        status::Code,
        test_utils::{
            init_node, LDK_TEST_NODE_CONFIG, REGTEST_NODE_CONFIG, TEST_NODE_CONFIG, TEST_SEED,
        },
    };

    #[test]
    fn test_address_list_default_types() {
        let node = init_node(LDK_TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);
        let request = AddressListRequest {
            address_type: None,
            start: Some(1),
            count: Some(3),
            path: Some(DerivationPath::from_str("11h/4").unwrap()),
        };

        let response = server.handle_address_list(request).unwrap();

        assert_eq!(response.addresses.len(), 3);
        assert_eq!(response.network, "testnet");
        assert_eq!(
            0,
            response.addresses.iter().filter(|a| a.address_type != AddressType::Native).count()
        );

        assert_eq!("tb1q2hr2jnqvv8ruegfxs4rau0pm34sa8hk4mlsu3p", response.addresses[0].address);
        assert_eq!("11'/4/1", response.addresses[0].path);
        assert_eq!("tb1q5ranxtm72p6lpujkewj2tj4nkpe9922zfvcxqt", response.addresses[1].address);
        assert_eq!("11'/4/2", response.addresses[1].path);
        assert_eq!("tb1qkqeuxx69rtxfzjw8r3r2yw7jgynrersjue5vc8", response.addresses[2].address);
        assert_eq!("11'/4/3", response.addresses[2].path);
    }

    #[test]
    fn test_address_list_specific_types() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);
        let request = AddressListRequest {
            address_type: Some(AddressType::Wrapped),
            start: Some(0),
            count: Some(3),
            path: None,
        };

        let response = server.handle_address_list(request).unwrap();

        assert_eq!(response.addresses.len(), 3);
        assert_eq!(
            0,
            response.addresses.iter().filter(|a| a.address_type != AddressType::Wrapped).count()
        );
    }

    #[test]
    fn test_address_verify() {
        let node = init_node(REGTEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node.clone());
        let address = "bcrt1q64wyjwvrmdj3uyz8w32mr4qgcv08a833zepjm3".to_owned();
        let request = AddressVerifyRequest {
            address: address.clone(),
            start: Some(9),
            limit: Some(20),
            path: None,
        };

        let response = server.handle_address_verify(request).unwrap();

        assert_eq!(address, response.address);
        assert!(response.valid);
        assert!(response.address_info.is_some());
        let derivation = response.address_info.unwrap();
        assert_eq!(derivation.address_type, AddressType::Native);
        assert_eq!(derivation.path, "11");
    }

    #[test]
    fn test_address_verify_invalid_address() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);

        let request = AddressVerifyRequest {
            address: "invalid_address".to_string(),
            start: Some(0),
            limit: Some(20),
            path: None,
        };

        let result = server.handle_address_verify(request);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!("invalid address: base58 error", error.message());
    }

    #[test]
    fn test_address_verify_not_found_in_range() {
        let node = init_node(REGTEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node);
        let address = "bcrt1q64wyjwvrmdj3uyz8w32mr4qgcv08a833zepjm3".to_owned();
        let request = AddressVerifyRequest {
            address: address.clone(),
            start: Some(0),
            limit: Some(5),
            path: None,
        };

        let result = server.handle_address_verify(request).unwrap();
        assert_eq!(address, result.address);
        assert!(!result.valid);
    }

    #[test]
    fn test_request_parsing() {
        let params = Params::new(Some("{\"address_type\":null,\"count\":null}"));
        let addresslist: AddressListRequest = params.parse().unwrap();
        assert!(addresslist.address_type.is_none());
    }
}
