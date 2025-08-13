pub mod address_generation;
pub mod model;
pub mod server;

pub use model::{
    AddressInfo, AddressListRequest, AddressListResponse, AddressType, AddressVerifyRequest,
    AddressVerifyResponse, InfoModel,
};
pub use server::start_rpc_server;
pub use server::RpcServer;
