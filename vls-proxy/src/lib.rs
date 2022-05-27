//! Proxy connection from node to VLS.
//! In particular, a replacement for CLN's hsmd binary.

pub mod client;
pub mod connection;
pub mod grpc;
pub mod portfront;
pub mod util;
