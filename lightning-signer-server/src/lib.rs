#![crate_name = "lightning_signer_server"]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

pub use lightning_signer;

use lightning_signer::lightning;

pub mod fslogger;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "frontend")]
pub mod nodefront;
#[cfg(feature = "persist")]
pub mod persist;
#[cfg(feature = "grpc")]
mod util;

pub const SERVER_APP_NAME: &str = "vlsd";
pub const CLIENT_APP_NAME: &str = "vls-cli";
pub const NETWORK_NAMES: [&str; 3] = ["testnet", "regtest", "signet"];
