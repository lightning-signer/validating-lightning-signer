#![crate_name = "lightning_signer_server"]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate hex;
#[cfg(feature = "grpc")]
extern crate tonic;

use lightning_signer::lightning;

pub mod fslogger;
pub mod persist;
pub mod util;
#[macro_use]
#[cfg(feature = "grpc")]
pub mod client;
#[cfg(feature = "grpc")]
pub mod server;

pub const SERVER_APP_NAME: &str = "vlsd";
pub const CLIENT_APP_NAME: &str = "vls-cli";
pub const NETWORK_NAMES: [&str; 3] = ["testnet", "regtest", "signet"];
