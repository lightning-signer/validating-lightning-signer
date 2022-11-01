#![crate_name = "lightning_signer_server"]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

pub use lightning_signer;
pub use vls_persist as persist;

pub mod fslogger;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "frontend")]
pub mod nodefront;
#[cfg(feature = "grpc")]
mod util;

pub const SERVER_APP_NAME: &str = "vlsd";
pub const CLIENT_APP_NAME: &str = "vls-cli";
pub const NETWORK_NAMES: &[&str] = &["testnet", "regtest", "signet", "bitcoin"];

/// Useful with clap's `Arg::default_value_ifs`
pub const CLAP_NETWORK_URL_MAPPING: &[(&str, Option<&str>, &str)] = &[
    ("network", Some("bitcoin"), "http://user:pass@127.0.0.1:8332"),
    ("network", Some("testnet"), "http://user:pass@127.0.0.1:18332"),
    ("network", Some("regtest"), "http://user:pass@127.0.0.1:18443"),
    ("network", Some("signet"), "http://user:pass@127.0.0.1:18443"),
];
