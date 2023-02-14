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
pub mod tstamp;
#[cfg(feature = "grpc")]
mod util;

pub const SERVER_APP_NAME: &str = "vlsd";
pub const CLIENT_APP_NAME: &str = "vls-cli";
pub const NETWORK_NAMES: &[&str] = &["testnet", "regtest", "signet", "bitcoin"];

/// Useful with clap's `Arg::default_value_ifs`
pub const CLAP_NETWORK_URL_MAPPING: &[(&str, Option<&str>, Option<&str>)] = &[
    ("network", Some("bitcoin"), Some("http://user:pass@127.0.0.1:8332")),
    ("network", Some("testnet"), Some("http://user:pass@127.0.0.1:18332")),
    ("network", Some("regtest"), Some("http://user:pass@127.0.0.1:18443")),
    ("network", Some("signet"), Some("http://user:pass@127.0.0.1:18443")),
];
