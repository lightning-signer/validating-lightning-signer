#![crate_name = "bitcoind_client"]

//! A bitcoind RPC client.

#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

/// Bitcoind RPC client
pub mod bitcoind_client;
mod convert;

pub use self::bitcoind_client::{BitcoindClient, BlockSource, Error};
