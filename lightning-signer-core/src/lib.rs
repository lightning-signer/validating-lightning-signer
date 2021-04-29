#![crate_name = "lightning_signer"] // NOT TESTED
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate hex;
extern crate rand;
#[cfg(feature = "grpc")]
extern crate tonic;

#[macro_use]
pub mod util;
pub mod node;
pub mod persist;
pub mod policy;
pub mod signer;
pub mod tx;
