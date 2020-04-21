#![crate_name = "lightning_signer"]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate hex;
extern crate rand;
extern crate secp256k1;
extern crate tonic;

// FILE NOT TESTED

pub mod tx;
#[macro_use]
pub mod util;
pub mod client;
pub mod node;
pub mod server;
pub mod test;
