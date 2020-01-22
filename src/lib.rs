#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate hex;
extern crate rand;
extern crate secp256k1;
extern crate tonic;

pub mod test;
#[allow(unused_imports)] pub mod functional_test;
mod server;
mod client;
