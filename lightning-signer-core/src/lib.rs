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

// TODO provide no_std implementations of the items below

/// This trait will be used to apply Send + Sync gated by no_std
pub trait SendSync: Send + Sync {}

pub use std::rc::Rc;
pub use std::sync::{Arc, Mutex, MutexGuard};
pub use std::io::{Error as IOError, Read as IORead};
pub use std::collections::BTreeSet as Set;
pub use std::collections::HashMap as Map;
pub use std::error::Error as StdError;
