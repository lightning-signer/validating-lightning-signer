#![crate_name = "lightning_signer"] // NOT TESTED
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

extern crate bitcoin;
extern crate hex;
extern crate rand;
#[cfg(feature = "grpc")]
extern crate tonic;
extern crate alloc;

#[macro_use]
pub mod util;
pub mod node;
pub mod persist;
pub mod policy;
pub mod signer;
pub mod tx;

#[cfg(not(feature = "std"))]
mod nostd;

// TODO these are required because of rust-lightning
pub use std::io::{Error as IOError, Read as IORead};

/// This trait will be used to apply Send + Sync gated by no_std
#[cfg(feature = "std")]
pub trait SendSync: Send + Sync {}

#[cfg(feature = "std")]
pub use std::sync::{Mutex, MutexGuard};

#[cfg(not(feature = "std"))]
pub use nostd::*;

pub use alloc::sync::Arc;
pub use alloc::rc::Rc;
pub use alloc::collections::BTreeSet as Set;
pub use hashbrown::HashMap as Map;
