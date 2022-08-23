#![crate_name = "lightning_signer"]

//! A policy-enforcing signer for Lightning
//! See [`node::Node`] for the entry point.

#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[cfg(not(feature = "std"))]
extern crate core2;

#[macro_use]
extern crate alloc;
extern crate core;
#[cfg(feature = "grpc")]
extern crate tonic;

pub use bitcoin;
pub use lightning;
pub use lightning_invoice;

/// Chain tracking and validation
pub mod chain;
/// Various utilities
#[macro_use]
pub mod util;
/// Channel
pub mod channel;
/// Channel on-chain monitor
pub mod monitor;
/// Node
pub mod node;
/// Persistence
pub mod persist;
/// Policy enforcement
pub mod policy;
/// KeysManager
pub mod signer;
/// Transaction parsing and construction
pub mod tx;
/// Layer-1 wallet
pub mod wallet;

#[cfg(not(feature = "std"))]
mod io_extras {
    pub use core2::io::{self, Error, Read, Write};

    /// A writer which will move data into the void.
    pub struct Sink {
        _priv: (),
    }

    /// Creates an instance of a writer which will successfully consume all data.
    pub const fn sink() -> Sink {
        Sink { _priv: () }
    }

    impl core2::io::Write for Sink {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
            Ok(buf.len())
        }

        #[inline]
        fn flush(&mut self) -> core2::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
mod io_extras {
    pub use std::io::{self, sink, Error, Read};
}

pub use io_extras::io;

pub use alloc::collections::BTreeSet as OrderedSet;
pub use alloc::rc::Rc;
pub use alloc::sync::{Arc, Weak};

#[cfg(not(feature = "std"))]
mod nostd;

/// std / no_std compat
pub mod prelude {
    pub use alloc::{boxed::Box, string::String, vec, vec::Vec};

    // TODO clean up naming
    pub use hashbrown::HashMap as Map;
    pub use hashbrown::HashSet as UnorderedSet;

    pub use alloc::collections::BTreeMap as OrderedMap;
    pub use alloc::collections::BTreeSet as OrderedSet;

    pub use alloc::borrow::ToOwned;
    pub use alloc::string::ToString;

    #[cfg(not(feature = "std"))]
    pub use crate::nostd::*;

    #[cfg(feature = "std")]
    pub use std::sync::{Mutex, MutexGuard};

    /// Convenience trait for Send + Sync
    #[cfg(feature = "std")]
    pub trait SendSync: Send + Sync {}
}

pub use prelude::SendSync;

#[cfg(feature = "std")]
mod sync {
    pub use ::std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, Weak};
}

#[cfg(not(feature = "std"))]
#[allow(unused)]
mod sync;

#[cfg(test)]
mod ready_channel_tests;
#[cfg(test)]
mod sign_counterparty_commitment_tests;
#[cfg(test)]
mod sign_counterparty_htlc_sweep_tests;
#[cfg(test)]
mod sign_delayed_sweep_tests;
#[cfg(test)]
mod sign_holder_commitment_tests;
#[cfg(test)]
mod sign_htlc_tx_tests;
#[cfg(test)]
mod sign_justice_sweep_tests;
#[cfg(test)]
mod sign_mutual_close_tests;
#[cfg(test)]
mod sign_onchain_tx_tests;
#[cfg(test)]
mod validate_counterparty_revocation_tests;
#[cfg(test)]
mod validate_holder_commitment_tests;
