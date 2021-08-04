#![crate_name = "lightning_signer"] // NOT TESTED
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(broken_intra_doc_links)]
// #![warn(missing_docs)]

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[cfg(not(feature = "std"))] extern crate core2;

#[macro_use]
extern crate alloc;
extern crate core;
extern crate bitcoin;
#[cfg(feature = "std")]
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
    pub use std::io::{Error, Read, sink};
}

pub use alloc::collections::BTreeSet as Set;
pub use alloc::rc::Rc;
pub use alloc::sync::{Arc, Weak};

#[cfg(not(feature = "std"))]
mod nostd;

pub mod prelude {
    pub use alloc::{vec, vec::Vec, string::String, boxed::Box};
    pub use hashbrown::HashMap as Map;

    pub use alloc::borrow::ToOwned;
    pub use alloc::string::ToString;

    #[cfg(not(feature = "std"))]
    pub use crate::nostd::*;

    #[cfg(feature = "std")]
    pub use std::sync::{Mutex, MutexGuard};

    #[cfg(feature = "std")]
    pub trait SendSync: Send + Sync {}
}

#[cfg(feature = "std")]
mod sync {
    pub use ::std::sync::{Arc, Mutex, Condvar, MutexGuard, RwLock, RwLockReadGuard, Weak};
}

#[cfg(not(feature = "std"))]
#[allow(unused)]
mod sync;
