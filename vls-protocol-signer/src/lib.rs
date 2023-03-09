//! A protocol handler for the VLS protocol.
//! See [handler::Handler] for more details.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![forbid(unsafe_code)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

extern crate alloc;

/// External approver plugins
pub mod approver;
/// Protocol handler
pub mod handler;
/// Utilities
pub mod util;

pub use lightning_signer;
pub use vls_protocol;
