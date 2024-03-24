#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

mod error;
pub mod features;
pub mod model;
pub mod msgs;
/// Streaming PSBT
pub mod psbt;
pub mod util;

pub use error::{Error, Result};
pub use serde_bolt;
