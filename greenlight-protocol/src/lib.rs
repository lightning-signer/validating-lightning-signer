#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

pub mod msgs;
pub mod model;
mod error;
mod io;

pub use serde_bolt;
pub use error::{Error, Result};
