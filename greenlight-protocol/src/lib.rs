#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

mod error;
mod io;
pub mod model;
pub mod msgs;

pub use error::{Error, Result};
pub use serde_bolt;
