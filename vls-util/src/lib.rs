//! Utility functions for the Validating Lightning Signer

pub mod config;
pub mod env_var;
pub mod observability;
#[cfg(feature = "otlp")]
mod otlp;
pub mod persist;
pub mod util;

pub use env_var::*;

// Defines GIT_DESC
include!(concat!(env!("OUT_DIR"), "/version.rs"));
