/// Policy errors
#[macro_use]
pub mod error;
/// Filter
pub mod filter;
/// Null policy enforcement
#[cfg(feature = "test_utils")]
pub mod null_validator;
/// Basic policy enforcement plus on-chain validation
pub mod onchain_validator;
/// Basic policy enforcement
pub mod simple_validator;
/// Policy enforcement interface
pub mod validator;

use crate::prelude::*;
use crate::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};

/// The default velocity control for L1 fees
pub const DEFAULT_FEE_VELOCITY_CONTROL: VelocityControlSpec =
    VelocityControlSpec { limit: 1000000, interval_type: VelocityControlIntervalType::Daily };

/// Default maximum number of concurrent channels
pub const MAX_CHANNELS: usize = 100;

/// Default maximum number of outstanding invoices (issued and approved)
pub const MAX_INVOICES: usize = 1000;

/// The maximum L1 transaction size
pub const MAX_ONCHAIN_TX_SIZE: usize = 32 * 1024;

/// An enforcement policy
pub trait Policy {
    /// A policy error has occurred.
    /// Policy errors can be converted to warnings by returning `Ok(())`
    fn policy_error(&self, _tag: String, msg: String) -> Result<(), error::ValidationError>;
    /// Log at ERROR or WARN matching the policy error handling
    fn policy_log(&self, _tag: String, msg: String);
    /// Velocity control to apply to the entire node
    fn global_velocity_control(&self) -> VelocityControlSpec;
    /// Maximum number of concurrent channels
    fn max_channels(&self) -> usize {
        MAX_CHANNELS
    }
    /// Maximum number of concurrent invoices (issued and approved)
    fn max_invoices(&self) -> usize {
        MAX_INVOICES
    }
    /// Velocity control to apply to L1 fees paid by the node
    fn fee_velocity_control(&self) -> VelocityControlSpec;
}
