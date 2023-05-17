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

use crate::policy::error::temporary_policy_error;
use crate::prelude::*;
use crate::util::velocity::{VelocityControlIntervalType, VelocityControlSpec};
use core::time::Duration;
use error::{policy_error, ValidationError};
use filter::{FilterResult, PolicyFilter};
use log::warn;

/// The default velocity control for L1 fees
pub const DEFAULT_FEE_VELOCITY_CONTROL: VelocityControlSpec = VelocityControlSpec {
    limit_msat: 1_000_000_000,
    interval_type: VelocityControlIntervalType::Daily,
};

/// Default maximum number of concurrent channels
pub const MAX_CHANNELS: usize = 1000; // WORKAROUND for #305, #306

/// Default maximum number of outstanding invoices (issued and approved)
pub const MAX_INVOICES: usize = 1000;

/// The maximum L1 transaction size
pub const MAX_ONCHAIN_TX_SIZE: usize = 32 * 1024;

/// A new invoice must not expire sooner than this many seconds from now.
pub const MIN_INVOICE_EXPIRY: Duration = Duration::from_secs(60);

/// Allowed clock skew (e.g. from invoice issuer to us)
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// An enforcement policy
pub trait Policy {
    /// A policy error has occurred.
    /// Policy errors can be converted to warnings by returning `Ok(())`
    fn policy_error(&self, _tag: String, msg: String) -> Result<(), error::ValidationError>;
    /// A temporary policy error has occurred.
    /// Policy errors can be converted to warnings by returning `Ok(())`
    fn temporary_policy_error(
        &self,
        _tag: String,
        msg: String,
    ) -> Result<(), error::ValidationError>;
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

fn policy_error_with_filter(
    tag: String,
    msg: String,
    filter: &PolicyFilter,
) -> Result<(), ValidationError> {
    if filter.filter(tag.clone()) == FilterResult::Error {
        Err(policy_error(msg))
    } else {
        warn!("policy failed: {} {}", tag, msg);
        #[cfg(feature = "use_backtrace")]
        warn!("BACKTRACE:\n{:?}", backtrace::Backtrace::new());
        Ok(())
    }
}

fn temporary_policy_error_with_filter(
    tag: String,
    msg: String,
    filter: &PolicyFilter,
) -> Result<(), ValidationError> {
    if filter.filter(tag.clone()) == FilterResult::Error {
        Err(temporary_policy_error(msg))
    } else {
        warn!("policy temporarily failed: {} {}", tag, msg);
        #[cfg(feature = "use_backtrace")]
        warn!("BACKTRACE:\n{:?}", backtrace::Backtrace::new());
        Ok(())
    }
}
