use crate::prelude::*;
use core::cmp::min;
use core::fmt::{self, Debug, Formatter};

/// Limit velocity per unit time.
///
/// We track velocity in intervals instead of tracking each send, to keep
/// storage requirements constant.
#[derive(Clone)]
pub struct VelocityControl {
    /// start second for the current velocity epoch
    pub start_sec: u64,
    /// the number of seconds represented by a bucket
    pub bucket_interval: u32,
    /// each bucket entry is the total velocity detected in that interval, in satoshi
    pub buckets: Vec<u64>,
    /// the limit, or MAX if the control is disabled
    pub limit: u64,
}

impl Debug for VelocityControl {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("VelocityControl")
            .field("start_sec", &self.start_sec)
            .field("bucket_interval", &self.bucket_interval)
            .field("buckets", &format_args!("{:?}", self.buckets))
            .field("limit", &self.limit)
            .finish()
    }
}

/// The total interval in which to track velocity
#[derive(Clone, Copy, Debug)]
pub enum VelocityControlIntervalType {
    /// Tracked in 5 minute sub-intervals
    Hourly,
    /// Tracked in 1 hour sub-intervals
    Daily,
    /// Unlimited velocity
    Unlimited,
}

/// A specifier for creating velocity controls
#[derive(Clone, Copy, Debug)]
pub struct VelocityControlSpec {
    /// The limit per interval in msat
    pub limit_msat: u64,
    /// The interval type
    pub interval_type: VelocityControlIntervalType,
}

impl VelocityControlSpec {
    /// A velocity control spec for controls which don't limit velocity
    pub const UNLIMITED: VelocityControlSpec = VelocityControlSpec {
        limit_msat: 0,
        interval_type: VelocityControlIntervalType::Unlimited,
    };
}

impl VelocityControl {
    /// Create a velocity control with arbitrary specified intervals
    /// current_sec: the current second
    /// num_buckets: how many buckets to keep track of
    /// bucket_interval: each bucket represents this number of seconds
    /// limit: the total velocity limit when summing the buckets
    pub fn new_with_intervals(limit_msat: u64, bucket_interval: u32, num_buckets: usize) -> Self {
        assert!(bucket_interval > 0 && num_buckets > 0);
        let mut buckets = Vec::new();
        buckets.resize(num_buckets, 0);
        VelocityControl { start_sec: 0, bucket_interval, buckets, limit: limit_msat }
    }

    /// Create an unlimited velocity control (i.e. no actual control)
    pub fn new_unlimited(bucket_interval: u32, num_buckets: usize) -> Self {
        assert!(bucket_interval > 0 && num_buckets > 0);
        let mut buckets = Vec::new();
        buckets.resize(num_buckets, 0);
        VelocityControl { start_sec: 0, bucket_interval, buckets, limit: u64::MAX }
    }

    /// Create a velocity control with the given interval type
    pub fn new(spec: VelocityControlSpec) -> Self {
        let (limit, bucket_interval, num_buckets) = Self::spec_to_triple(&spec);
        Self::new_with_intervals(limit, bucket_interval, num_buckets)
    }

    /// Whether the spec matches this control
    pub fn spec_matches(&self, spec: &VelocityControlSpec) -> bool {
        let (limit, bucket_interval, num_buckets) = Self::spec_to_triple(spec);
        self.limit == limit
            && self.bucket_interval == bucket_interval
            && self.buckets.len() == num_buckets
    }

    /// Update this control to match the given spec.  If the spec does not
    /// match the previous spec, the control is reset.
    pub fn update_spec(&mut self, spec: &VelocityControlSpec) {
        if !self.spec_matches(spec) {
            let (limit, bucket_interval, num_buckets) = Self::spec_to_triple(spec);
            self.limit = limit;
            self.bucket_interval = bucket_interval;
            self.buckets = Vec::new();
            self.buckets.resize(num_buckets, 0);
            self.start_sec = 0;
        }
    }

    // Convert a spec to a (limit, bucket_interval, num_buckets) triple
    fn spec_to_triple(spec: &VelocityControlSpec) -> (u64, u32, usize) {
        match spec.interval_type {
            VelocityControlIntervalType::Hourly => (spec.limit_msat, 300, 12),
            VelocityControlIntervalType::Daily => (spec.limit_msat, 3600, 24),
            VelocityControlIntervalType::Unlimited => (u64::MAX, 300, 12),
        }
    }

    /// Load from persistence
    pub fn load_from_state(spec: VelocityControlSpec, state: (u64, Vec<u64>)) -> Self {
        let control = Self::new(spec);
        control.with_state(state)
    }

    fn with_state(mut self, state: (u64, Vec<u64>)) -> VelocityControl {
        self.start_sec = state.0;
        self.buckets = state.1;
        self
    }

    /// Get the state for persistence
    pub fn get_state(&self) -> (u64, Vec<u64>) {
        (self.start_sec, self.buckets.clone())
    }

    /// Whether this instance is unlimited (no control)
    pub fn is_unlimited(&self) -> bool {
        self.limit == u64::MAX
    }

    /// Update the velocity given the passage of time given by `current_sec`
    /// and the given velocity.  If the limit would be exceeded, the given velocity
    /// is not inserted and false is returned.
    pub fn insert(&mut self, current_sec: u64, velocity_msat: u64) -> bool {
        let nshift = (current_sec - self.start_sec) / self.bucket_interval as u64;
        let len = self.buckets.len();
        let nshift = min(len, nshift as usize);
        self.buckets.resize(len - nshift, 0);
        for _ in 0..nshift {
            self.buckets.insert(0, 0);
        }
        self.start_sec = current_sec - (current_sec % self.bucket_interval as u64);
        let current_velocity = self.velocity();
        if current_velocity.saturating_add(velocity_msat) > self.limit {
            false
        } else {
            self.buckets[0] = self.buckets[0].saturating_add(velocity_msat);
            true
        }
    }

    /// Clear the control (e.g. when the user manually approves)
    pub fn clear(&mut self) {
        for bucket in self.buckets.iter_mut() {
            *bucket = 0;
        }
    }

    /// The total msat velocity in the tracked interval.
    ///
    /// If this is an unlimited control, zero is always returned.
    pub fn velocity(&self) -> u64 {
        let mut sum = 0u64;
        for bucket in self.buckets.iter() {
            sum = sum.saturating_add(*bucket)
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use crate::util::velocity::VelocityControl;

    #[test]
    fn test_velocity() {
        let mut c = VelocityControl::new_with_intervals(100, 10, 4);
        assert_eq!(c.velocity(), 0);
        assert!(c.insert(1100, 90));
        assert_eq!(c.velocity(), 90);
        assert!(!c.insert(1101, 11));
        assert_eq!(c.velocity(), 90);
        assert!(c.insert(1101, 10));
        assert_eq!(c.velocity(), 100);
        assert!(!c.insert(1139, 90));
        assert_eq!(c.velocity(), 100);
        assert!(c.insert(1140, 90));
        assert_eq!(c.velocity(), 90);
        assert!(c.insert(1150, 5));
        assert_eq!(c.velocity(), 95);
        assert!(c.insert(1180, 80));
        assert_eq!(c.velocity(), 85);
        assert!(c.insert(1190, 1));
        assert_eq!(c.velocity(), 81);
    }

    #[test]
    fn test_unlimited() {
        let mut c = VelocityControl::new_unlimited(10, 4);
        assert!(c.insert(0, u64::MAX - 1));
        assert_eq!(c.velocity(), u64::MAX - 1);
        assert!(c.insert(0, 1));
        assert_eq!(c.velocity(), u64::MAX);
        assert!(c.insert(0, 1));
        assert_eq!(c.velocity(), u64::MAX);
    }
}
