use crate::prelude::*;
use core::cmp::min;

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

/// The total interval in which to track velocity
#[derive(Clone, Copy)]
pub enum VelocityControlIntervalType {
    /// Tracked in 5 minute sub-intervals
    Hourly,
    /// Tracked in 1 hour sub-intervals
    Daily,
    /// Unlimited velocity
    Unlimited,
}

/// A specifier for creating velocity controls
#[derive(Clone, Copy)]
pub struct VelocityControlSpec {
    /// The limit per interval
    pub limit: u64,
    /// The interval type
    pub interval_type: VelocityControlIntervalType,
}

impl VelocityControlSpec {
    /// A velocity control spec for controls which don't limit velocity
    pub const UNLIMITED: VelocityControlSpec =
        VelocityControlSpec { limit: 0, interval_type: VelocityControlIntervalType::Unlimited };
}

impl VelocityControl {
    /// Create a velocity control with arbitrary specified intervals
    /// current_sec: the current second
    /// num_buckets: how many buckets to keep track of
    /// bucket_interval: each bucket represents this number of seconds
    /// limit: the total velocity limit when summing the buckets
    pub fn new_with_intervals(limit: u64, bucket_interval: u32, num_buckets: usize) -> Self {
        assert!(bucket_interval > 0 && num_buckets > 0);
        let mut buckets = Vec::new();
        buckets.resize(num_buckets, 0);
        VelocityControl { start_sec: 0, bucket_interval, buckets, limit }
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
        match spec.interval_type {
            VelocityControlIntervalType::Hourly => Self::new_with_intervals(spec.limit, 300, 12),
            VelocityControlIntervalType::Daily => Self::new_with_intervals(spec.limit, 3600, 24),
            VelocityControlIntervalType::Unlimited => Self::new_unlimited(300, 12),
        }
    }

    /// Whether this instance is unlimited (no control)
    pub fn is_unlimited(&self) -> bool {
        self.limit == u64::MAX
    }

    /// Update the velocity given the passage of time given by `current_sec`
    /// and the given velocity.  If the limit would be exceeded, the given velocity
    /// is not inserted and false is returned.
    pub fn insert(&mut self, current_sec: u64, velocity: u64) -> bool {
        let nshift = (current_sec - self.start_sec) / self.bucket_interval as u64;
        let len = self.buckets.len();
        let nshift = min(len, nshift as usize);
        self.buckets.resize(len - nshift, 0);
        for _ in 0..nshift {
            self.buckets.insert(0, 0);
        }
        self.start_sec = current_sec - (current_sec % self.bucket_interval as u64);
        let current_velocity = self.velocity();
        if current_velocity.saturating_add(velocity) > self.limit {
            false
        } else {
            self.buckets[0] = self.buckets[0].saturating_add(velocity);
            true
        }
    }

    /// The total velocity in the tracked interval.
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
