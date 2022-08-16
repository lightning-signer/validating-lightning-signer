use crate::SendSync;
use core::time::Duration;

/// A clock provider
///
/// On std platforms, use the StandardClock implementation
pub trait Clock: SendSync {
    /// A duration since the UNIX epoch
    fn now(&self) -> Duration;
}

#[cfg(feature = "std")]
mod standard {
    use super::SendSync;
    use core::time::Duration;
    use std::time::SystemTime;

    /// A clock provider using the std::time::SystemTime
    pub struct StandardClock();

    impl SendSync for StandardClock {}

    impl super::Clock for StandardClock {
        fn now(&self) -> Duration {
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
        }
    }
}

#[cfg(feature = "std")]
pub use standard::*;

mod manual {
    use crate::prelude::*;
    use alloc::sync::Arc;
    use core::time::Duration;

    /// A clock provider with manually updated notion of "now"
    pub struct ManualClock(Arc<Mutex<Duration>>);

    impl SendSync for ManualClock {}

    impl super::Clock for ManualClock {
        fn now(&self) -> Duration {
            self.0.lock().unwrap().clone()
        }
    }

    impl ManualClock {
        /// Create a manual clock
        pub fn new(now: Duration) -> Self {
            ManualClock(Arc::new(Mutex::new(now)))
        }

        /// Set the current time as duration since the UNIX epoch
        pub fn set(&self, now: Duration) {
            *self.0.lock().unwrap() = now;
        }
    }
}

pub use manual::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::SystemTime;

    #[test]
    fn std_test() {
        let clock = StandardClock();
        clock.now();
    }

    #[test]
    fn manual_test() {
        let now1 = now();
        let clock = ManualClock::new(now1);
        let dur1 = clock.now();
        sleep(Duration::from_millis(1));
        let now2 = now();
        assert_ne!(now1, now2);
        clock.set(now2);
        let dur2 = clock.now();
        assert_ne!(dur1, dur2);
    }

    fn now() -> Duration {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()
    }
}
