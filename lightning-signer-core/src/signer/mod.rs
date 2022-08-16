/// An implementation of KeysInterface
pub mod my_keys_manager;
/// A multi-node signer
#[macro_use]
pub mod multi_signer;
/// Derivation styles
pub mod derive;

#[cfg(feature = "std")]
use alloc::sync::Arc;

/// A factory for entropy generation (often using the precise real time)
pub trait StartingTimeFactory: Send + Sync {
    /// Generate unique entropy
    //
    // LDK: KeysManager: starting_time isn't strictly required to actually be a time, but it must
    // absolutely, without a doubt, be unique to this instance
    fn starting_time(&self) -> (u64, u32);
}

/// A starting time factory which uses a hi-res tstamp for entropy
#[cfg(feature = "std")]
pub struct ClockStartingTimeFactory {}

#[cfg(feature = "std")]
impl StartingTimeFactory for ClockStartingTimeFactory {
    // LDK: KeysManager: starting_time isn't strictly required to actually be a time, but it must
    // absolutely, without a doubt, be unique to this instance
    fn starting_time(&self) -> (u64, u32) {
        use std::time::SystemTime;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        (now.as_secs(), now.subsec_nanos())
    }
}

#[cfg(feature = "std")]
impl ClockStartingTimeFactory {
    /// Create a ClockStartingTimeFactory
    pub fn new() -> Arc<dyn StartingTimeFactory> {
        Arc::new(ClockStartingTimeFactory {})
    }
}
