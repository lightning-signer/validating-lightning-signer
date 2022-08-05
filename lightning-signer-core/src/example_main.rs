use lightning_signer::signer::{multi_signer::MultiSigner, ClockStartingTimeFactory};

/// A trivial program, just to check code size
pub fn main() {
    let _signer = MultiSigner::new(ClockStartingTimeFactory::new());
}
