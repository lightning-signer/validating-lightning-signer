use alloc::sync::Arc;
use core::cell::RefCell;
use rand_core::RngCore;

use stm32f4xx_hal::rng::Rng;

use crate::lightning_signer::prelude::SendSync;
use crate::lightning_signer::signer::StartingTimeFactory;

/// A starting time factory which uses entropy from the RNG
pub(crate) struct RandomStartingTimeFactory {
    rng: RefCell<Rng>,
}

impl SendSync for RandomStartingTimeFactory {}

impl StartingTimeFactory for RandomStartingTimeFactory {
    // LDK: KeysManager: starting_time isn't strictly required to actually be a time, but it must
    // absolutely, without a doubt, be unique to this instance
    fn starting_time(&self) -> (u64, u32) {
        let mut rng = self.rng.borrow_mut();
        (rng.next_u64(), rng.next_u32())
    }
}

impl RandomStartingTimeFactory {
    pub(crate) fn new(rng: RefCell<Rng>) -> Arc<dyn StartingTimeFactory> {
        Arc::new(RandomStartingTimeFactory { rng })
    }
}
