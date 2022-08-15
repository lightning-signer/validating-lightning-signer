use lightning_signer::node::NodeServices;
use lightning_signer::persist::DummyPersister;
use lightning_signer::policy::simple_validator::SimpleValidatorFactory;
use lightning_signer::signer::{multi_signer::MultiSigner, ClockStartingTimeFactory};
use lightning_signer::util::clock::StandardClock;
use std::sync::Arc;

/// A trivial program, just to check code size
pub fn main() {
    let validator_factory = SimpleValidatorFactory::new();
    let starting_time_factory = ClockStartingTimeFactory::new();
    let clock = StandardClock();
    let services = NodeServices {
        validator_factory: Arc::new(validator_factory),
        starting_time_factory,
        persister: Arc::new(DummyPersister {}),
        clock: Arc::new(clock),
    };
    let _signer = MultiSigner::new(services);
}
