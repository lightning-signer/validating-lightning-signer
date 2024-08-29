#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Action {
    AddHtlc(),
}

fn run(data: Vec<Action>) {
    for action in data {
        match action {
            Action::AddHtlc() => {}
        }
    }
}

fuzz_target!(|data: Vec<Action>| {
    run(data);
});
