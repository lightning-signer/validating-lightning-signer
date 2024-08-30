#![no_main]

use libfuzzer_sys::fuzz_target;
use vls_fuzz::channel::{Action, ChannelFuzz};

fuzz_target!(|data: Vec<Action>| {
    let mut fuzz = ChannelFuzz::new();
    fuzz.run(data).unwrap();
});
