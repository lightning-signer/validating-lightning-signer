//! Test suite for the Web and headless browsers.

// Use if tests are only suitable for wasm32 test
// #![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;

use bindgen_test::{make_node, JSChannelPublicKeys, JSChannelSetup, JSOutPoint};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[wasm_bindgen_test]
fn channel_test() {
    let node = make_node();
    let channel_id = node.new_channel();
    let cp_keys = JSChannelPublicKeys::new();
    let outpoint = JSOutPoint::default();
    let setup = JSChannelSetup::new(cp_keys, outpoint);
    node.ready_channel(channel_id, setup).unwrap();
}
