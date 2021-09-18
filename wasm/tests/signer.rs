//! Test suite for the Web and headless browsers.

// Use if tests are only suitable for wasm32 test
// #![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;

use bindgen_test::{make_node, JSChannelPublicKeys, JSChannelSetup, JSOutPoint, JSPublicKey};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[wasm_bindgen_test]
fn channel_test() {
    let node = make_node();
    let channel_id = node.new_channel();
    let cp_keys = JSChannelPublicKeys::new(
        JSPublicKey::new_test_key(100),
        JSPublicKey::new_test_key(101),
        JSPublicKey::new_test_key(102),
        JSPublicKey::new_test_key(103),
        JSPublicKey::new_test_key(104),
    );
    let outpoint = JSOutPoint::default();
    let setup = JSChannelSetup::new(false, 10000, 0, outpoint, 6, cp_keys, 6);
    node.ready_channel(&channel_id, &setup).unwrap();
    let _sig1 = node
        .sign_holder_commitment(
            &channel_id,
            0,    // Commitment number
            9000, // to holder
            0,    // to counterparty
        )
        .unwrap();
}
