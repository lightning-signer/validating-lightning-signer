
* Prefix Node and Channel logging with terse node_id and channel_id.
* EnforcingChannelKeys::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?
* sign_remote_commitment and sign_closing_transaction return ambiguous errors (untyped).

Coverage extension:
* MyKeysManager::get_channel_keys
* MySigner::get_unilateral_close_key
* MySigner::ecdh
* invoice_utils::hash_from_parts "overhang case"
* byte_utils.rs
* EnforcingChannelKeys::check_keys (maybe not used?)
* test_utils.rs (lots of dead code?)
* LoopbackChannelSigner:{pubkeys,remote_pubkeys}
* functional_test_utils.{connect_blocks, SendEvent::from_node}
* tx/script.rs Into<String> for ValidationError
* tx/script.rs expect_number
* tx/build_commitment_tx {info.offered_htlcs, info.received_htlcs, sort txouts
* tx (handle_received_htlc_script, handle_offered_htlc_script}
* node.rs Channel::{invalid_argument, internal_error, is_ready}
* node.rs Channel::sign_remote_commitment_tx_phase2 htlc_signature in sigs
* node.rs Node::{invalid_argument, internal_error}
