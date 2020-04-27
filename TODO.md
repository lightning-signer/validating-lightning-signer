
* Prefix Node and Channel logging with terse node_id and channel_id.
* EnforcingChannelKeys::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?
* sign_remote_commitment and sign_closing_transaction return ambiguous errors (untyped).

#### Coverage extension:

Can we get coverage from c-lightning integration tests?

Need Real Unit Test:

* MySigner::get_unilateral_close_key

Needs Further Thought:

* EnforcingChannelKeys::check_keys (maybe not used?)
* test_utils.rs (lots of dead code?)
* tx/script.rs Into<String> for ValidationError
* tx/script.rs untested ValidationError, expect_op, expect_number, expect_script_end, expect_data
* tx/script.rs expect_number PushBytes case
* tx/tx.rs build_commitment_tx {info.offered_htlcs, info.received_htlcs, sort txouts}
* tx/tx.rs (handle_received_htlc_script, handle_offered_htlc_script}
* node/node.rs Channel::sign_remote_commitment_tx_phase2 htlc_signature in sigs

#### Appeal to rust-lightning to expose:

* lightning::util::byte_utils;
* lightning::util::test_utils;
