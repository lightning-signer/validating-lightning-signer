
* Prefix Node and Channel logging with terse node_id and channel_id.
* EnforcingChannelKeys::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?
* sign_remote_commitment and sign_closing_transaction return ambiguous errors (untyped).

#### Coverage extension:

Can we get coverage from c-lightning integration tests?

Needs Further Thought:

* EnforcingChannelKeys::check_keys (maybe not used?)
* node/node.rs Channel::sign_remote_commitment_tx_phase2 htlc_signature in sigs

#### Appeal to rust-lightning to expose:

* lightning::util::byte_utils;
* lightning::util::test_utils;
