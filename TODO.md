
* Consider an enhanced error package; specifically when we get a
  validation error, the current logging reports the location of where
  validation error was fielded instead of where it was generated.
  Would adding context in the `anyhow` crate be a good solution?

* Prefix Node and Channel logging with terse node_id and channel_id.

* EnforcingSigner::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?

* sign_remote_commitment and sign_closing_transaction return ambiguous errors (untyped).

* Disallow coldstart in prod.

Needs Further Thought:

* EnforcingSigner::check_keys (maybe not used?)
* node/node.rs Channel::sign_remote_commitment_tx_phase2 htlc_signature in sigs

#### Appeal to rust-lightning to expose:

* lightning::util::byte_utils;
* lightning::util::test_utils;

