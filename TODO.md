
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

### ready-channel punch list

* Confirm handling in `check_client_capabilities`, is permissive ok?
* Figure out some sanity checks for hsmd.c<hsmd>

* Rebase onto latest `rust-lightning`.

* Convert Phase1 interfaces w/ Tx to Phase2 w/ info.

* Consider adding `push_msat`
* Consider adding `feerate_per_kw`
* How do we know when we've got them all?  Isn't generating the
  messages the proof we've done it?

* Disallow coldstart in prod.
