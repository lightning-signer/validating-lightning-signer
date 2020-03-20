
* EnforcingChannelKeys::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?
* Prefix Node and Channel logging with terse node_id and channel_id.
* sign_remote_commitment and sign_closing_transaction return ambiguous errors (untyped).
