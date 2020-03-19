
* Convert all `Status::internal` to `self.internal_error`
* Add format! of error to all map_err
* Look for all `|_|` and consider format!
* EnforcingChannelKeys::{sign_remote_commitment,sign_closing_transaction}
  seem pretty happy to panic, is this ok?
