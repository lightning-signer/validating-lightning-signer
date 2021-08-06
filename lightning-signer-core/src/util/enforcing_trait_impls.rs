use log::debug;

use bitcoin::secp256k1::key::PublicKey;
use crate::policy::error::{policy_error, ValidationError};

#[derive(Clone, Debug)]
pub struct EnforcementState {
    pub next_holder_commit_num: u64,
    pub next_counterparty_commit_num: u64,
    pub next_counterparty_revoke_num: u64,
    pub current_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 1
    pub previous_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 2
}

impl EnforcementState {
    pub fn new() -> EnforcementState {
        EnforcementState {
            next_holder_commit_num: 0,
            next_counterparty_commit_num: 0,
            next_counterparty_revoke_num: 0,
            current_counterparty_point: None,
            previous_counterparty_point: None
        }
    }

    pub fn set_next_holder_commit_num(&mut self, num: u64) -> Result<(), ValidationError> {
        let current = self.next_holder_commit_num;
        if num != current && num != current + 1 {
            return Err(policy_error(format!(
                "invalid next_holder_commit_num progression: {} to {}",
                current, num
            )));
        }
        self.next_holder_commit_num = num;
        debug!("next_holder_commit_num {} -> {}", current, num);
        Ok(())
    }

    pub fn set_next_counterparty_commit_num(
        &mut self,
        num: u64,
        current_point: PublicKey,
    ) -> Result<(), ValidationError> {
        if num == 0 {
            return Err(policy_error(format!(
                "set_next_counterparty_commit_num: can't set next to 0"
            )));
        }

        // The initial commitment is special, it can advance even though next_revoke is 0.
        let delta = if num == 1 { 1 } else { 2 };

        // Ensure that next_commit is ok relative to next_revoke
        if num < self.next_counterparty_revoke_num + delta {
            return Err(policy_error(format!(
                "next_counterparty_commit_num {} too small \
                 relative to next_counterparty_revoke_num {}",
                num, self.next_counterparty_revoke_num
            )));
        }
        if num > self.next_counterparty_revoke_num + 2 {
            return Err(policy_error(format!(
                "next_counterparty_commit_num {} too large \
                 relative to next_counterparty_revoke_num {}",
                num, self.next_counterparty_revoke_num
            )));
        }

        let current = self.next_counterparty_commit_num;
        if num == current {
            // This is a retry.
            assert!(
                self.current_counterparty_point.is_some(),
                "set_next_counterparty_commit_num {} retry: \
                     current_counterparty_point not set, \
                     this shouldn't be possible",
                num
            );
            // policy-v2-commitment-retry-same
            if current_point != self.current_counterparty_point.unwrap() {
                debug!(
                    "current_point {} != prior {}",
                    current_point,
                    self.current_counterparty_point.unwrap()
                );
                return Err(policy_error(format!(
                    "set_next_counterparty_commit_num {} retry: \
                     point different than prior",
                    num
                )));
            }
        } else if num == current + 1 {
            self.previous_counterparty_point = self.current_counterparty_point;
            self.current_counterparty_point = Some(current_point);
        } else {
            return Err(policy_error(format!(
                "invalid next_counterparty_commit_num progression: {} to {}",
                current, num
            )));
        }

        self.next_counterparty_commit_num = num;
        debug!(
            "next_counterparty_commit_num {} -> {} current {}",
            current, num, current_point
        );
        Ok(())
    }

    pub fn get_previous_counterparty_point(&self, num: u64) -> Result<PublicKey, ValidationError> {
        let point = if num + 1 == self.next_counterparty_commit_num {
            &self.current_counterparty_point
        } else if num + 2 == self.next_counterparty_commit_num {
            &self.previous_counterparty_point
        } else {
            return Err(policy_error(format!(
                "get_previous_counterparty_point {} out of range",
                num
            )));
        }
        .unwrap_or_else(|| {
            panic!(
                "counterparty point for commit_num {} not set, \
                 next_commitment_number is {}",
                num, self.next_counterparty_commit_num
            );
        });
        Ok(point)
    }

    pub fn set_next_counterparty_revoke_num(&mut self, num: u64) -> Result<(), ValidationError> {
        if num == 0 {
            return Err(policy_error(format!(
                "set_next_counterparty_revoke_num: can't set next to 0"
            )));
        }

        // Ensure that next_revoke is ok relative to next_commit.
        if num + 2 < self.next_counterparty_commit_num {
            return Err(policy_error(format!(
                "next_counterparty_revoke_num {} too small \
                 relative to next_counterparty_commit_num {}",
                num, self.next_counterparty_commit_num
            )));
        }
        if num + 1 > self.next_counterparty_commit_num {
            return Err(policy_error(format!(
                "next_counterparty_revoke_num {} too large \
                 relative to next_counterparty_commit_num {}",
                num, self.next_counterparty_commit_num
            )));
        }

        let current = self.next_counterparty_revoke_num;
        if num != current && num != current + 1 {
            return Err(policy_error(format!(
                "invalid next_counterparty_revoke_num progression: {} to {}",
                current, num
            )));
        }

        self.next_counterparty_revoke_num = num;
        debug!("next_counterparty_revoke_num {} -> {}", current, num);
        Ok(())
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_holder_commit_num_for_testing(&mut self, num: u64) {
        debug!(
            "set_next_holder_commit_num_for_testing: {} -> {}",
            self.next_holder_commit_num, num
        );
        self.next_holder_commit_num = num;
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_counterparty_commit_num_for_testing(&mut self, num: u64, current_point: PublicKey) {
        debug!(
            "set_next_counterparty_commit_num_for_testing: {} -> {}",
            self.next_counterparty_commit_num, num
        );
        self.previous_counterparty_point = self.current_counterparty_point;
        self.current_counterparty_point = Some(current_point);
        self.next_counterparty_commit_num = num;
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_counterparty_revoke_num_for_testing(&mut self, num: u64) {
        debug!(
            "set_next_counterparty_revoke_num_for_testing: {} -> {}",
            self.next_counterparty_revoke_num, num
        );
        self.next_counterparty_revoke_num = num;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::test_utils::make_test_pubkey;

    use test_env_log::test;

    macro_rules! assert_policy_err {
        ($status: expr, $msg: expr) => {
            assert!($status.is_err());
            assert_eq!($status.unwrap_err(), policy_error($msg.to_string()));
        };
    }

    #[test]
    fn enforcement_state_previous_counterparty_point_test() {
        let mut state = EnforcementState::new();

        let point0 = make_test_pubkey(0x12);

        // you can never set next to 0
        assert_policy_err!(
            state.set_next_counterparty_commit_num(0, point0.clone()),
            "set_next_counterparty_commit_num: can\'t set next to 0"
        );

        // point for 0 is not set yet
        assert_policy_err!(
            state.get_previous_counterparty_point(0),
            "get_previous_counterparty_point 0 out of range"
        );

        // can't look forward either
        assert_policy_err!(
            state.get_previous_counterparty_point(1),
            "get_previous_counterparty_point 1 out of range"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(2, point0.clone()),
            "invalid next_counterparty_commit_num progression: 0 to 2"
        );

        // set point 0
        assert!(state
            .set_next_counterparty_commit_num(1, point0.clone())
            .is_ok());

        // and now you can get it.
        assert_eq!(
            state.get_previous_counterparty_point(0).unwrap(),
            point0.clone()
        );

        // you can set it again to the same thing (retry)
        // policy-v2-commitment-retry-same
        assert!(state
            .set_next_counterparty_commit_num(1, point0.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 1);

        // but setting it to something else is an error
        // policy-v2-commitment-retry-same
        let point1 = make_test_pubkey(0x16);
        assert_policy_err!(
            state.set_next_counterparty_commit_num(1, point1.clone()),
            "set_next_counterparty_commit_num 1 retry: point different than prior"
        );
        assert_eq!(state.next_counterparty_commit_num, 1);

        // can't get commit_num 1 yet
        assert_policy_err!(
            state.get_previous_counterparty_point(1),
            "get_previous_counterparty_point 1 out of range"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(3, point1.clone()),
            "next_counterparty_commit_num 3 too large relative to next_counterparty_revoke_num 0"
        );
        assert_eq!(state.next_counterparty_commit_num, 1);

        // set point 1
        assert!(state
            .set_next_counterparty_commit_num(2, point1.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 2);

        // you can still get commit_num 0
        assert_eq!(
            state.get_previous_counterparty_point(0).unwrap(),
            point0.clone()
        );

        // Now you can get commit_num 1
        assert_eq!(
            state.get_previous_counterparty_point(1).unwrap(),
            point1.clone()
        );

        // can't look forward
        assert_policy_err!(
            state.get_previous_counterparty_point(2),
            "get_previous_counterparty_point 2 out of range"
        );

        // can't skip forward
        assert_policy_err!(
            state.set_next_counterparty_commit_num(4, point1.clone()),
            "next_counterparty_commit_num 4 too large relative to next_counterparty_revoke_num 0"
        );
        assert_eq!(state.next_counterparty_commit_num, 2);

        assert!(state.set_next_counterparty_revoke_num(1).is_ok());

        // set point 2
        let point2 = make_test_pubkey(0x20);
        assert!(state
            .set_next_counterparty_commit_num(3, point2.clone())
            .is_ok());
        assert_eq!(state.next_counterparty_commit_num, 3);

        // You can't get commit_num 0 anymore
        assert_policy_err!(
            state.get_previous_counterparty_point(0),
            "get_previous_counterparty_point 0 out of range"
        );

        // you can still get commit_num 1
        assert_eq!(
            state.get_previous_counterparty_point(1).unwrap(),
            point1.clone()
        );

        // now you can get commit_num 2
        assert_eq!(
            state.get_previous_counterparty_point(2).unwrap(),
            point2.clone()
        );

        // can't look forward
        assert_policy_err!(
            state.get_previous_counterparty_point(3),
            "get_previous_counterparty_point 3 out of range"
        );
    }
}
