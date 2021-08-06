use crate::io_extras::{Error as IOError, Read as IORead};
use crate::prelude::*;
use crate::sync::Arc;

use log::debug;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};
use bitcoin::secp256k1::{All, Secp256k1, Signature};
use chain::keysinterface::InMemorySigner;
use lightning::chain;
use lightning::chain::keysinterface::BaseSign;
use lightning::ln;
use lightning::ln::chan_utils::{
    ChannelTransactionParameters, CommitmentTransaction, HolderCommitmentTransaction,
};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use ln::chan_utils::{ChannelPublicKeys, HTLCOutputInCommitment};
use ln::msgs;

use crate::policy::error::{policy_error, ValidationError};

/// Enforces some rules on Sign calls. Eventually we will
/// probably want to expose a variant of this which would essentially
/// be what you'd want to run on a hardware wallet.
#[derive(Clone)]
pub struct EnforcingSigner {
    inner: InMemorySigner,
    pub state: Arc<Mutex<EnforcementState>>,
}

#[derive(Clone, Debug)]
pub struct EnforcementState {
    pub next_holder_commit_num: u64,
    pub next_counterparty_commit_num: u64,
    pub next_counterparty_revoke_num: u64,
    pub current_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 1
    pub previous_counterparty_point: Option<PublicKey>, // next_counterparty_commit_num - 2
}

impl EnforcementState {
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
}

impl EnforcingSigner {
    pub fn new(inner: InMemorySigner) -> Self {
        let state = EnforcementState {
            next_holder_commit_num: 0,
            next_counterparty_commit_num: 0,
            next_counterparty_revoke_num: 0,
            current_counterparty_point: None,
            previous_counterparty_point: None,
        };
        EnforcingSigner::new_with_state(inner, state)
    }

    pub fn new_with_state(inner: InMemorySigner, state: EnforcementState) -> EnforcingSigner {
        Self {
            inner,
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn enforcement_state(&self) -> EnforcementState {
        self.state.lock().unwrap().clone()
    }

    pub fn counterparty_pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.counterparty_pubkeys()
    }

    pub fn inner(&self) -> InMemorySigner {
        self.inner.clone()
    }

    pub fn next_holder_commit_num(&self) -> u64 {
        self.state.lock().unwrap().next_holder_commit_num
    }

    pub fn next_counterparty_commit_num(&self) -> u64 {
        self.state.lock().unwrap().next_counterparty_commit_num
    }

    pub fn next_counterparty_revoke_num(&self) -> u64 {
        self.state.lock().unwrap().next_counterparty_revoke_num
    }

    pub fn set_next_holder_commit_num(&self, num: u64) -> Result<(), ValidationError> {
        let mut state = self.state.lock().unwrap();
        state.set_next_holder_commit_num(num)
    }

    pub fn set_next_counterparty_commit_num(
        &self,
        num: u64,
        current_point: PublicKey,
    ) -> Result<(), ValidationError> {
        let mut state = self.state.lock().unwrap();
        state.set_next_counterparty_commit_num(num, current_point)
    }

    pub fn set_next_counterparty_revoke_num(&self, num: u64) -> Result<(), ValidationError> {
        let mut state = self.state.lock().unwrap();
        state.set_next_counterparty_revoke_num(num)
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_holder_commit_num_for_testing(&self, num: u64) {
        let mut state = self.state.lock().unwrap();
        debug!(
            "set_next_holder_commit_num_for_testing: {} -> {}",
            state.next_holder_commit_num, num
        );
        state.next_holder_commit_num = num;
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_counterparty_commit_num_for_testing(&self, num: u64, current_point: PublicKey) {
        let mut state = self.state.lock().unwrap();
        debug!(
            "set_next_counterparty_commit_num_for_testing: {} -> {}",
            state.next_counterparty_commit_num, num
        );
        state.previous_counterparty_point = state.current_counterparty_point;
        state.current_counterparty_point = Some(current_point);
        state.next_counterparty_commit_num = num;
    }

    #[cfg(feature = "test_utils")]
    pub fn set_next_counterparty_revoke_num_for_testing(&self, num: u64) {
        let mut state = self.state.lock().unwrap();
        debug!(
            "set_next_counterparty_revoke_num_for_testing: {} -> {}",
            state.next_counterparty_revoke_num, num
        );
        state.next_counterparty_revoke_num = num;
    }

    // TODO leaking secrets below.
    // We don't take advantage of the signing operations in InMemorySigner because that
    // requires phase 2. In particular, the commitment and HTLCs must be signed in one operation.
    pub fn funding_key(&self) -> &SecretKey {
        &self.inner.funding_key
    }
    pub fn revocation_base_key(&self) -> &SecretKey {
        &self.inner.revocation_base_key
    }
    pub fn payment_key(&self) -> &SecretKey {
        &self.inner.payment_key
    }
    pub fn delayed_payment_base_key(&self) -> &SecretKey {
        &self.inner.delayed_payment_base_key
    }
    pub fn htlc_base_key(&self) -> &SecretKey {
        &self.inner.htlc_base_key
    }
}

impl BaseSign for EnforcingSigner {
    fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<All>) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
        self.inner.release_commitment_secret(idx)
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }

    // BEGIN NOT TESTED
    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner.channel_keys_id()
    }
    // END NOT TESTED

    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.sign_counterparty_commitment(commitment_tx, secp_ctx)
    }

    fn sign_holder_commitment_and_htlcs(
        &self,
        local_commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner
            .sign_holder_commitment_and_htlcs(local_commitment_tx, secp_ctx)
    }

    #[cfg(feature = "test_utils")]
    fn unsafe_sign_holder_commitment_and_htlcs(
        &self,
        local_commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner
            .unsafe_sign_holder_commitment_and_htlcs(local_commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_output(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            secp_ctx,
        )
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_htlc(
            justice_tx,
            input,
            amount,
            per_commitment_key,
            htlc,
            secp_ctx,
        )
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(
            htlc_tx,
            input,
            amount,
            per_commitment_point,
            htlc,
            secp_ctx,
        )
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &Transaction,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        Ok(self
            .inner
            .sign_closing_transaction(closing_tx, secp_ctx)
            .unwrap())
    }

    // BEGIN NOT TESTED
    fn sign_channel_announcement(
        &self,
        msg: &msgs::UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_channel_announcement(msg, secp_ctx)
    }
    // END NOT TESTED

    fn ready_channel(&mut self, channel_parameters: &ChannelTransactionParameters) {
        self.inner.ready_channel(channel_parameters)
    }
}

// BEGIN NOT TESTED
impl Writeable for EnforcingSigner {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), IOError> {
        self.inner.write(writer)?;
        let state = self.state.lock().unwrap();
        state.next_holder_commit_num.write(writer)?;
        state.next_counterparty_commit_num.write(writer)?;
        state.next_counterparty_revoke_num.write(writer)?;
        state.current_counterparty_point.write(writer)?;
        state.previous_counterparty_point.write(writer)?;
        Ok(())
    }
}
// END NOT TESTED

impl Readable for EnforcingSigner {
    fn read<R: IORead>(reader: &mut R) -> Result<Self, DecodeError> {
        let inner = Readable::read(reader)?;
        let next_holder_commit_num = Readable::read(reader)?;
        let next_counterparty_commit_num = Readable::read(reader)?;
        let next_counterparty_revoke_num = Readable::read(reader)?;
        let current_counterparty_point = Readable::read(reader)?;
        let previous_counterparty_point = Readable::read(reader)?;
        let state = EnforcementState {
            next_holder_commit_num,
            next_counterparty_commit_num,
            next_counterparty_revoke_num,
            current_counterparty_point,
            previous_counterparty_point,
        };
        Ok(EnforcingSigner {
            inner,
            state: Arc::new(Mutex::new(state)),
        })
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
        let mut state = EnforcementState {
            next_holder_commit_num: 0,
            next_counterparty_commit_num: 0,
            next_counterparty_revoke_num: 0,
            current_counterparty_point: None,
            previous_counterparty_point: None,
        };

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
