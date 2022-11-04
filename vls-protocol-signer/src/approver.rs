use lightning_signer::bitcoin::secp256k1::PublicKey;
use lightning_signer::Arc;

use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::lightning_invoice::SignedRawInvoice;
use lightning_signer::node::{Node, PaymentState};
use lightning_signer::prelude::{Mutex, SendSync};
use lightning_signer::util::clock::Clock;
use lightning_signer::util::status::Status;
use lightning_signer::util::velocity::VelocityControl;

/// Approve payments
pub trait Approve: SendSync {
    /// Approve an invoice for payment
    fn approve_invoice(&self, hash: &PaymentHash, payment_state: &PaymentState) -> bool;

    /// Checks invoice for approval and adds to the node if needed and appropriate
    fn handle_proposed_invoice(
        &self,
        node: &Arc<Node>,
        signed: SignedRawInvoice,
    ) -> Result<(), Status> {
        let (payment_hash, payment_state, invoice_hash) =
            Node::payment_state_from_invoice(signed.clone())?;

        // shortcut if node already has this invoice
        if node.has_invoice(&payment_hash, &invoice_hash)? {
            return Ok(());
        }

        // otherwise ask approver
        if self.approve_invoice(&payment_hash, &payment_state) {
            node.add_invoice(signed)
        } else {
            Err(Status::invalid_argument("invoice declined"))
        }
    }

    /// Checks keysend for approval and adds to the node if needed and appropriate.
    /// The payee is not validated yet.
    fn handle_proposed_keysend(
        &self,
        node: &Arc<Node>,
        payee: PublicKey,
        payment_hash: PaymentHash,
        amount_msat: u64,
    ) -> Result<(), Status> {
        let (payment_state, invoice_hash) =
            Node::payment_state_from_keysend(payee, payment_hash, amount_msat)?;

        // shortcut if node already has this invoice
        if node.has_invoice(&payment_hash, &invoice_hash)? {
            return Ok(());
        }

        // otherwise ask approver
        if self.approve_invoice(&payment_hash, &payment_state) {
            node.add_keysend(payee, payment_hash, amount_msat)
        } else {
            Err(Status::invalid_argument("keysend declined"))
        }
    }
}

/// An approver that always approves
#[derive(Copy, Clone)]
pub struct PositiveApprover();

impl SendSync for PositiveApprover {}

impl Approve for PositiveApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _payment_state: &PaymentState) -> bool {
        true
    }
}

/// An approver that always declines
#[derive(Copy, Clone)]
pub struct NegativeApprover();

impl SendSync for NegativeApprover {}

impl Approve for NegativeApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _payment_state: &PaymentState) -> bool {
        false
    }
}

/// An approver that auto-approves invoices under a certain velocity.
/// If the invoice is over the velocity, it is passed on to a delegate approver.
/// ```rust
/// # use std::sync::Arc;
/// # use std::time::Duration;
/// use lightning_signer::util::clock::ManualClock;
/// use lightning_signer::util::velocity::{
///     VelocityControl,
///     VelocityControlIntervalType::Hourly,
///     VelocityControlSpec
/// };
/// # use vls_protocol_signer::approver::{NegativeApprover, VelocityApprover};
///
/// let delegate = NegativeApprover();
/// let clock = Arc::new(ManualClock::new(Duration::ZERO));
/// let spec = VelocityControlSpec {
///     limit: 1000000,
///     interval_type: Hourly
/// };
/// let control = VelocityControl::new(spec);
/// let approver = VelocityApprover::new(clock.clone(), control, delegate);
/// let state = approver.control().get_state();
/// // persist the state here if you don't want the velocity control to be cleared
/// // every time the signer restarts
/// // ...
/// // now restore from the state
/// let restored_control = VelocityControl::load_from_state(spec, state);
/// let restored_approver = VelocityApprover::new(clock.clone(), restored_control, delegate);
/// ```
pub struct VelocityApprover<A: Approve> {
    clock: Arc<dyn Clock>,
    control: Mutex<VelocityControl>,
    delegate: A,
}

impl<A: Approve> VelocityApprover<A> {
    /// Create a new velocity approver with the given velocity control and delgate approver
    pub fn new(clock: Arc<dyn Clock>, control: VelocityControl, delegate: A) -> Self {
        Self { control: Mutex::new(control), clock, delegate }
    }

    /// Get a snapshot of the velocity control, for persistence
    pub fn control(&self) -> VelocityControl {
        self.control.lock().unwrap().clone()
    }
}

impl<A: Approve> SendSync for VelocityApprover<A> {}

impl<A: Approve> Approve for VelocityApprover<A> {
    fn approve_invoice(&self, hash: &PaymentHash, payment_state: &PaymentState) -> bool {
        let mut control = self.control.lock().unwrap();
        let success = control.insert(self.clock.now().as_secs(), payment_state.amount_msat);
        if success {
            true
        } else {
            let success = self.delegate.approve_invoice(hash, payment_state);
            if success {
                // since we got a manual approval, clear the control, so that we
                // don't bother the user until more transactions flow through
                control.clear();
            }
            success
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::approver::{Approve, NegativeApprover, PositiveApprover, VelocityApprover};
    use lightning_signer::bitcoin::secp256k1::PublicKey;
    use lightning_signer::lightning::ln::PaymentHash;
    use lightning_signer::node::{Node, PaymentState};
    use lightning_signer::util::clock::ManualClock;
    use lightning_signer::util::velocity::{
        VelocityControl, VelocityControlIntervalType::Hourly, VelocityControlSpec,
    };
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_velocity_approver_negative() {
        let delegate = NegativeApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit: 1000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let (payment_hash, payment_state) = make_payment(1);
        let success = approver.approve_invoice(&payment_hash, &payment_state);
        assert!(success);

        let (payment_hash, payment_state) = make_payment(2);
        let success = approver.approve_invoice(&payment_hash, &payment_state);
        assert!(!success);
        assert_eq!(approver.control.lock().unwrap().velocity(), 600);
    }

    #[test]
    fn test_velocity_approver_positive() {
        let delegate = PositiveApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit: 1000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let (payment_hash, payment_state) = make_payment(1);
        let success = approver.approve_invoice(&payment_hash, &payment_state);
        assert!(success);
        assert_eq!(approver.control.lock().unwrap().velocity(), 600);

        let (payment_hash, payment_state) = make_payment(2);
        let success = approver.approve_invoice(&payment_hash, &payment_state);
        assert!(success);
        // the approval of the second invoice should have cleared the velocity control
        assert_eq!(approver.control.lock().unwrap().velocity(), 0);
    }

    fn make_payment(x: u8) -> (PaymentHash, PaymentState) {
        let payee = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let payment_hash = PaymentHash([x; 32]);
        let (payment_state, _invoice_hash) =
            Node::payment_state_from_keysend(payee, payment_hash, 600).unwrap();
        (payment_hash, payment_state)
    }
}
