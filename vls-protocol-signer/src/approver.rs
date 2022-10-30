use lightning_signer::Arc;

use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::lightning_invoice::SignedRawInvoice;
use lightning_signer::node::{InvoiceState, Node};
use lightning_signer::prelude::{Mutex, SendSync};
use lightning_signer::util::clock::Clock;
use lightning_signer::util::status::Status;
use lightning_signer::util::velocity::VelocityControl;

/// Approve payments
pub trait Approve: SendSync {
    /// Approve an invoice for payment
    fn approve_invoice(&self, hash: &PaymentHash, invoice_state: &InvoiceState) -> bool;

    /// Checks invoice for approval and adds to the node if needed and appropriate
    fn handle_proposed_invoice(
        &self,
        node: &Arc<Node>,
        signed: SignedRawInvoice,
    ) -> Result<(), Status> {
        let (hash, invoice_state, invoice_hash) = Node::invoice_state_from_invoice(signed.clone())?;

        // shortcut if node already has this invoice
        if node.has_invoice(&hash, &invoice_hash)? {
            return Ok(());
        }

        // otherwise ask approver
        if self.approve_invoice(&hash, &invoice_state) {
            node.add_invoice(signed)
        } else {
            Err(Status::invalid_argument("invoice declined"))
        }
    }
}

/// An approver that always approves
#[derive(Copy, Clone)]
pub struct PositiveApprover();

impl SendSync for PositiveApprover {}

impl Approve for PositiveApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _invoice_state: &InvoiceState) -> bool {
        true
    }
}

/// An approver that always declines
#[derive(Copy, Clone)]
pub struct NegativeApprover();

impl SendSync for NegativeApprover {}

impl Approve for NegativeApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _invoice_state: &InvoiceState) -> bool {
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
    fn approve_invoice(&self, hash: &PaymentHash, invoice_state: &InvoiceState) -> bool {
        let mut control = self.control.lock().unwrap();
        let success = control.insert(self.clock.now().as_secs(), invoice_state.amount_msat);
        if success {
            true
        } else {
            let success = self.delegate.approve_invoice(hash, invoice_state);
            if success {
                // since we got a manual approval, clear the control, so that we
                // don't bother the user until more transactions flow through
                control.clear();
            }
            success
        }
    }
}
