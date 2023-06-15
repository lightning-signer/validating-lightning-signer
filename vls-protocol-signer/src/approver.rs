use lightning_signer::bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning_signer::bitcoin::Transaction;
use lightning_signer::prelude::*;
use lightning_signer::Arc;
use log::*;

use lightning_signer::invoice::{Invoice, InvoiceAttributes};
use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::node::{Node, SpendType};
use lightning_signer::policy::error::ValidationErrorKind;
use lightning_signer::prelude::{Mutex, SendSync};
use lightning_signer::util::clock::Clock;
use lightning_signer::util::debug_utils::DebugBytes;
use lightning_signer::util::status::Status;
use lightning_signer::util::velocity::VelocityControl;
use lightning_signer::wallet::Wallet;

/// Control payment approval.
///
/// You should implement this to present a user interface to allow the user to
/// approve or reject payments.
/// An approval here is meant to override other controls, such as the node allowlist.
///
/// This can also be used for automatic approval of micropayments to arbitrary destinations
/// - see [`VelocityApprover`].
///
/// Implement the `approve_invoice`, `approve_keysend` and `approve_onchain` methods to
/// control which payments are approved.
///
/// The flow is as follows:
/// - TODO the node allowlist is consulted, and the payment is approved if there is a match
/// - if an L2 payment was previously approved, it is automatically approved again
/// - the approver is consulted, and the payment is rejected if false was returned
/// - the global node velocity control is consulted if configured,
///   and the payment is rejected if the velocity is exceeded
/// - otherwise, the payment is approved
pub trait Approve: SendSync {
    /// Approve an invoice for payment
    fn approve_invoice(&self, invoice: &Invoice) -> bool;

    /// Approve a keysend (ad-hoc payment)
    fn approve_keysend(&self, payment_hash: PaymentHash, amount_msat: u64) -> bool;

    /// Approve an onchain payment to an unknown destination
    /// * `tx` - the transaction to be sent
    /// * `values_sat` - the values of the inputs in satoshis
    /// * `unknown_indices` is the list of tx output indices that are unknown.
    fn approve_onchain(
        &self,
        tx: &Transaction,
        values_sat: &[u64],
        unknown_indices: &[usize],
    ) -> bool;

    /// Checks invoice for approval and adds to the node if needed and appropriate
    fn handle_proposed_invoice(&self, node: &Arc<Node>, invoice: Invoice) -> Result<bool, Status> {
        let (payment_hash, _payment_state, invoice_hash) =
            Node::payment_state_from_invoice(&invoice)?;

        // shortcut if node already has this invoice
        if node.has_payment(&payment_hash, &invoice_hash)? {
            debug!(
                "node already approved invoice with payment_hash {:?} invoice_hash {:?}",
                DebugBytes(&payment_hash.0),
                DebugBytes(&invoice_hash)
            );
            return Ok(true);
        }

        // otherwise ask approver
        let payee = invoice.payee_pub_key();
        if node.allowlist_contains_payee(payee) {
            debug!(
                "node allowlist contains payee {:?} for invoice with amount {}",
                payee,
                invoice.amount_milli_satoshis()
            );
            node.add_invoice(invoice)
        } else if self.approve_invoice(&invoice) {
            debug!(
                "invoice to {:?} approved with amount {}",
                payee,
                invoice.amount_milli_satoshis()
            );
            node.add_invoice(invoice)
        } else {
            warn!(
                "invoice to {:?} not approved with amount {}",
                payee,
                invoice.amount_milli_satoshis()
            );
            Ok(false)
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
    ) -> Result<bool, Status> {
        let now = node.get_clock().now();
        let (_payment_state, invoice_hash) =
            Node::payment_state_from_keysend(payee, payment_hash, amount_msat, now)?;

        // shortcut if node already has this payment
        if node.has_payment(&payment_hash, &invoice_hash)? {
            debug!(
                "node already approved keysend with payment_hash {:?} invoice_hash {:?}",
                DebugBytes(&payment_hash.0),
                DebugBytes(&invoice_hash)
            );
            return Ok(true);
        }

        // TODO when payee validated by by generating the onion ourselves check if payee public key
        // in allowlist

        // otherwise ask approver
        if self.approve_keysend(payment_hash, amount_msat) {
            debug!("keysend to {:?} approved with amount {}", payee, amount_msat);
            node.add_keysend(payee, payment_hash, amount_msat).map_err(|err| {
                warn!("add_keysend failed: {}", err);
                err
            })
        } else {
            warn!("keysend to {:?} not approved with amount {}", payee, amount_msat);
            Ok(false)
        }
    }

    /// Checks onchain payment for unknown destinations and checks approval
    /// for any such outputs.
    /// Returns Ok(false) if any unknown destinations were not approved.
    fn handle_proposed_onchain(
        &self,
        node: &Arc<Node>,
        tx: &Transaction,
        input_txs: &[&Transaction],
        values_sat: &[u64],
        spendtypes: &[SpendType],
        uniclosekeys: &[Option<(SecretKey, Vec<Vec<u8>>)>],
        opaths: &[Vec<u32>],
    ) -> Result<bool, Status> {
        let check_result =
            node.check_onchain_tx(&tx, input_txs, &values_sat, &spendtypes, &uniclosekeys, &opaths);
        match check_result {
            Ok(()) => {}
            Err(ve) => match ve.kind {
                ValidationErrorKind::UnknownDestinations(_, ref indices) => {
                    if self.approve_onchain(&tx, &values_sat, indices) {
                        info!("approved onchain tx with unknown outputs");
                    } else {
                        info!("rejected onchain tx with unknown outputs");
                        return Ok(false);
                    }
                }
                _ => {
                    return Err(Status::failed_precondition(ve.to_string()))?;
                }
            },
        }
        Ok(true)
    }
}

/// An approver that always approves, for testing and for permissive mode.
///
/// NOTE - this version approves quietly, if the approval should be logged
/// with a warning use [`WarningPositiveApprover`] instead.
#[derive(Copy, Clone)]
pub struct PositiveApprover();

impl SendSync for PositiveApprover {}

impl Approve for PositiveApprover {
    fn approve_invoice(&self, _invoice: &Invoice) -> bool {
        true
    }

    fn approve_keysend(&self, _payment_hash: PaymentHash, _amount_msat: u64) -> bool {
        true
    }

    fn approve_onchain(
        &self,
        _tx: &Transaction,
        _values_sat: &[u64],
        _unknown_indices: &[usize],
    ) -> bool {
        true
    }
}

/// An approver that always approves, for testing and for permissive mode.
///
/// NOTE - this version generates a warning to the log so the user is aware
/// of the automatic approvals.
#[derive(Copy, Clone)]
pub struct WarningPositiveApprover();

impl SendSync for WarningPositiveApprover {}

impl Approve for WarningPositiveApprover {
    fn approve_invoice(&self, invoice: &Invoice) -> bool {
        warn!("AUTOAPPROVED INVOICE {:?}", invoice);
        true
    }

    fn approve_keysend(&self, payment_hash: PaymentHash, amount_msat: u64) -> bool {
        warn!(
            "AUTOAPPROVED KEYSEND of {} msat with payment_hash {:?}",
            amount_msat,
            DebugBytes(&payment_hash.0)
        );
        true
    }

    fn approve_onchain(
        &self,
        tx: &Transaction,
        values_sat: &[u64],
        unknown_indices: &[usize],
    ) -> bool {
        warn!(
            "AUTOAPPROVED ONCHAIN tx {:?} with values_sat {:?} and unknown_indices {:?}",
            tx, values_sat, unknown_indices
        );
        true
    }
}

/// An approver that always declines, in case only the allowlist is used
#[derive(Copy, Clone)]
pub struct NegativeApprover();

impl SendSync for NegativeApprover {}

impl Approve for NegativeApprover {
    fn approve_invoice(&self, _invoice: &Invoice) -> bool {
        false
    }

    fn approve_keysend(&self, _payment_hash: PaymentHash, _amount_msat: u64) -> bool {
        false
    }

    fn approve_onchain(
        &self,
        _tx: &Transaction,
        _values_sat: &[u64],
        _unknown_indices: &[usize],
    ) -> bool {
        false
    }
}

/// An approver that auto-approves L2 payments under a certain velocity.
/// If the invoice is over the velocity, it is passed on to a delegate approver.
/// You can use this to allow micropayments to arbitrary destinations.
///
/// You can also pass in a delegate approver, to allow asking the user
/// for approval for payments over the micropayment maximum velocity.
///
/// L1 payments are always passed to the delegate approver (i.e. velocity control
/// is not used for approval).
///
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
///     limit_msat: 1000000,
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

    /// Set the velocity control
    pub fn set_control(&self, control: VelocityControl) {
        *self.control.lock().unwrap() = control;
    }
}

impl<A: Approve> SendSync for VelocityApprover<A> {}

impl<A: Approve> Approve for VelocityApprover<A> {
    fn approve_invoice(&self, invoice: &Invoice) -> bool {
        let mut control = self.control.lock().unwrap();
        let success = control.insert(self.clock.now().as_secs(), invoice.amount_milli_satoshis());
        if success {
            true
        } else {
            let success = self.delegate.approve_invoice(invoice);
            if success {
                // since we got a manual approval, clear the control, so that we
                // don't bother the user until more transactions flow through
                control.clear();
            }
            success
        }
    }

    fn approve_keysend(&self, payment_hash: PaymentHash, amount_msat: u64) -> bool {
        let mut control = self.control.lock().unwrap();
        let success = control.insert(self.clock.now().as_secs(), amount_msat);
        if success {
            true
        } else {
            let success = self.delegate.approve_keysend(payment_hash, amount_msat);
            if success {
                // since we got a manual approval, clear the control, so that we
                // don't bother the user until more transactions flow through
                control.clear();
            }
            success
        }
    }

    fn approve_onchain(
        &self,
        tx: &Transaction,
        values_sat: &[u64],
        unknown_indices: &[usize],
    ) -> bool {
        self.delegate.approve_onchain(tx, values_sat, unknown_indices)
    }
}

/// An approval that is memorized by `MemoApprover`
#[derive(Debug)]
pub enum Approval {
    /// An invoice was approved
    Invoice(Invoice),
    /// A keysend was approved
    KeySend(PaymentHash, u64),
    /// An onchain transaction was approved
    Onchain(Transaction),
}

/// An approver that memorizes the last approval, and uses it for the next
/// approval request.
///
/// If the request is for a different action, the memoized approval is cleared
/// and the request is passed on to the delegate approver.
pub struct MemoApprover<A: Approve> {
    delegate: A,
    approvals: Mutex<Vec<Approval>>,
}

impl<A: Approve> MemoApprover<A> {
    /// Create a new memo approver with the given delegate approver
    pub fn new(delegate: A) -> Self {
        Self { delegate, approvals: Mutex::new(Vec::new()) }
    }

    /// Set an approval to be memorized.
    ///
    /// This approval will be used for the next approval request.
    /// If there is already a memoized approval, it will be overwritten.
    pub fn approve(&self, approvals: Vec<Approval>) {
        *self.approvals.lock().unwrap() = approvals;
    }
}

impl<A: Approve> SendSync for MemoApprover<A> {}

impl<A: Approve> Approve for MemoApprover<A> {
    fn approve_invoice(&self, invoice: &Invoice) -> bool {
        let mut approvals = self.approvals.lock().unwrap();
        for approval in approvals.drain(..) {
            match approval {
                Approval::Invoice(approved_invoice) => {
                    if approved_invoice.invoice_hash() == invoice.invoice_hash() {
                        return true;
                    }
                }
                _ => {}
            }
        }
        return self.delegate.approve_invoice(invoice);
    }

    fn approve_keysend(&self, payment_hash: PaymentHash, amount_msat: u64) -> bool {
        let mut approvals = self.approvals.lock().unwrap();
        for approval in approvals.drain(..) {
            match approval {
                Approval::KeySend(approved_payment_hash, approved_amount_msat) =>
                    if approved_payment_hash == payment_hash && approved_amount_msat == amount_msat
                    {
                        return true;
                    },
                _ => {}
            }
        }
        return self.delegate.approve_keysend(payment_hash, amount_msat);
    }

    fn approve_onchain(
        &self,
        tx: &Transaction,
        values_sat: &[u64],
        unknown_indices: &[usize],
    ) -> bool {
        let mut approvals = self.approvals.lock().unwrap();
        for approval in approvals.drain(..) {
            match approval {
                Approval::Onchain(approved_tx) =>
                    if approved_tx == *tx {
                        return true;
                    },
                _ => {}
            }
        }
        return self.delegate.approve_onchain(tx, values_sat, unknown_indices);
    }
}

#[cfg(test)]
mod tests {
    use crate::approver::{
        Approve, NegativeApprover, PositiveApprover, VelocityApprover, WarningPositiveApprover,
    };
    use lightning_signer::bitcoin::secp256k1::PublicKey;
    use lightning_signer::invoice::InvoiceAttributes;
    use lightning_signer::lightning::ln::PaymentHash;
    use lightning_signer::node::{Node, PaymentState};
    use lightning_signer::util::clock::Clock;
    use lightning_signer::util::clock::ManualClock;
    use lightning_signer::util::test_utils::{
        make_current_test_invoice, make_node, make_test_invoice,
    };
    use lightning_signer::util::velocity::{
        VelocityControl, VelocityControlIntervalType::Hourly, VelocityControlSpec,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use test_log::test;

    #[test]
    fn test_invoice_velocity_approver_negative() {
        let delegate = NegativeApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit_msat: 1_000_000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let amt = 600_000_u64;
        let invoice = make_test_invoice(1, amt);
        let success = approver.approve_invoice(&invoice);
        assert!(success);

        let invoice = make_test_invoice(2, amt);
        let success = approver.approve_invoice(&invoice);
        assert!(!success);
        assert_eq!(approver.control.lock().unwrap().velocity(), amt);
    }

    #[test]
    fn test_handle_invoice_allowlist() {
        // need a node for this test for the allowlist
        let (_, node, _) = make_node();
        let approver = NegativeApprover();
        let invoice = make_current_test_invoice(1, 600_000);
        assert!(!approver.handle_proposed_invoice(&node, invoice.clone()).unwrap());

        let allowable = format!("payee:{}", invoice.payee_pub_key());
        node.add_allowlist(&[allowable]).unwrap();
        assert!(approver.handle_proposed_invoice(&node, invoice).unwrap());
    }

    #[test]
    fn test_invoice_velocity_approver_positive() {
        let delegate = PositiveApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit_msat: 1_000_000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let amt = 600_000_u64;
        let invoice = make_test_invoice(1, amt);
        let success = approver.approve_invoice(&invoice);
        assert!(success);
        assert_eq!(approver.control.lock().unwrap().velocity(), amt);

        let invoice = make_test_invoice(2, amt);
        let success = approver.approve_invoice(&invoice);
        assert!(success);
        // the approval of the second invoice should have cleared the velocity control
        assert_eq!(approver.control.lock().unwrap().velocity(), 0);
    }

    #[test]
    fn test_keysend_velocity_approver_negative() {
        let delegate = NegativeApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit_msat: 1000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let (payment_hash, payment_state) = make_keysend_payment(1, clock.now());
        let success = approver.approve_keysend(payment_hash, payment_state.amount_msat);
        assert!(success);

        let (payment_hash, payment_state) = make_keysend_payment(2, clock.now());
        let success = approver.approve_keysend(payment_hash, payment_state.amount_msat);
        assert!(!success);
        assert_eq!(approver.control.lock().unwrap().velocity(), 600);
    }

    #[test]
    fn test_keysend_velocity_approver_positive() {
        let delegate = PositiveApprover();
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let spec = VelocityControlSpec { limit_msat: 1000, interval_type: Hourly };
        let control = VelocityControl::new(spec);
        let approver = VelocityApprover::new(clock.clone(), control, delegate);
        let (payment_hash, payment_state) = make_keysend_payment(1, clock.now());
        let success = approver.approve_keysend(payment_hash, payment_state.amount_msat);
        assert!(success);
        assert_eq!(approver.control.lock().unwrap().velocity(), 600);

        let (payment_hash, payment_state) = make_keysend_payment(2, clock.now());
        let success = approver.approve_keysend(payment_hash, payment_state.amount_msat);
        assert!(success);
        // the approval of the second invoice should have cleared the velocity control
        assert_eq!(approver.control.lock().unwrap().velocity(), 0);
    }

    fn make_keysend_payment(x: u8, now: Duration) -> (PaymentHash, PaymentState) {
        let payee = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let payment_hash = PaymentHash([x; 32]);
        let (payment_state, _invoice_hash) =
            Node::payment_state_from_keysend(payee, payment_hash, 600, now).unwrap();
        (payment_hash, payment_state)
    }

    #[test]
    fn test_invoice_approver_with_warning() {
        let approver = WarningPositiveApprover();
        let amt = 600_000_u64;
        let invoice = make_test_invoice(1, amt);
        let success = approver.approve_invoice(&invoice);
        assert!(success);
    }

    #[test]
    fn test_keysend_approver_with_warning() {
        let clock = Arc::new(ManualClock::new(Duration::ZERO));
        let approver = WarningPositiveApprover();
        let (payment_hash, payment_state) = make_keysend_payment(1, clock.now());
        let success = approver.approve_keysend(payment_hash, payment_state.amount_msat);
        assert!(success);
    }
}
