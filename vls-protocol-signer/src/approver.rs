use lightning_signer::Arc;

use lightning_signer::lightning::ln::PaymentHash;
use lightning_signer::lightning_invoice::SignedRawInvoice;
use lightning_signer::node::{InvoiceState, Node};
use lightning_signer::util::status::Status;

/// Approve payments
pub trait Approver: Sync + Send {
    ///  Approve an invoice for payment
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
pub struct PositiveApprover();

impl Approver for PositiveApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _invoice_state: &InvoiceState) -> bool {
        true
    }
}

/// An approver that always declines
pub struct NegativeApprover();

impl Approver for NegativeApprover {
    fn approve_invoice(&self, _hash: &PaymentHash, _invoice_state: &InvoiceState) -> bool {
        false
    }
}
