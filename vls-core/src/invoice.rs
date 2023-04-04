use core::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

use lightning::ln::PaymentHash;

pub use lightning::offers::invoice as bolt12;
pub use lightning_invoice as bolt11;

/// Generic invoice methods for both BOLT-11 and BOLT-12 invoices.
pub trait InvoiceAttributes {
    /// The hash of the invoice, as a unique ID
    fn invoice_hash(&self) -> [u8; 32];
    /// The payment hash of the invoice
    fn payment_hash(&self) -> PaymentHash;
    /// Invoiced amount
    fn amount_milli_satoshis(&self) -> u64;
    /// Payee's public key
    fn payee_pub_key(&self) -> PublicKey;
    /// Timestamp of the payment, as duration since the UNIX epoch
    fn duration_since_epoch(&self) -> Duration;
    /// Expiry, as duration since the timestamp
    fn expiry_duration(&self) -> Duration;
}

/// A BOLT11 or BOLT12 invoice
#[derive(Clone, Debug)]
pub enum Invoice {
    /// A BOLT11 Invoice and its raw invoice hash
    Bolt11(bolt11::Invoice),
    /// A BOLT12 Invoice
    Bolt12(bolt12::Invoice),
}

impl InvoiceAttributes for Invoice {
    fn invoice_hash(&self) -> [u8; 32] {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.signable_hash(),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }

    fn payment_hash(&self) -> PaymentHash {
        match self {
            Invoice::Bolt11(bolt11) => PaymentHash(bolt11.payment_hash().as_inner().clone()),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }

    fn amount_milli_satoshis(&self) -> u64 {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.amount_milli_satoshis().unwrap_or(0),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }

    fn payee_pub_key(&self) -> PublicKey {
        match self {
            Invoice::Bolt11(bolt11) => bolt11
                .payee_pub_key()
                .map(|p| p.clone())
                .unwrap_or_else(|| bolt11.recover_payee_pub_key()),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }

    fn duration_since_epoch(&self) -> Duration {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.duration_since_epoch(),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }

    fn expiry_duration(&self) -> Duration {
        match self {
            Invoice::Bolt11(bolt11) => bolt11.expiry_time(),
            Invoice::Bolt12(_bolt12) => unimplemented!(),
        }
    }
}
