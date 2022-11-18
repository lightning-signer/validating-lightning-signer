use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::min;

use log::*;

use cortex_m::prelude::_embedded_hal_blocking_delay_DelayMs;

use vls_protocol_signer::approver::Approve;
use vls_protocol_signer::lightning_signer::{
    bitcoin::hashes::sha256,
    bitcoin::secp256k1::PublicKey,
    lightning::ln::PaymentHash,
    lightning_invoice::{Invoice, InvoiceDescription},
    prelude::SendSync,
    Arc,
};

use crate::device::DeviceContext;
use crate::pretty_thousands;

pub struct ScreenApprover {
    devctx: Arc<RefCell<DeviceContext>>,
}

impl SendSync for ScreenApprover {}

impl ScreenApprover {
    pub fn new(devctx: Arc<RefCell<DeviceContext>>) -> Self {
        Self { devctx }
    }
}

impl Approve for ScreenApprover {
    fn approve_invoice(&self, invoice: &Invoice) -> bool {
        info!("approve_invoice entered");

        let devctx: &mut DeviceContext = &mut self.devctx.borrow_mut();

        let amount_msec = invoice.amount_milli_satoshis().unwrap_or(0);
        let payee_pubkey = invoice
            .payee_pub_key()
            .map(|p| p.clone())
            .unwrap_or_else(|| invoice.recover_payee_pub_key());
        let expiry_secs = invoice.expiry_time().as_secs();
        let payment_hash = invoice.payment_hash();
        let descrstr = match invoice.description() {
            InvoiceDescription::Direct(d) => d.to_string(),
            InvoiceDescription::Hash(h) => format!("hash: {:?}", h),
        };

        let mut lines = vec![
            format!("{: ^19}", "Approve Invoice?"),
            format!("{: >19}", format_invoice_amount(amount_msec)),
            format!("n {:17}", format_payee_pubkey(&payee_pubkey)),
            format!("x {:17}", format_expiration(expiry_secs)),
            format!("p {:17}", format_payment_hash(payment_hash)),
        ];
        lines.extend(format_description("d ".to_string() + &descrstr));
        lines.resize_with(9, || format!(""));
        lines.push(format!("{:^9} {:^9}", "Approve", "Decline"));

        devctx.disp.clear_screen();
        devctx.disp.show_texts(&lines);

        loop {
            let (row, col) =
                devctx.disp.wait_for_touch(&mut devctx.touchscreen.inner, &mut devctx.i2c);
            info!("row:{}, col:{} touched", row, col);
            if row == 9 {
                if col < 8 {
                    break true;
                } else if col > 10 {
                    break false;
                }
            }
            devctx.delay.delay_ms(100u16);
        }
    }

    fn approve_keysend(&self, _payment_hash: PaymentHash, _amount_msat: u64) -> bool {
        true
    }
}

fn format_invoice_amount(amount_msat: u64) -> String {
    // Using msat is too wide for display.  Probably a fancy units mapper
    // would be appropriate, maybe ok to lose precision on large values ...
    format!("{} sat", pretty_thousands(amount_msat as i64 / 1000))
}

fn format_payee_pubkey(pubkey: &PublicKey) -> String {
    // Return value should be exactly 17 chars wide
    let nodeid = pubkey.to_string();
    let part0 = &nodeid[0..8];
    let part1 = &nodeid[nodeid.len() - 7..nodeid.len()];
    format!("{}..{}", part0, part1)
}

fn format_expiration(expiry: u64) -> String {
    // Return value should be maximum 17 chars wide
    // TODO - figure out how to format this!
    format!("{}s", expiry)
}

fn format_payment_hash(payment_hash: &sha256::Hash) -> String {
    // Return value should be exactly 17 chars wide
    let hashstr = payment_hash.to_string();
    let part0 = &hashstr[0..8];
    let part1 = &hashstr[hashstr.len() - 7..hashstr.len()];
    format!("{}..{}", part0, part1)
}

fn format_description(mut descrstr: String) -> Vec<String> {
    // Break into 17 char substrs
    let mut rv = vec![];
    while descrstr.len() > 0 {
        rv.push(descrstr.drain(..min(descrstr.len(), 17)).collect());
    }
    rv
}
