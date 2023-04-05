use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cmp::min;

use log::*;

use cortex_m::prelude::_embedded_hal_blocking_delay_DelayMs;

use lightning_signer::bitcoin::Transaction;
use vls_protocol_signer::approver::Approve;
use vls_protocol_signer::lightning_signer::{
    self,
    bitcoin::hashes::hex::ToHex,
    bitcoin::secp256k1::PublicKey,
    invoice::{Invoice, InvoiceAttributes},
    lightning::ln::PaymentHash,
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

        let amount_msat = invoice.amount_milli_satoshis();
        let payee_pubkey = invoice.payee_pub_key();
        let expiry_secs = invoice.expiry_duration().as_secs();
        let payment_hash = invoice.payment_hash();
        let desc = invoice.description();

        let mut lines = vec![
            format!("{: ^19}", "Approve Invoice?"),
            format!("{: >19}", format_payment_amount(amount_msat)),
            format!("n {:17}", format_payee_pubkey(&payee_pubkey)),
            format!("x {:17}", format_expiration(expiry_secs)),
            format!("p {:17}", format_payment_hash(&payment_hash)),
        ];
        lines.extend(format_description("d ".to_string() + &desc));
        lines.resize_with(9, || format!(""));
        lines.push(format!("{:^9} {:^9}", "Approve", "Decline"));

        devctx.disp.clear_screen();
        devctx.disp.show_texts(&lines);

        wait_for_approval(devctx)
    }

    fn approve_keysend(&self, payment_hash: PaymentHash, amount_msat: u64) -> bool {
        info!("approve_keysend entered");

        let devctx: &mut DeviceContext = &mut self.devctx.borrow_mut();

        let mut lines = vec![
            format!("{: ^19}", "Approve Keysend?"),
            format!("{: >19}", format_payment_amount(amount_msat)),
            format!("p {:17}", format_payment_hash(&payment_hash)),
        ];
        lines.resize_with(9, || format!(""));
        lines.push(format!("{:^9} {:^9}", "Approve", "Decline"));

        devctx.disp.clear_screen();
        devctx.disp.show_texts(&lines);

        wait_for_approval(devctx)
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

fn wait_for_approval(devctx: &mut DeviceContext) -> bool {
    loop {
        let (row, col) = devctx.disp.wait_for_touch(&mut devctx.touchscreen.inner, &mut devctx.i2c);
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

fn format_payment_amount(amount_msat: u64) -> String {
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

fn format_payment_hash(payment_hash: &PaymentHash) -> String {
    // Return value should be exactly 17 chars wide
    let hashstr = payment_hash.0.to_hex();
    let part0 = &hashstr[0..8];
    let part1 = &hashstr[hashstr.len() - 7..hashstr.len()];
    format!("{}..{}", part0, part1)
}

fn format_description(mut desc: String) -> Vec<String> {
    // Break into 17 char substrs
    let mut rv = vec![];
    while desc.len() > 0 {
        rv.push(desc.drain(..min(desc.len(), 17)).collect());
    }
    rv
}
