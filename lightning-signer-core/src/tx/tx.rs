use crate::prelude::*;
use core::cmp;
use core::convert::TryInto;
use core::fmt;

use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_DROP, OP_DUP, OP_ELSE,
    OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_IFDUP, OP_NOTIF, OP_PUSHNUM_1,
    OP_PUSHNUM_16, OP_PUSHNUM_2, OP_SIZE, OP_SWAP,
};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::address::Payload;
use bitcoin::{OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};
use lightning::chain::keysinterface::{BaseSign, InMemorySigner};
use lightning::ln::chan_utils;
use lightning::ln::chan_utils::{
    get_anchor_redeemscript, get_revokeable_redeemscript, HTLCOutputInCommitment, TxCreationKeys,
};
use lightning::ln::PaymentHash;

use crate::channel::ChannelSetup;
use crate::policy::error::{
    mismatch_error, script_format_error, transaction_format_error, ValidationError,
};
use crate::tx::script::{
    expect_data, expect_number, expect_op, expect_script_end, get_delayed_redeemscript,
};
use crate::util::crypto_utils::payload_for_p2wpkh;
use crate::util::debug_utils::DebugPayload;
use crate::util::AddedItemsIter;
use bitcoin::hashes::hex::ToHex;

const MAX_DELAY: i64 = 1000;
/// Value for anchor outputs
pub(crate) const ANCHOR_SAT: u64 = 330;

pub(crate) fn get_commitment_transaction_number_obscure_factor(
    local_payment_basepoint: &PublicKey,
    counterparty_payment_basepoint: &PublicKey,
    outbound: bool,
) -> u64 {
    let mut sha = Sha256::engine();

    let their_payment_basepoint = counterparty_payment_basepoint.serialize();
    if outbound {
        sha.input(&local_payment_basepoint.serialize());
        sha.input(&their_payment_basepoint);
    } else {
        sha.input(&their_payment_basepoint);
        sha.input(&local_payment_basepoint.serialize());
    }
    let res = Sha256::from_engine(sha).into_inner();

    ((res[26] as u64) << 5 * 8)
        | ((res[27] as u64) << 4 * 8)
        | ((res[28] as u64) << 3 * 8)
        | ((res[29] as u64) << 2 * 8)
        | ((res[30] as u64) << 1 * 8)
        | ((res[31] as u64) << 0 * 8)
}

pub(crate) fn build_commitment_tx(
    keys: &TxCreationKeys,
    info: &CommitmentInfo2,
    obscured_commitment_transaction_number: u64,
    outpoint: OutPoint,
    option_anchors: bool,
    workaround_local_funding_pubkey: &PublicKey,
    workaround_remote_funding_pubkey: &PublicKey,
) -> (Transaction, Vec<Script>, Vec<HTLCOutputInCommitment>) {
    let txins = {
        let mut ins: Vec<TxIn> = Vec::new();
        let sequence =
            ((0x80 as u32) << 8 * 3) | ((obscured_commitment_transaction_number >> 3 * 8) as u32);
        ins.push(TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence(sequence),
            witness: Witness::default(),
        });
        ins
    };

    let mut txouts: Vec<(TxOut, (Script, Option<HTLCOutputInCommitment>))> = Vec::new();

    if info.to_countersigner_value_sat > 0 {
        if !option_anchors {
            let script = payload_for_p2wpkh(&info.to_countersigner_pubkey).script_pubkey();
            txouts.push((
                TxOut {
                    script_pubkey: script.clone(),
                    value: info.to_countersigner_value_sat as u64,
                },
                (script, None),
            ))
        } else {
            let delayed_script = get_delayed_redeemscript(&info.to_countersigner_pubkey);
            txouts.push((
                TxOut {
                    script_pubkey: delayed_script.to_v0_p2wsh(),
                    value: info.to_countersigner_value_sat as u64,
                },
                (delayed_script, None),
            ));
            let anchor_script = get_anchor_redeemscript(workaround_remote_funding_pubkey);
            txouts.push((
                TxOut { script_pubkey: anchor_script.to_v0_p2wsh(), value: ANCHOR_SAT },
                (anchor_script, None),
            ));
        }
    }

    if info.to_broadcaster_value_sat > 0 {
        let redeem_script = get_revokeable_redeemscript(
            &info.revocation_pubkey,
            info.to_self_delay,
            &info.to_broadcaster_delayed_pubkey,
        );
        txouts.push((
            TxOut {
                script_pubkey: redeem_script.to_v0_p2wsh(),
                value: info.to_broadcaster_value_sat as u64,
            },
            (redeem_script, None),
        ));
        if option_anchors {
            let anchor_script = get_anchor_redeemscript(workaround_local_funding_pubkey);
            txouts.push((
                TxOut { script_pubkey: anchor_script.to_v0_p2wsh(), value: ANCHOR_SAT },
                (anchor_script, None),
            ));
        }
    }

    for out in &info.offered_htlcs {
        let htlc_in_tx = HTLCOutputInCommitment {
            offered: true,
            amount_msat: out.value_sat * 1000,
            cltv_expiry: out.cltv_expiry,
            payment_hash: out.payment_hash,
            transaction_output_index: None,
        };
        let script = chan_utils::get_htlc_redeemscript(&htlc_in_tx, option_anchors, &keys);
        let txout = TxOut { script_pubkey: script.to_v0_p2wsh(), value: out.value_sat };
        txouts.push((txout, (script, Some(htlc_in_tx))));
    }

    for out in &info.received_htlcs {
        let htlc_in_tx = HTLCOutputInCommitment {
            offered: false,
            amount_msat: out.value_sat * 1000,
            cltv_expiry: out.cltv_expiry,
            payment_hash: out.payment_hash,
            transaction_output_index: None,
        };
        let script = chan_utils::get_htlc_redeemscript(&htlc_in_tx, option_anchors, &keys);
        let txout = TxOut { script_pubkey: script.to_v0_p2wsh(), value: out.value_sat };
        txouts.push((txout, (script, Some(htlc_in_tx))));
    }
    sort_outputs(&mut txouts, |a, b| {
        if let &(_, Some(ref a_htlcout)) = a {
            if let &(_, Some(ref b_htlcout)) = b {
                a_htlcout.cltv_expiry.cmp(&b_htlcout.cltv_expiry)
            } else {
                cmp::Ordering::Equal
            }
        } else {
            cmp::Ordering::Equal
        }
    });
    let mut outputs = Vec::with_capacity(txouts.len());
    let mut scripts = Vec::with_capacity(txouts.len());
    let mut htlcs = Vec::new();
    for (idx, mut out) in txouts.drain(..).enumerate() {
        outputs.push(out.0);
        scripts.push((out.1).0.clone());
        if let Some(mut htlc) = (out.1).1.take() {
            htlc.transaction_output_index = Some(idx as u32);
            htlcs.push(htlc);
        }
    }

    let lock_time = PackedLockTime(
        ((0x20 as u32) << 8 * 3) | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
    );
    (Transaction { version: 2, lock_time, input: txins, output: outputs }, scripts, htlcs)
}

pub(crate) fn sort_outputs<T, C: Fn(&T, &T) -> cmp::Ordering>(
    outputs: &mut Vec<(TxOut, T)>,
    tie_breaker: C,
) {
    outputs.sort_unstable_by(|a, b| {
        a.0.value.cmp(&b.0.value).then_with(|| {
            a.0.script_pubkey[..].cmp(&b.0.script_pubkey[..]).then_with(|| tie_breaker(&a.1, &b.1))
        })
    });
}

/// Phase 1 HTLC info
#[derive(Clone)]
pub struct HTLCInfo {
    /// HTLC value
    pub value_sat: u64,
    /// RIPEMD160 of 32 bytes hash
    pub payment_hash_hash: [u8; 20],
    /// This is zero (unknown) for offered HTLCs in phase 1
    pub cltv_expiry: u32,
}

// Implement manually so we can have hex encoded payment_hash_hash.
impl fmt::Debug for HTLCInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HTLCInfo")
            .field("value_sat", &self.value_sat)
            .field("payment_hash_hash", &self.payment_hash_hash.to_hex())
            .field("cltv_expiry", &self.cltv_expiry)
            .finish()
    }
}

/// Phase 2 HTLC info
#[derive(Clone, PartialEq, Eq)]
pub struct HTLCInfo2 {
    /// The value in satoshi
    pub value_sat: u64,
    /// The payment hash
    pub payment_hash: PaymentHash,
    /// This is zero for offered HTLCs in phase 1
    pub cltv_expiry: u32,
}

// Implement manually because PaymentHash doesn't support
impl Ord for HTLCInfo2 {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.value_sat
            .cmp(&other.value_sat)
            .then_with(|| self.payment_hash.0.cmp(&other.payment_hash.0))
            .then_with(|| self.cltv_expiry.cmp(&other.cltv_expiry))
    }
}

// Implement manually because PaymentHash doesn't support
impl PartialOrd for HTLCInfo2 {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Implement manually so we can have hex encoded payment_hash.
impl fmt::Debug for HTLCInfo2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HTLCInfo2")
            .field("value_sat", &self.value_sat)
            .field("payment_hash", &self.payment_hash.0.to_hex())
            .field("cltv_expiry", &self.cltv_expiry)
            .finish()
    }
}

/// This trait answers whether a preimage is known
pub trait PreimageMap {
    /// Whether a preimage is known for the payment hash
    fn has_preimage(&self, hash: &PaymentHash) -> bool;
}

#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub struct CommitmentInfo2 {
    pub is_counterparty_broadcaster: bool,
    pub to_countersigner_pubkey: PublicKey,
    pub to_countersigner_value_sat: u64,
    /// Broadcaster revocation pubkey
    pub revocation_pubkey: PublicKey,
    pub to_broadcaster_delayed_pubkey: PublicKey,
    pub to_broadcaster_value_sat: u64,
    pub to_self_delay: u16,
    pub offered_htlcs: Vec<HTLCInfo2>,
    pub received_htlcs: Vec<HTLCInfo2>,
    pub feerate_per_kw: u32,
}

impl CommitmentInfo2 {
    /// Construct a normalized CommitmentInfo2
    pub fn new(
        is_counterparty_broadcaster: bool,
        to_countersigner_pubkey: PublicKey,
        to_countersigner_value_sat: u64,
        revocation_pubkey: PublicKey,
        to_broadcaster_delayed_pubkey: PublicKey,
        to_broadcaster_value_sat: u64,
        to_self_delay: u16,
        mut offered_htlcs: Vec<HTLCInfo2>,
        mut received_htlcs: Vec<HTLCInfo2>,
        feerate_per_kw: u32,
    ) -> CommitmentInfo2 {
        offered_htlcs.sort();
        received_htlcs.sort();
        CommitmentInfo2 {
            is_counterparty_broadcaster,
            to_countersigner_pubkey,
            to_countersigner_value_sat,
            revocation_pubkey,
            to_broadcaster_delayed_pubkey,
            to_broadcaster_value_sat,
            to_self_delay,
            offered_htlcs,
            received_htlcs,
            feerate_per_kw,
        }
    }

    /// Returns true if there are no pending HTLCS
    pub fn htlcs_is_empty(&self) -> bool {
        self.offered_htlcs.is_empty() && self.received_htlcs.is_empty()
    }

    /// Returns offered HTLCs added and removed in new commitment tx
    pub fn delta_offered_htlcs<'a>(
        &'a self,
        new: &'a CommitmentInfo2,
    ) -> (AddedItemsIter<'a, HTLCInfo2>, AddedItemsIter<'a, HTLCInfo2>) {
        (
            AddedItemsIter::new(&self.offered_htlcs, &new.offered_htlcs),
            AddedItemsIter::new(&new.offered_htlcs, &self.offered_htlcs),
        )
    }

    /// Returns offered HTLCs added and removed in new commitment tx
    pub fn delta_received_htlcs<'a>(
        &'a self,
        new: &'a CommitmentInfo2,
    ) -> (AddedItemsIter<'a, HTLCInfo2>, AddedItemsIter<'a, HTLCInfo2>) {
        (
            AddedItemsIter::new(&self.received_htlcs, &new.received_htlcs),
            AddedItemsIter::new(&new.received_htlcs, &self.received_htlcs),
        )
    }

    /// Value in satoshis to holder and counterparty, respectively.
    /// Does not include HTLCs.
    pub fn value_to_parties(&self) -> (u64, u64) {
        if self.is_counterparty_broadcaster {
            (self.to_countersigner_value_sat, self.to_broadcaster_value_sat)
        } else {
            (self.to_broadcaster_value_sat, self.to_countersigner_value_sat)
        }
    }

    /// The total output value of this transaction.
    /// This is smaller than the total channel value, due to on-chain fees.
    pub fn total_value(&self) -> u64 {
        self.to_broadcaster_value_sat
            + self.to_countersigner_value_sat
            + self.offered_htlcs.iter().map(|h| h.value_sat).sum::<u64>()
            + self.received_htlcs.iter().map(|h| h.value_sat).sum::<u64>()
    }

    /// Compute claimable balance in sat, defined as the sum of:
    /// - the output to us
    /// - HTLCs offered to us for which the preimage is known
    /// - HTLCs we offer for which the preimage is unknown
    pub fn claimable_balance<T: PreimageMap>(
        &self,
        preimage_map: &T,
        is_outbound: bool,
        channel_value: u64,
    ) -> u64 {
        let mut balance = self.value_to_parties().0;
        if is_outbound {
            let total_value = self.total_value();
            let fee = channel_value.checked_sub(total_value).unwrap();
            balance = balance.checked_add(fee).unwrap();
        }
        let (offered, received) = if self.is_counterparty_broadcaster {
            (&self.received_htlcs, &self.offered_htlcs)
        } else {
            (&self.offered_htlcs, &self.received_htlcs)
        };
        for o in offered {
            if !preimage_map.has_preimage(&o.payment_hash) {
                balance = balance.checked_add(o.value_sat).expect("overflow");
            }
        }
        for r in received {
            if preimage_map.has_preimage(&r.payment_hash) {
                balance = balance.checked_add(r.value_sat).expect("overflow");
            }
        }
        balance
    }

    /// Return the total received and offered htlc balances
    pub fn htlc_balance(&self) -> (u64, u64) {
        let mut sum_received: u64 = 0;
        let mut sum_offered: u64 = 0;
        let (offered, received) = if self.is_counterparty_broadcaster {
            (&self.received_htlcs, &self.offered_htlcs)
        } else {
            (&self.offered_htlcs, &self.received_htlcs)
        };
        for o in offered {
            sum_offered = sum_offered.checked_add(o.value_sat).expect("overflow");
        }
        for r in received {
            sum_received = sum_received.checked_add(r.value_sat).expect("overflow");
        }
        (sum_received, sum_offered)
    }
}

#[allow(dead_code)]
#[allow(missing_docs)]
pub struct CommitmentInfo {
    pub is_counterparty_broadcaster: bool,
    pub to_countersigner_address: Option<Payload>,
    pub to_countersigner_pubkey: Option<PublicKey>,
    pub to_countersigner_value_sat: u64,
    pub to_countersigner_anchor_count: u16,
    /// Broadcaster revocation pubkey
    pub revocation_pubkey: Option<PublicKey>,
    pub to_broadcaster_delayed_pubkey: Option<PublicKey>,
    pub to_broadcaster_value_sat: u64,
    pub to_self_delay: u16,
    pub to_broadcaster_anchor_count: u16,
    pub offered_htlcs: Vec<HTLCInfo>,
    pub received_htlcs: Vec<HTLCInfo>,
}

// Define manually because Payload's fmt::Debug is lame.
impl fmt::Debug for CommitmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentInfo")
            .field("is_counterparty_broadcaster", &self.is_counterparty_broadcaster)
            // Wrap the to_countersigner_address Payload w/ a nicer printing one.
            .field(
                "to_countersigner_address",
                &self.to_countersigner_address.as_ref().map(|p| DebugPayload(&p)),
            )
            .field("to_countersigner_pubkey", &self.to_countersigner_pubkey)
            .field("to_countersigner_value_sat", &self.to_countersigner_value_sat)
            .field("to_countersigner_anchor_count", &self.to_countersigner_anchor_count)
            .field("revocation_pubkey", &self.revocation_pubkey)
            .field("to_broadcaster_delayed_pubkey", &self.to_broadcaster_delayed_pubkey)
            .field("to_broadcaster_value_sat", &self.to_broadcaster_value_sat)
            .field("to_self_delay", &self.to_self_delay)
            .field("to_broadcaster_anchor_count", &self.to_broadcaster_anchor_count)
            .field("offered_htlcs", &self.offered_htlcs)
            .field("received_htlcs", &self.received_htlcs)
            .finish()
    }
}

pub(crate) fn parse_received_htlc_script(
    script: &Script,
    option_anchors: bool,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64), ValidationError> {
    let iter = &mut script.instructions();
    expect_op(iter, OP_DUP)?;
    expect_op(iter, OP_HASH160)?;
    let revocation_hash = expect_data(iter)?;
    expect_op(iter, OP_EQUAL)?;
    expect_op(iter, OP_IF)?;
    expect_op(iter, OP_CHECKSIG)?;
    expect_op(iter, OP_ELSE)?;
    let remote_htlc_pubkey = expect_data(iter)?;
    expect_op(iter, OP_SWAP)?;
    expect_op(iter, OP_SIZE)?;
    let thirty_two = expect_number(iter)?;
    if thirty_two != 32 {
        return Err(mismatch_error(format!("expected 32, saw {}", thirty_two)));
    }
    expect_op(iter, OP_EQUAL)?;
    expect_op(iter, OP_IF)?;
    expect_op(iter, OP_HASH160)?;
    let payment_hash_vec = expect_data(iter)?;
    expect_op(iter, OP_EQUALVERIFY)?;
    expect_op(iter, OP_PUSHNUM_2)?;
    expect_op(iter, OP_SWAP)?;
    let local_htlc_pubkey = expect_data(iter)?;
    expect_op(iter, OP_PUSHNUM_2)?;
    expect_op(iter, OP_CHECKMULTISIG)?;
    expect_op(iter, OP_ELSE)?;
    expect_op(iter, OP_DROP)?;
    let cltv_expiry = expect_number(iter)?;
    expect_op(iter, OP_CLTV)?;
    expect_op(iter, OP_DROP)?;
    expect_op(iter, OP_CHECKSIG)?;
    expect_op(iter, OP_ENDIF)?;
    if option_anchors {
        expect_op(iter, OP_PUSHNUM_1)?;
        expect_op(iter, OP_CSV)?;
        expect_op(iter, OP_DROP)?;
    }
    expect_op(iter, OP_ENDIF)?;
    expect_script_end(iter)?;
    Ok((revocation_hash, remote_htlc_pubkey, payment_hash_vec, local_htlc_pubkey, cltv_expiry))
}

pub(crate) fn parse_offered_htlc_script(
    script: &Script,
    option_anchors: bool,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), ValidationError> {
    let iter = &mut script.instructions();
    expect_op(iter, OP_DUP)?;
    expect_op(iter, OP_HASH160)?;
    let revocation_hash = expect_data(iter)?;
    expect_op(iter, OP_EQUAL)?;
    expect_op(iter, OP_IF)?;
    expect_op(iter, OP_CHECKSIG)?;
    expect_op(iter, OP_ELSE)?;
    let remote_htlc_pubkey = expect_data(iter)?;
    expect_op(iter, OP_SWAP)?;
    expect_op(iter, OP_SIZE)?;
    let thirty_two = expect_number(iter)?;
    if thirty_two != 32 {
        return Err(mismatch_error(format!("expected 32, saw {}", thirty_two)));
    }
    expect_op(iter, OP_EQUAL)?;
    expect_op(iter, OP_NOTIF)?;
    expect_op(iter, OP_DROP)?;
    expect_op(iter, OP_PUSHNUM_2)?;
    expect_op(iter, OP_SWAP)?;
    let local_htlc_pubkey = expect_data(iter)?;
    expect_op(iter, OP_PUSHNUM_2)?;
    expect_op(iter, OP_CHECKMULTISIG)?;
    expect_op(iter, OP_ELSE)?;
    expect_op(iter, OP_HASH160)?;
    let payment_hash_vec = expect_data(iter)?;
    expect_op(iter, OP_EQUALVERIFY)?;
    expect_op(iter, OP_CHECKSIG)?;
    expect_op(iter, OP_ENDIF)?;
    if option_anchors {
        expect_op(iter, OP_PUSHNUM_1)?;
        expect_op(iter, OP_CSV)?;
        expect_op(iter, OP_DROP)?;
    }
    expect_op(iter, OP_ENDIF)?;
    expect_script_end(iter)?;
    Ok((revocation_hash, remote_htlc_pubkey, local_htlc_pubkey, payment_hash_vec))
}

pub(crate) fn parse_revokeable_redeemscript(
    script: &Script,
    _option_anchors: bool,
) -> Result<(Vec<u8>, i64, Vec<u8>), ValidationError> {
    let iter = &mut script.instructions();
    expect_op(iter, OP_IF)?;
    let revocation_key = expect_data(iter)?;
    expect_op(iter, OP_ELSE)?;
    let contest_delay = expect_number(iter)?;
    expect_op(iter, OP_CSV)?;
    expect_op(iter, OP_DROP)?;
    let delayed_pubkey = expect_data(iter)?;
    expect_op(iter, OP_ENDIF)?;
    expect_op(iter, OP_CHECKSIG)?;
    expect_script_end(iter)?;
    Ok((revocation_key, contest_delay, delayed_pubkey))
}

impl CommitmentInfo {
    // FIXME - should the new_for_{holder,counterparty} wrappers move
    // to Validator::make_info_for_{holder,counterparty}?
    #[cfg(test)]
    pub(crate) fn new_for_holder() -> Self {
        CommitmentInfo::new(false)
    }

    #[cfg(test)]
    pub(crate) fn new_for_counterparty() -> Self {
        CommitmentInfo::new(true)
    }

    /// Construct
    pub fn new(is_counterparty_broadcaster: bool) -> Self {
        CommitmentInfo {
            is_counterparty_broadcaster,
            to_countersigner_address: None,
            to_countersigner_pubkey: None,
            to_countersigner_value_sat: 0,
            to_countersigner_anchor_count: 0,
            revocation_pubkey: None,
            to_broadcaster_delayed_pubkey: None,
            to_broadcaster_value_sat: 0,
            to_self_delay: 0,
            to_broadcaster_anchor_count: 0,
            offered_htlcs: vec![],
            received_htlcs: vec![],
        }
    }

    pub(crate) fn has_to_broadcaster(&self) -> bool {
        self.to_broadcaster_delayed_pubkey.is_some()
    }

    pub(crate) fn has_to_countersigner(&self) -> bool {
        self.to_countersigner_address.is_some() || self.to_countersigner_pubkey.is_some()
    }

    /// The amount used by the broadcaster anchor
    pub fn to_broadcaster_anchor_value_sat(&self) -> u64 {
        if self.to_broadcaster_anchor_count == 1 {
            ANCHOR_SAT
        } else {
            0
        }
    }

    /// The amount used by the countersigner anchor
    pub fn to_countersigner_anchor_value_sat(&self) -> u64 {
        if self.to_countersigner_anchor_count == 1 {
            ANCHOR_SAT
        } else {
            0
        }
    }

    fn parse_to_broadcaster_script(
        &self,
        script: &Script,
    ) -> Result<(Vec<u8>, i64, Vec<u8>), ValidationError> {
        let iter = &mut script.instructions();
        expect_op(iter, OP_IF)?;
        let revocation_pubkey = expect_data(iter)?;
        expect_op(iter, OP_ELSE)?;
        let delay = expect_number(iter)?;
        expect_op(iter, OP_CSV)?;
        expect_op(iter, OP_DROP)?;
        let delayed_pubkey = expect_data(iter)?;
        expect_op(iter, OP_ENDIF)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_script_end(iter)?;
        Ok((revocation_pubkey, delay, delayed_pubkey))
    }

    fn handle_to_broadcaster_output(
        &mut self,
        out: &TxOut,
        vals: (Vec<u8>, i64, Vec<u8>),
    ) -> Result<(), ValidationError> {
        let (revocation_pubkey, delay, delayed_pubkey) = vals;
        // policy-commitment-singular-to-holder
        // policy-commitment-singular-to-counterparty
        if self.has_to_broadcaster() {
            return Err(transaction_format_error(
                "more than one to_broadcaster output".to_string(),
            ));
        }

        if delay < 0 {
            return Err(script_format_error("negative delay".to_string()));
        }
        if delay > MAX_DELAY {
            return Err(script_format_error("delay too large".to_string()));
        }

        // This is safe because we checked for negative
        self.to_self_delay = delay as u16;
        self.to_broadcaster_value_sat = out.value;
        self.to_broadcaster_delayed_pubkey = Some(
            PublicKey::from_slice(delayed_pubkey.as_slice())
                .map_err(|err| mismatch_error(format!("delayed_pubkey malformed: {}", err)))?,
        );
        self.revocation_pubkey = Some(
            PublicKey::from_slice(revocation_pubkey.as_slice())
                .map_err(|err| mismatch_error(format!("revocation_pubkey malformed: {}", err)))?,
        );

        Ok(())
    }

    fn parse_to_countersigner_delayed_script(
        &self,
        script: &Script,
    ) -> Result<Vec<u8>, ValidationError> {
        let iter = &mut script.instructions();
        let pubkey_data = expect_data(iter)?;
        expect_op(iter, OP_CHECKSIGVERIFY)?;
        expect_op(iter, OP_PUSHNUM_1)?;
        expect_op(iter, OP_CSV)?;
        expect_script_end(iter)?;
        Ok(pubkey_data)
    }

    /// 1 block delayed because of anchor usage
    fn handle_to_countersigner_delayed_output(
        &mut self,
        out: &TxOut,
        to_countersigner_delayed_pubkey_data: Vec<u8>,
    ) -> Result<(), ValidationError> {
        // policy-commitment-singular-to-holder
        // policy-commitment-singular-to-counterparty
        if self.has_to_countersigner() {
            return Err(transaction_format_error(
                "more than one to_countersigner output".to_string(),
            ));
        }
        self.to_countersigner_pubkey =
            Some(PublicKey::from_slice(to_countersigner_delayed_pubkey_data.as_slice()).map_err(
                |err| mismatch_error(format!("to_countersigner delayed pubkey malformed: {}", err)),
            )?);
        self.to_countersigner_value_sat = out.value;
        Ok(())
    }

    fn handle_received_htlc_output(
        &mut self,
        out: &TxOut,
        vals: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64),
    ) -> Result<(), ValidationError> {
        let (
            _revocation_hash,
            _remote_htlc_pubkey,
            payment_hash_vec,
            _local_htlc_pubkey,
            cltv_expiry,
        ) = vals;
        let payment_hash_hash = payment_hash_vec
            .as_slice()
            .try_into()
            .map_err(|_| mismatch_error("payment hash RIPEMD160 must be length 20".to_string()))?;

        if cltv_expiry < 0 {
            return Err(script_format_error("negative CLTV".to_string()));
        }

        let cltv_expiry = cltv_expiry as u32;

        let htlc = HTLCInfo { value_sat: out.value, payment_hash_hash, cltv_expiry };
        self.received_htlcs.push(htlc);

        Ok(())
    }

    fn handle_offered_htlc_output(
        &mut self,
        out: &TxOut,
        vals: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> Result<(), ValidationError> {
        let (_revocation_hash, _remote_htlc_pubkey, _local_htlc_pubkey, payment_hash_vec) = vals;

        let payment_hash_hash = payment_hash_vec
            .as_slice()
            .try_into()
            .map_err(|_| mismatch_error("payment hash RIPEMD160 must be length 20".to_string()))?;

        let htlc = HTLCInfo { value_sat: out.value, payment_hash_hash, cltv_expiry: 0 };
        self.offered_htlcs.push(htlc);

        Ok(())
    }

    fn parse_anchor_script(&self, script: &Script) -> Result<Vec<u8>, ValidationError> {
        let iter = &mut script.instructions();
        let to_pubkey_data = expect_data(iter)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_op(iter, OP_IFDUP)?;
        expect_op(iter, OP_NOTIF)?;
        expect_op(iter, OP_PUSHNUM_16)?;
        expect_op(iter, OP_CSV)?;
        expect_op(iter, OP_ENDIF)?;
        expect_script_end(iter)?;
        Ok(to_pubkey_data)
    }

    fn handle_anchor_output(
        &mut self,
        keys: &InMemorySigner,
        out: &TxOut,
        to_pubkey_data: Vec<u8>,
    ) -> Result<(), ValidationError> {
        let to_pubkey = PublicKey::from_slice(to_pubkey_data.as_slice())
            .map_err(|err| mismatch_error(format!("anchor to_pubkey malformed: {}", err)))?;

        // These are dependent on which side owns this commitment.
        let (to_broadcaster_funding_pubkey, to_countersigner_funding_pubkey) =
            if self.is_counterparty_broadcaster {
                (keys.counterparty_pubkeys().funding_pubkey, keys.pubkeys().funding_pubkey)
            } else {
                (keys.pubkeys().funding_pubkey, keys.counterparty_pubkeys().funding_pubkey)
            };

        // policy-commitment-anchor-amount
        if out.value != ANCHOR_SAT {
            return Err(mismatch_error(format!("anchor wrong size: {}", out.value)));
        }

        if to_pubkey == to_broadcaster_funding_pubkey {
            // local anchor
            self.to_broadcaster_anchor_count += 1;
        } else if to_pubkey == to_countersigner_funding_pubkey {
            // remote anchor
            self.to_countersigner_anchor_count += 1;
        } else {
            // policy-commitment-anchor-match-fundingkey
            return Err(mismatch_error(format!(
                "anchor to_pubkey {} doesn't match local or remote",
                to_pubkey_data.to_hex()
            )));
        }
        Ok(())
    }

    pub(crate) fn handle_output(
        &mut self,
        keys: &InMemorySigner,
        setup: &ChannelSetup,
        out: &TxOut,
        script_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        if out.script_pubkey.is_v0_p2wpkh() {
            // FIXME - Does this need it's own policy tag?
            if setup.option_anchors() {
                return Err(transaction_format_error(
                    "p2wpkh to_countersigner not valid with anchors".to_string(),
                ));
            }
            // policy-commitment-singular-to-holder
            // policy-commitment-singular-to-counterparty
            if self.has_to_countersigner() {
                return Err(transaction_format_error(
                    "more than one to_countersigner output".to_string(),
                ));
            }
            self.to_countersigner_address = Payload::from_script(&out.script_pubkey).ok();
            self.to_countersigner_value_sat = out.value;
        } else if out.script_pubkey.is_v0_p2wsh() {
            if script_bytes.is_empty() {
                return Err(transaction_format_error("missing witscript for p2wsh".to_string()));
            }
            let script = Script::from(script_bytes.to_vec());
            // FIXME - Does this need it's own policy tag?
            if out.script_pubkey != script.to_v0_p2wsh() {
                return Err(transaction_format_error(
                    "script pubkey doesn't match inner script".to_string(),
                ));
            }
            let vals = self.parse_to_broadcaster_script(&script);
            if vals.is_ok() {
                return self.handle_to_broadcaster_output(out, vals.unwrap());
            }
            let vals = parse_received_htlc_script(&script, setup.option_anchors());
            if vals.is_ok() {
                return self.handle_received_htlc_output(out, vals.unwrap());
            }
            let vals = parse_offered_htlc_script(&script, setup.option_anchors());
            if vals.is_ok() {
                return self.handle_offered_htlc_output(out, vals.unwrap());
            }
            let vals = self.parse_anchor_script(&script);
            if vals.is_ok() {
                return self.handle_anchor_output(keys, out, vals.unwrap());
            }
            if setup.option_anchors() {
                let vals = self.parse_to_countersigner_delayed_script(&script);
                if vals.is_ok() {
                    return self.handle_to_countersigner_delayed_output(out, vals.unwrap());
                }
            }
            // policy-commitment-no-unrecognized-outputs
            return Err(transaction_format_error("unknown p2wsh script".to_string()));
        } else {
            // policy-commitment-no-unrecognized-outputs
            return Err(transaction_format_error("unknown output type".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Builder;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network};

    use crate::channel::CommitmentType;
    use crate::util::key_utils::make_test_pubkey;
    use crate::util::test_utils::{hex_encode, make_test_channel_keys, make_test_channel_setup};

    use super::*;

    use test_log::test;

    #[test]
    fn htlc2_sorting() {
        // Defined in order ...
        let htlc0 =
            HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 2 << 16 };
        let htlc1 =
            HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([1; 32]), cltv_expiry: 3 << 16 };
        let htlc2 =
            HTLCInfo2 { value_sat: 4000, payment_hash: PaymentHash([2; 32]), cltv_expiry: 3 << 16 };
        let htlc3 =
            HTLCInfo2 { value_sat: 5000, payment_hash: PaymentHash([2; 32]), cltv_expiry: 3 << 16 };
        let sorted = vec![&htlc0, &htlc1, &htlc2, &htlc3];

        // Reverse order
        let mut unsorted0 = vec![&htlc3, &htlc2, &htlc1, &htlc0];
        unsorted0.sort();
        assert_eq!(unsorted0, sorted);

        // Random order
        let mut unsorted1 = vec![&htlc2, &htlc0, &htlc3, &htlc1];
        unsorted1.sort();
        assert_eq!(unsorted1, sorted);
    }

    #[test]
    fn parse_test_err() {
        let info = CommitmentInfo::new_for_holder();
        let script = Builder::new().into_script();
        let err = info.parse_to_broadcaster_script(&script);
        assert!(err.is_err());
    }

    #[test]
    fn parse_test() {
        let secp_ctx = Secp256k1::signing_only();
        let mut info = CommitmentInfo::new_for_holder();
        let out = TxOut { value: 123, script_pubkey: Default::default() };
        let revocation_pubkey =
            PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[4u8; 32]).unwrap());
        let delayed_pubkey =
            PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let script = get_revokeable_redeemscript(&revocation_pubkey, 5, &delayed_pubkey);
        let vals = info.parse_to_broadcaster_script(&script).unwrap();
        let res = info.handle_to_broadcaster_output(&out, vals);
        assert!(res.is_ok());
        assert!(info.has_to_broadcaster());
        assert!(!info.has_to_countersigner());
        assert_eq!(info.revocation_pubkey.unwrap(), revocation_pubkey);
        assert_eq!(info.to_broadcaster_delayed_pubkey.unwrap(), delayed_pubkey);
        assert_eq!(info.to_self_delay, 5);
        assert_eq!(info.to_broadcaster_value_sat, 123);
        // Make sure you can't do it again (can't have two to_broadcaster outputs).
        let vals = info.parse_to_broadcaster_script(&script);
        let res = info.handle_to_broadcaster_output(&out, vals.unwrap());
        assert!(res.is_err());
        #[rustfmt::skip]
        assert_eq!(
            transaction_format_error("more than one to_broadcaster output".to_string()),
                    res.expect_err("expecting err")
        );
    }

    #[test]
    fn handle_anchor_wrong_size_test() {
        let mut info = CommitmentInfo::new_for_holder();
        let keys = make_test_channel_keys();
        let out = TxOut { value: 329, script_pubkey: Default::default() };
        let to_pubkey_data = keys.pubkeys().funding_pubkey.serialize().to_vec();
        let res = info.handle_anchor_output(&keys, &out, to_pubkey_data);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), mismatch_error(format!("anchor wrong size: {}", out.value)));
    }

    #[test]
    fn handle_anchor_not_local_or_remote_test() {
        let mut info = CommitmentInfo::new_for_holder();
        let keys = make_test_channel_keys();
        let out = TxOut { value: 330, script_pubkey: Default::default() };
        let to_pubkey_data = make_test_pubkey(42).serialize().to_vec(); // doesn't match
        let res = info.handle_anchor_output(&keys, &out, to_pubkey_data.clone());
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            mismatch_error(format!(
                "anchor to_pubkey {} doesn\'t match local or remote",
                hex_encode(&to_pubkey_data)
            ))
        );
    }

    // policy-commitment-no-unrecognized-outputs
    #[test]
    fn handle_output_unknown_output_type_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let setup = make_test_channel_setup();
        let out = TxOut { value: 42, script_pubkey: Default::default() };
        let script_bytes = [3u8; 30];
        let res = info.handle_output(&keys, &setup, &out, &script_bytes);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), transaction_format_error("unknown output type".to_string()));
    }

    // policy-commitment-no-unrecognized-outputs
    #[test]
    fn handle_output_unknown_p2wsh_script_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let setup = make_test_channel_setup();
        let script = Builder::new()
            .push_slice(&[0u8; 42]) // invalid
            .into_script();
        let out = TxOut {
            value: 42,
            script_pubkey: Address::p2wsh(&script, Network::Testnet).script_pubkey(),
        };
        let res = info.handle_output(&keys, &setup, &out, script.as_bytes());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), transaction_format_error("unknown p2wsh script".to_string()));
    }

    #[test]
    fn handle_output_p2wpkh_to_countersigner_with_anchors_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let mut setup = make_test_channel_setup();
        setup.commitment_type = CommitmentType::Anchors;
        let pubkey = bitcoin::PublicKey::from_slice(&make_test_pubkey(43).serialize()[..]).unwrap();
        let out = TxOut {
            value: 42,
            script_pubkey: Address::p2wpkh(&pubkey, Network::Testnet).unwrap().script_pubkey(),
        };
        let res = info.handle_output(&keys, &setup, &out, &[0u8; 0]);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            transaction_format_error("p2wpkh to_countersigner not valid with anchors".to_string())
        );
    }

    #[test]
    fn handle_output_more_than_one_to_countersigner_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let setup = make_test_channel_setup();
        let pubkey = bitcoin::PublicKey::from_slice(&make_test_pubkey(43).serialize()[..]).unwrap();
        let address = Address::p2wpkh(&pubkey, Network::Testnet).unwrap();
        let out = TxOut { value: 42, script_pubkey: address.script_pubkey() };

        // Make the info look like a to_remote has already been seen.
        info.to_countersigner_address = Some(address.payload);

        let res = info.handle_output(&keys, &setup, &out, &[0u8; 0]);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            transaction_format_error("more than one to_countersigner output".to_string())
        );
    }

    #[test]
    fn handle_output_missing_witscript_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let setup = make_test_channel_setup();
        let script = Builder::new().into_script();
        let out = TxOut {
            value: 42,
            script_pubkey: Address::p2wsh(&script, Network::Testnet).script_pubkey(),
        };
        let res = info.handle_output(&keys, &setup, &out, script.as_bytes());
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            transaction_format_error("missing witscript for p2wsh".to_string())
        );
    }

    #[test]
    fn handle_output_script_pubkey_doesnt_match_test() {
        let mut info = CommitmentInfo::new_for_counterparty();
        let keys = make_test_channel_keys();
        let setup = make_test_channel_setup();
        let script0 = Builder::new().into_script();
        let script1 = Builder::new().push_slice(&[0u8; 42]).into_script();
        let out = TxOut {
            value: 42,
            script_pubkey: Address::p2wsh(&script0, Network::Testnet).script_pubkey(),
        };
        let res = info.handle_output(&keys, &setup, &out, script1.as_bytes());
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            transaction_format_error("script pubkey doesn\'t match inner script".to_string())
        );
    }
}
