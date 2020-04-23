use std::cmp;
use std::cmp::Ordering;

use bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut};
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL,
    OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_NOTIF, OP_PUSHNUM_2, OP_SIZE, OP_SWAP,
};
use bitcoin::util::address::Payload;
use bitcoin::util::bip143;
use bitcoin_hashes::{Hash, HashEngine};
use bitcoin_hashes::sha256::Hash as Sha256;
use lightning::chain::keysinterface::ChannelKeys;
use lightning::ln::chan_utils;
use lightning::ln::chan_utils::{
    HTLCOutputInCommitment, make_funding_redeemscript, TxCreationKeys,
};
use lightning::ln::channelmanager::PaymentHash;
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, Signature};

use crate::policy::error::ValidationError::{Mismatch, ScriptFormat, TransactionFormat};
use crate::policy::error::ValidationError;
use crate::tx::script::{
    expect_data, expect_number, expect_op, expect_script_end, get_revokeable_redeemscript,
};
use crate::util::enforcing_trait_impls::EnforcingChannelKeys;

const MAX_DELAY: i64 = 1000;

pub fn get_commitment_transaction_number_obscure_factor(
    secp_ctx: &Secp256k1<All>,
    local_payment_base_key: &SecretKey,
    remote_payment_basepoint: &PublicKey,
    outbound: bool,
) -> u64 {
    let mut sha = Sha256::engine();
    let our_payment_basepoint = PublicKey::from_secret_key(secp_ctx, local_payment_base_key);

    let their_payment_basepoint = remote_payment_basepoint.serialize();
    if outbound {
        sha.input(&our_payment_basepoint.serialize());
        sha.input(&their_payment_basepoint);
    } else {
        sha.input(&their_payment_basepoint); // NOT TESTED
        sha.input(&our_payment_basepoint.serialize()); // NOT TESTED
    }
    let res = Sha256::from_engine(sha).into_inner();

    ((res[26] as u64) << 5 * 8)
        | ((res[27] as u64) << 4 * 8)
        | ((res[28] as u64) << 3 * 8)
        | ((res[29] as u64) << 2 * 8)
        | ((res[30] as u64) << 1 * 8)
        | ((res[31] as u64) << 0 * 8)
}

pub fn build_close_tx(
    to_local_value: u64,
    to_remote_value: u64,
    local_shutdown_script: &Script,
    remote_shutdown_script: &Script,
    outpoint: OutPoint,
) -> Transaction {
    let txins = {
        let mut ins: Vec<TxIn> = Vec::new();
        ins.push(TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: Vec::new(),
        });
        ins
    };

    let mut txouts: Vec<(TxOut, ())> = Vec::new();

    if to_remote_value > 0 {
        txouts.push((
            TxOut {
                script_pubkey: remote_shutdown_script.clone(),
                value: to_remote_value,
            },
            (),
        ));
    }

    if to_local_value > 0 {
        txouts.push((
            TxOut {
                script_pubkey: local_shutdown_script.clone(),
                value: to_local_value,
            },
            (),
        ));
    }

    sort_outputs(&mut txouts, |_, _| cmp::Ordering::Equal); // Ordering doesnt matter if they used our pubkey...

    let mut outputs: Vec<TxOut> = Vec::new();
    for out in txouts.drain(..) {
        outputs.push(out.0);
    }

    Transaction {
        version: 2,
        lock_time: 0,
        input: txins,
        output: outputs,
    }
}

pub fn build_commitment_tx(
    keys: &TxCreationKeys,
    info: &CommitmentInfo2,
    obscured_commitment_transaction_number: u64,
    outpoint: OutPoint,
) -> (Transaction, Vec<Script>, Vec<HTLCOutputInCommitment>) {
    let txins = {
        let mut ins: Vec<TxIn> = Vec::new();
        ins.push(TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: ((0x80 as u32) << 8 * 3)
                | ((obscured_commitment_transaction_number >> 3 * 8) as u32),
            witness: Vec::new(),
        });
        ins
    };

    let mut txouts: Vec<(TxOut, (Script, Option<HTLCOutputInCommitment>))> = Vec::new();

    if info.to_remote_value > 0 {
        let script = info.to_remote_address.script_pubkey();
        txouts.push((
            TxOut {
                script_pubkey: script.clone(),
                value: info.to_remote_value as u64,
            },
            (script, None),
        ))
    }

    if info.to_local_value > 0 {
        let redeem_script = get_revokeable_redeemscript(
            &info.revocation_key,
            info.to_local_delay,
            &info.to_local_delayed_key,
        );
        txouts.push((
            TxOut {
                script_pubkey: redeem_script.to_v0_p2wsh(),
                value: info.to_local_value as u64,
            },
            (redeem_script, None),
        ))
    }

    for out in &info.offered_htlcs {
        let htlc_in_tx = HTLCOutputInCommitment {
            offered: true,
            amount_msat: out.value * 1000,
            cltv_expiry: out.cltv_expiry,
            payment_hash: out.payment_hash,
            transaction_output_index: None,
        };
        let script = chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys);
        let txout = TxOut {
            script_pubkey: script.to_v0_p2wsh(),
            value: out.value,
        };
        txouts.push((txout, (script, Some(htlc_in_tx))));
    }

    for out in &info.received_htlcs {
        let htlc_in_tx = HTLCOutputInCommitment {
            offered: false,
            amount_msat: out.value * 1000,
            cltv_expiry: out.cltv_expiry,
            payment_hash: out.payment_hash,
            transaction_output_index: None,
        };
        let script = chan_utils::get_htlc_redeemscript(&htlc_in_tx, &keys);
        let txout = TxOut {
            script_pubkey: script.to_v0_p2wsh(),
            value: out.value,
        };
        txouts.push((txout, (script, Some(htlc_in_tx))));
    }
    sort_outputs(&mut txouts, |a, b| {
        // BEGIN NOT TESTED
        if let &(_, Some(ref a_htlcout)) = a {
            if let &(_, Some(ref b_htlcout)) = b {
                a_htlcout.cltv_expiry.cmp(&b_htlcout.cltv_expiry)
            } else {
                cmp::Ordering::Equal
            }
        } else {
            cmp::Ordering::Equal
        }
        // END NOT TESTED
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

    (
        Transaction {
            version: 2,
            lock_time: ((0x20 as u32) << 8 * 3)
                | ((obscured_commitment_transaction_number & 0xffffffu64) as u32),
            input: txins,
            output: outputs,
        },
        scripts,
        htlcs,
    )
}

pub fn sign_commitment(
    secp_ctx: &Secp256k1<All>,
    keys: &EnforcingChannelKeys,
    remote_funding_pubkey: &PublicKey,
    tx: &Transaction,
    channel_value_satoshi: u64,
) -> Result<Signature, secp256k1::Error> {
    let funding_key = keys.funding_key();
    let funding_pubkey = keys.pubkeys().funding_pubkey;
    let channel_funding_redeemscript =
        make_funding_redeemscript(&funding_pubkey, &remote_funding_pubkey);

    let commitment_sighash = Message::from_slice(
        &bip143::SighashComponents::new(&tx).sighash_all(
            &tx.input[0],
            &channel_funding_redeemscript,
            channel_value_satoshi,
        )[..],
    )?;
    Ok(secp_ctx.sign(&commitment_sighash, funding_key))
}

pub fn sort_outputs<T, C: Fn(&T, &T) -> Ordering>(outputs: &mut Vec<(TxOut, T)>, tie_breaker: C) {
    outputs.sort_unstable_by(|a, b| {
        a.0.value.cmp(&b.0.value).then_with(|| {
            // BEGIN NOT TESTED
            a.0.script_pubkey[..]
                .cmp(&b.0.script_pubkey[..])
                .then_with(|| tie_breaker(&a.1, &b.1))
            // END NOT TESTED
        })
    });
}

// BEGIN NOT TESTED
#[derive(Debug, Clone)]
pub struct HTLCInfo {
    pub value: u64,
    pub payment_hash: PaymentHash,
    pub cltv_expiry: u32,
}
// END NOT TESTED

// BEGIN NOT TESTED
#[derive(Debug, Clone)]
pub struct CommitmentInfo2 {
    pub to_remote_address: Payload,
    pub to_remote_value: u64,
    pub revocation_key: PublicKey,
    pub to_local_delayed_key: PublicKey,
    pub to_local_value: u64,
    pub to_local_delay: u16,
    pub offered_htlcs: Vec<HTLCInfo>,
    pub received_htlcs: Vec<HTLCInfo>,
}
// END NOT TESTED

#[allow(dead_code)]
pub struct CommitmentInfo {
    pub to_remote_address: Option<Payload>,
    pub to_remote_value: u64,
    pub revocation_key: Option<PublicKey>,
    pub to_local_delayed_key: Option<PublicKey>,
    pub to_local_value: u64,
    pub to_local_delay: u16,
    // TODO fine-grained HTLC info
    pub offered_htlcs: Vec<TxOut>,
    pub received_htlcs: Vec<TxOut>,
}

impl CommitmentInfo {
    pub fn new() -> Self {
        CommitmentInfo {
            to_remote_address: None,
            to_remote_value: 0,
            revocation_key: None,
            to_local_delayed_key: None,
            to_local_value: 0,
            to_local_delay: 0,
            offered_htlcs: vec![],
            received_htlcs: vec![],
        }
    }

    fn has_to_local(&self) -> bool {
        self.to_local_delayed_key.is_some()
    }

    fn has_to_remote(&self) -> bool {
        self.to_remote_address.is_some()
    }

    fn handle_to_local_script(
        &mut self,
        out: &TxOut,
        script: &Script,
    ) -> Result<(), ValidationError> {
        let iter = &mut script.iter(true);
        expect_op(iter, OP_IF)?;
        let revocation_key = expect_data(iter)?;
        expect_op(iter, OP_ELSE)?;
        let delay = expect_number(iter)?;
        expect_op(iter, OP_CSV)?;
        expect_op(iter, OP_DROP)?;
        let to_local_delayed_key = expect_data(iter)?;
        expect_op(iter, OP_ENDIF)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_script_end(iter)?;

        if self.has_to_local() {
            return Err(TransactionFormat("already have to local".to_string()));
        }
        if delay < 0 {
            return Err(ScriptFormat("negative delay".to_string())); // NOT TESTED
        }
        if delay > MAX_DELAY {
            return Err(ScriptFormat("delay too large".to_string())); // NOT TESTED
        }

        // This is safe because we checked for negative
        self.to_local_delay = delay as u16;
        self.to_local_value = out.value;
        self.to_local_delayed_key = Some(
            PublicKey::from_slice(to_local_delayed_key.as_slice())
                .map_err(|err| Mismatch(format!("to_local_delayed_key mismatch: {}", err)))?,
        );
        self.revocation_key = Some(
            PublicKey::from_slice(revocation_key.as_slice())
                .map_err(|err| Mismatch(format!("revocation_key mismatch: {}", err)))?,
        );

        Ok(())
    }

    fn handle_received_htlc_script(
        &mut self,
        out: &TxOut,
        script: &Script,
    ) -> Result<(), ValidationError> {
        let iter = &mut script.iter(true);
        expect_op(iter, OP_DUP)?;
        expect_op(iter, OP_HASH160)?;
        let _revocation_hash = expect_data(iter)?;
        expect_op(iter, OP_EQUAL)?;
        expect_op(iter, OP_IF)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_op(iter, OP_ELSE)?;
        let _remote_htlc_key = expect_data(iter)?;
        expect_op(iter, OP_SWAP)?;
        expect_op(iter, OP_SIZE)?;
        let thirty_two = expect_number(iter)?;
        if thirty_two != 32 {
            return Err(Mismatch(format!("expected 32, saw {}", thirty_two))); // NOT TESTED
        }
        expect_op(iter, OP_EQUAL)?;
        expect_op(iter, OP_IF)?;
        expect_op(iter, OP_HASH160)?;
        let _payment_hash = expect_data(iter)?;
        expect_op(iter, OP_EQUALVERIFY)?;
        expect_op(iter, OP_PUSHNUM_2)?;
        expect_op(iter, OP_SWAP)?;
        let _local_htlc_key = expect_data(iter)?;
        expect_op(iter, OP_PUSHNUM_2)?;
        expect_op(iter, OP_CHECKMULTISIG)?;
        expect_op(iter, OP_ELSE)?;
        expect_op(iter, OP_DROP)?;
        let _delay = expect_number(iter)?;
        expect_op(iter, OP_CLTV)?;
        expect_op(iter, OP_DROP)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_op(iter, OP_ENDIF)?;
        expect_op(iter, OP_ENDIF)?;
        expect_script_end(iter)?;

        self.received_htlcs.push(out.clone());
        Ok(())
    }

    fn handle_offered_htlc_script(
        &mut self,
        out: &TxOut,
        script: &Script,
    ) -> Result<(), ValidationError> {
        let iter = &mut script.iter(true);
        expect_op(iter, OP_DUP)?;
        expect_op(iter, OP_HASH160)?;
        let _revocation_hash = expect_data(iter)?;
        expect_op(iter, OP_EQUAL)?;
        expect_op(iter, OP_IF)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_op(iter, OP_ELSE)?;
        let _remote_htlc_key = expect_data(iter)?;
        expect_op(iter, OP_SWAP)?;
        expect_op(iter, OP_SIZE)?;
        let thirty_two = expect_number(iter)?;
        if thirty_two != 32 {
            return Err(Mismatch(format!("expected 32, saw {}", thirty_two))); // NOT TESTED
        }
        expect_op(iter, OP_EQUAL)?;
        expect_op(iter, OP_NOTIF)?;
        expect_op(iter, OP_DROP)?;
        expect_op(iter, OP_PUSHNUM_2)?;
        expect_op(iter, OP_SWAP)?;
        let _local_htlc_key = expect_data(iter)?;
        expect_op(iter, OP_PUSHNUM_2)?;
        expect_op(iter, OP_CHECKMULTISIG)?;
        expect_op(iter, OP_ELSE)?;
        expect_op(iter, OP_HASH160)?;
        let _payment_hash = expect_data(iter)?;
        expect_op(iter, OP_EQUALVERIFY)?;
        expect_op(iter, OP_CHECKSIG)?;
        expect_op(iter, OP_ENDIF)?;
        expect_op(iter, OP_ENDIF)?;
        expect_script_end(iter)?;

        self.offered_htlcs.push(out.clone());
        Ok(())
    }

    pub fn handle_output(
        &mut self,
        out: &TxOut,
        script_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        if out.script_pubkey.is_v0_p2wpkh() {
            if self.has_to_remote() {
                // BEGIN NOT TESTED
                return Err(TransactionFormat("more than one to remote".to_string()));
                // END NOT TESTED
            }
            self.to_remote_address = Payload::from_script(&out.script_pubkey);
            self.to_remote_value = out.value;
        } else if out.script_pubkey.is_v0_p2wsh() {
            if script_bytes.is_empty() {
                // BEGIN NOT TESTED
                return Err(TransactionFormat("missing witscript for p2wsh".to_string()));
                // END NOT TESTED
            }
            let script = Script::from(script_bytes.to_vec());
            if out.script_pubkey != script.to_v0_p2wsh() {
                return Err(TransactionFormat(
                    "script pubkey doesn't match inner script".to_string(), // NOT TESTED
                ));
            }
            let res = self.handle_to_local_script(out, &script);
            if res.is_ok() {
                return Ok(());
            }
            let res = self.handle_received_htlc_script(out, &script);
            if res.is_ok() {
                return Ok(());
            }
            let res = self.handle_offered_htlc_script(out, &script);
            if res.is_ok() {
                return Ok(());
            }
            return Err(TransactionFormat("unknown p2wsh format".to_string())); // NOT TESTED
        } else {
            return Err(TransactionFormat("unknown output type".to_string())); // NOT TESTED
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Builder;
    use secp256k1::{Secp256k1, SecretKey};

    use crate::tx::script::get_revokeable_redeemscript;

    use super::*;

    #[test]
    fn parse_test_err() {
        let mut info = CommitmentInfo::new();
        let out = TxOut {
            value: 0,
            script_pubkey: Default::default(),
        };
        let script = Builder::new().into_script();
        let err = info.handle_to_local_script(&out, &script);
        assert!(err.is_err());
    }

    #[test]
    fn parse_test() {
        let secp_ctx = Secp256k1::signing_only();
        let mut info = CommitmentInfo::new();
        let out = TxOut {
            value: 123,
            script_pubkey: Default::default(),
        };
        let revocation_key =
            PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[4u8; 32]).unwrap());
        let delayed_key =
            PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let script = get_revokeable_redeemscript(&revocation_key, 5, &delayed_key);
        let res = info.handle_to_local_script(&out, &script);
        assert!(res.is_ok());
        assert!(info.has_to_local());
        assert!(!info.has_to_remote());
        assert_eq!(info.revocation_key.unwrap(), revocation_key);
        assert_eq!(info.to_local_delayed_key.unwrap(), delayed_key);
        assert_eq!(info.to_local_delay, 5);
        assert_eq!(info.to_local_value, 123);
        let res = info.handle_to_local_script(&out, &script);
        assert!(res.is_err());
        #[rustfmt::skip]
        assert!( // NOT TESTED
            TransactionFormat("already have to local".to_string())
                == res.expect_err("expecting err")
        );
    }
}
