use std::i16;

use bitcoin::{blockdata, Script, TxOut};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP, OP_DUP, OP_ELSE,
                                       OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_NOTIF, OP_PUSHNUM_2,
                                       OP_SIZE, OP_SWAP};
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::script::Instruction::PushBytes;
use bitcoin::blockdata::script::Instructions;
use bitcoin::util::address::Payload;
use secp256k1::PublicKey;

use crate::server::script::ValidationError::{Mismatch, ScriptFormat, TransactionFormat};

const MAX_DELAY: i16 = 1000;

#[derive(PartialEq)]
pub enum ValidationError {
    TransactionFormat(String),
    ScriptFormat(String),
    Mismatch(),
}

impl Into<String> for ValidationError {
    fn into(self) -> String {
        match self {
            TransactionFormat(s) => "transaction format ".to_string() + &s,
            ScriptFormat(s) => "script format ".to_string() + &s,
            Mismatch() => "script template mismatch".to_string(),
        }
    }
}

#[inline]
fn expect_op(iter: &mut Instructions, op: opcodes::All) -> Result<(), ValidationError> {
    match iter.next() {
        Some(blockdata::script::Instruction::Op(o)) =>
            if o == op { Ok(()) } else { Err(Mismatch()) },
        _ => Err(Mismatch())
    }
}

#[inline]
fn expect_number(iter: &mut Instructions) -> Result<i16, ValidationError> {
    match iter.next() {
        Some(blockdata::script::Instruction::Op(op)) => {
            match op.classify() {
                Class::PushNum(i) => {
                    if i < i16::MIN as i32 || i > i16::MAX as i32 { Err(Mismatch()) }
                    else { Ok(i as i16) }
                },
                _ => Err(Mismatch())
            }
        },
        Some(PushBytes(d)) => {
            if d.len() == 0 {
                Ok(0)
            } else if d.len() == 1 {
                Ok(d[0] as i16)
            } else if d.len() == 2 {
                Ok(((d[1] as i16) << 8) | (d[0] as i16))
            } else {
                Err(Mismatch())
            }
        },
        _ => Err(Mismatch())
    }
}

#[inline]
fn expect_script_end(iter: &mut Instructions) -> Result<(), ValidationError> {
    if iter.next() == None {
        Ok(())
    } else {
        Err(Mismatch())
    }
}

#[inline]
fn expect_data(iter: &mut Instructions) -> Result<Vec<u8>, ValidationError> {
    match iter.next() {
        Some(PushBytes(d)) => Ok(d.to_vec()),
        _ => return Err(Mismatch())
    }
}

#[allow(dead_code)]
pub struct CommitmentInfo {
    to_remote_address: Option<Payload>,
    to_remote_value: u64,
    revocation_key: Option<PublicKey>,
    to_local_delayed_key: Option<PublicKey>,
    to_local_value: u64,
    to_local_delay: u16,
    // TODO fine-grained HTLC info
    offered_htlcs: Vec<TxOut>,
    received_htlcs: Vec<TxOut>,
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

    fn handle_to_local_script(&mut self, _out: &TxOut, script: &Script) -> Result<(), ValidationError> {
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

        if self.has_to_local() { return Err(TransactionFormat("already have to local".to_string())) }
        if delay < 0 { return Err(ScriptFormat("negative delay".to_string())) }
        if delay > MAX_DELAY { return Err(ScriptFormat("delay too large".to_string())) }

        // This is safe because we checked for negative
        self.to_local_delay = delay as u16;
        self.to_local_delayed_key = Some(PublicKey::from_slice(to_local_delayed_key.as_slice())
            .map_err(|_| Mismatch())?);
        self.revocation_key = Some(PublicKey::from_slice(revocation_key.as_slice())
            .map_err(|_| Mismatch())?);

        Ok(())
    }

    fn handle_received_htlc_script(&mut self, out: &TxOut, script: &Script) -> Result<(), ValidationError> {
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
        if thirty_two != 32 { return Err(Mismatch()) }
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

    fn handle_offered_htlc_script(&mut self, out: &TxOut, script: &Script) -> Result<(), ValidationError> {
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
        if thirty_two != 32 { return Err(Mismatch()) }
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

    pub fn handle_output(&mut self, out: &TxOut, script_bytes: &[u8]) -> Result<(), ValidationError> {
        if out.script_pubkey.is_v0_p2wpkh() {
            if self.has_to_remote() {
                return Err(TransactionFormat("more than one to remote".to_string()))
            }
            self.to_remote_address = Payload::from_script(&out.script_pubkey);
            self.to_remote_value = out.value;
        } else if out.script_pubkey.is_v0_p2wsh() {
            if script_bytes.is_empty() {
                return Err(TransactionFormat("missing witscript for p2wsh".to_string()))
            }
            let script = Script::from(script_bytes.to_vec());
            if out.script_pubkey != script.to_v0_p2wsh() {
                return Err(TransactionFormat("script pubkey doesn't match inner script".to_string()))
            }
            let res = self.handle_to_local_script(out, &script);
            if res.is_ok() {
                return Ok(())
            }
            let res = self.handle_received_htlc_script(out, &script);
            if res.is_ok() {
                return Ok(())
            }
            let res = self.handle_offered_htlc_script(out, &script);
            if res.is_ok() {
                return Ok(())
            }
            return Err(TransactionFormat("unknown format p2wsh".to_string()))
        } else {
            return Err(TransactionFormat("unknown output type".to_string()))
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Builder;
    use secp256k1::{Secp256k1, SecretKey};

    use super::*;

    #[test]
    fn parse_test_err() {
        let mut info = CommitmentInfo::new();
        let out = TxOut { value: 0, script_pubkey: Default::default() };
        let script = Builder::new()
            .into_script();
        let err = info.handle_to_local_script(&out, &script);
        assert!(err.is_err());
    }

    #[test]
    fn parse_test() {
        let secp_ctx = Secp256k1::signing_only();
        let mut info = CommitmentInfo::new();
        let out = TxOut { value: 0, script_pubkey: Default::default() };
        let revocation_key = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[4u8; 32]).unwrap());
        let delayed_key = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[3u8; 32]).unwrap());
        let script = build_to_local_script(&revocation_key, &delayed_key, 5);
        let res = info.handle_to_local_script(&out, &script);
        assert!(res.is_ok());
        assert!(info.has_to_local());
        assert!(!info.has_to_remote());
        assert_eq!(info.revocation_key.unwrap(), revocation_key);
        assert_eq!(info.to_local_delayed_key.unwrap(), delayed_key);
        assert_eq!(info.to_local_delay, 5);
        let res = info.handle_to_local_script(&out, &script);
        assert!(res.is_err());
        assert!(TransactionFormat("already have to local".to_string()) == res.expect_err("expecting err"));
    }

    fn build_to_local_script(revocation_key: &PublicKey, delayed_key: &PublicKey, delay: i64) -> Script {
        let script = Builder::new()
            .push_opcode(OP_IF)
            .push_slice(&revocation_key.serialize())
            .push_opcode(OP_ELSE)
            .push_int(delay)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_slice(&delayed_key.serialize())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        script
    }
}
