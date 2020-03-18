use std::i16;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::script::Instruction::PushBytes;
use bitcoin::blockdata::script::{Builder, Instructions};
use bitcoin::{blockdata, Script};
use secp256k1::PublicKey;

use crate::tx::script::ValidationError::{Mismatch, ScriptFormat, TransactionFormat};

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
pub fn expect_op(iter: &mut Instructions, op: opcodes::All) -> Result<(), ValidationError> {
    match iter.next() {
        Some(blockdata::script::Instruction::Op(o)) => {
            if o == op {
                Ok(())
            } else {
                Err(Mismatch())
            }
        }
        _ => Err(Mismatch()),
    }
}

#[inline]
pub fn expect_number(iter: &mut Instructions) -> Result<i16, ValidationError> {
    match iter.next() {
        Some(blockdata::script::Instruction::Op(op)) => match op.classify() {
            Class::PushNum(i) => {
                if i < i16::MIN as i32 || i > i16::MAX as i32 {
                    Err(Mismatch())
                } else {
                    Ok(i as i16)
                }
            }
            _ => Err(Mismatch()),
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
        }
        _ => Err(Mismatch()),
    }
}

#[inline]
pub fn expect_script_end(iter: &mut Instructions) -> Result<(), ValidationError> {
    if iter.next() == None {
        Ok(())
    } else {
        Err(Mismatch())
    }
}

#[inline]
pub fn expect_data(iter: &mut Instructions) -> Result<Vec<u8>, ValidationError> {
    match iter.next() {
        Some(PushBytes(d)) => Ok(d.to_vec()),
        _ => return Err(Mismatch()),
    }
}

// FIXME - This is copied from chan_utils.
pub fn get_revokeable_redeemscript(
    revocation_key: &PublicKey,
    to_self_delay: u16,
    delayed_payment_key: &PublicKey,
) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(&revocation_key.serialize())
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(to_self_delay as i64)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(&delayed_payment_key.serialize())
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}
