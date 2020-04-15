use std::i16;

use bitcoin::{blockdata, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::script::read_scriptint;
use bitcoin::blockdata::script::Instruction::PushBytes;
use bitcoin::blockdata::script::{Builder, Instructions};
use bitcoin::blockdata::script::Instruction::PushBytes;
use secp256k1::PublicKey;

use crate::tx::script::ValidationError::{Mismatch, Policy, ScriptFormat, TransactionFormat};

#[derive(Debug, PartialEq, Debug)]
pub enum ValidationError {
    TransactionFormat(String),
    Mismatch(String),     // NOT TESTED
    ScriptFormat(String), // NOT TESTED
    Policy(String),
}

// BEGIN NOT TESTED
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
// END NOT TESTED

// BEGIN NOT TESTED
impl Into<String> for ValidationError {
    fn into(self) -> String {
        match self {
            TransactionFormat(s) => "transaction format ".to_string() + &s,
            ScriptFormat(s) => "script format ".to_string() + &s,
            Mismatch(s) => "script template mismatch ".to_string() + &s,
            Policy(s) => "policy failure ".to_string() + &s,
        }
    }
}
// END NOT TESTED

#[inline]
pub fn expect_op(iter: &mut Instructions, op: opcodes::All) -> Result<(), ValidationError> {
    let ins = iter.next();
    match ins {
        Some(blockdata::script::Instruction::Op(o)) => {
            if o == op {
                Ok(())
            } else {
                Err(Mismatch(format!("expected op {}, saw {}", op, o)))
            }
        }
        _ => Err(Mismatch(format!("expected op, saw {:?}", ins))),
    }
}

#[inline]
pub fn expect_number(iter: &mut Instructions) -> Result<i64, ValidationError> {
    let ins = iter.next();
    match ins {
        Some(blockdata::script::Instruction::Op(op)) => {
            let cls = op.classify();
            match cls {
                Class::PushNum(i) => Ok(i as i64),
                _ => Err(Mismatch(format!("expected PushNum, saw {:?}", cls))), // NOT TESTED
            }
        }
        Some(PushBytes(d)) => {
            read_scriptint(&d).map_err(|err| Mismatch(format!("read_scriptint failed: {:?}", err)))
        }
        _ => Err(Mismatch(format!("expected number, saw {:?}", ins))), // NOT TESTED
    }
}

#[inline]
pub fn expect_script_end(iter: &mut Instructions) -> Result<(), ValidationError> {
    let ins = iter.next();
    if ins == None {
        Ok(())
    } else {
        Err(Mismatch(format!("expected script end, saw {:?}", ins))) // NOT TESTED
    }
}

#[inline]
pub fn expect_data(iter: &mut Instructions) -> Result<Vec<u8>, ValidationError> {
    let ins = iter.next();
    match ins {
        Some(PushBytes(d)) => Ok(d.to_vec()),
        _ => return Err(Mismatch(format!("expected data, saw {:?}", ins))), // NOT TESTED
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
#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Builder;
    use std::{i16, i32, i8, u16, u8};

    use super::*;

    #[test]
    #[rustfmt::skip]
    fn expect_int_test() {
        let script = Builder::new()
            .push_int(i32::MIN as i64 + 1)	// OP_PUSHBYTES_4 ffffffff
            .push_int(i16::MIN as i64)		// OP_PUSHBYTES_3 008080
            .push_int(i16::MIN as i64 + 1)	// OP_PUSHBYTES_2 ffff
            .push_int(i8::MIN as i64)		// OP_PUSHBYTES_2 8080
            .push_int(i8::MIN as i64 + 1)	// OP_PUSHBYTES_1 ff
            .push_int(-1)					// OP_PUSHNUM_NEG1
            .push_int(0)					// OP_0
            .push_int(i8::MAX as i64)		// OP_PUSHBYTES_1 7f
            .push_int(i8::MAX as i64 + 1)	// OP_PUSHBYTES_2 8000
            .push_int(u8::MAX as i64)		// OP_PUSHBYTES_2 ff00
            .push_int(u8::MAX as i64 + 1)	// OP_PUSHBYTES_2 0001
            .push_int(i16::MAX as i64)		// OP_PUSHBYTES_2 ff7f
            .push_int(i16::MAX as i64 + 1)	// OP_PUSHBYTES_3 008000
            .push_int(u16::MAX as i64)		// OP_PUSHBYTES_3 ffff00
            .push_int(u16::MAX as i64 + 1)	// OP_PUSHBYTES_3 000001
            .push_int(i32::MAX as i64)		// OP_PUSHBYTES_4 ffffff7f
            .into_script();
        println!("{:?}", script);
        let iter = &mut script.iter(true);
        assert_eq!(expect_number(iter).unwrap(), i32::MIN as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), i16::MIN as i64);
        assert_eq!(expect_number(iter).unwrap(), i16::MIN as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), i8::MIN as i64);
        assert_eq!(expect_number(iter).unwrap(), i8::MIN as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), -1);
        assert_eq!(expect_number(iter).unwrap(), 0);
        assert_eq!(expect_number(iter).unwrap(), i8::MAX as i64);
        assert_eq!(expect_number(iter).unwrap(), i8::MAX as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), u8::MAX as i64);
        assert_eq!(expect_number(iter).unwrap(), u8::MAX as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), i16::MAX as i64);
        assert_eq!(expect_number(iter).unwrap(), i16::MAX as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), u16::MAX as i64);
        assert_eq!(expect_number(iter).unwrap(), u16::MAX as i64 + 1);
        assert_eq!(expect_number(iter).unwrap(), i32::MAX as i64);
    }
}
