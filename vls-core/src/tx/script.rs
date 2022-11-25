use crate::prelude::*;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::opcodes::ClassifyContext::Legacy;
use bitcoin::blockdata::script::{read_scriptint, Builder, Instruction, Instructions};
use bitcoin::hash_types::WPubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{blockdata, Script};

use crate::policy::error::{mismatch_error, ValidationError};

#[inline]
fn expect_next<'a>(iter: &'a mut Instructions) -> Result<Instruction<'a>, ValidationError> {
    iter.next()
        .ok_or(mismatch_error("unexpected end".to_string()))?
        .map_err(|_| mismatch_error("unparseable opcode".to_string()))
}

#[inline]
pub(crate) fn expect_op(iter: &mut Instructions, op: opcodes::All) -> Result<(), ValidationError> {
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::Op(o) =>
            if o == op {
                Ok(())
            } else {
                Err(mismatch_error(format!("expected op {}, saw {}", op, o)))
            },
        _ => Err(mismatch_error(format!("expected op, saw {:?}", ins))),
    }
}

#[inline]
pub(crate) fn expect_number(iter: &mut Instructions) -> Result<i64, ValidationError> {
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::Op(op) => {
            let cls = op.classify(Legacy);
            match cls {
                Class::PushNum(i) => Ok(i as i64),
                _ => Err(mismatch_error(format!("expected PushNum, saw {:?}", cls))),
            }
        }
        blockdata::script::Instruction::PushBytes(d) => read_scriptint(&d)
            .map_err(|err| mismatch_error(format!("read_scriptint failed: {:?}", err))),
    }
}

#[inline]
pub(crate) fn expect_script_end(iter: &mut Instructions) -> Result<(), ValidationError> {
    let ins = iter.next();
    if ins == None {
        Ok(())
    } else {
        Err(mismatch_error(format!("expected script end, saw {:?}", ins)))
    }
}

#[inline]
pub(crate) fn expect_data(iter: &mut Instructions) -> Result<Vec<u8>, ValidationError> {
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::PushBytes(d) => Ok(d.to_vec()),
        _ => Err(mismatch_error(format!("expected data, saw {:?}", ins))),
    }
}

/// The BOLT specified anchor output size.
// TODO - Should use the one in ln::channel, but is private
pub const ANCHOR_OUTPUT_VALUE_SATOSHI: u64 = 330;

/// Gets the redeemscript for the to_remote output when anchors are enabled.
// TODO - Should use the one in chan_utils, need relaxed visibility
#[inline]
pub fn get_to_countersignatory_with_anchors_redeemscript(payment_point: &PublicKey) -> Script {
    Builder::new()
        .push_slice(&payment_point.serialize()[..])
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_int(1)
        .push_opcode(opcodes::all::OP_CSV)
        .into_script()
}

/// Get the p2wpkh redeemscript
// TODO - Should use the one in chan_utils, need relaxed visibility
pub fn get_p2wpkh_redeemscript(key: &PublicKey) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_PUSHBYTES_0)
        .push_slice(&WPubkeyHash::hash(&key.serialize())[..])
        .into_script()
}

/// To-counterparty redeem script when anchors are enabled - one block delay
// TODO - This should be in chan_utils.
pub(crate) fn get_delayed_redeemscript(delayed_key: &PublicKey) -> Script {
    Builder::new()
        .push_slice(&delayed_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_opcode(opcodes::all::OP_CSV)
        .into_script()
}

#[cfg(test)]
mod tests {
    use core::{i16, i32, i8, u16, u8};

    use bitcoin::blockdata::script::Builder;

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
        let iter = &mut script.instructions();
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
