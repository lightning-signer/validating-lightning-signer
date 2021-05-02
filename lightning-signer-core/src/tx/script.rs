use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::script::{read_scriptint, Builder, Instruction, Instructions};
use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{blockdata, Script};
use lightning::ln::chan_utils::{HTLCOutputInCommitment, TxCreationKeys};

use crate::policy::error::ValidationError;
use crate::policy::error::ValidationError::Mismatch;
use bitcoin::hashes::Hash;

#[inline]
fn expect_next<'a>(iter: &'a mut Instructions) -> Result<Instruction<'a>, ValidationError> {
    iter.next()
        .ok_or(Mismatch("unexpected end".to_string()))?
        .map_err(|_| Mismatch("unparseable opcode".to_string())) // NOT TESTED
}

#[inline]
pub fn expect_op(iter: &mut Instructions, op: opcodes::All) -> Result<(), ValidationError> {
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::Op(o) => {
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
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::Op(op) => {
            let cls = op.classify();
            match cls {
                Class::PushNum(i) => Ok(i as i64),
                _ => Err(Mismatch(format!("expected PushNum, saw {:?}", cls))), // NOT TESTED
            }
        }
        blockdata::script::Instruction::PushBytes(d) => {
            read_scriptint(&d).map_err(|err| Mismatch(format!("read_scriptint failed: {:?}", err)))
        }
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
    let ins = expect_next(iter)?;
    match ins {
        blockdata::script::Instruction::PushBytes(d) => Ok(d.to_vec()),
        _ => Err(Mismatch(format!("expected data, saw {:?}", ins))), // NOT TESTED
    }
}

// BEGIN NOT TESTED

/// To-counterparty redeem script when anchors are enabled - one block delay
// FIXME - This should be in chan_utils.
pub fn get_delayed_redeemscript(delayed_key: &PublicKey) -> Script {
    Builder::new()
        .push_slice(&delayed_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_opcode(opcodes::all::OP_CSV)
        .into_script()
}

/// Anchor redeem script
// FIXME - This should be in chan_utils.
pub fn get_anchor_redeemscript(funding_key: &PublicKey) -> Script {
    Builder::new()
        .push_slice(&funding_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_IFDUP)
        .push_opcode(opcodes::all::OP_NOTIF)
        .push_opcode(opcodes::all::OP_PUSHNUM_16)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script()
}

/// HTLC redeem script when anchors are enabled
// FIXME - yup, chan_utils.
#[inline]
pub fn get_htlc_anchor_redeemscript(
    htlc: &HTLCOutputInCommitment,
    keys: &TxCreationKeys,
) -> Script {
    get_htlc_anchor_redeemscript_with_explicit_keys(
        htlc,
        &keys.broadcaster_htlc_key,
        &keys.countersignatory_htlc_key,
        &keys.revocation_key,
    )
}

fn get_htlc_anchor_redeemscript_with_explicit_keys(
    htlc: &HTLCOutputInCommitment,
    a_htlc_key: &PublicKey,
    b_htlc_key: &PublicKey,
    revocation_key: &PublicKey,
) -> Script {
    let payment_hash160 = Ripemd160::hash(&htlc.payment_hash.0[..]).into_inner();
    if htlc.offered {
        Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&PubkeyHash::hash(&revocation_key.serialize())[..])
            .push_opcode(opcodes::all::OP_EQUAL)
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_slice(&b_htlc_key.serialize()[..])
            .push_opcode(opcodes::all::OP_SWAP)
            .push_opcode(opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(opcodes::all::OP_EQUAL)
            .push_opcode(opcodes::all::OP_NOTIF)
            .push_opcode(opcodes::all::OP_DROP)
            .push_int(2)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_slice(&a_htlc_key.serialize()[..])
            .push_int(2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&payment_hash160)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script()
    } else {
        Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&PubkeyHash::hash(&revocation_key.serialize())[..])
            .push_opcode(opcodes::all::OP_EQUAL)
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_slice(&b_htlc_key.serialize()[..])
            .push_opcode(opcodes::all::OP_SWAP)
            .push_opcode(opcodes::all::OP_SIZE)
            .push_int(32)
            .push_opcode(opcodes::all::OP_EQUAL)
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&payment_hash160)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(opcodes::all::OP_SWAP)
            .push_slice(&a_htlc_key.serialize()[..])
            .push_int(2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_opcode(opcodes::all::OP_DROP)
            .push_int(htlc.cltv_expiry as i64)
            .push_opcode(opcodes::all::OP_CLTV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script()
    }
}

// END NOT TESTED

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
