use serde_bolt::Read;

use crate::error::{Error, Result};

pub(crate) fn read_u64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    let len = reader.read(&mut buf)?;
    if len == 0 {
        return Err(Error::Eof);
    }
    if len < buf.len() {
        return Err(Error::ShortRead);
    }
    Ok(u64::from_be_bytes(buf))
}

pub(crate) fn read_u32<R: Read>(reader: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    let len = reader.read(&mut buf)?;
    if len == 0 {
        return Err(Error::Eof);
    }
    if len < buf.len() {
        return Err(Error::ShortRead);
    }
    Ok(u32::from_be_bytes(buf))
}

pub(crate) fn read_u16<R: Read>(reader: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    let len = reader.read(&mut buf)?;
    if len == 0 {
        return Err(Error::Eof);
    }
    if len < buf.len() {
        return Err(Error::ShortRead);
    }
    Ok(u16::from_be_bytes(buf))
}
