use serde::{de, ser};
use serde_bolt::{from_vec, to_vec};
use serde_bolt::{Read, Write, LargeBytes};
use serde_derive::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::io::{read_u16, read_u32};
use crate::model::*;

pub trait TypedMessage {
    const TYPE: u16;
}

/// hsmd Init
#[derive(Debug, Serialize, Deserialize)]
pub struct HsmdInit {
    key_version: Bip32KeyVersion,
    chain_params: BlockID,
    encryption_key: Option<Secret>,
    dev_privkey: Option<PrivKey>,
    dev_bip32_seed: Option<Secret>,
    dev_channel_secrets: Option<Vec<Secret>>,
    dev_channel_secrets_shaseed: Option<Sha256>,
}

impl TypedMessage for HsmdInit {
    const TYPE: u16 = 11;
}

/// Connect a new client
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHsmFd {
    id: PubKey,
    dbid: u64,
    capabilities: u64,
}

impl TypedMessage for ClientHsmFd {
    const TYPE: u16 = 9;
}

/// Sign invoice
#[derive(Debug, Serialize, Deserialize)]
pub struct SignInvoice {
    u5bytes: Vec<u8>,
    hrp: Vec<u8>,
}

impl TypedMessage for SignInvoice {
    const TYPE: u16 = 8;
}

/// Sign invoice
#[derive(Debug, Serialize, Deserialize)]
pub struct Ecdh {
    point: PubKey,
}

impl TypedMessage for Ecdh {
    const TYPE: u16 = 1;
}

/// Memleak
#[derive(Debug, Serialize, Deserialize)]
pub struct Memleak {
}

impl TypedMessage for Memleak {
    const TYPE: u16 = 33;
}

/// Sign channel update
#[derive(Debug, Serialize, Deserialize)]
pub struct SignChannelUpdate {
    update: Vec<u8>,
}

impl TypedMessage for SignChannelUpdate {
    const TYPE: u16 = 3;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetPerCommitmentPoint {
    n: u64,
}

impl TypedMessage for GetPerCommitmentPoint {
    const TYPE: u16 = 18;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRemoteCommitmentTx {
    tx: LargeBytes,
    psbt: LargeBytes,
    remote_funding_key: PubKey,
    remote_per_commitment_point: PubKey,
    option_static_remotekey: bool,
}

impl TypedMessage for SignRemoteCommitmentTx {
    const TYPE: u16 = 19;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetChannelBasepoints {
    node_id: PubKey,
    dbid: u64,
}

impl TypedMessage for GetChannelBasepoints {
    const TYPE: u16 = 10;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRemoteHtlcTx {
    tx: LargeBytes,
    psbt: LargeBytes,
    wscript: Vec<u8>,
    remote_per_commitment_point: PubKey,
    option_anchor_outputs: bool,
}

impl TypedMessage for SignRemoteHtlcTx {
    const TYPE: u16 = 20;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignPenaltyToUs {
    revocation_secret: Secret,
    tx: LargeBytes,
    psbt: LargeBytes,
    wscript: Vec<u8>,
}

impl TypedMessage for SignPenaltyToUs {
    const TYPE: u16 = 14;
}

/// An unknown message
#[derive(Debug)]
pub struct Unknown {
    /// Message type
    pub message_type: u16,
    /// Unparsed data
    pub data: Vec<u8>,
}

/// An enum representing all messages we can read and write
#[derive(Debug)]
pub enum Message {
    HsmdInit(HsmdInit),
    ClientHsmFd(ClientHsmFd),
    SignInvoice(SignInvoice),
    Ecdh(Ecdh),
    Memleak(Memleak),
    SignChannelUpdate(SignChannelUpdate),
    GetPerCommitmentPoint(GetPerCommitmentPoint),
    SignRemoteCommitmentTx(SignRemoteCommitmentTx),
    GetChannelBasepoints(GetChannelBasepoints),
    SignRemoteHtlcTx(SignRemoteHtlcTx),
    SignPenaltyToUs(SignPenaltyToUs),
    Unknown(Unknown),
}

fn from_vec_no_trailing<T>(s: &mut Vec<u8>) -> Result<T>
    where T: de::DeserializeOwned,
{
    let res: T = from_vec(s)?;
    if !s.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(res)
}

/// Read a BOLT message:
///
/// - u32 packet length
/// - u16 packet type
/// - data
pub fn read<R: Read>(reader: &mut R) -> Result<Message> {
    let len = read_u32(reader)?;
    let mut data = Vec::new();
    if len < 2 {
        return Err(Error::ShortRead)
    }
    let message_type = read_u16(reader)?;
    data.resize(len as usize - 2, 0);
    let len = reader.read(&mut data)?;
    if len < data.len() {
        return Err(Error::ShortRead);
    }

    match message_type {
        HsmdInit::TYPE => Ok(Message::HsmdInit(from_vec_no_trailing(&mut data)?)),
        ClientHsmFd::TYPE => Ok(Message::ClientHsmFd(from_vec_no_trailing(&mut data)?)),
        SignInvoice::TYPE => Ok(Message::SignInvoice(from_vec_no_trailing(&mut data)?)),
        Ecdh::TYPE => Ok(Message::Ecdh(from_vec_no_trailing(&mut data)?)),
        Memleak::TYPE => Ok(Message::Memleak(from_vec_no_trailing(&mut data)?)),
        SignChannelUpdate::TYPE => Ok(Message::SignChannelUpdate(from_vec_no_trailing(&mut data)?)),
        GetPerCommitmentPoint::TYPE => Ok(Message::GetPerCommitmentPoint(from_vec_no_trailing(&mut data)?)),
        SignRemoteCommitmentTx::TYPE => Ok(Message::SignRemoteCommitmentTx(from_vec_no_trailing(&mut data)?)),
        GetChannelBasepoints::TYPE => Ok(Message::GetChannelBasepoints(from_vec_no_trailing(&mut data)?)),
        SignRemoteHtlcTx::TYPE => Ok(Message::SignRemoteHtlcTx(from_vec_no_trailing(&mut data)?)),
        SignPenaltyToUs::TYPE => Ok(Message::SignPenaltyToUs(from_vec_no_trailing(&mut data)?)),
        _ => {
            Ok(Message::Unknown(Unknown { message_type, data }))
        }
    }
}

pub fn write<W: Write, T: ser::Serialize + TypedMessage>(writer: &mut W, value: T) -> Result<()> {
    let buf = to_vec(&value)?;
    let len = buf.len() + 2;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&T::TYPE.to_be_bytes())?;
    // FIXME write type
    writer.write_all(&buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use regex::Regex;

    use crate::msgs::{Message, read};

    use super::*;

    #[test]
    fn parse_fixtures_test() {
        assert_eq!(parse_fixture("r_3"), 16);
        assert_eq!(parse_fixture("r_5"), 1);
        assert_eq!(parse_fixture("r_6"), 39);
    }

    fn parse_fixture(fixture: &str) -> u32 {
        println!("processing {}", fixture);
        let contents_with_whitespace = fs::read_to_string(format!("fixtures/{}.hex", fixture)).unwrap();
        let contents_hex = Regex::new(r"\s").unwrap().replace_all(&contents_with_whitespace, "");
        let mut contents = hex::decode(&*contents_hex).unwrap();
        let mut num_read = 0;
        loop {
            let res = read(&mut contents);
            match res {
                Ok(Message::Unknown(u)) => {
                    println!("unknown {} {}", u.message_type, u.data.len());
                }
                Ok(msg) => { println!("read {:x?}", msg) }
                Err(Error::Eof) => {
                    println!("done");
                    break;
                }
                Err(e) => {
                    panic!("unexpected error {:?}", e);
                }
            }
            num_read += 1;
        }
        num_read
    }
}
