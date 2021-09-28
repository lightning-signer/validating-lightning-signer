#![allow(missing_docs)]

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
    pub key_version: Bip32KeyVersion,
    pub chain_params: BlockID,
    pub encryption_key: Option<Secret>,
    pub dev_privkey: Option<PrivKey>,
    pub dev_bip32_seed: Option<Secret>,
    pub dev_channel_secrets: Option<Vec<Secret>>,
    pub dev_channel_secrets_shaseed: Option<Sha256>,
}

impl TypedMessage for HsmdInit {
    const TYPE: u16 = 11;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct HsmdInitReply {
    pub node_id: PubKey,
    pub bip32: ExtKey,
    pub bolt12: PubKey32,
    // pub onion_reply_secret: Secret,
}

impl TypedMessage for HsmdInitReply {
    const TYPE: u16 = 111;
}

/// Connect a new client
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHsmFd {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub capabilities: u64,
}

impl TypedMessage for ClientHsmFd {
    const TYPE: u16 = 9;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHsmFdReply {
    // TODO fd handling
}

impl TypedMessage for ClientHsmFdReply {
    const TYPE: u16 = 109;
}

/// Sign invoice
#[derive(Debug, Serialize, Deserialize)]
pub struct SignInvoice {
    pub u5bytes: Vec<u8>,
    pub hrp: Vec<u8>,
}

impl TypedMessage for SignInvoice {
    const TYPE: u16 = 8;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignInvoiceReply {
    pub signature: RecoverableSignature,
}

impl TypedMessage for SignInvoiceReply {
    const TYPE: u16 = 108;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct Ecdh {
    pub point: PubKey,
}

impl TypedMessage for Ecdh {
    const TYPE: u16 = 1;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct EcdhReply {
    pub secret: Secret,
}

impl TypedMessage for EcdhReply {
    const TYPE: u16 = 100;
}

/// Memleak
#[derive(Debug, Serialize, Deserialize)]
pub struct Memleak {
}

impl TypedMessage for Memleak {
    const TYPE: u16 = 33;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct MemleakReply {
    pub result: bool,
}

impl TypedMessage for MemleakReply {
    const TYPE: u16 = 133;
}

/// Sign channel update
#[derive(Debug, Serialize, Deserialize)]
pub struct SignChannelUpdate {
    pub update: Vec<u8>,
}

impl TypedMessage for SignChannelUpdate {
    const TYPE: u16 = 3;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignChannelUpdateReply {
    pub update: Vec<u8>,
}

impl TypedMessage for SignChannelUpdateReply {
    const TYPE: u16 = 103;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetPerCommitmentPoint {
    pub commitment_number: u64,
}

impl TypedMessage for GetPerCommitmentPoint {
    const TYPE: u16 = 18;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetPerCommitmentPointReply {
    pub point: PubKey,
    pub secret: Option<Secret>,
}

impl TypedMessage for GetPerCommitmentPointReply {
    const TYPE: u16 = 118;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyChannel {
    pub is_outbound: bool,
    pub channel_value: u64,
    pub push_value: u64,
    pub funding_txid: TxId,
    pub funding_txout: u16,
    pub to_self_delay: u16,
    pub local_shutdown_script: Vec<u8>,
    pub local_shutdown_wallet_index: u32,
    pub remote_basepoints: Basepoints,
    pub remote_funding_pubkey: PubKey,
    pub remote_to_self_delay: u16,
    pub remote_shutdown_script: Vec<u8>,
    pub option_static_remotekey: bool,
    pub option_anchor_outputs: bool,
}

impl TypedMessage for ReadyChannel {
    const TYPE: u16 = 31;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyChannelReply {
}

impl TypedMessage for ReadyChannelReply {
    const TYPE: u16 = 131;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRemoteCommitmentTx {
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub remote_funding_key: PubKey,
    pub remote_per_commitment_point: PubKey,
    pub option_static_remotekey: bool,
    pub commitment_number: u64,
    pub htlcs: Vec<Htlc>,
    pub feerate: u32,
}

impl TypedMessage for SignRemoteCommitmentTx {
    const TYPE: u16 = 19;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignTxReply {
    pub signature: Signature,
    pub sighash: u8,
}

impl TypedMessage for SignTxReply {
    const TYPE: u16 = 112;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct NewChannel {
    pub node_id: PubKey,
    pub dbid: u64,
}

impl TypedMessage for NewChannel {
    const TYPE: u16 = 30;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct NewChannelReply {
}

impl TypedMessage for NewChannelReply {
    const TYPE: u16 = 130;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetChannelBasepoints {
    pub node_id: PubKey,
    pub dbid: u64,
}

impl TypedMessage for GetChannelBasepoints {
    const TYPE: u16 = 10;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct GetChannelBasepointsReply {
    pub basepoints: Basepoints,
    pub funding: PubKey,
}

impl TypedMessage for GetChannelBasepointsReply {
    const TYPE: u16 = 110;
}


///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRemoteHtlcTx {
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub wscript: Vec<u8>,
    pub remote_per_commitment_point: PubKey,
    pub option_anchor_outputs: bool,
}

impl TypedMessage for SignRemoteHtlcTx {
    const TYPE: u16 = 20;
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct SignPenaltyToUs {
    pub revocation_secret: Secret,
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub wscript: Vec<u8>,
}

impl TypedMessage for SignPenaltyToUs {
    const TYPE: u16 = 14;
}

/// An unknown message
#[derive(Debug, Serialize)]
pub struct Unknown {
    /// Message type
    pub message_type: u16,
    /// Unparsed data
    pub data: Vec<u8>,
}

/// An enum representing all messages we can read and write
#[derive(Debug, Serialize)]
pub enum Message {
    HsmdInit(HsmdInit),
    HsmdInitReply(HsmdInitReply),
    ClientHsmFd(ClientHsmFd),
    ClientHsmFdReply(ClientHsmFdReply),
    SignInvoice(SignInvoice),
    SignInvoiceReply(SignInvoiceReply),
    Ecdh(Ecdh),
    EcdhReply(EcdhReply),
    Memleak(Memleak),
    MemleakReply(MemleakReply),
    SignChannelUpdate(SignChannelUpdate),
    SignChannelUpdateReply(SignChannelUpdateReply),
    GetPerCommitmentPoint(GetPerCommitmentPoint),
    GetPerCommitmentPointReply(GetPerCommitmentPointReply),
    ReadyChannel(ReadyChannel),
    ReadyChannelReply(ReadyChannelReply),
    SignRemoteCommitmentTx(SignRemoteCommitmentTx),
    SignTxReply(SignTxReply),
    GetChannelBasepoints(GetChannelBasepoints),
    GetChannelBasepointsReply(GetChannelBasepointsReply),
    NewChannel(NewChannel),
    NewChannelReply(NewChannelReply),
    SignRemoteHtlcTx(SignRemoteHtlcTx),
    SignPenaltyToUs(SignPenaltyToUs),
    Unknown(Unknown),
}

fn from_vec_no_trailing<T: TypedMessage>(s: &mut Vec<u8>) -> Result<T>
    where T: de::DeserializeOwned,
{
    let res: T = from_vec(s)?;
    if !s.is_empty() {
        return Err(Error::TrailingBytes(T::TYPE));
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

    read_message(&mut data, message_type)
}

fn read_message(mut data: &mut Vec<u8>, message_type: u16) -> Result<Message> {
    let message = match message_type {
        HsmdInit::TYPE => Message::HsmdInit(from_vec_no_trailing(&mut data)?),
        HsmdInitReply::TYPE => Message::HsmdInitReply(from_vec_no_trailing(&mut data)?),
        ClientHsmFd::TYPE => Message::ClientHsmFd(from_vec_no_trailing(&mut data)?),
        ClientHsmFdReply::TYPE => Message::ClientHsmFdReply(from_vec_no_trailing(&mut data)?),
        SignInvoice::TYPE => Message::SignInvoice(from_vec_no_trailing(&mut data)?),
        SignInvoiceReply::TYPE => Message::SignInvoiceReply(from_vec_no_trailing(&mut data)?),
        Ecdh::TYPE => Message::Ecdh(from_vec_no_trailing(&mut data)?),
        EcdhReply::TYPE => Message::EcdhReply(from_vec_no_trailing(&mut data)?),
        Memleak::TYPE => Message::Memleak(from_vec_no_trailing(&mut data)?),
        MemleakReply::TYPE => Message::MemleakReply(from_vec_no_trailing(&mut data)?),
        SignChannelUpdate::TYPE => Message::SignChannelUpdate(from_vec_no_trailing(&mut data)?),
        SignChannelUpdateReply::TYPE => Message::SignChannelUpdateReply(from_vec_no_trailing(&mut data)?),
        GetPerCommitmentPoint::TYPE => Message::GetPerCommitmentPoint(from_vec_no_trailing(&mut data)?),
        GetPerCommitmentPointReply::TYPE => Message::GetPerCommitmentPointReply(from_vec_no_trailing(&mut data)?),
        ReadyChannel::TYPE => Message::ReadyChannel(from_vec_no_trailing(&mut data)?),
        ReadyChannelReply::TYPE => Message::ReadyChannelReply(from_vec_no_trailing(&mut data)?),
        SignRemoteCommitmentTx::TYPE => Message::SignRemoteCommitmentTx(from_vec_no_trailing(&mut data)?),
        SignTxReply::TYPE => Message::SignTxReply(from_vec_no_trailing(&mut data)?),
        GetChannelBasepoints::TYPE => Message::GetChannelBasepoints(from_vec_no_trailing(&mut data)?),
        GetChannelBasepointsReply::TYPE => Message::GetChannelBasepointsReply(from_vec_no_trailing(&mut data)?),
        NewChannel::TYPE => Message::NewChannel(from_vec_no_trailing(&mut data)?),
        NewChannelReply::TYPE => Message::NewChannelReply(from_vec_no_trailing(&mut data)?),
        SignRemoteHtlcTx::TYPE => Message::SignRemoteHtlcTx(from_vec_no_trailing(&mut data)?),
        SignPenaltyToUs::TYPE => Message::SignPenaltyToUs(from_vec_no_trailing(&mut data)?),
        _ => {
            Message::Unknown(Unknown { message_type, data: data.clone() })
        }
    };
    Ok(message)
}

#[cfg(test)]
fn read_message_and_data<R: Read>(reader: &mut R) -> Result<(Message, Vec<u8>)> {
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
    let saved_data = data.clone();

    read_message(&mut data, message_type).map(|m| (m, saved_data))
}

pub fn write<W: Write, T: ser::Serialize + TypedMessage>(writer: &mut W, value: T) -> Result<()> {
    let buf = to_vec(&value)?;
    let len: u32 = buf.len() as u32 + 2;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&T::TYPE.to_be_bytes())?;
    writer.write_all(&buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use regex::Regex;

    use crate::msgs::Message;

    use super::*;

    #[test]
    fn parse_read_fixtures_test() {
        assert_eq!(parse_fixture("r_3"), 16);
        assert_eq!(parse_fixture("r_5"), 1);
        assert_eq!(parse_fixture("r_6"), 39);
    }

    #[test]
    fn parse_write_fixtures_test() {
        // TODO negative message type IDs?
        // assert_eq!(parse_fixture("w_0"), 16);
        assert_eq!(parse_fixture("w_3"), 16);
        assert_eq!(parse_fixture("w_4"), 1);
        assert_eq!(parse_fixture("w_5"), 1);
        assert_eq!(parse_fixture("w_6"), 52);
    }

    fn parse_fixture(fixture: &str) -> u32 {
        println!("processing {}", fixture);
        let contents_with_whitespace = fs::read_to_string(format!("fixtures/{}.hex", fixture)).unwrap();
        let contents_hex = Regex::new(r"\s").unwrap().replace_all(&contents_with_whitespace, "");
        let mut contents = hex::decode(&*contents_hex).unwrap();
        let mut num_read = 0;
        loop {
            let res = read_message_and_data(&mut contents);
            match res {
                Ok((Message::Unknown(u), _)) => {
                    panic!("unknown {} {}", u.message_type, u.data.len());
                }
                Ok((msg, data)) => {
                    println!("read {:x?}", msg);
                    let encoded = to_vec(&msg).expect("encoding");
                    assert_eq!(encoded, data);
                }
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
