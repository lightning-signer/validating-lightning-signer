#![allow(missing_docs)]

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::io::{read_u16, read_u32};
use crate::model::*;
use bolt_derive::SerBolt;
use serde::{de, ser};
use serde_bolt::{from_vec as sb_from_vec, to_vec, WireString};
use serde_bolt::{LargeBytes, Read, Write};
use serde_derive::{Deserialize, Serialize};

pub trait TypedMessage {
    const TYPE: u16;
}

/// Serialize a message with a type prefix, in BOLT style
pub trait SerBolt {
    fn as_vec(&self) -> Vec<u8>;
}

pub trait DeBolt: Sized {
    fn from_vec(ser: Vec<u8>) -> Result<Self>;
}

/// hsmd Init
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct HsmdInit {
    pub key_version: Bip32KeyVersion,
    pub chain_params: BlockId,
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
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct HsmdInitReply {
    pub node_id: PubKey,
    pub bip32: ExtKey,
    pub bolt12: PubKey32,
    pub onion_reply_secret: Secret,
}

impl TypedMessage for HsmdInitReply {
    const TYPE: u16 = 111;
}

/// Connect a new client
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ClientHsmFd {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub capabilities: u64,
}

impl TypedMessage for ClientHsmFd {
    const TYPE: u16 = 9;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ClientHsmFdReply {
    // TODO fd handling
}

impl TypedMessage for ClientHsmFdReply {
    const TYPE: u16 = 109;
}

/// Sign invoice
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignInvoice {
    pub u5bytes: Vec<u8>,
    pub hrp: Vec<u8>,
}

impl TypedMessage for SignInvoice {
    const TYPE: u16 = 8;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignInvoiceReply {
    pub signature: RecoverableSignature,
}

impl TypedMessage for SignInvoiceReply {
    const TYPE: u16 = 108;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignWithdrawal {
    pub utxos: Vec<Utxo>,
    pub psbt: LargeBytes,
}

impl TypedMessage for SignWithdrawal {
    const TYPE: u16 = 7;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignWithdrawalReply {
    pub psbt: LargeBytes,
}

impl TypedMessage for SignWithdrawalReply {
    const TYPE: u16 = 107;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct Ecdh {
    pub point: PubKey,
}

impl TypedMessage for Ecdh {
    const TYPE: u16 = 1;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct EcdhReply {
    pub secret: Secret,
}

impl TypedMessage for EcdhReply {
    const TYPE: u16 = 100;
}

/// Memleak
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct Memleak {}

impl TypedMessage for Memleak {
    const TYPE: u16 = 33;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct MemleakReply {
    pub result: bool,
}

impl TypedMessage for MemleakReply {
    const TYPE: u16 = 133;
}

/// CheckFutureSecret
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct CheckFutureSecret {
    pub commitment_number: u64,
    pub secret: Secret,
}

impl TypedMessage for CheckFutureSecret {
    const TYPE: u16 = 22;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct CheckFutureSecretReply {
    pub result: bool,
}

impl TypedMessage for CheckFutureSecretReply {
    const TYPE: u16 = 122;
}

/// SignMessage
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub message: Vec<u8>,
}

impl TypedMessage for SignMessage {
    const TYPE: u16 = 23;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignMessageReply {
    pub signature: RecoverableSignature,
}

impl TypedMessage for SignMessageReply {
    const TYPE: u16 = 123;
}

/// SignBolt12
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignBolt12 {
    pub message_name: WireString,
    pub field_name: WireString,
    pub merkle_root: Sha256,
    pub public_tweak: Vec<u8>,
}

impl TypedMessage for SignBolt12 {
    const TYPE: u16 = 25;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignBolt12Reply {
    pub signature: Signature,
}

impl TypedMessage for SignBolt12Reply {
    const TYPE: u16 = 125;
}

/// Sign channel update
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignChannelUpdate {
    pub update: Vec<u8>,
}

impl TypedMessage for SignChannelUpdate {
    const TYPE: u16 = 3;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignChannelUpdateReply {
    pub update: Vec<u8>,
}

impl TypedMessage for SignChannelUpdateReply {
    const TYPE: u16 = 103;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignChannelAnnouncement {
    pub announcement: Vec<u8>,
}

impl TypedMessage for SignChannelAnnouncement {
    const TYPE: u16 = 2;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignChannelAnnouncementReply {
    pub node_signature: Signature,
    pub bitcoin_signature: Signature,
}

impl TypedMessage for SignChannelAnnouncementReply {
    const TYPE: u16 = 102;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignNodeAnnouncement {
    pub announcement: Vec<u8>,
}

impl TypedMessage for SignNodeAnnouncement {
    const TYPE: u16 = 6;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignNodeAnnouncementReply {
    pub node_signature: Signature,
}

impl TypedMessage for SignNodeAnnouncementReply {
    const TYPE: u16 = 106;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct GetPerCommitmentPoint {
    pub commitment_number: u64,
}

impl TypedMessage for GetPerCommitmentPoint {
    const TYPE: u16 = 18;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct GetPerCommitmentPointReply {
    pub point: PubKey,
    pub secret: Option<Secret>,
}

impl TypedMessage for GetPerCommitmentPointReply {
    const TYPE: u16 = 118;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ReadyChannel {
    pub is_outbound: bool,
    pub channel_value: u64,
    pub push_value: u64,
    pub funding_txid: TxId,
    pub funding_txout: u16,
    pub to_self_delay: u16,
    pub local_shutdown_script: Vec<u8>,
    pub local_shutdown_wallet_index: Option<u32>,
    pub remote_basepoints: Basepoints,
    pub remote_funding_pubkey: PubKey,
    pub remote_to_self_delay: u16,
    pub remote_shutdown_script: Vec<u8>,
    pub channel_type: Vec<u8>,
}

impl TypedMessage for ReadyChannel {
    const TYPE: u16 = 31;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ReadyChannelReply {}

impl TypedMessage for ReadyChannelReply {
    const TYPE: u16 = 131;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ValidateCommitmentTx {
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub htlcs: Vec<Htlc>,
    pub commitment_number: u64,
    pub feerate: u32,
    pub signature: BitcoinSignature,
    pub htlc_signatures: Vec<BitcoinSignature>,
}

impl TypedMessage for ValidateCommitmentTx {
    const TYPE: u16 = 35;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ValidateCommitmentTxReply {
    pub old_commitment_secret: Option<Secret>,
    pub next_per_commitment_point: PubKey,
}

impl TypedMessage for ValidateCommitmentTxReply {
    const TYPE: u16 = 135;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ValidateRevocation {
    pub commitment_number: u64,
    pub commitment_secret: Secret,
}

impl TypedMessage for ValidateRevocation {
    const TYPE: u16 = 36;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct ValidateRevocationReply {}

impl TypedMessage for ValidateRevocationReply {
    const TYPE: u16 = 136;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignCommitmentTx {
    pub peer_id: PubKey,
    pub dbid: u64,
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub remote_funding_key: PubKey,
    pub commitment_number: u64,
}

impl TypedMessage for SignCommitmentTx {
    const TYPE: u16 = 5;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
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
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignDelayedPaymentToUs {
    pub commitment_number: u64,
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub wscript: Vec<u8>,
}

impl TypedMessage for SignDelayedPaymentToUs {
    const TYPE: u16 = 12;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignRemoteHtlcToUs {
    pub remote_per_commitment_point: PubKey,
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub wscript: Vec<u8>,
    pub option_anchor_outputs: bool,
}

impl TypedMessage for SignRemoteHtlcToUs {
    const TYPE: u16 = 13;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignLocalHtlcTx {
    pub commitment_number: u64,
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub wscript: Vec<u8>,
    pub option_anchor_outputs: bool,
}

impl TypedMessage for SignLocalHtlcTx {
    const TYPE: u16 = 16;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignMutualCloseTx {
    pub tx: LargeBytes,
    pub psbt: LargeBytes,
    pub remote_funding_key: PubKey,
}

impl TypedMessage for SignMutualCloseTx {
    const TYPE: u16 = 21;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignCommitmentTxReply {
    pub signature: BitcoinSignature,
}

impl TypedMessage for SignCommitmentTxReply {
    const TYPE: u16 = 105;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct SignTxReply {
    pub signature: BitcoinSignature,
}

impl TypedMessage for SignTxReply {
    const TYPE: u16 = 112;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct NewChannel {
    pub node_id: PubKey,
    pub dbid: u64,
}

impl TypedMessage for NewChannel {
    const TYPE: u16 = 30;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct NewChannelReply {}

impl TypedMessage for NewChannelReply {
    const TYPE: u16 = 130;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct GetChannelBasepoints {
    pub node_id: PubKey,
    pub dbid: u64,
}

impl TypedMessage for GetChannelBasepoints {
    const TYPE: u16 = 10;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
pub struct GetChannelBasepointsReply {
    pub basepoints: Basepoints,
    pub funding: PubKey,
}

impl TypedMessage for GetChannelBasepointsReply {
    const TYPE: u16 = 110;
}

///
#[derive(SerBolt, Debug, Serialize, Deserialize)]
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
#[derive(SerBolt, Debug, Serialize, Deserialize)]
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
    SignWithdrawal(SignWithdrawal),
    SignWithdrawalReply(SignWithdrawalReply),
    Ecdh(Ecdh),
    EcdhReply(EcdhReply),
    Memleak(Memleak),
    MemleakReply(MemleakReply),
    CheckFutureSecret(CheckFutureSecret),
    CheckFutureSecretReply(CheckFutureSecretReply),
    SignBolt12(SignBolt12),
    SignBolt12Reply(SignBolt12Reply),
    SignMessage(SignMessage),
    SignMessageReply(SignMessageReply),
    SignChannelUpdate(SignChannelUpdate),
    SignChannelUpdateReply(SignChannelUpdateReply),
    SignChannelAnnouncement(SignChannelAnnouncement),
    SignChannelAnnouncementReply(SignChannelAnnouncementReply),
    SignNodeAnnouncement(SignNodeAnnouncement),
    SignNodeAnnouncementReply(SignNodeAnnouncementReply),
    GetPerCommitmentPoint(GetPerCommitmentPoint),
    GetPerCommitmentPointReply(GetPerCommitmentPointReply),
    ReadyChannel(ReadyChannel),
    ReadyChannelReply(ReadyChannelReply),
    ValidateCommitmentTx(ValidateCommitmentTx),
    ValidateCommitmentTxReply(ValidateCommitmentTxReply),
    ValidateRevocation(ValidateRevocation),
    ValidateRevocationReply(ValidateRevocationReply),
    SignRemoteCommitmentTx(SignRemoteCommitmentTx),
    SignDelayedPaymentToUs(SignDelayedPaymentToUs),
    SignRemoteHtlcToUs(SignRemoteHtlcToUs),
    SignLocalHtlcTx(SignLocalHtlcTx),
    SignCommitmentTx(SignCommitmentTx),
    SignMutualCloseTx(SignMutualCloseTx),
    SignTxReply(SignTxReply),
    SignCommitmentTxReply(SignCommitmentTxReply),
    GetChannelBasepoints(GetChannelBasepoints),
    GetChannelBasepointsReply(GetChannelBasepointsReply),
    NewChannel(NewChannel),
    NewChannelReply(NewChannelReply),
    SignRemoteHtlcTx(SignRemoteHtlcTx),
    SignPenaltyToUs(SignPenaltyToUs),
    Unknown(Unknown),
}

fn from_vec_no_trailing<T: TypedMessage>(s: &mut Vec<u8>) -> Result<T>
where
    T: de::DeserializeOwned,
{
    let res: T = sb_from_vec(s)?;
    if !s.is_empty() {
        return Err(Error::TrailingBytes(T::TYPE));
    }
    Ok(res)
}

/// Read a length framed BOLT message:
///
/// - u32 packet length
/// - u16 packet type
/// - data
pub fn read<R: Read>(reader: &mut R) -> Result<Message> {
    let len = read_u32(reader)?;
    from_reader(reader, len)
}

/// Read a BOLT message from a vector:
///
/// - u16 packet type
/// - data
pub fn from_vec(mut v: Vec<u8>) -> Result<Message> {
    let len = v.len();
    from_reader(&mut v, len as u32)
}

/// Read a BOLT message from a reader:
///
/// - u16 packet type
/// - data
pub fn from_reader<R: Read>(reader: &mut R, len: u32) -> Result<Message> {
    let mut data = Vec::new();
    if len < 2 {
        return Err(Error::ShortRead);
    }
    data.resize(len as usize - 2, 0);
    let message_type = read_u16(reader)?;
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
        SignWithdrawal::TYPE => Message::SignWithdrawal(from_vec_no_trailing(&mut data)?),
        SignWithdrawalReply::TYPE => Message::SignWithdrawalReply(from_vec_no_trailing(&mut data)?),
        Ecdh::TYPE => Message::Ecdh(from_vec_no_trailing(&mut data)?),
        EcdhReply::TYPE => Message::EcdhReply(from_vec_no_trailing(&mut data)?),
        Memleak::TYPE => Message::Memleak(from_vec_no_trailing(&mut data)?),
        MemleakReply::TYPE => Message::MemleakReply(from_vec_no_trailing(&mut data)?),
        CheckFutureSecret::TYPE => Message::CheckFutureSecret(from_vec_no_trailing(&mut data)?),
        CheckFutureSecretReply::TYPE =>
            Message::CheckFutureSecretReply(from_vec_no_trailing(&mut data)?),
        SignBolt12::TYPE => Message::SignBolt12(from_vec_no_trailing(&mut data)?),
        SignBolt12Reply::TYPE => Message::SignBolt12Reply(from_vec_no_trailing(&mut data)?),
        SignMessage::TYPE => Message::SignMessage(from_vec_no_trailing(&mut data)?),
        SignMessageReply::TYPE => Message::SignMessageReply(from_vec_no_trailing(&mut data)?),
        SignChannelUpdate::TYPE => Message::SignChannelUpdate(from_vec_no_trailing(&mut data)?),
        SignChannelUpdateReply::TYPE =>
            Message::SignChannelUpdateReply(from_vec_no_trailing(&mut data)?),
        SignChannelAnnouncement::TYPE =>
            Message::SignChannelAnnouncement(from_vec_no_trailing(&mut data)?),
        SignChannelAnnouncementReply::TYPE =>
            Message::SignChannelAnnouncementReply(from_vec_no_trailing(&mut data)?),
        SignNodeAnnouncement::TYPE =>
            Message::SignNodeAnnouncement(from_vec_no_trailing(&mut data)?),
        SignNodeAnnouncementReply::TYPE =>
            Message::SignNodeAnnouncementReply(from_vec_no_trailing(&mut data)?),
        GetPerCommitmentPoint::TYPE =>
            Message::GetPerCommitmentPoint(from_vec_no_trailing(&mut data)?),
        GetPerCommitmentPointReply::TYPE =>
            Message::GetPerCommitmentPointReply(from_vec_no_trailing(&mut data)?),
        ReadyChannel::TYPE => Message::ReadyChannel(from_vec_no_trailing(&mut data)?),
        ReadyChannelReply::TYPE => Message::ReadyChannelReply(from_vec_no_trailing(&mut data)?),
        ValidateCommitmentTx::TYPE =>
            Message::ValidateCommitmentTx(from_vec_no_trailing(&mut data)?),
        ValidateCommitmentTxReply::TYPE =>
            Message::ValidateCommitmentTxReply(from_vec_no_trailing(&mut data)?),
        ValidateRevocation::TYPE => Message::ValidateRevocation(from_vec_no_trailing(&mut data)?),
        ValidateRevocationReply::TYPE =>
            Message::ValidateRevocationReply(from_vec_no_trailing(&mut data)?),
        SignRemoteCommitmentTx::TYPE =>
            Message::SignRemoteCommitmentTx(from_vec_no_trailing(&mut data)?),
        SignDelayedPaymentToUs::TYPE =>
            Message::SignDelayedPaymentToUs(from_vec_no_trailing(&mut data)?),
        SignRemoteHtlcToUs::TYPE => Message::SignRemoteHtlcToUs(from_vec_no_trailing(&mut data)?),
        SignLocalHtlcTx::TYPE => Message::SignLocalHtlcTx(from_vec_no_trailing(&mut data)?),
        SignCommitmentTx::TYPE => Message::SignCommitmentTx(from_vec_no_trailing(&mut data)?),
        SignMutualCloseTx::TYPE => Message::SignMutualCloseTx(from_vec_no_trailing(&mut data)?),
        SignCommitmentTxReply::TYPE =>
            Message::SignCommitmentTxReply(from_vec_no_trailing(&mut data)?),
        SignTxReply::TYPE => Message::SignTxReply(from_vec_no_trailing(&mut data)?),
        GetChannelBasepoints::TYPE =>
            Message::GetChannelBasepoints(from_vec_no_trailing(&mut data)?),
        GetChannelBasepointsReply::TYPE =>
            Message::GetChannelBasepointsReply(from_vec_no_trailing(&mut data)?),
        NewChannel::TYPE => Message::NewChannel(from_vec_no_trailing(&mut data)?),
        NewChannelReply::TYPE => Message::NewChannelReply(from_vec_no_trailing(&mut data)?),
        SignRemoteHtlcTx::TYPE => Message::SignRemoteHtlcTx(from_vec_no_trailing(&mut data)?),
        SignPenaltyToUs::TYPE => Message::SignPenaltyToUs(from_vec_no_trailing(&mut data)?),
        _ => Message::Unknown(Unknown { message_type, data: data.clone() }),
    };
    Ok(message)
}

#[cfg(test)]
fn read_message_and_data<R: Read>(reader: &mut R) -> Result<(Message, Vec<u8>)> {
    let len = read_u32(reader)?;
    let mut data = Vec::new();
    if len < 2 {
        return Err(Error::ShortRead);
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
    let message_type = T::TYPE;
    let mut buf = message_type.to_be_bytes().to_vec();
    let mut val_buf = to_vec(&value)?;
    buf.append(&mut val_buf);
    write_vec(writer, buf)
}

pub fn write_vec<W: Write>(writer: &mut W, buf: Vec<u8>) -> Result<()> {
    let len: u32 = buf.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
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
    fn roundtrip_test() {
        let msg = SignChannelAnnouncementReply {
            node_signature: Signature([0; 64]),
            bitcoin_signature: Signature([1; 64]),
        };

        let ser = msg.as_vec();
        let dmsg = from_vec(ser).unwrap();
        if let Message::SignChannelAnnouncementReply(dmsg) = dmsg {
            assert_eq!(dmsg.node_signature.0, msg.node_signature.0);
            assert_eq!(dmsg.bitcoin_signature.0, msg.bitcoin_signature.0);
        } else {
            panic!("bad deser type")
        }
    }

    // ignore tests for now, the trace capture was not on the lightning-signer branch
    #[test]
    #[ignore]
    fn parse_read_fixtures_test() {
        assert_eq!(parse_fixture("r_3"), 16);
        assert_eq!(parse_fixture("r_5"), 1);
        assert_eq!(parse_fixture("r_6"), 39);
    }

    // ignore tests for now, the trace capture was not on the lightning-signer branch
    #[test]
    #[ignore]
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
        let contents_with_whitespace =
            fs::read_to_string(format!("fixtures/{}.hex", fixture)).unwrap();
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
