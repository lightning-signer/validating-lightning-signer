use std::convert::{TryFrom, TryInto};

use bitcoin::consensus::encode;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::Hash;
use bitcoin::util::uint::Uint256;
use bitcoin::{Block, BlockHash, BlockHeader, TxMerkleNode};
use serde::Deserialize;

use lightning_signer::bitcoin;

use crate::bitcoind_client::BlockHeaderData;

pub struct JsonResponse(pub serde_json::Value);

pub struct RawTx(pub String);

impl TryFrom<JsonResponse> for RawTx {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self(item.0.as_str().unwrap().to_string()))
    }
}

#[derive(Debug)]
pub struct BlockchainInfo {
    pub latest_height: usize,
    pub latest_blockhash: BlockHash,
}

impl TryFrom<JsonResponse> for BlockchainInfo {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self {
            latest_height: item.0["blocks"].as_u64().unwrap() as usize,
            latest_blockhash: BlockHash::from_hex(item.0["bestblockhash"].as_str().unwrap())
                .unwrap(),
        })
    }
}

impl TryInto<Option<BlockHash>> for JsonResponse {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Option<BlockHash>, Self::Error> {
        match self.0.as_str() {
            None => Ok(None),
            Some(s) => Ok(Some(BlockHash::from_hex(s).unwrap())),
        }
    }
}

pub fn hex_to_uint256(hex: &str) -> Result<Uint256, bitcoin::hashes::hex::Error> {
    let bytes = <[u8; 32]>::from_hex(hex)?;
    Ok(Uint256::from_be_bytes(bytes))
}

/// Response data from `getblockheader` RPC and `headers` REST requests.
#[derive(Deserialize)]
struct GetHeaderResponse {
    pub version: i32,
    pub merkleroot: String,
    pub time: u32,
    pub nonce: u32,
    pub bits: String,
    pub previousblockhash: String,

    pub chainwork: String,
    pub height: u32,
}

/// Converts from `GetHeaderResponse` to `BlockHeaderData`.
impl TryFrom<GetHeaderResponse> for BlockHeaderData {
    type Error = bitcoin::hashes::hex::Error;

    fn try_from(response: GetHeaderResponse) -> Result<Self, bitcoin::hashes::hex::Error> {
        Ok(BlockHeaderData {
            header: BlockHeader {
                version: response.version,
                prev_blockhash: BlockHash::from_hex(&response.previousblockhash)?,
                merkle_root: TxMerkleNode::from_hex(&response.merkleroot)?,
                time: response.time,
                bits: u32::from_be_bytes(<[u8; 4]>::from_hex(&response.bits)?),
                nonce: response.nonce,
            },
            chainwork: hex_to_uint256(&response.chainwork)?,
            height: response.height,
        })
    }
}

/// Converts a JSON value into block header data. The JSON value may be an object representing a
/// block header or an array of such objects. In the latter case, the first object is converted.
impl TryInto<BlockHeaderData> for JsonResponse {
    type Error = std::io::Error;

    fn try_into(self) -> std::io::Result<BlockHeaderData> {
        let mut header = match self.0 {
            serde_json::Value::Array(mut array) if !array.is_empty() =>
                array.drain(..).next().unwrap(),
            serde_json::Value::Object(_) => self.0,
            _ =>
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected JSON type",
                )),
        };

        if !header.is_object() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected JSON object",
            ));
        }

        // Add an empty previousblockhash for the genesis block.
        if let None = header.get("previousblockhash") {
            let hash: BlockHash = BlockHash::all_zeros();
            header
                .as_object_mut()
                .unwrap()
                .insert("previousblockhash".to_string(), serde_json::json!(hash.to_hex()));
        }

        match serde_json::from_value::<GetHeaderResponse>(header) {
            Err(_) =>
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header response")),
            Ok(response) => match response.try_into() {
                Err(_) =>
                    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid header data")),
                Ok(header) => Ok(header),
            },
        }
    }
}

/// Converts a JSON value into a block. Assumes the block is hex-encoded in a JSON string.
impl TryInto<Block> for JsonResponse {
    type Error = std::io::Error;

    fn try_into(self) -> std::io::Result<Block> {
        match self.0.as_str() {
            None =>
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected JSON string")),
            Some(hex_data) => match Vec::<u8>::from_hex(hex_data) {
                Err(_) =>
                    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex data")),
                Ok(block_data) => match encode::deserialize(&block_data) {
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid block data",
                    )),
                    Ok(block) => Ok(block),
                },
            },
        }
    }
}
