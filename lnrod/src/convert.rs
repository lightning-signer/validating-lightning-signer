use std::convert::TryFrom;
use std::str::FromStr;

use bitcoin::BlockHash;
use lightning_block_sync::http::JsonResponse;
use lightning_signer::bitcoin;

pub struct FundedTx {
    pub changepos: i64,
    pub hex: String,
}

impl TryFrom<JsonResponse> for FundedTx {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self {
            changepos: item.0["changepos"].as_i64().unwrap(),
            hex: item.0["hex"].as_str().unwrap().to_string(),
        })
    }
}

pub struct RawTx(pub String);

impl TryFrom<JsonResponse> for RawTx {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self(item.0.as_str().unwrap().to_string()))
    }
}

pub struct SignedTx {
    pub complete: bool,
    pub hex: String,
}

impl TryFrom<JsonResponse> for SignedTx {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self {
            hex: item.0["hex"].as_str().unwrap().to_string(),
            complete: item.0["complete"].as_bool().unwrap(),
        })
    }
}

#[allow(dead_code)]
pub struct NewAddress(pub String);

impl TryFrom<JsonResponse> for NewAddress {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self(item.0.as_str().unwrap().to_string()))
    }
}

#[allow(dead_code)]
pub struct FeeResponse {
    pub feerate: Option<u32>,
    pub errored: bool,
}

impl TryFrom<JsonResponse> for FeeResponse {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        let errored = !item.0["errors"].is_null();
        Ok(Self {
            errored,
            feerate: match errored {
                true => None,
                // The feerate from bitcoind is in BTC/kb, and we want satoshis/kb.
                false => Some((item.0["feerate"].as_f64().unwrap() * 100_000_000.0).round() as u32),
            },
        })
    }
}

pub struct BlockchainInfo {
    pub latest_height: usize,
    pub latest_blockhash: BlockHash,
}

impl TryFrom<JsonResponse> for BlockchainInfo {
    type Error = std::io::Error;
    fn try_from(item: JsonResponse) -> std::io::Result<Self> {
        Ok(Self {
            latest_height: item.0["blocks"].as_u64().unwrap() as usize,
            latest_blockhash: BlockHash::from_str(item.0["bestblockhash"].as_str().unwrap())
                .unwrap(),
        })
    }
}
