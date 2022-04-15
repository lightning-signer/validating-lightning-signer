use core::fmt;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::uint::Uint256;
use bitcoin::{Block, BlockHash, BlockHeader};
use jsonrpc_async::error::Error::Rpc;
use jsonrpc_async::simple_http::SimpleHttpTransport;
use jsonrpc_async::Client;
use lightning_signer::bitcoin;
use log::{self, error};
use serde;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::convert::{BlockchainInfo, JsonResponse};

/// Async client for RPC to bitcoin core daemon
#[derive(Clone, Debug)]
pub struct BitcoindClient {
    rpc: Arc<Mutex<Client>>,
    host: String,
    port: u16,
}

/// RPC errors
#[derive(Debug)]
pub enum Error {
    /// JSON RPC Error
    JsonRpc(jsonrpc_async::error::Error),
    /// JSON Error
    Json(serde_json::error::Error),
    /// IO Error
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(format!("{:?}", self).as_str())
    }
}

impl std::error::Error for Error {}

impl From<jsonrpc_async::error::Error> for Error {
    fn from(e: jsonrpc_async::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

/// BitcoindClient Error
pub type BitcoindClientResult<T> = Result<T, Error>;

impl BitcoindClient {
    /// Create a new BitcoindClient
    pub async fn new(host: String, port: u16, rpc_user: String, rpc_password: String) -> Self {
        let url = format!("http://{}:{}", host, port);
        let mut builder = SimpleHttpTransport::builder().url(&url).await.unwrap();
        builder = builder.auth(rpc_user, Some(rpc_password));
        let rpc = Client::with_transport(builder.build());
        let client = Self { rpc: Arc::new(Mutex::new(rpc)), host, port };
        client
    }

    /// Make a getblockchaininfo RPC call
    pub async fn get_blockchain_info(&self) -> BitcoindClientResult<BlockchainInfo> {
        Ok(self.call_into("getblockchaininfo", &[]).await?)
    }

    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T, Error> {
        let rpc = self.rpc.lock().await;
        let v_args: Vec<_> = args
            .iter()
            .map(serde_json::value::to_raw_value)
            .collect::<std::result::Result<_, serde_json::Error>>()?;
        let req = rpc.build_request(cmd, &v_args[..]);
        log::trace!("JSON-RPC request: {} {}", cmd, serde_json::Value::from(args));

        let res = rpc.send_request(req).await;
        let resp = res.map_err(Error::from);
        if let Err(ref err) = resp {
            error!("{}: {}:{}: {}", cmd, self.host, self.port, err);
        }
        // log_response(cmd, &resp);
        Ok(resp?.result()?)
    }

    async fn call_into<T>(&self, cmd: &str, args: &[serde_json::Value]) -> Result<T, Error>
    where
        JsonResponse: TryInto<T, Error = std::io::Error>,
    {
        let value: Value = self.call(cmd, args).await?;
        Ok(JsonResponse(value).try_into()?)
    }
}

/// BlockSource Error
pub type BlockSourceResult<T> = Result<T, Error>;

/// Abstract type for retrieving block headers and data.
#[async_trait]
pub trait BlockSource: Sync + Send {
    /// Returns the header for a given hash. A height hint may be provided in case a block source
    /// cannot easily find headers based on a hash. This is merely a hint and thus the returned
    /// header must have the same hash as was requested. Otherwise, an error must be returned.
    ///
    /// Implementations that cannot find headers based on the hash should return a `Transient` error
    /// when `height_hint` is `None`.
    async fn get_header(
        &self,
        header_hash: &BlockHash,
        height_hint: Option<u32>,
    ) -> BlockSourceResult<BlockHeaderData>;

    /// Returns the block for a given hash. A headers-only block source should return a `Transient`
    /// error.
    async fn get_block(&self, header_hash: &BlockHash) -> BlockSourceResult<Block>;

    /// Returns hash of block in best-block-chain at height provided.
    async fn get_block_hash(&self, height: u32) -> BlockSourceResult<Option<BlockHash>>;

    /// Returns the hash of the best block and, optionally, its height.
    ///
    /// When polling a block source, [`Poll`] implementations may pass the height to [`get_header`]
    /// to allow for a more efficient lookup.
    ///
    /// [`get_header`]: Self::get_header
    async fn get_best_block(&self) -> BlockSourceResult<(BlockHash, u32)>;
}

/// A block header and some associated data. This information should be available from most block
/// sources (and, notably, is available in Bitcoin Core's RPC and REST interfaces).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockHeaderData {
    /// The block header itself.
    pub header: BlockHeader,

    /// The block height where the genesis block has height 0.
    pub height: u32,

    /// The total chain work in expected number of double-SHA256 hashes required to build a chain
    /// of equivalent weight.
    pub chainwork: Uint256,
}

#[async_trait]
impl BlockSource for BitcoindClient {
    async fn get_header(
        &self,
        header_hash: &BlockHash,
        _height_hint: Option<u32>,
    ) -> BlockSourceResult<BlockHeaderData> {
        Ok(self.call_into("getblockheader", &[json!(header_hash.to_hex())]).await?)
    }

    async fn get_block(&self, header_hash: &BlockHash) -> BlockSourceResult<Block> {
        Ok(self.call_into("getblock", &[json!(header_hash.to_hex()), json!(0)]).await?)
    }

    async fn get_block_hash(&self, height: u32) -> BlockSourceResult<Option<BlockHash>> {
        let result = self.call_into("getblockhash", &[json!(height)]).await;
        match result {
            Ok(r) => Ok(r),
            Err(e) => match e {
                Error::JsonRpc(Rpc(ref rpce)) =>
                    if rpce.code == -8 {
                        Ok(None)
                    } else {
                        Err(e)
                    },
                _ => Err(e),
            },
        }
    }

    async fn get_best_block(&self) -> BlockSourceResult<(BlockHash, u32)> {
        let info = self.get_blockchain_info().await?;
        Ok((info.latest_blockhash, info.latest_height as u32))
    }
}
