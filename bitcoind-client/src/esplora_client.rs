use crate::{Error, Explorer};
use async_trait::async_trait;
use lightning_signer::bitcoin;
use lightning_signer::bitcoin::hashes::hex::ToHex;
use lightning_signer::bitcoin::psbt::serialize::Serialize;
use lightning_signer::lightning::chain::transaction::OutPoint;
use log::info;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

/// Async client for RPC to Esplora block explorer
#[derive(Clone, Debug)]
pub struct EsploraClient {
    rpc: Arc<Mutex<Client>>,
    url: Url,
}

impl EsploraClient {
    /// Create a new EsploraClient
    pub async fn new(url: Url) -> Self {
        let builder = Client::builder();
        let rpc = builder.build().unwrap();
        let client = Self { rpc: Arc::new(Mutex::new(rpc)), url };
        client
    }

    async fn get<T: for<'a> serde::de::Deserialize<'a>>(&self, path: &str) -> Result<T, Error> {
        let rpc = self.rpc.lock().await;
        let res = rpc
            .get(&format!("{}/{}", self.url, path))
            .send()
            .await
            .map_err(|e| Error::Esplora(e.to_string()))?;
        if res.status().is_server_error() || res.status().is_client_error() {
            return Err(Error::Esplora(format!(
                "server error: {} {}",
                res.status(),
                res.text().await.unwrap()
            )));
        }
        let res = res.json::<T>().await.map_err(|e| Error::Esplora(e.to_string()))?;
        Ok(res)
    }

    #[allow(unused)]
    async fn post<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        path: &str,
        body: String,
    ) -> Result<T, Error> {
        let rpc = self.rpc.lock().await;
        let res = rpc
            .post(&format!("{}/{}", self.url, path))
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Esplora(e.to_string()))?;
        if res.status().is_server_error() || res.status().is_client_error() {
            return Err(Error::Esplora(format!(
                "server error: {} {}",
                res.status(),
                res.text().await.unwrap()
            )));
        }
        let res = res.json::<T>().await.map_err(|e| Error::Esplora(e.to_string()))?;
        Ok(res)
    }

    async fn post_returning_body(&self, path: &str, body: String) -> Result<String, Error> {
        let rpc = self.rpc.lock().await;
        let res = rpc
            .post(&format!("{}/{}", self.url, path))
            .body(body)
            .send()
            .await
            .map_err(|e| Error::Esplora(e.to_string()))?;
        if res.status().is_server_error() || res.status().is_client_error() {
            return Err(Error::Esplora(format!(
                "server error: {} {}",
                res.status(),
                res.text().await.unwrap()
            )));
        }
        Ok(res.text().await.map_err(|e| Error::Esplora(e.to_string()))?)
    }
}

#[derive(serde::Deserialize, Debug)]
struct TxOutResponse {
    spent: bool,
}

#[derive(serde::Deserialize, Debug)]
struct TxResponse {
    confirmed: bool,
    block_height: Option<u64>,
}

#[async_trait]
impl Explorer for EsploraClient {
    async fn get_utxo_confirmations(&self, txout: &OutPoint) -> Result<Option<u64>, Error> {
        let txout_res: TxOutResponse =
            self.get(&format!("/tx/{}/outspend/{}", txout.txid, txout.index)).await?;
        if txout_res.spent {
            Ok(None)
        } else {
            let tx_res: TxResponse = self.get(&format!("/tx/{}/status", txout.txid)).await?;
            if tx_res.confirmed {
                let chain_height: u64 = self.get("/blocks/tip/height").await?;
                Ok(Some(chain_height - tx_res.block_height.unwrap() + 1))
            } else {
                Ok(None)
            }
        }
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        let txid: String = self.post_returning_body("/tx", tx.serialize().to_hex()).await?;
        info!("broadcasted txid: {}", txid);
        Ok(())
    }
}
