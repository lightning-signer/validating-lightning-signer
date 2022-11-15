use bitcoind_client::esplora_client::EsploraClient;
use bitcoind_client::Explorer;
use lightning_signer::bitcoin::hashes::hex::FromHex;
use lightning_signer::bitcoin::psbt::serialize::Deserialize;
use lightning_signer::bitcoin::{Transaction, Txid};
use lightning_signer::lightning::chain::transaction::OutPoint;
use url::Url;

#[tokio::main]
async fn main() {
    let client = EsploraClient::new(Url::parse("https://blockstream.info/api").unwrap()).await;
    let txid =
        Txid::from_hex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098").unwrap();
    let index = 0;
    let res = client.get_utxo_confirmations(&OutPoint { txid, index }).await.unwrap();
    println!("res: {:?}", res);
    let tx = Transaction::deserialize(&Vec::from_hex("02000000000101cd8623d06e3a041eb40f4447b06ba262e8e60941bc41ae4bf1daa337751a68880100000017160014e2ca7f632f16affddab5a50706b6be142f7a081afdffffff02d7e565000000000017a91453809507ee2c6a8a00e714b898d5e4b96caa8dbb87cbf43d000000000017a914fe9254d18d000f1a77869b423d9b37a1c747557a87024730440220029eec48b094ebfa23840df3f9ab7c2221b3fb9b960c00b0374324f82958644202206349af61db4f9fd6245cff3c54ab2340b13f0256c416706e8e11288649c50cdb0121033f06c1f39b25d7d03d8ab60fce91807a4fafdabd0358ffd9d90991111a187713a3a50b00").unwrap()).unwrap();
    let result = client.broadcast_transaction(&tx).await;
    println!("result: {:?}", result);
}
