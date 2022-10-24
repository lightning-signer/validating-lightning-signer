use bitcoin::consensus::Decodable;
use bitcoin::psbt::serialize::Deserialize;
use lightning_signer::bitcoin;
use std::env::args;
use vls_protocol::msgs::SignMutualCloseTx;
use vls_protocol::msgs::{self, Message};

pub fn main() {
    let msg_hex = args().nth(1).expect("usage: decode-vls <message-hex>");
    let msg = msgs::from_vec(hex::decode(msg_hex).unwrap()).unwrap();
    match msg {
        Message::SignMutualCloseTx(SignMutualCloseTx {
            tx: tx_bytes, psbt: psbt_bytes, ..
        }) => {
            let tx = bitcoin::Transaction::deserialize(&tx_bytes.0).unwrap();
            let psbt = bitcoin::psbt::PartiallySignedTransaction::consensus_decode(
                &mut psbt_bytes.0.as_slice(),
            )
            .unwrap();
            println!("SignMutualCloseTxRequest {} {:?} {:?}", hex::encode(tx_bytes.0), tx, psbt);
        }
        msg => {
            println!("{:?}", msg);
        }
    }
}
