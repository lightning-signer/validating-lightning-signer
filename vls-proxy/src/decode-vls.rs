use bitcoin::psbt::serialize::Deserialize;
use lightning_signer::bitcoin;
use std::env::args;
use vls_protocol::msgs::SignMutualCloseTx;
use vls_protocol::msgs::{self, Message};

pub fn main() {
    let msg_hex = args().nth(1).expect("usage: decode-vls <message-hex>");
    let msg = msgs::from_vec(hex::decode(msg_hex).unwrap()).unwrap();
    match msg {
        Message::SignMutualCloseTx(SignMutualCloseTx { tx: tx_bytes, psbt, .. }) => {
            let tx = bitcoin::Transaction::deserialize(&tx_bytes.0).unwrap();
            println!("SignMutualCloseTxRequest {} {:?} {:?}", hex::encode(tx_bytes.0), tx, psbt.0);
        }
        msg => {
            println!("{:?}", msg);
        }
    }
}
